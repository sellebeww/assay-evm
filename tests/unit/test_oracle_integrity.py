"""IntegrityOracle: every detection, on small synthetic contracts and on the fixture patches."""

import difflib
import shutil
from pathlib import Path

import pytest

from assay.ingest import Snapshot, create_snapshot
from assay.ingest.patch import (
    PatchPolicy,
    PreparedPatch,
    parse_patch,
    prepare_patched_revision,
)
from assay.ledger import RevisionKind, Verdict
from assay.oracles.base import OracleResult
from assay.oracles.integrity import IntegrityContext, IntegrityOracle, is_hard
from assay.oracles.integrity.solidity import (
    always_reverts,
    contracts,
    imports,
    literals,
    mask,
    modifier_bricks,
    statements,
)
from assay.oracles.runtree import load_harness

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures" / "reentrancy" / "single_function"

BANK = """\
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @notice A small bank. The number 1000 appears in the vulnerable sources.
contract Bank {
    mapping(address account => uint256 amount) public balanceOf;
    address public owner;
    uint256 public constant FEE = 1000;

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "balance");
        (bool sent,) = msg.sender.call{value: amount}("");
        require(sent, "send");
        balanceOf[msg.sender] -= amount;
    }

    function sweep(address to) external onlyOwner {
        payable(to).transfer(address(this).balance);
    }

    function total() external view returns (uint256) {
        return address(this).balance;
    }
}
"""

POC = """\
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Bank} from "../src/Bank.sol";

contract BankExploit {
    address internal constant HELPER = 0x00000000000000000000000000000000DeaDBeef;
    bytes4 internal constant WITHDRAW = 0x2e1a7d4d;

    function run(Bank bank) external {
        uint256 knob = 7_777;
        uint256 small = 5;
        uint256 fee = 1000;
        bank.withdraw(1 ether + knob + small + fee);
    }
}
"""


def diff(path: str, before: str, after: str) -> bytes:
    lines = difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True), f"a/{path}", f"b/{path}"
    )
    return "".join(lines).encode()


def write(root: Path, files: dict[str, str]) -> Path:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return root


def check(
    tmp_path: Path,
    patched: str,
    *,
    base: str = BANK,
    poc: str = POC,
    extra: dict[str, str] | None = None,
) -> OracleResult:
    """Run the oracle on a patch that turns `base` into `patched` (src/Bank.sol)."""
    project = write(
        tmp_path / "project",
        {"src/Bank.sol": base, "test/Bank.t.sol": "contract BankTest {}\n", **(extra or {})},
    )
    poc_dir = write(tmp_path / "poc", {"BankExploit.t.sol": poc})
    base_snapshot = create_snapshot(project, tmp_path / "base")
    poc_snapshot = create_snapshot(poc_dir, tmp_path / "poc-snapshot")
    data = diff("src/Bank.sol", base, patched)
    prepared = prepare_patched_revision(base_snapshot, data, tmp_path / "patched")
    assert prepared.snapshot is not None, prepared.problems
    return run_oracle(base_snapshot, poc_snapshot, prepared)


def run_oracle(base: Snapshot, poc: Snapshot, prepared: PreparedPatch) -> OracleResult:
    context = IntegrityContext(
        base=base, poc=poc, prepared=prepared, policy=PatchPolicy(), harness=load_harness()
    )
    return IntegrityOracle().run(context)


def details(result: OracleResult, code: str) -> list[str]:
    return [item.detail for item in result.reasons if item.code == code]


# -- the Solidity reader ----------------------------------------------------------------------


def test_mask_keeps_offsets_and_lines() -> None:
    source = "a = \"x // y\"; // comment\n/* block\n 1 ether */ b = 'q';\n"
    masked = mask(source)
    assert len(masked) == len(source)
    assert masked.count("\n") == source.count("\n")
    assert "comment" not in masked
    assert "ether" not in masked
    assert '"' in masked
    assert "x // y" not in masked
    assert "x // y" in mask(source, keep_strings=True)


def test_contracts_functions_and_modifiers_are_found() -> None:
    (bank,) = contracts(BANK)
    assert (bank.kind, bank.name) == ("contract", "Bank")
    assert set(bank.functions) == {"deposit()", "withdraw(uint256)", "sweep(address)", "total()"}
    sweep = bank.functions["sweep(address)"]
    assert (sweep.visibility, sweep.modifiers, sweep.external) == ("external", ("onlyOwner",), True)
    assert bank.functions["total()"].mutability == "view"
    assert bank.functions["withdraw(uint256)"].line == 19
    assert set(bank.modifiers) == {"onlyOwner"}
    assert bank.external_calls == 2


def test_statements_and_reverts() -> None:
    body = "if (a) { revert(); } else { x = 1; }\nrequire(b);\nunchecked { y++; }\nreturn;"
    assert statements(body) == [
        "if (a) { revert(); } else { x = 1; }",
        "require(b);",
        "unchecked { y++; }",
        "return;",
    ]
    assert not always_reverts("if (a) revert(); x = 1;")
    assert always_reverts("x = 1; revert Paused();")
    assert always_reverts("require(false, 'off');")
    assert always_reverts("assert(false);")
    assert always_reverts("require(1 == 2);")
    assert not always_reverts("require(2 == 2); x = 1;")
    assert not always_reverts("return 1; revert();")
    assert modifier_bricks("require(msg.sender == owner); _;") is None
    assert modifier_bricks("x = 1;") is not None
    assert modifier_bricks("require(msg.sender == address(0)); _;") is not None


def test_literals_are_read_with_their_values() -> None:
    found = literals(
        mask("pragma solidity 0.8.36; x = 1 ether + 0.01 ether + 10_000 + 1e18 + 0x10 + 2 days;")
    )
    assert [(item.kind, item.value) for item in found] == [
        ("number", 10**18),
        ("number", 10**16),
        ("number", 10_000),
        ("number", 10**18),
        ("number", 16),
        ("number", 2 * 86400),
    ]
    (address,) = literals("a = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;")
    assert address.kind == "address"
    (selector,) = literals("s = 0x2e1a7d4d;")
    assert selector.kind == "selector"
    assert literals("uint256 knob0 = x2;") == []


def test_imports_ignore_comments() -> None:
    source = '// import "forge-std/Test.sol";\nimport {A} from "./A.sol";\nimport "b/B.sol";\n'
    assert imports(source) == [("./A.sol", 2), ("b/B.sol", 3)]


# -- fixture patches --------------------------------------------------------------------------


Inputs = tuple[Snapshot, Snapshot]


@pytest.fixture
def fixture_inputs(tmp_path: Path) -> Inputs:
    base = create_snapshot(FIXTURE, tmp_path / "base")
    poc = create_snapshot(FIXTURE / "poc", tmp_path / "poc")
    return base, poc


@pytest.mark.parametrize("label", ["good", "overfit", "regressing"])
def test_fixture_patches_that_keep_behavior_pass(
    tmp_path: Path,
    fixture_inputs: Inputs,
    label: str,
) -> None:
    base, poc = fixture_inputs
    data = (FIXTURE / "patches" / f"{label}.diff").read_bytes()
    result = run_oracle(base, poc, prepare_patched_revision(base, data, tmp_path / label))
    assert result.verdict is Verdict.PASS, result.reasons
    (execution,) = result.executions
    assert execution.revision is RevisionKind.PATCHED
    assert (execution.argv, execution.seed, execution.exit_code) == ((), None, None)


def test_the_destructive_fixture_patch_is_vacuous(
    tmp_path: Path,
    fixture_inputs: Inputs,
) -> None:
    base, poc = fixture_inputs
    data = (FIXTURE / "patches" / "destructive.diff").read_bytes()
    result = run_oracle(base, poc, prepare_patched_revision(base, data, tmp_path / "d"))
    assert result.verdict is Verdict.FAIL
    assert result.codes() == ["vacuous_patch"]
    assert not is_hard(result)


def test_an_empty_patch_passes(tmp_path: Path, fixture_inputs: Inputs) -> None:
    base, poc = fixture_inputs
    result = run_oracle(base, poc, prepare_patched_revision(base, b"", tmp_path / "e"))
    assert result.verdict is Verdict.PASS


def test_the_result_is_deterministic(tmp_path: Path, fixture_inputs: Inputs) -> None:
    base, poc = fixture_inputs
    data = (FIXTURE / "patches" / "destructive.diff").read_bytes()
    first = run_oracle(base, poc, prepare_patched_revision(base, data, tmp_path / "1"))
    second = run_oracle(base, poc, prepare_patched_revision(base, data, tmp_path / "2"))
    assert first == second
    assert str(tmp_path) not in first.model_dump_json()


# -- patches that are not accepted ------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "code", "hard"),
    [
        (b"--- a/../x.sol\n+++ b/../x.sol\n@@ -1 +1 @@\n-a\n+b\n", "path_traversal", True),
        (
            b"diff --git a/src/L.sol b/src/L.sol\nnew file mode 120000\n--- /dev/null\n"
            b"+++ b/src/L.sol\n@@ -0,0 +1 @@\n+/etc/passwd\n",
            "symlink",
            True,
        ),
        (b"Binary files a/src/x and b/src/x differ\n", "binary_file", True),
        (
            b"--- a/test/Vault.t.sol\n+++ b/test/Vault.t.sol\n@@ -1 +1 @@\n-a\n+b\n",
            "protected_path_modified",
            True,
        ),
        (
            b"--- a/poc/VaultReentrancy.t.sol\n+++ b/poc/VaultReentrancy.t.sol\n"
            b"@@ -1 +1 @@\n-a\n+b\n",
            "protected_path_modified",
            True,
        ),
        (b"--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-a\n+b\n", "out_of_scope", True),
        (b"not a patch\n", "malformed_patch", False),
        (
            b"--- a/src/Vault.sol\n+++ b/src/Vault.sol\n@@ -1 +1 @@\n-x\n+y\n",
            "patch_does_not_apply",
            False,
        ),
    ],
)
def test_rejected_patches_fail_integrity(
    tmp_path: Path,
    fixture_inputs: Inputs,
    data: bytes,
    code: str,
    hard: bool,
) -> None:
    base, poc = fixture_inputs
    result = run_oracle(base, poc, prepare_patched_revision(base, data, tmp_path / "p"))
    assert result.verdict is Verdict.FAIL
    assert code in result.codes()
    assert is_hard(result) is hard
    assert result.executions[0].revision is RevisionKind.VULNERABLE


def test_a_changed_protected_file_is_detected_by_hash(
    tmp_path: Path,
    fixture_inputs: Inputs,
) -> None:
    base, poc = fixture_inputs
    altered = tmp_path / "altered"
    shutil.copytree(base.tree_dir, altered)
    (altered / "test" / "Vault.t.sol").write_text("// replaced\n")
    snapshot = create_snapshot(altered, tmp_path / "altered-snapshot")
    prepared = PreparedPatch(
        patch=parse_patch(b""), sha256="0" * 64, problems=(), snapshot=snapshot
    )
    result = run_oracle(base, poc, prepared)
    assert result.verdict is Verdict.FAIL
    assert [(item.code, item.path) for item in result.reasons] == [
        ("protected_path_modified", "test/Vault.t.sol")
    ]
    assert is_hard(result)


# -- vacuous patches --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        (
            "    function deposit() external payable {\n"
            "        balanceOf[msg.sender] += msg.value;\n    }\n",
            "",
            "removes the external function Bank.deposit()",
        ),
        (
            "function deposit() external payable",
            "function deposit() internal",
            "makes Bank.deposit() internal",
        ),
        (
            'require(balanceOf[msg.sender] >= amount, "balance");',
            'revert("paused");',
            "Bank.withdraw(uint256) now always reverts",
        ),
        (
            'require(balanceOf[msg.sender] >= amount, "balance");',
            'require(false, "off");',
            "Bank.withdraw(uint256) now always reverts",
        ),
        ("balanceOf[msg.sender] += msg.value;", "assert(false);", "now always reverts"),
        ("balanceOf[msg.sender] += msg.value;", "require(1 == 2);", "now always reverts"),
        ("balanceOf[msg.sender] += msg.value;", "", "empties the body of Bank.deposit()"),
        ("balanceOf[msg.sender] += msg.value;", "return;", "empties the body of Bank.deposit()"),
    ],
)
def test_vacuous_changes_are_detected(tmp_path: Path, old: str, new: str, expected: str) -> None:
    assert old in BANK
    result = check(tmp_path, BANK.replace(old, new))
    assert result.verdict is Verdict.FAIL
    assert any(expected in detail for detail in details(result, "vacuous_patch")), result.reasons


@pytest.mark.parametrize(
    ("modifier", "why"),
    [
        ('modifier paused() {\n        revert("paused");\n        _;\n    }', "always reverts"),
        (
            "modifier paused() {\n        require(msg.sender == address(0));\n        _;\n    }",
            "address(0)",
        ),
        ("modifier paused() {\n        balanceOf[msg.sender] += 0;\n    }", "no `_;`"),
    ],
)
def test_a_modifier_that_blocks_every_call_is_detected(
    tmp_path: Path, modifier: str, why: str
) -> None:
    patched = BANK.replace(
        "    function deposit()", f"    {modifier}\n\n    function deposit()"
    ).replace(
        "function withdraw(uint256 amount) external {",
        "function withdraw(uint256 amount) external paused {",
    )
    result = check(tmp_path, patched)
    found = details(result, "vacuous_patch")
    assert any("modifier paused blocks every call of Bank.withdraw(uint256)" in d for d in found)
    assert any(why in d for d in found), found


def test_a_reentrancy_lock_is_not_vacuous(tmp_path: Path) -> None:
    patched = BANK.replace(
        "    address public owner;\n",
        "    address public owner;\n    bool private locked;\n\n"
        "    modifier lock() {\n        if (locked) revert();\n        locked = true;\n"
        "        _;\n        locked = false;\n    }\n",
    ).replace(
        "function withdraw(uint256 amount) external {",
        "function withdraw(uint256 amount) external lock {",
    )
    result = check(tmp_path, patched)
    assert result.verdict is Verdict.PASS, result.reasons


def test_a_conditional_revert_is_not_vacuous(tmp_path: Path) -> None:
    patched = BANK.replace(
        'require(sent, "send");', 'require(sent, "send");\n        if (amount == 0) revert("zero");'
    )
    assert check(tmp_path, patched).verdict is Verdict.PASS


def test_a_modifier_that_already_blocked_calls_is_not_blamed_on_the_patch(tmp_path: Path) -> None:
    base = BANK.replace('require(msg.sender == owner, "owner");', "revert();")
    patched = base.replace('require(sent, "send");', 'require(sent, "send");\n        // checked')
    assert check(tmp_path, patched, base=base).verdict is Verdict.PASS


def test_removing_every_external_call_is_vacuous(tmp_path: Path) -> None:
    patched = BANK.replace(
        '        (bool sent,) = msg.sender.call{value: amount}("");\n'
        '        require(sent, "send");\n',
        "",
    ).replace("payable(to).transfer(address(this).balance);", "to;")
    result = check(tmp_path, patched)
    assert details(result, "vacuous_patch") == [
        "contract Bank no longer makes any external call or value transfer "
        "(2 in the vulnerable revision)"
    ]


def test_removing_one_of_two_external_calls_is_not_vacuous(tmp_path: Path) -> None:
    patched = BANK.replace("payable(to).transfer(address(this).balance);", "to;")
    assert check(tmp_path, patched).verdict is Verdict.PASS


# -- special-casing ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("added", "expected"),
    [
        (
            "require(msg.sender != 0x00000000000000000000000000000000DeaDBeef);",
            "a value the PoC uses",
        ),
        ('if (amount == 1 ether) revert("no");', "1 ether, a value the PoC uses"),
        ("if (amount == 1e18) revert();", "1e18, a value the PoC uses (1 ether)"),
        ("if (amount == 7777) revert();", "7777, a value the PoC uses (7_777)"),
        ("if (msg.sig == 0x2e1a7d4d) revert();", "a value the PoC uses"),
        (
            "require(tx.origin != 0x1111111111111111111111111111111111111111);",
            "compares an address with the hard-coded value",
        ),
        ("if (msg.sig == 0x12345678) revert();", "compares msg.sig with the hard-coded value"),
    ],
)
def test_special_casing_is_detected(tmp_path: Path, added: str, expected: str) -> None:
    anchor = 'require(sent, "send");'
    result = check(tmp_path, BANK.replace(anchor, f"{anchor}\n        {added}"))
    found = details(result, "special_casing")
    assert any(expected in detail for detail in found), result.reasons
    assert all(item.line == 23 for item in result.reasons if item.code == "special_casing")


@pytest.mark.parametrize(
    "added",
    [
        "uint256 limit = 5;",
        "uint256 fee = 1000;",
        "// at most 1 ether per call",
        'string memory note = "1 ether";',
        "uint256 cap = 2 ether;",
    ],
)
def test_ordinary_values_are_not_special_casing(tmp_path: Path, added: str) -> None:
    anchor = 'require(sent, "send");'
    result = check(tmp_path, BANK.replace(anchor, f"{anchor}\n        {added}"))
    assert result.verdict is Verdict.PASS, result.reasons


def test_values_on_removed_lines_do_not_count(tmp_path: Path) -> None:
    base = BANK.replace('require(sent, "send");', 'require(sent, "send");\n        x = 1 ether;')
    result = check(tmp_path, base.replace("        x = 1 ether;\n", ""), base=base)
    assert result.verdict is Verdict.PASS, result.reasons


# -- environment sniffing ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("added", "expected"),
    [
        ("if (block.chainid == 31337) return;", "chain id of the local test network"),
        (
            "address vm = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;",
            "Foundry's cheatcode address",
        ),
        (
            "if (tx.origin == 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38) return;",
            "Foundry's default sender",
        ),
        (
            'address vm = address(uint160(uint256(keccak256("hevm cheat code"))));',
            "derives Foundry's cheatcode address",
        ),
    ],
)
def test_environment_sniffing_is_detected(tmp_path: Path, added: str, expected: str) -> None:
    anchor = 'require(sent, "send");'
    result = check(tmp_path, BANK.replace(anchor, f"{anchor}\n        {added}"))
    assert any(expected in detail for detail in details(result, "environment_sniffing"))


@pytest.mark.parametrize(
    "line",
    ['import "forge-std/console.sol";', 'import {console2} from "./lib/console2.sol";'],
)
def test_test_library_imports_are_sniffing(tmp_path: Path, line: str) -> None:
    patched = BANK.replace("pragma solidity 0.8.36;\n", f"pragma solidity 0.8.36;\n{line}\n")
    result = check(tmp_path, patched)
    assert any(
        "imports the test library file" in d for d in details(result, "environment_sniffing")
    )


def test_sniffing_in_the_target_itself_is_reported(tmp_path: Path) -> None:
    base = BANK.replace(
        'require(sent, "send");', 'require(sent, "send");\n        if (block.chainid == 31337) {}'
    )
    patched = base.replace("function total()", "function total2()")
    result = check(tmp_path, patched, base=base)
    assert "environment_sniffing" in result.codes()
