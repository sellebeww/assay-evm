"""RegressionOracle: parsing and comparison of storage layout, ABI and events, and the oracle
with a stand-in runner (no Docker)."""

import json
from pathlib import Path
from typing import Any

import pytest
from fake_forge import (
    VAULT_ABI,
    VAULT_ABI_ENTRIES,
    VAULT_LAYOUT,
    BenignTests,
    FakeForge,
    event,
    function,
    layout_json,
)

from assay.ingest import Snapshot, create_snapshot
from assay.ledger import RevisionKind, Verdict
from assay.oracles.base import OracleResult
from assay.oracles.behavior import SuiteSettings
from assay.oracles.regression import (
    Interface,
    InterfaceError,
    RegressionContext,
    RegressionOracle,
    compare_interface,
    compare_layout,
    parse_abi,
    parse_interface,
    parse_layout,
    target_contracts,
)
from assay.oracles.runtree import load_harness

BALANCE = ("balanceOf", 0, 0, "t_mapping(t_address,t_uint256)")
TOTAL = ("totalDeposits", 1, 0, "t_uint256")


def layout(*variables: tuple[str, int, int, str]) -> Any:
    return parse_layout(layout_json(*variables))


def kinds(changes: list[Any]) -> list[tuple[str, bool]]:
    return [(change.kind, change.breaking) for change in changes]


# -- storage layout ---------------------------------------------------------------------------


def test_the_same_layout_has_no_change() -> None:
    assert compare_layout(layout(BALANCE, TOTAL), layout(BALANCE, TOTAL)) == []


def test_a_variable_appended_after_the_last_slot_is_only_a_warning() -> None:
    changes = compare_layout(
        layout(BALANCE, TOTAL), layout(BALANCE, TOTAL, ("paused", 2, 0, "t_bool"))
    )
    assert kinds(changes) == [("layout", False)]
    assert "`paused` (slot 2, offset 0, bool) appended" in changes[0].detail


@pytest.mark.parametrize(
    ("new", "expected"),
    [
        # a new variable placed before the existing ones (every existing one moves)
        (
            (
                ("locked", 0, 0, "t_bool"),
                ("balanceOf", 1, 0, BALANCE[3]),
                ("totalDeposits", 2, 0, "t_uint256"),
            ),
            "storage variable #0 `balanceOf`",
        ),
        # a new variable packed into the free bytes of the last used slot
        (
            (BALANCE, ("flag", 1, 0, "t_bool"), ("totalDeposits", 2, 0, "t_uint256")),
            "storage variable #1 `totalDeposits`",
        ),
        # a changed type
        (
            (BALANCE, ("totalDeposits", 1, 0, "t_uint128")),
            "is now `totalDeposits` (slot 1, offset 0, uint128)",
        ),
        # a changed offset
        ((BALANCE, ("totalDeposits", 1, 16, "t_uint256")), "offset 16"),
        # a renamed variable
        ((BALANCE, ("sumOfDeposits", 1, 0, "t_uint256")), "is now `sumOfDeposits`"),
        # a removed variable
        ((BALANCE,), "`totalDeposits` (slot 1, offset 0, uint256) removed"),
        # swapped order
        ((("totalDeposits", 0, 0, "t_uint256"), ("balanceOf", 1, 0, BALANCE[3])), "#0"),
    ],
)
def test_breaking_layout_changes(new: tuple[tuple[str, int, int, str], ...], expected: str) -> None:
    changes = compare_layout(layout(BALANCE, TOTAL), layout(*new))
    assert changes, "a breaking change must be reported"
    assert all(change.kind == "layout" for change in changes)
    assert any(change.breaking for change in changes)
    assert any(expected in change.detail for change in changes), changes


def test_a_shifted_variable_is_not_reported_as_appended() -> None:
    new = layout(
        ("locked", 0, 0, "t_bool"),
        ("balanceOf", 1, 0, BALANCE[3]),
        ("totalDeposits", 2, 0, "t_uint256"),
    )
    changes = compare_layout(layout(BALANCE, TOTAL), new)
    assert all(change.breaking for change in changes)
    assert "moved behind its old position" in changes[-1].detail


def test_a_variable_packed_into_the_last_used_slot_is_breaking() -> None:
    base = layout(("owner", 0, 0, "t_address"))
    packed = layout(("owner", 0, 0, "t_address"), ("paused", 0, 20, "t_bool"))
    assert kinds(compare_layout(base, packed)) == [("layout", True)]
    appended = layout(("owner", 0, 0, "t_address"), ("paused", 1, 0, "t_bool"))
    assert kinds(compare_layout(base, appended)) == [("layout", False)]


def test_struct_members_are_compared_not_only_the_type_name() -> None:
    def with_member(member_type: str) -> str:
        return json.dumps(
            {
                "storage": [
                    {
                        "astId": 9,
                        "contract": "c",
                        "label": "position",
                        "offset": 0,
                        "slot": "0",
                        "type": "t_struct(Position)12_storage",
                    }
                ],
                "types": {
                    "t_struct(Position)12_storage": {
                        "encoding": "inplace",
                        "label": "struct Vault.Position",
                        "numberOfBytes": "32",
                        "members": [
                            {
                                "astId": 10,
                                "contract": "c",
                                "label": "amount",
                                "offset": 0,
                                "slot": "0",
                                "type": member_type,
                            }
                        ],
                    },
                    "t_uint256": {"encoding": "inplace", "label": "uint256", "numberOfBytes": "32"},
                    "t_uint128": {"encoding": "inplace", "label": "uint128", "numberOfBytes": "16"},
                },
            }
        )

    before, after = parse_layout(with_member("t_uint256")), parse_layout(with_member("t_uint128"))
    changes = compare_layout(before, after)
    assert kinds(changes) == [("layout", True)]
    assert "with a different type layout" in changes[0].detail


def test_type_identifiers_with_other_ast_ids_compare_equal() -> None:
    def struct(type_id: str) -> str:
        return json.dumps(
            {
                "storage": [
                    {
                        "astId": 1,
                        "contract": "c",
                        "label": "p",
                        "offset": 0,
                        "slot": "0",
                        "type": type_id,
                    }
                ],
                "types": {
                    type_id: {
                        "encoding": "inplace",
                        "label": "struct V.P",
                        "numberOfBytes": "32",
                        "members": [
                            {
                                "astId": 2,
                                "contract": "c",
                                "label": "a",
                                "offset": 0,
                                "slot": "0",
                                "type": "t_uint256",
                            }
                        ],
                    },
                    "t_uint256": {"encoding": "inplace", "label": "uint256", "numberOfBytes": "32"},
                },
            }
        )

    assert (
        compare_layout(
            parse_layout(struct("t_struct(P)5_storage")),
            parse_layout(struct("t_struct(P)77_storage")),
        )
        == []
    )


def test_recursive_types_terminate() -> None:
    text = json.dumps(
        {
            "storage": [
                {
                    "astId": 1,
                    "contract": "c",
                    "label": "nodes",
                    "offset": 0,
                    "slot": "0",
                    "type": "t_mapping(t_uint256,t_struct(N)3_storage)",
                }
            ],
            "types": {
                "t_mapping(t_uint256,t_struct(N)3_storage)": {
                    "encoding": "mapping",
                    "label": "mapping(uint256 => struct V.N)",
                    "numberOfBytes": "32",
                    "key": "t_uint256",
                    "value": "t_struct(N)3_storage",
                },
                "t_struct(N)3_storage": {
                    "encoding": "inplace",
                    "label": "struct V.N",
                    "numberOfBytes": "32",
                    "members": [
                        {
                            "astId": 2,
                            "contract": "c",
                            "label": "children",
                            "offset": 0,
                            "slot": "0",
                            "type": "t_mapping(t_uint256,t_struct(N)3_storage)",
                        }
                    ],
                },
                "t_uint256": {"encoding": "inplace", "label": "uint256", "numberOfBytes": "32"},
            },
        }
    )
    (variable,) = parse_layout(text)
    assert "(recursive)" in variable.type


@pytest.mark.parametrize(
    "text",
    [
        "not json",
        "[]",
        json.dumps(
            {
                "storage": [{"label": "x", "offset": 0, "slot": "0", "type": "t_missing"}],
                "types": {},
            }
        ),
        json.dumps(
            {
                "storage": [{"label": "x", "offset": 40, "slot": "0", "type": "t_uint256"}],
                "types": {},
            }
        ),
        json.dumps(
            {
                "storage": [{"label": "x", "offset": 0, "slot": "-1", "type": "t_uint256"}],
                "types": {},
            }
        ),
        json.dumps(
            {
                "storage": [{"label": "x", "offset": "0", "slot": "0", "type": "t_uint256"}],
                "types": {},
            }
        ),
    ],
)
def test_malformed_layouts_are_rejected(text: str) -> None:
    with pytest.raises(InterfaceError):
        parse_layout(text)


# -- ABI and events ---------------------------------------------------------------------------


def abi(*entries: Any) -> str:
    return json.dumps(list(entries))


def test_the_vault_abi_is_parsed_without_errors() -> None:
    functions, events = parse_abi(VAULT_ABI)
    assert functions == {
        "balanceOf(address)": "returns (uint256) view",
        "deposit()": "returns () payable",
        "totalDeposits()": "returns (uint256) view",
        "withdraw(uint256)": "returns () nonpayable",
    }
    assert events == {
        "Deposited(address,uint256)": "[indexed,-]",
        "Withdrawn(address,uint256)": "[indexed,-]",
    }


def interface(entries: list[Any]) -> Interface:
    return parse_interface(VAULT_LAYOUT, json.dumps(entries))


BASE = interface(VAULT_ABI_ENTRIES)


def without(name: str) -> list[Any]:
    return [entry for entry in VAULT_ABI_ENTRIES if entry.get("name") != name]


@pytest.mark.parametrize(
    ("entries", "expected"),
    [
        (without("withdraw"), ("abi", "function `withdraw(uint256)` removed")),
        (
            [*without("withdraw"), function("withdraw", ["uint128"], [], "nonpayable")],
            ("abi", "function `withdraw(uint256)` removed (or its parameter types changed)"),
        ),
        (
            [*without("totalDeposits"), function("totalDeposits", [], ["uint128"], "view")],
            ("abi", "returns (uint256) view -> returns (uint128) view"),
        ),
        (
            [*without("deposit"), function("deposit", [], [], "nonpayable")],
            ("abi", "returns () payable -> returns () nonpayable"),
        ),
        (without("Withdrawn"), ("events", "event `Withdrawn(address,uint256)` removed")),
        (
            [*without("Withdrawn"), event("Withdrawn", ("address", False), ("uint256", False))],
            ("events", "[indexed,-] -> [-,-]"),
        ),
        (
            [
                *without("Withdrawn"),
                event("Withdrawn", ("address", True), ("uint256", False), anonymous=True),
            ],
            ("events", "[indexed,-] -> [indexed,-] anonymous"),
        ),
    ],
)
def test_breaking_abi_and_event_changes(entries: list[Any], expected: tuple[str, str]) -> None:
    changes = compare_interface(BASE, interface(entries))
    breaking = [(change.kind, change.detail) for change in changes if change.breaking]
    assert any(kind == expected[0] and expected[1] in detail for kind, detail in breaking), changes


def test_additions_are_warnings_and_names_and_errors_are_ignored() -> None:
    renamed = [
        {**entry, "inputs": [{**param, "name": "renamed"} for param in entry["inputs"]]}
        for entry in VAULT_ABI_ENTRIES
        if entry["type"] != "error"
    ]
    entries = [
        *renamed,
        function("pause", [], [], "nonpayable"),
        event("Paused", ("address", False)),
        {"type": "error", "name": "Paused", "inputs": []},
    ]
    changes = compare_interface(BASE, interface(entries))
    assert [(change.kind, change.breaking, change.detail) for change in changes] == [
        ("abi", False, "new function `pause()`"),
        ("events", False, "new event `Paused(address)`"),
    ]


def test_constructor_receive_fallback_and_tuples_are_part_of_the_abi() -> None:
    tuple_param = {
        "name": "order",
        "type": "tuple[]",
        "components": [{"name": "a", "type": "address"}, {"name": "b", "type": "uint256[2]"}],
    }
    entries = [
        {
            "type": "constructor",
            "inputs": [{"name": "o", "type": "address"}],
            "stateMutability": "nonpayable",
        },
        {"type": "receive", "stateMutability": "payable"},
        {"type": "fallback", "stateMutability": "nonpayable"},
        {
            "type": "function",
            "name": "fill",
            "inputs": [tuple_param],
            "outputs": [],
            "stateMutability": "nonpayable",
        },
    ]
    functions, _ = parse_abi(abi(*entries))
    assert set(functions) == {
        "constructor(address)",
        "receive()",
        "fallback()",
        "fill((address,uint256[2])[])",
    }
    base = parse_interface(VAULT_LAYOUT, abi(*entries))
    changed = parse_interface(VAULT_LAYOUT, abi({**entries[0], "inputs": []}, *entries[1:]))
    assert any(
        change.breaking and "constructor(address)" in change.detail
        for change in compare_interface(base, changed)
    )


@pytest.mark.parametrize(
    "text",
    [
        "{}",
        abi({"type": "function", "name": "f", "inputs": [], "outputs": []}),
        abi({"type": "function", "inputs": [], "outputs": [], "stateMutability": "view"}),
        abi({"type": "unknown"}),
        abi(
            {
                "type": "function",
                "name": "f",
                "inputs": [{"type": "uint 256"}],
                "stateMutability": "view",
            }
        ),
        abi(
            {
                "type": "function",
                "name": "f",
                "inputs": [{"type": "tuple"}],
                "stateMutability": "view",
            }
        ),
        abi(function("f", [], [], "view"), function("f", [], [], "view")),
    ],
)
def test_malformed_abis_are_rejected(text: str) -> None:
    with pytest.raises(InterfaceError):
        parse_abi(text)


# -- target contracts -------------------------------------------------------------------------


def snapshot(tmp_path: Path, name: str, files: dict[str, str]) -> Snapshot:
    root = tmp_path / f"{name}-src"
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return create_snapshot(root, tmp_path / name)


def test_targets_are_the_concrete_contracts_under_src(tmp_path: Path) -> None:
    files = {
        "src/Vault.sol": "contract Vault {}\nabstract contract Base {}\ninterface IVault {}\n",
        "src/lib/Math.sol": "library Math {}\ncontract Token {}\n",
        "test/Vault.t.sol": "contract VaultTest {}\n",
        "script/Deploy.sol": "contract Deploy {}\n",
    }
    assert target_contracts(snapshot(tmp_path, "s", files)) == (
        "src/Vault.sol:Vault",
        "src/lib/Math.sol:Token",
    )


# -- the oracle -------------------------------------------------------------------------------

VAULT = "contract Vault {}\n"


def run(
    tmp_path: Path,
    *,
    patched_source: str = "// patched\ncontract Vault {}\n",
    interface_of: Any = None,
    benign: Any = None,
    build_fails: Any = None,
    tests: bool = True,
) -> tuple[OracleResult, FakeForge]:
    files = {"src/Vault.sol": VAULT}
    if tests:
        files["test/Vault.t.sol"] = "contract VaultTest {}\n"
    runner = FakeForge(
        lambda tree, number: "blocked",
        interface=interface_of,
        benign=benign,
        build_fails=build_fails or (lambda tree: False),
    )
    vulnerable = snapshot(tmp_path, "vulnerable", files)
    patched = snapshot(tmp_path, "patched", {**files, "src/Vault.sol": patched_source})
    work = tmp_path / "work"
    work.mkdir()
    context = RegressionContext(
        runner=runner,
        vulnerable=vulnerable,
        patched=patched,
        harness=load_harness(),
        work_dir=work,
        targets=target_contracts(vulnerable),
    )
    return RegressionOracle(SuiteSettings(fuzz_runs=32)).run(context), runner


def is_patched(tree: Path) -> bool:
    return "patched" in (tree / "src" / "Vault.sol").read_text()


def test_an_unchanged_interface_and_a_passing_suite_pass(tmp_path: Path) -> None:
    result, runner = run(tmp_path)
    assert result.verdict is Verdict.PASS, result
    vulnerable, patched = result.executions
    assert (vulnerable.revision, patched.revision) == (
        RevisionKind.VULNERABLE,
        RevisionKind.PATCHED,
    )
    assert vulnerable.argv[:2] == ("forge", "inspect")
    assert patched.argv == (
        "forge",
        "test",
        "--json",
        "-vv",
        "--threads",
        "1",
        "--fuzz-seed",
        "0x1",
        "--fuzz-runs",
        "32",
    )
    assert patched.seed == 1
    assert [call[3] for call in runner.commands("inspect")] == ["storageLayout", "abi"] * 2
    assert {item.name for item in vulnerable.evidence + patched.evidence} >= {
        "interface-vulnerable.json",
        "interface-patched.json",
    }


def test_a_breaking_layout_change_fails_and_an_addition_warns(tmp_path: Path) -> None:
    locked = layout_json(
        ("locked", 0, 0, "t_bool"),
        ("balanceOf", 1, 0, BALANCE[3]),
        ("totalDeposits", 2, 0, "t_uint256"),
    )
    with_pause = json.dumps([*VAULT_ABI_ENTRIES, function("pause", [], [], "nonpayable")])

    def interface_of(tree: Path, contract: str, field: str) -> str:
        if field == "storageLayout":
            return locked if is_patched(tree) else VAULT_LAYOUT
        return with_pause if is_patched(tree) else VAULT_ABI

    result, _ = run(tmp_path, interface_of=interface_of)
    assert result.verdict is Verdict.FAIL
    assert result.codes() == ["layout_changed"]
    assert [item.code for item in result.warnings] == ["function_added"]
    assert all(item.path == "src/Vault.sol" for item in result.reasons)
    names = {item.name for item in result.executions[1].evidence}
    assert "interface-changes.json" in names


def test_a_removed_contract_is_an_abi_change(tmp_path: Path) -> None:
    result, _ = run(
        tmp_path, patched_source="// patched\nabstract contract Vault {}\ncontract Other {}\n"
    )
    assert result.verdict is Verdict.FAIL
    assert result.codes() == ["abi_changed"]
    assert "no longer exists as a concrete contract" in result.reasons[0].detail
    assert [item.code for item in result.warnings] == ["contract_added"]


def test_a_failing_test_suite_fails(tmp_path: Path) -> None:
    def benign(tree: Path) -> BenignTests:
        status = "Failure" if is_patched(tree) else "Success"
        return {"test_a()": ("Success", []), "test_b()": (status, [])}

    result, _ = run(tmp_path, benign=benign)
    assert result.verdict is Verdict.FAIL
    assert result.codes() == ["test_suite_failed"]
    assert "test_b()" in result.reasons[0].detail


def test_a_patched_revision_that_does_not_compile_fails(tmp_path: Path) -> None:
    result, runner = run(tmp_path, build_fails=is_patched)
    assert result.verdict is Verdict.FAIL
    assert result.codes() == ["test_suite_failed"]
    assert "does not compile" in result.reasons[0].detail
    assert runner.tests(None) == []


def test_a_vulnerable_revision_that_does_not_compile_is_inconclusive(tmp_path: Path) -> None:
    result, _ = run(tmp_path, build_fails=lambda tree: not is_patched(tree))
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.codes() == ["vulnerable_build_failed"]
    assert len(result.executions) == 1


def test_unusable_inspect_output_is_inconclusive(tmp_path: Path) -> None:
    result, _ = run(tmp_path, interface_of=lambda tree, contract, field: "{}")
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.codes() == ["unusable_output"]


def test_without_tests_the_suite_is_inconclusive(tmp_path: Path) -> None:
    result, runner = run(tmp_path, tests=False)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.codes() == ["no_tests"]
    assert runner.tests(None) == []


def test_a_breaking_change_still_fails_when_the_suite_times_out(tmp_path: Path) -> None:
    locked = layout_json(("locked", 0, 0, "t_bool"))

    def interface_of(tree: Path, contract: str, field: str) -> str:
        if field == "storageLayout" and is_patched(tree):
            return locked
        return VAULT_LAYOUT if field == "storageLayout" else VAULT_ABI

    result, _ = run(tmp_path, interface_of=interface_of, benign=lambda tree: "timeout")
    assert result.verdict is Verdict.FAIL
    assert result.codes() == ["layout_changed"]
    incomplete = result.executions[1].trace["incomplete"]
    assert isinstance(incomplete, list)
    assert [item["code"] for item in incomplete] == ["timeout"]  # type: ignore[index]


def test_no_target_contract_is_inconclusive(tmp_path: Path) -> None:
    runner = FakeForge(lambda tree, number: "blocked")
    files = {"src/Lib.sol": "library Lib {}\n", "test/T.t.sol": "contract T {}\n"}
    vulnerable = snapshot(tmp_path, "v", files)
    work = tmp_path / "work"
    work.mkdir()
    context = RegressionContext(
        runner=runner,
        vulnerable=vulnerable,
        patched=vulnerable,
        harness=load_harness(),
        work_dir=work,
        targets=target_contracts(vulnerable),
    )
    result = RegressionOracle().run(context)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.codes() == ["no_target_contracts"]
    assert runner.calls == []
