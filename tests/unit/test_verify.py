"""`assay verify` with a stand-in runner (no Docker): verdicts, exit codes, output and ledger."""

import json
import re
import shutil
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from fake_forge import VAULT_ABI, VAULT_ABI_ENTRIES, VAULT_LAYOUT, FakeForge, function
from hypothesis import given
from hypothesis import strategies as st
from typer.testing import CliRunner, Result
from vault_scenario import FIXTURE, ROOT, vault_forge, vault_source

from assay.cli.main import app
from assay.ledger import FinalVerdict, Ledger, OracleName, Verdict
from assay.oracles.base import Reason
from assay.oracles.variant import derive_seeds
from assay.orchestrator.verify import ORACLE_ORDER, VERIFIED_REASON, OracleRow, decide
from assay.sandbox import runner as runner_module

MISSING = "missing_oracles: variant, behavior, regression"
FORBIDDEN = re.compile(r"\b(safe|proven|guaranteed|unhackable)\b", re.IGNORECASE)
BOUND = "fuzz: 3 of 3 seeds of 256 runs (768 runs), no variant found"
SEEDS = derive_seeds("0x1", 3)
ORACLES = ["integrity", "exploit", "variant", "behavior", "regression"]

cli = CliRunner()


@pytest.fixture
def forge(monkeypatch: pytest.MonkeyPatch) -> FakeForge:
    fake = vault_forge()
    monkeypatch.setattr("assay.cli.verify.SandboxRunner", lambda: fake)
    return fake


def ledger_path(tmp_path: Path) -> Path:
    return tmp_path / ".assay" / "ledger.db"


def verify(
    tmp_path: Path,
    patch: str | bytes,
    *options: str,
    base: Path = FIXTURE,
    poc: Path | None = None,
) -> Result:
    if isinstance(patch, bytes):
        patch_file = tmp_path / "patch.diff"
        patch_file.write_bytes(patch)
    else:
        patch_file = FIXTURE / "patches" / f"{patch}.diff"
    args = [
        "verify",
        "--base",
        str(base),
        "--patch",
        str(patch_file),
        "--poc",
        str(poc if poc is not None else base / "poc"),
        "--ledger",
        str(ledger_path(tmp_path)),
        *options,
    ]
    return cli.invoke(app, args)


def assert_clean(text: str) -> None:
    assert "secure" not in text.lower()
    assert FORBIDDEN.search(text) is None, text


def table(stdout: str) -> dict[str, tuple[str, str]]:
    """Verdict and reason column of every oracle line of the verdict table."""
    found = {}
    for line in stdout.splitlines():
        parts = line.split(None, 2)
        if parts and parts[0] in ORACLES and len(parts) == 3:
            found[parts[0]] = (parts[1], parts[2])
    return found


# -- the final verdict ------------------------------------------------------------------------


def row(oracle: OracleName, verdict: Verdict | None, status: str = "ran") -> OracleRow:
    reasons = () if verdict is not Verdict.FAIL else (Reason(code=f"{oracle}_failed", detail="x"),)
    if verdict is Verdict.INCONCLUSIVE:
        reasons = (Reason(code="timeout", detail="x"),)
    return OracleRow(
        oracle=oracle,
        status=status,  # type: ignore[arg-type]
        verdict=verdict,
        reasons=reasons,
        summary="s",
    )


def test_only_five_passes_give_verified_within_bounds() -> None:
    rows = [row(oracle, Verdict.PASS) for oracle in ORACLE_ORDER]
    assert decide(rows) == (FinalVerdict.VERIFIED_WITHIN_BOUNDS, ())
    assert decide(rows[:2]) == (FinalVerdict.INCONCLUSIVE, (MISSING,))
    with_missing = rows[:2] + [row(oracle, None, "missing") for oracle in ORACLE_ORDER[2:]]
    assert decide(with_missing) == (FinalVerdict.INCONCLUSIVE, (MISSING,))


def test_a_failure_rejects_and_inconclusive_results_are_kept() -> None:
    rows = [row(OracleName.INTEGRITY, Verdict.FAIL), row(OracleName.EXPLOIT, Verdict.INCONCLUSIVE)]
    assert decide(rows) == (FinalVerdict.REJECTED, ("integrity_failed",))
    rows = [row(OracleName.INTEGRITY, Verdict.PASS), row(OracleName.EXPLOIT, Verdict.INCONCLUSIVE)]
    assert decide(rows) == (FinalVerdict.INCONCLUSIVE, ("timeout", MISSING))
    rows = [row(OracleName.INTEGRITY, Verdict.PASS), row(OracleName.EXPLOIT, None, "skipped")]
    verdict, reasons = decide(rows)
    assert verdict is FinalVerdict.INCONCLUSIVE
    assert reasons[0] == "skipped_oracles: exploit"


@given(
    st.lists(
        st.sampled_from(
            [
                (Verdict.PASS, "ran"),
                (Verdict.FAIL, "ran"),
                (Verdict.INCONCLUSIVE, "ran"),
                (None, "missing"),
                (None, "skipped"),
                (None, "absent"),
            ]
        ),
        min_size=5,
        max_size=5,
    )
)
def test_verified_within_bounds_needs_every_required_oracle_to_pass(
    outcomes: list[tuple[Verdict | None, str]],
) -> None:
    rows = [
        row(oracle, verdict, status)
        for oracle, (verdict, status) in zip(ORACLE_ORDER, outcomes, strict=True)
        if status != "absent"
    ]
    verdict, reasons = decide(rows)
    all_pass = all(outcome == (Verdict.PASS, "ran") for outcome in outcomes)
    assert (verdict is FinalVerdict.VERIFIED_WITHIN_BOUNDS) == all_pass
    if any(outcome[0] is Verdict.FAIL for outcome in outcomes):
        assert verdict is FinalVerdict.REJECTED
    if verdict is not FinalVerdict.VERIFIED_WITHIN_BOUNDS:
        assert reasons


# -- the fixture patches ----------------------------------------------------------------------


def test_the_good_patch_is_verified_within_bounds(tmp_path: Path, forge: FakeForge) -> None:
    result = verify(tmp_path, "good")
    assert result.exit_code == 0, result.output
    assert table(result.stdout) == dict.fromkeys(ORACLES, ("PASS", "-"))
    lines = result.stdout.splitlines()
    assert "final verdict: VERIFIED_WITHIN_BOUNDS" in lines
    assert "reason: every required oracle passed" in lines
    assert BOUND in result.stdout
    assert f"variant: profile standard, base seed 0x1, seeds {', '.join(SEEDS)}" in result.stdout
    assert "no variant found within these runs; this is not a proof of absence" in result.stdout
    assert "invariant: no invariant in the PoC directory" in result.stdout
    assert any(line.startswith("time: ") and " s in total" in line for line in lines)
    assert any(line.startswith("limits: ") and "not a proof of absence" in line for line in lines)
    assert_clean(result.output)


def test_the_overfit_patch_is_rejected_for_a_variant(tmp_path: Path, forge: FakeForge) -> None:
    result = verify(tmp_path, "overfit")
    assert result.exit_code == 1, result.output
    rows = table(result.stdout)
    assert rows["exploit"] == ("PASS", "-")
    assert rows["variant"] == ("FAIL", "variant_found")
    assert rows["behavior"] == rows["regression"] == ("PASS", "-")
    assert "reason: variant_found" in result.stdout
    assert BOUND not in result.stdout
    assert "knobs 7886, 3, 0, 0" in result.stdout
    assert_clean(result.output)


def test_the_destructive_patch_is_rejected(tmp_path: Path, forge: FakeForge) -> None:
    result = verify(tmp_path, "destructive")
    assert result.exit_code == 1, result.output
    rows = table(result.stdout)
    assert rows["integrity"] == ("FAIL", "vacuous_patch")
    assert rows["behavior"] == ("FAIL", "benign_test_failed")
    assert rows["regression"] == ("FAIL", "test_suite_failed")
    assert "reason: vacuous_patch; benign_test_failed; test_suite_failed" in result.stdout
    assert_clean(result.output)


def test_the_regressing_patch_is_rejected_by_the_regression_oracle(
    tmp_path: Path, forge: FakeForge
) -> None:
    result = verify(tmp_path, "regressing")
    assert result.exit_code == 1, result.output
    rows = table(result.stdout)
    assert rows["regression"] == ("FAIL", "layout_changed")
    assert all(rows[name] == ("PASS", "-") for name in ORACLES[:4])
    assert "reason: layout_changed" in result.stdout
    assert "storage variable #0 `balanceOf`" in result.stdout
    assert "moved behind its old position" in result.stdout
    assert_clean(result.output)


def test_an_empty_patch_leaves_the_exploit_reproducible(tmp_path: Path, forge: FakeForge) -> None:
    result = verify(tmp_path, b"")
    assert result.exit_code == 1, result.output
    rows = table(result.stdout)
    assert rows["exploit"] == ("FAIL", "exploit_still_reproducible")
    assert rows["variant"] == ("FAIL", "variant_found")
    assert "reason: exploit_still_reproducible; variant_found" in result.stdout
    assert_clean(result.output)


def test_a_comment_only_patch_leaves_the_exploit_reproducible(
    tmp_path: Path, forge: FakeForge
) -> None:
    patch = b"""\
--- a/src/Vault.sol
+++ b/src/Vault.sol
@@ -5,2 +5,3 @@
 /// @title Vault
+/// @dev Reviewed.
 /// @notice Keeps ether for its depositors. Each depositor can take back what they put in.
"""
    result = verify(tmp_path, patch)
    assert result.exit_code == 1, result.output
    assert "reason: exploit_still_reproducible" in result.stdout


def test_oracles_after_a_failure_still_run(tmp_path: Path, forge: FakeForge) -> None:
    result = verify(tmp_path, "destructive")
    assert result.exit_code == 1
    assert forge.tests("^testFuzz_variants[(]")
    assert len(forge.tests(None)) == 3, "benign tests on both revisions and the whole suite"
    assert [call[3] for call in forge.commands("inspect")].count("storageLayout") == 2


def test_fuzz_runs_reach_every_fuzz_campaign_and_the_bounds(
    tmp_path: Path, forge: FakeForge
) -> None:
    result = verify(tmp_path, "good", "--fuzz-runs", "64", "--json")
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["bounds"]["fuzz_runs"] == 64
    assert (
        "fuzz: 3 of 3 seeds of 64 runs (192 runs), no variant found" in (report["bounds_statement"])
    )
    assert report["bounds"]["variant"]["runs_per_seed"] == 64
    assert report["bounds"]["profile"] == "standard"
    fuzzing = forge.tests("^testFuzz_variants[(]") + forge.tests(None)
    assert fuzzing
    assert all(call[call.index("--fuzz-runs") + 1] == "64" for call in fuzzing)
    for value in ("0", "1000001", "x"):
        assert verify(tmp_path, "good", "--fuzz-runs", value).exit_code == 2


PAUSE_PATCH = "\n".join(
    [
        "--- a/src/Vault.sol",
        "+++ b/src/Vault.sol",
        "@@ -31,11 +31,14 @@",
        "         uint256 available = balanceOf[msg.sender];",
        "         if (amount > available) revert InsufficientBalance(amount, available);",
        " ",
        "+        balanceOf[msg.sender] = available - amount;",
        "+        totalDeposits -= amount;",
        "+",
        '         (bool sent,) = msg.sender.call{value: amount}("");',
        "         if (!sent) revert TransferFailed();",
        " ",
        "-        balanceOf[msg.sender] = available - amount;",
        "-        totalDeposits -= amount;",
        "         emit Withdrawn(msg.sender, amount);",
        "     }",
        "+",
        "+    function pause() external {}",
        " }",
        "",
    ]
).encode()


def test_warnings_are_shown_and_do_not_fail(tmp_path: Path, forge: FakeForge) -> None:
    with_pause = json.dumps([*VAULT_ABI_ENTRIES, function("pause", [], [], "nonpayable")])

    def interface(tree: Path, contract: str, field: str) -> str:
        if field == "storageLayout":
            return VAULT_LAYOUT
        return with_pause if "function pause()" in vault_source(tree) else VAULT_ABI

    forge.interface = interface
    result = verify(tmp_path, PAUSE_PATCH)
    assert result.exit_code == 0, result.output
    assert "warnings (they do not change the verdict):" in result.stdout
    expected = "regression: function_added: src/Vault.sol:Vault: new function `pause()`"
    assert expected in result.stdout
    assert "final verdict: VERIFIED_WITHIN_BOUNDS" in result.stdout


# -- patches that stop verification -----------------------------------------------------------


@pytest.mark.parametrize(
    ("patch", "code"),
    [
        (b"--- a/../../etc/x\n+++ b/../../etc/x\n@@ -1 +1 @@\n-a\n+b\n", "path_traversal"),
        (
            b"diff --git a/src/L.sol b/src/L.sol\nnew file mode 120000\n--- /dev/null\n"
            b"+++ b/src/L.sol\n@@ -0,0 +1 @@\n+/etc/passwd\n",
            "symlink",
        ),
        (b"diff --git a/src/x b/src/x\nGIT binary patch\nliteral 1\nA\n", "binary_file"),
        (
            b"--- a/test/Vault.t.sol\n+++ b/test/Vault.t.sol\n@@ -1 +1 @@\n-x\n+y\n",
            "protected_path_modified",
        ),
        (
            b"--- a/foundry.toml\n+++ b/foundry.toml\n@@ -1 +1 @@\n-x\n+y\n",
            "protected_path_modified",
        ),
        (b"--- a/script/X.sol\n+++ b/script/X.sol\n@@ -1 +1 @@\n-x\n+y\n", "out_of_scope"),
    ],
)
def test_integrity_violations_stop_before_anything_runs(
    tmp_path: Path, forge: FakeForge, patch: bytes, code: str
) -> None:
    result = verify(tmp_path, patch)
    assert result.exit_code == 5, result.output
    assert forge.calls == [], "nothing may run after an integrity violation"
    assert re.search(rf"integrity\s+FAIL\s+{code}", result.stdout)
    for oracle in ORACLES[1:]:
        assert re.search(rf"{oracle}\s+-\s+skipped", result.stdout)
    assert "final verdict: REJECTED" in result.stdout
    assert_clean(result.output)


def test_a_patch_that_does_not_apply_is_rejected_without_running(
    tmp_path: Path, forge: FakeForge
) -> None:
    patch = b"--- a/src/Vault.sol\n+++ b/src/Vault.sol\n@@ -1 +1 @@\n-nothing here\n+x\n"
    result = verify(tmp_path, patch)
    assert result.exit_code == 1, result.output
    assert forge.calls == []
    assert "reason: patch_does_not_apply" in result.stdout


def test_a_vacuous_poc_makes_the_verification_inconclusive(
    tmp_path: Path, forge: FakeForge
) -> None:
    forge.decide = lambda tree, number: "blocked"
    result = verify(tmp_path, "good")
    assert result.exit_code == 3, result.output
    assert "reason: vacuous_poc" in result.stdout.splitlines()
    assert "VERIFIED_WITHIN_BOUNDS" not in result.stdout.replace("VERIFIED_WITHIN_BOUNDS means", "")


def test_a_search_that_finds_nothing_on_the_vulnerable_revision_is_inconclusive(
    tmp_path: Path, forge: FakeForge
) -> None:
    forge.variant = lambda tree: "none"
    result = verify(tmp_path, "good")
    assert result.exit_code == 3, result.output
    assert table(result.stdout)["variant"] == ("INCONCLUSIVE", "variant_search_ineffective")
    assert "reason: variant_search_ineffective" in result.stdout.splitlines()


# -- JSON, determinism, vocabulary ------------------------------------------------------------


def test_json_output_is_stable(tmp_path: Path, forge: FakeForge) -> None:
    first = verify(tmp_path, "overfit", "--json")
    second = verify(tmp_path, "overfit", "--json")
    assert first.exit_code == second.exit_code == 1
    # Only the measured durations (`timing`) may differ between two runs of the same inputs.
    reports = [json.loads(run.stdout) for run in (first, second)]
    assert [{k: v for k, v in r.items() if k != "timing"} for r in reports[:1]] == [
        {k: v for k, v in r.items() if k != "timing"} for r in reports[1:]
    ]
    report = reports[0]
    assert report["final_verdict"] == "REJECTED"
    assert report["reasons"] == ["variant_found"]
    assert report["integrity_violation"] is False
    assert [item["oracle"] for item in report["oracles"]] == ORACLES
    assert report["bounds"]["exploit_replays_per_revision"] == 3
    assert report["bounds"]["fuzz_seed"] == "0x1"
    assert report["bounds"]["fuzz_runs"] == 256
    assert report["bounds"]["interface_contracts"] == ["src/Vault.sol:Vault"]
    assert report["bounds"]["oracles_run"] == ORACLES
    assert str(tmp_path) not in first.stdout
    assert str(ROOT) not in first.stdout
    assert_clean(first.stdout)


# -- the ledger -------------------------------------------------------------------------------


def query(tmp_path: Path, sql: str) -> list[tuple[object, ...]]:
    with closing(sqlite3.connect(ledger_path(tmp_path))) as conn:
        return conn.execute(sql).fetchall()


def test_every_oracle_execution_is_recorded(tmp_path: Path, forge: FakeForge) -> None:
    assert verify(tmp_path, "good").exit_code == 0
    runs = query(
        tmp_path,
        "SELECT r.oracle, v.kind, r.verdict, r.seed, r.exit_code, r.argv_json, r.image_digest, "
        "c.status FROM oracle_run AS r JOIN revision AS v ON v.id = r.revision_id "
        "JOIN claim AS c ON c.id = r.claim_id ORDER BY r.id",
    )
    assert [run[:5] for run in runs] == [
        ("integrity", "patched", "PASS", None, None),
        ("exploit", "vulnerable", "PASS", "1", 0),
        ("exploit", "patched", "PASS", "1", 1),
        ("variant", "vulnerable", "PASS", "1", 1),
        ("variant", "patched", "PASS", "1", 0),
        ("behavior", "vulnerable", "PASS", "1", 0),
        ("behavior", "patched", "PASS", "1", 0),
        ("regression", "vulnerable", "PASS", None, 0),
        ("regression", "patched", "PASS", "1", 0),
    ]
    assert json.loads(str(runs[1][5]))[:2] == ["forge", "test"]
    assert json.loads(str(runs[3][5]))[4:] == [
        "--threads",
        "1",
        "--match-test",
        "^testFuzz_variants[(]",
        "--fuzz-seed",
        SEEDS[0],
        "--fuzz-runs",
        "256",
    ]
    assert json.loads(str(runs[7][5]))[:2] == ["forge", "inspect"]
    assert {run[6] for run in runs} == {forge.image_id()}
    assert {run[7] for run in runs} == {"trusted"}
    (verification,) = query(
        tmp_path,
        "SELECT final_verdict, reason, bounds_json, bundle_manifest_sha256 FROM verification",
    )
    assert verification[:2] == ("VERIFIED_WITHIN_BOUNDS", VERIFIED_REASON)
    assert json.loads(str(verification[2]))["oracles_not_run"] == []
    assert verification[3] is None
    with Ledger.open(ledger_path(tmp_path), read_only=True) as ledger:
        assert ledger.verify_chain().ok
        (trace,) = query(tmp_path, "SELECT trace_blob_sha256 FROM oracle_run WHERE id = 2")[0]
        assert json.loads(ledger.read_blob(str(trace)))["detail"]["replays_planned"] == 3


def test_no_claim_is_trusted_without_a_passing_run(tmp_path: Path, forge: FakeForge) -> None:
    for patch in ("good", "destructive"):
        verify(tmp_path, patch)
    verify(tmp_path, b"")
    verify(tmp_path, b"--- a/../x\n+++ b/../x\n@@ -1 +1 @@\n-a\n+b\n")
    orphans = query(
        tmp_path,
        "SELECT c.id FROM claim AS c WHERE c.status = 'trusted' AND NOT EXISTS ("
        "SELECT 1 FROM oracle_run AS r WHERE r.claim_id = c.id AND r.verdict = 'PASS')",
    )
    assert orphans == []
    statuses = query(
        tmp_path,
        "SELECT c.status, r.verdict FROM claim AS c JOIN oracle_run AS r ON r.claim_id = c.id",
    )
    expected = {"PASS": "trusted", "FAIL": "refuted", "INCONCLUSIVE": "inconclusive"}
    assert all(status == expected[str(verdict)] for status, verdict in statuses)
    assert ("refuted", "FAIL") in statuses
    verdicts = [row[0] for row in query(tmp_path, "SELECT final_verdict FROM verification")]
    assert verdicts == ["VERIFIED_WITHIN_BOUNDS", "REJECTED", "REJECTED", "REJECTED"]
    findings = query(tmp_path, "SELECT stable_id, state FROM finding")
    assert all(state == "CANDIDATE" for _, state in findings)
    assert len({stable_id for stable_id, _ in findings}) == 4


def test_the_same_inputs_can_be_verified_twice(tmp_path: Path, forge: FakeForge) -> None:
    assert verify(tmp_path, "good").exit_code == 0
    assert verify(tmp_path, "good").exit_code == 0
    stable_ids = sorted(str(row[0]) for row in query(tmp_path, "SELECT stable_id FROM finding"))
    assert stable_ids[1] == stable_ids[0] + ".2"


# -- inputs and infrastructure ----------------------------------------------------------------


def test_without_docker_the_exit_code_is_4(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner_module, "find_docker", lambda: None)
    result = verify(tmp_path, "good")
    assert result.exit_code == 4
    assert "docker CLI not found" in result.stderr


def copy_fixture(tmp_path: Path) -> Path:
    base = tmp_path / "base"
    shutil.copytree(FIXTURE, base)
    return base


def test_a_base_with_its_own_harness_directory_is_rejected(
    tmp_path: Path, forge: FakeForge
) -> None:
    base = copy_fixture(tmp_path)
    (base / "assay").mkdir()
    (base / "assay" / "AssayExploit.sol").write_text("contract Fake {}\n")
    result = verify(tmp_path, "good", base=base)
    assert result.exit_code == 5
    assert "reserved for the shared harness" in result.stderr
    assert forge.calls == []


def test_a_base_with_a_symlink_out_of_the_tree_is_rejected(
    tmp_path: Path, forge: FakeForge
) -> None:
    base = copy_fixture(tmp_path)
    (base / "src" / "Link.sol").symlink_to("/etc/hosts")
    result = verify(tmp_path, "good", base=base)
    assert result.exit_code == 5
    assert "symlink_outside_tree" in result.stderr


def test_usage_errors(tmp_path: Path, forge: FakeForge) -> None:
    assert verify(tmp_path, "good", poc=FIXTURE.parent).exit_code == 2
    no_sources = copy_fixture(tmp_path)
    for path in (no_sources / "src").iterdir():
        path.unlink()
    (no_sources / "src").rmdir()
    assert verify(tmp_path, "good", base=no_sources, poc=FIXTURE / "poc").exit_code == 2
    big = tmp_path / "big.diff"
    big.write_bytes(b"x" * (1024 * 1024 + 1))
    result = cli.invoke(
        app,
        [
            "verify",
            "--base",
            str(FIXTURE),
            "--patch",
            str(big),
            "--poc",
            str(FIXTURE / "poc"),
            "--ledger",
            str(ledger_path(tmp_path)),
        ],
    )
    assert result.exit_code == 2
    missing = cli.invoke(app, ["verify", "--base", str(FIXTURE), "--poc", str(FIXTURE / "poc")])
    assert missing.exit_code == 2
