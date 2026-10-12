"""`assay verify` and `assay replay` on the reentrancy fixture, against the real runner image.

The expected final verdict and reason of each patch come from the fixture's `expected.json`,
which `make fixtures-check` establishes with plain Foundry, independently of the oracles.
"""

import json
import re
import shutil
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from assay.cli.main import app
from assay.cli.verify import render
from assay.ledger import Ledger
from assay.orchestrator.verify import VerifyReport

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("runner")]

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures" / "reentrancy" / "single_function"
EXPECTED = json.loads((FIXTURE / "expected.json").read_text())["variants"]
FORBIDDEN = re.compile(r"\b(secure|safe|proven|guaranteed|unhackable)\b", re.IGNORECASE)
LABELS = ("good", "overfit", "destructive", "regressing")
CASES = (*LABELS, "empty")
BOUND = "fuzz: 3 of 3 seeds of 256 runs (768 runs), no variant found"
INVARIANT_BOUND = "invariant: 3 of 3 seeds of 64 sequences of up to 25 calls (192 sequences"

cli = CliRunner()


class Run:
    def __init__(self, exit_code: int, output: str, bundle: Path) -> None:
        self.exit_code = exit_code
        self.output = output
        self.bundle = bundle
        self.report: dict[str, Any] = json.loads(output)

    def oracle(self, name: str) -> dict[str, Any]:
        (found,) = [item for item in self.report["oracles"] if item["oracle"] == name]
        return found

    def codes(self, name: str) -> list[str]:
        return [item["code"] for item in self.oracle(name)["reasons"]]


@pytest.fixture(scope="module")
def workspace(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("verify")


def patch_file(workspace: Path, case: str) -> Path:
    if case == "empty":
        empty = workspace / "empty.diff"
        empty.write_bytes(b"")
        return empty
    return FIXTURE / "patches" / f"{case}.diff"


def verify(workspace: Path, case: str, bundle: Path) -> Run:
    result = cli.invoke(
        app,
        [
            "verify",
            "--base",
            str(FIXTURE),
            "--patch",
            str(patch_file(workspace, case)),
            "--poc",
            str(FIXTURE / "poc"),
            "--ledger",
            str(workspace / ".assay" / "ledger.db"),
            "--bundle-out",
            str(bundle),
            "--json",
        ],
    )
    assert result.exit_code in (0, 1, 3), f"{case}: {result.output}"
    return Run(result.exit_code, result.stdout, bundle)


@pytest.fixture(scope="module")
def runs(workspace: Path) -> dict[str, Run]:
    return {case: verify(workspace, case, workspace / "bundles" / case) for case in CASES}


@pytest.mark.parametrize("label", LABELS)
def test_each_patch_gets_the_verdict_and_reason_of_its_label(
    runs: dict[str, Run], label: str
) -> None:
    run, spec = runs[label], EXPECTED[label]
    assert run.report["final_verdict"] == spec["verdict"]
    assert run.exit_code == (0 if spec["verdict"] == "VERIFIED_WITHIN_BOUNDS" else 1)
    if spec["reason"] is not None:
        assert spec["reason"] in run.report["reasons"]
    assert run.report["integrity_violation"] is False
    assert run.oracle("exploit")["verdict"] == "PASS", "every patch blocks the original PoC"


def test_the_good_patch_passes_all_five_oracles(runs: dict[str, Run]) -> None:
    run = runs["good"]
    assert run.report["final_verdict"] == "VERIFIED_WITHIN_BOUNDS"
    assert [item["verdict"] for item in run.report["oracles"]] == ["PASS"] * 5
    assert run.report["reasons"] == []
    statement = run.report["bounds_statement"]
    assert "variant: profile standard, base seed 0x1" in statement
    assert BOUND in statement
    assert INVARIANT_BOUND in statement
    assert "no variant found within these runs; this is not a proof of absence" in statement
    assert "the search found the exploit" in run.oracle("variant")["summary"]


def test_the_overfit_patch_is_caught_by_the_variant_search(runs: dict[str, Run]) -> None:
    run = runs["overfit"]
    assert run.report["reasons"] == ["variant_found"]
    assert run.oracle("variant")["verdict"] == "FAIL"
    for name in ("integrity", "behavior", "regression"):
        assert run.oracle(name)["verdict"] == "PASS", name
    counterexample = json.loads(
        (run.bundle / "evidence" / "variant" / "counterexample.json").read_text()
    )
    assert counterexample["revision"] == "patched"
    assert re.fullmatch(r"0x[0-9a-fA-F]{40}", counterexample["attacker"])
    assert len(counterexample["knobs"]) == 4
    assert counterexample["predicates"][0]["kind"] == "attacker_profit"


def test_the_destructive_patch_fails_the_benign_tests(runs: dict[str, Run]) -> None:
    run = runs["destructive"]
    assert run.oracle("behavior")["verdict"] == "FAIL"
    assert run.codes("behavior") == ["benign_test_failed"]
    assert run.oracle("variant")["verdict"] == "PASS"


def test_the_regressing_patch_is_rejected_by_the_regression_oracle(runs: dict[str, Run]) -> None:
    run = runs["regressing"]
    assert run.report["reasons"] == ["layout_changed"]
    assert run.oracle("regression")["verdict"] == "FAIL"
    assert set(run.codes("regression")) == {"layout_changed"}
    for name in ("integrity", "exploit", "variant", "behavior"):
        assert run.oracle(name)["verdict"] == "PASS", name


def test_an_empty_patch_leaves_the_exploit_reproducible(runs: dict[str, Run]) -> None:
    run = runs["empty"]
    assert run.report["final_verdict"] == "REJECTED"
    assert run.report["reasons"][:2] == ["exploit_still_reproducible", "variant_found"]
    assert run.report["inputs"]["patched_tree_sha256"] == run.report["inputs"]["base_tree_sha256"]


def test_no_output_uses_forbidden_words(runs: dict[str, Run]) -> None:
    for case, run in runs.items():
        text = render(VerifyReport.model_validate(run.report))
        assert FORBIDDEN.search(run.output) is None, case
        assert FORBIDDEN.search(text) is None, case
        assert FORBIDDEN.search((run.bundle / "manifest.json").read_text()) is None, case


def test_the_ledger_holds_every_oracle_run(workspace: Path, runs: dict[str, Run]) -> None:
    database = workspace / ".assay" / "ledger.db"
    with closing(sqlite3.connect(database)) as conn:
        runs_per_oracle = dict(
            conn.execute("SELECT oracle, count(*) FROM oracle_run GROUP BY oracle").fetchall()
        )
        orphans = conn.execute(
            "SELECT c.id FROM claim AS c WHERE c.status = 'trusted' AND NOT EXISTS ("
            "SELECT 1 FROM oracle_run AS r WHERE r.claim_id = c.id AND r.verdict = 'PASS')"
        ).fetchall()
        unpromoted = conn.execute("SELECT count(*) FROM claim WHERE status = 'asserted'").fetchone()
        verdicts = conn.execute(
            "SELECT final_verdict, bundle_manifest_sha256 FROM verification ORDER BY id"
        ).fetchall()
    count = len(CASES)
    assert runs_per_oracle == {
        "integrity": count,
        "exploit": 2 * count,
        "variant": 2 * count,
        "behavior": 2 * count,
        "regression": 2 * count,
    }
    assert orphans == []
    assert unpromoted == (0,)
    assert [row[0] for row in verdicts] == [
        "VERIFIED_WITHIN_BOUNDS",
        "REJECTED",
        "REJECTED",
        "REJECTED",
        "REJECTED",
    ]
    assert all(re.fullmatch(r"[0-9a-f]{64}", str(row[1])) for row in verdicts)
    with Ledger.open(database, read_only=True) as ledger:
        assert ledger.verify_chain().ok


# -- replay -----------------------------------------------------------------------------------


@pytest.mark.parametrize("case", ["good", "overfit"])
def test_an_intact_bundle_replays_to_a_match(runs: dict[str, Run], case: str) -> None:
    result = cli.invoke(app, ["replay", str(runs[case].bundle)])
    assert result.exit_code == 0, result.output
    assert result.stdout.splitlines()[0] == "REPLAY MATCH"
    assert FORBIDDEN.search(result.output) is None


def test_a_bundle_with_one_changed_byte_is_refused(runs: dict[str, Run], workspace: Path) -> None:
    tampered = workspace / "tampered"
    shutil.copytree(runs["good"].bundle, tampered)
    target = tampered / "base" / "src" / "Vault.sol"
    data = bytearray(target.read_bytes())
    data[100] ^= 0x01
    target.write_bytes(bytes(data))
    result = cli.invoke(app, ["replay", str(tampered)])
    assert result.exit_code == 5, result.output
    assert "changed: base/src/Vault.sol" in result.stderr
    assert "REPLAY MATCH" not in result.stdout
