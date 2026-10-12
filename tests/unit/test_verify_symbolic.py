"""`assay verify --symbolic` with stand-in runners (no Docker): the symbolic oracle runs after
the variant search, its result takes part in the final verdict (a timeout or unknown result is
never a pass), the bounds and the report state what ran, and the evidence level follows the
oracle results."""

import json
import shutil
from pathlib import Path

import pytest
from fake_forge import FakeForge
from fake_halmos import FakeHalmos, HalmosAnswer, entry, model, report
from typer.testing import CliRunner, Result
from vault_scenario import FIXTURE, unchanged, vault_forge

from assay.cli.main import app
from assay.ledger import FinalVerdict, OracleName, RevisionKind, Verdict
from assay.oracles.base import Reason
from assay.orchestrator.models import REPORT_ORDER
from assay.orchestrator.verify import ORACLE_ORDER, OracleRow, decide, evidence_level

CONTRACT = "test/symbolic/VaultCheck.t.sol:VaultCheck"
CHECK = "check_variant_withdraw(address,uint256)"
WITNESS = model({"caller": ("address", 160, 0xAA), "amount": ("uint256", 256, 3)})

cli = CliRunner()


def row(oracle: OracleName, verdict: Verdict, code: str | None = None) -> OracleRow:
    reasons = () if code is None else (Reason(code=code, detail="x"),)
    return OracleRow(oracle=oracle, status="ran", verdict=verdict, reasons=reasons, summary="s")


def required(verdict: Verdict = Verdict.PASS) -> list[OracleRow]:
    return [row(oracle, verdict) for oracle in ORACLE_ORDER]


def test_the_symbolic_oracle_runs_after_the_variant_search() -> None:
    assert REPORT_ORDER.index(OracleName.SYMBOLIC) == REPORT_ORDER.index(OracleName.VARIANT) + 1


def test_a_symbolic_result_takes_part_in_the_final_verdict() -> None:
    passed = [*required(), row(OracleName.SYMBOLIC, Verdict.PASS)]
    assert decide(passed) == (FinalVerdict.VERIFIED_WITHIN_BOUNDS, ())
    unknown = [*required(), row(OracleName.SYMBOLIC, Verdict.INCONCLUSIVE, "symbolic_unknown")]
    assert decide(unknown) == (FinalVerdict.INCONCLUSIVE, ("symbolic_unknown",))
    found = [*required(), row(OracleName.SYMBOLIC, Verdict.FAIL, "variant_found")]
    assert decide(found) == (FinalVerdict.REJECTED, ("variant_found",))


def test_the_evidence_level_follows_the_oracle_results() -> None:
    assert evidence_level(required(), FinalVerdict.VERIFIED_WITHIN_BOUNDS) == "E3"
    no_variant = [
        *(item for item in required() if item.oracle is not OracleName.VARIANT),
        row(OracleName.VARIANT, Verdict.INCONCLUSIVE, "timeout"),
    ]
    assert evidence_level(no_variant, FinalVerdict.INCONCLUSIVE) == "E2"
    blocked_not_closed = [
        row(OracleName.INTEGRITY, Verdict.PASS),
        row(OracleName.EXPLOIT, Verdict.FAIL, "exploit_still_reproducible"),
    ]
    assert evidence_level(blocked_not_closed, FinalVerdict.REJECTED) == "E1"
    variant = [*required()[:2], row(OracleName.VARIANT, Verdict.FAIL, "variant_found")]
    assert evidence_level(variant, FinalVerdict.REJECTED) == "E1"
    vacuous = [row(OracleName.EXPLOIT, Verdict.INCONCLUSIVE, "vacuous_poc")]
    assert evidence_level(vacuous, FinalVerdict.INCONCLUSIVE) == "E0"
    unknown = [*required(), row(OracleName.SYMBOLIC, Verdict.INCONCLUSIVE, "symbolic_unknown")]
    assert evidence_level(unknown, FinalVerdict.INCONCLUSIVE) == "E2"


def vault_revision(tree: Path) -> RevisionKind:
    return RevisionKind.VULNERABLE if unchanged(tree) else RevisionKind.PATCHED


def poc_with_properties(tmp_path: Path) -> Path:
    poc = tmp_path / "poc"
    shutil.copytree(FIXTURE / "poc", poc)
    (poc / "symbolic").mkdir()
    (poc / "symbolic" / "VaultCheck.t.sol").write_text("contract VaultCheck {}\n")
    return poc


def verify(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    patch: str,
    answer: HalmosAnswer | None,
    *options: str,
    poc: Path | None = None,
    replays: str = "reproduced",
) -> tuple[Result, FakeForge, FakeHalmos]:
    forge = vault_forge()
    forge.confirm = lambda tree, number: replays
    vault_interface = forge.interface

    def interface(tree: Path, contract: str, field: str) -> str:
        if contract != CONTRACT:
            return vault_interface(tree, contract, field)
        inputs = [{"name": "caller", "type": "address"}, {"name": "amount", "type": "uint256"}]
        return json.dumps([{"type": "function", "name": CHECK.split("(")[0], "inputs": inputs}])

    forge.interface = interface
    found = report({CONTRACT: [entry(CHECK, 1, [WITNESS])]}, 1)
    halmos = FakeHalmos(
        lambda revision, prefix: (
            found if revision is RevisionKind.VULNERABLE else (answer if answer else found)
        ),
        vault_revision,
    )
    monkeypatch.setattr("assay.cli.verify.SandboxRunner", lambda: forge)
    monkeypatch.setattr("assay.cli.verify.symbolic_runner", lambda: halmos)
    args = [
        "verify",
        "--base",
        str(FIXTURE),
        "--patch",
        str(FIXTURE / "patches" / f"{patch}.diff"),
        "--poc",
        str(poc if poc is not None else poc_with_properties(tmp_path)),
        "--ledger",
        str(tmp_path / ".assay" / "ledger.db"),
        "--profile",
        "quick",
        *options,
    ]
    return cli.invoke(app, args), forge, halmos


CLEAN = report({CONTRACT: [entry(CHECK, 0)]})


def test_symbolic_is_off_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    result, _, halmos = verify(tmp_path, monkeypatch, "good", CLEAN, "--json")
    document = json.loads(result.stdout)
    assert result.exit_code == 0
    assert [item["oracle"] for item in document["oracles"]] == [
        oracle.value for oracle in ORACLE_ORDER
    ]
    assert halmos.calls == []
    assert document["bounds"]["symbolic"] is None
    assert document["annotations"] == []
    assert document["evidence_level"] == "E3"


def test_a_good_patch_is_verified_with_the_symbolic_bounds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, _, halmos = verify(tmp_path, monkeypatch, "good", CLEAN, "--symbolic")
    assert result.exit_code == 0, result.stdout
    lines = result.stdout.splitlines()
    assert "final verdict: VERIFIED_WITHIN_BOUNDS" in lines
    assert any(line.startswith("symbolic") and "PASS" in line for line in lines)
    statement = next(line for line in lines if line.startswith("symbolic: "))
    assert statement.startswith(
        "symbolic: no counterexample within loop bound 3 for check_variant_withdraw "
        "(calldata 4+32*2 bytes)"
    )
    assert "evidence level: E3" in lines
    assert "bounded equivalence: no equivalence properties in the PoC directory" in lines
    assert len(halmos.calls) == 2


def test_a_symbolic_timeout_makes_the_verdict_inconclusive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, _, _ = verify(tmp_path, monkeypatch, "good", "timeout", "--symbolic", "--json")
    document = json.loads(result.stdout)
    assert result.exit_code == 3
    assert document["final_verdict"] == "INCONCLUSIVE"
    assert document["reasons"] == ["symbolic_unknown"]
    assert document["annotations"][0].startswith("symbolic: unknown (timeout 900 s)")
    assert document["annotations"][1] == (
        "bounded equivalence: no equivalence properties in the PoC directory"
    )
    assert document["evidence_level"] == "E2"
    rows = {item["oracle"]: item for item in document["oracles"]}
    assert rows["symbolic"]["verdict"] == "INCONCLUSIVE"


def test_a_confirmed_symbolic_counterexample_rejects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    found = report({CONTRACT: [entry(CHECK, 1, [WITNESS])]}, 1)
    result, _, _ = verify(tmp_path, monkeypatch, "good", found, "--symbolic", "--json")
    document = json.loads(result.stdout)
    assert result.exit_code == 1
    assert document["final_verdict"] == "REJECTED"
    assert document["reasons"] == ["variant_found"]
    assert document["bounds"]["symbolic"]["confirmed_property"] == CHECK


def test_a_symbolic_counterexample_that_does_not_replay_is_inconclusive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    found = report({CONTRACT: [entry(CHECK, 1, [WITNESS])]}, 1)
    result, _, _ = verify(
        tmp_path, monkeypatch, "good", found, "--symbolic", "--json", replays="blocked"
    )
    document = json.loads(result.stdout)
    assert result.exit_code == 3
    assert document["reasons"] == ["flaky_counterexample"]


def test_without_properties_symbolic_is_inconclusive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, _, halmos = verify(
        tmp_path, monkeypatch, "good", CLEAN, "--symbolic", "--json", poc=FIXTURE / "poc"
    )
    document = json.loads(result.stdout)
    assert result.exit_code == 3
    assert document["reasons"] == ["no_symbolic_properties"]
    assert halmos.calls == []


def test_a_symbolic_bundle_records_the_symbolic_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "bundle"
    result, _, _ = verify(
        tmp_path, monkeypatch, "good", CLEAN, "--symbolic", "--bundle-out", str(bundle)
    )
    assert result.exit_code == 0, result.stdout
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert manifest["settings"]["symbolic"] is True
    assert manifest["symbolic_environment"]["tool_versions"] == {"halmos": "0.3.3"}
    assert manifest["evidence_level"] == "E3"
    assert manifest["annotations"][0].startswith("symbolic: no counterexample")
    assert manifest["bounds"]["symbolic"]["loop_bound"] == 3
    assert (bundle / "evidence" / "symbolic" / "result.json").is_file()
