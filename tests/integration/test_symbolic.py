"""The SymbolicOracle against the real runner images (Halmos in the symbolic image, the replays
of a counterexample in the regular image), on two tractable fixtures.

For `access_control/missing_modifier` and `delegatecall/user_controlled_target`, the `good` patch
must pass within the stated bounds with no difference in bounded equivalence, and the `overfit`
patch must give a counterexample that three Foundry replays confirm. Running the same patch twice
must give the same verdict, bounds and per-property results with the pinned tools.
"""

import json
from pathlib import Path

import pytest

from assay.ingest import create_snapshot
from assay.ingest.patch import prepare_patched_revision
from assay.ledger import RevisionKind, Verdict
from assay.oracles.runtree import load_harness
from assay.oracles.symbolic import SymbolicContext, SymbolicOracle, SymbolicOutcome
from assay.oracles.variant import VARIANT_POC_FILE
from assay.sandbox import SandboxRunner

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("runner", "symbolic_runner")]

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = {
    "access_control/missing_modifier": "check_variant_payOut(address,uint256)",
    "delegatecall/user_controlled_target": "check_variant_runUpkeepBatch(address,address,bool)",
}


def check(
    runner: SandboxRunner, halmos: SandboxRunner, fixture: str, label: str, work: Path
) -> SymbolicOutcome:
    base_dir = ROOT / "fixtures" / fixture
    base = create_snapshot(base_dir, work / "base")
    poc = create_snapshot(base_dir / "poc", work / "poc")
    prepared = prepare_patched_revision(
        base, (base_dir / "patches" / f"{label}.diff").read_bytes(), work / "patched"
    )
    assert prepared.snapshot is not None
    (work / "symbolic").mkdir()
    return SymbolicOracle(halmos_version="0.3.3").search(
        SymbolicContext(
            runner=runner,
            symbolic_runner=halmos,
            vulnerable=base,
            patched=prepared.snapshot,
            poc=poc,
            harness=load_harness(),
            work_dir=work / "symbolic",
        )
    )


@pytest.mark.parametrize("fixture", sorted(FIXTURES))
def test_the_good_patch_passes_within_the_bounds(
    runner: SandboxRunner, symbolic_runner: SandboxRunner, tmp_path: Path, fixture: str
) -> None:
    outcome = check(runner, symbolic_runner, fixture, "good", tmp_path)
    result = outcome.result
    assert result.verdict is Verdict.PASS, result.reasons
    assert [item.verdict for item in result.executions] == [Verdict.PASS, Verdict.PASS]
    vulnerable = [
        item
        for item in outcome.bounds.checks
        if item.revision is RevisionKind.VULNERABLE and item.kind == "variant"
    ]
    assert vulnerable
    assert all(item.outcome == "counterexample" for item in vulnerable)
    patched = [
        item
        for item in outcome.bounds.checks
        if item.revision is RevisionKind.PATCHED and item.kind == "variant"
    ]
    assert all(item.outcome == "no_counterexample" for item in patched)
    assert outcome.statement.startswith("symbolic: no counterexample within loop bound 3 for ")
    assert outcome.statement.endswith("this is not a proof of absence")
    assert outcome.bounds.equivalence == "no_difference"
    assert result.warnings == ()


@pytest.mark.parametrize("fixture", sorted(FIXTURES))
def test_the_overfit_patch_gives_a_confirmed_counterexample(
    runner: SandboxRunner, symbolic_runner: SandboxRunner, tmp_path: Path, fixture: str
) -> None:
    outcome = check(runner, symbolic_runner, fixture, "overfit", tmp_path)
    result = outcome.result
    assert result.verdict is Verdict.FAIL, result.reasons
    assert result.codes() == ["variant_found"]
    assert outcome.bounds.confirmed_property == FIXTURES[fixture]
    assert outcome.bounds.replays_reproduced == 3
    evidence = {item.name: item for item in result.executions[1].evidence if item.name}
    assert VARIANT_POC_FILE in evidence
    document = json.loads(evidence["counterexample.json"].data)
    assert document["property"] == FIXTURES[fixture]
    assert document["confirmation"]["reproduced"] == 3


def test_the_same_patch_gives_the_same_result_twice(
    runner: SandboxRunner, symbolic_runner: SandboxRunner, tmp_path: Path
) -> None:
    fixture = "access_control/missing_modifier"
    outcomes = []
    for name in ("one", "two"):
        (tmp_path / name).mkdir()
        outcomes.append(check(runner, symbolic_runner, fixture, "overfit", tmp_path / name))
    first, second = outcomes
    assert first.result.verdict is second.result.verdict
    assert first.bounds == second.bounds
    assert first.statement == second.statement
