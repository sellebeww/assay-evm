"""The full VariantOracle against the real runner image, on two fixtures with invariants.

For the reentrancy and the rounding fixture, the `good` patch must pass within the bounds of the
profile and the `overfit` patch must give a confirmed variant, with the `quick` and the
`standard` profile. Both fixtures carry an invariant, so both search modes run.
"""

import json
from pathlib import Path

import pytest

from assay.ingest import create_snapshot
from assay.ingest.patch import prepare_patched_revision
from assay.ledger import RevisionKind, Verdict
from assay.oracles.runtree import load_harness
from assay.oracles.variant import (
    COUNTEREXAMPLE_FILE,
    VARIANT_POC_FILE,
    VariantContext,
    VariantOracle,
    VariantOutcome,
    VariantSettings,
    profile,
)
from assay.sandbox import SandboxRunner

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("runner")]

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ("reentrancy/single_function", "rounding/share_inflation")
PROFILES = ("quick", "standard")


def search(
    runner: SandboxRunner, fixture: str, label: str, name: str, work: Path
) -> VariantOutcome:
    base_dir = ROOT / "fixtures" / fixture
    base = create_snapshot(base_dir, work / "base")
    poc = create_snapshot(base_dir / "poc", work / "poc")
    prepared = prepare_patched_revision(
        base, (base_dir / "patches" / f"{label}.diff").read_bytes(), work / "patched"
    )
    assert prepared.snapshot is not None
    (work / "variant").mkdir()
    return VariantOracle(VariantSettings(profile=profile(name))).search(
        VariantContext(
            runner=runner,
            vulnerable=base,
            patched=prepared.snapshot,
            poc=poc,
            harness=load_harness(),
            work_dir=work / "variant",
        )
    )


def vulnerable_modes(outcome: VariantOutcome) -> set[str]:
    return {
        item.mode
        for item in outcome.bounds.searches
        if item.revision is RevisionKind.VULNERABLE and item.found_at_seed is not None
    }


@pytest.mark.parametrize("name", PROFILES)
@pytest.mark.parametrize("fixture", FIXTURES)
def test_the_good_patch_passes_within_the_bounds_of_the_profile(
    runner: SandboxRunner, tmp_path: Path, fixture: str, name: str
) -> None:
    outcome = search(runner, fixture, "good", name, tmp_path)
    result = outcome.result
    assert result.verdict is Verdict.PASS, result.summary
    assert vulnerable_modes(outcome) == {"fuzz", "invariant"}, "both modes find the exploit"
    chosen = profile(name)
    statement = outcome.statement
    assert statement.startswith(f"profile {name}, base seed 0x1")
    assert f"fuzz: {chosen.seeds} of {chosen.seeds} seeds of {chosen.runs_per_seed} runs" in (
        statement
    )
    assert (
        f"invariant: {chosen.seeds} of {chosen.seeds} seeds of {chosen.invariant_runs} sequences "
        f"of up to {chosen.invariant_depth} calls" in statement
    )
    assert statement.endswith("this is not a proof of absence")
    patched = {
        item.mode: item for item in outcome.bounds.searches if item.revision.value == "patched"
    }
    assert patched["fuzz"].runs == chosen.seeds * chosen.runs_per_seed
    assert patched["invariant"].runs == chosen.seeds * chosen.invariant_runs
    assert outcome.timing.total_s > 0


@pytest.mark.parametrize("name", PROFILES)
@pytest.mark.parametrize("fixture", FIXTURES)
def test_the_overfit_patch_gives_a_confirmed_variant(
    runner: SandboxRunner, tmp_path: Path, fixture: str, name: str
) -> None:
    outcome = search(runner, fixture, "overfit", name, tmp_path)
    result = outcome.result
    assert result.verdict is Verdict.FAIL, result.summary
    assert result.codes() == ["variant_found"]
    assert "confirmed by 3 of 3 replays" in result.reasons[0].detail
    assert outcome.bounds.replays_reproduced == 3
    patched = result.executions[1]
    names = {item.name: item for item in patched.evidence if item.name is not None}
    document = json.loads(names[COUNTEREXAMPLE_FILE].data)
    assert document["revision"] == "patched"
    assert document["profile"] == name
    assert document["confirmation"]["status"] == "confirmed"
    source = names[VARIANT_POC_FILE].data.decode()
    assert "contract AssayVariantPoC is " in source
    assert "function test_variant() public {" in source


def test_an_invariant_search_repeats_exactly(runner: SandboxRunner, tmp_path: Path) -> None:
    """The same profile and base seed give the same campaigns, the same shrunk sequence and the
    same generated test (the invariant sender is fixed; see AssayInvariant)."""
    outcomes = []
    for index in range(2):
        work = tmp_path / f"run-{index}"
        work.mkdir()
        outcomes.append(search(runner, "rounding/share_inflation", "overfit", "standard", work))
    first, second = outcomes
    assert first.bounds == second.bounds
    assert first.statement == second.statement
    for left, right in zip(first.result.executions, second.result.executions, strict=True):
        assert left.trace == right.trace
        assert [item.data for item in left.evidence] == [item.data for item in right.evidence]
