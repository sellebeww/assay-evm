"""VariantOracle with a stand-in runner (no Docker): profiles and seeds, the search modes, the
sanity check per mode, the confirmation of a counterexample, the verdicts and the bounds."""

import json
from collections.abc import Callable
from pathlib import Path

import fake_forge
import pytest
from fake_forge import Confirm, FakeForge, Invariant, Variant

from assay.analyzers.foundry import ForgeOutOfMemory, parse_test_output, summarize
from assay.analyzers.foundry.models import ForgeTestRun
from assay.ingest import Snapshot, create_snapshot
from assay.ledger import RevisionKind, Verdict
from assay.oracles.runtree import load_harness
from assay.oracles.variant import (
    COUNTEREXAMPLE_FILE,
    INVARIANT_FILTER,
    REPLAY_CONTRACT_FILTER,
    VARIANT_FILTER,
    VARIANT_POC_FILE,
    VariantContext,
    VariantOracle,
    VariantOutcome,
    VariantSettings,
    classify_invariant,
    classify_search,
    derive_seeds,
    profile,
)

TOPIC = "0x" + "ab" * 32
SEEDS = derive_seeds("0x1", 3)


def snapshot(tmp_path: Path, name: str, files: dict[str, str]) -> Snapshot:
    root = tmp_path / f"{name}-src"
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return create_snapshot(root, tmp_path / name)


def vulnerable_tree(tree: Path) -> bool:
    return "VULNERABLE" in (tree / "src" / "Target.sol").read_text()


def per_revision(vulnerable: str, patched: str) -> Callable[[Path], str]:
    return lambda tree: vulnerable if vulnerable_tree(tree) else patched


def search(
    tmp_path: Path,
    variant: Variant,
    *,
    invariant: Invariant | None = None,
    confirm: Confirm | None = None,
    settings: VariantSettings | None = None,
    build_fails: Callable[[Path], bool] | None = None,
) -> tuple[VariantOutcome, FakeForge]:
    runner = FakeForge(
        lambda tree, number: "blocked",
        variant=variant,
        invariant=invariant,
        confirm=confirm,
        build_fails=build_fails or (lambda tree: False),
    )
    work = tmp_path / "work"
    work.mkdir()
    context = VariantContext(
        runner=runner,
        vulnerable=snapshot(tmp_path, "vulnerable", {"src/Target.sol": "// VULNERABLE\n"}),
        patched=snapshot(tmp_path, "patched", {"src/Target.sol": "// fixed\n"}),
        poc=snapshot(tmp_path, "poc", {"Exploit.t.sol": "contract ExploitPoC {}\n"}),
        harness=load_harness(),
        work_dir=work,
    )
    return VariantOracle(settings).search(context), runner


def seeds_of(runner: FakeForge, match: str) -> list[str]:
    return [call[call.index("--fuzz-seed") + 1] for call in runner.tests(match)]


# -- profiles and seeds ------------------------------------------------------------------------


def test_the_default_settings_use_the_standard_profile_and_derived_seeds() -> None:
    settings = VariantSettings()
    assert settings.profile == profile("standard")
    assert settings.base_seed == "0x1"
    assert settings.seeds == SEEDS
    assert settings.fuzz_runs == 256
    assert VariantSettings(runs_per_seed=17).fuzz_runs == 17
    assert VariantSettings(base_seed="0x2a").seed == 42
    with pytest.raises(ValueError, match="runs_per_seed"):
        VariantSettings(runs_per_seed=0)
    with pytest.raises(ValueError, match="base_seed"):
        VariantSettings(base_seed="0x1; rm")


def test_every_campaign_uses_its_derived_seed_and_the_profile_limits(tmp_path: Path) -> None:
    outcome, runner = search(tmp_path, per_revision("found", "none"))
    assert outcome.result.verdict is Verdict.PASS
    # Vulnerable: the first seed finds the exploit, so the mode stops; patched: every seed runs.
    assert seeds_of(runner, VARIANT_FILTER) == [SEEDS[0], *SEEDS]
    assert all(
        call[call.index("--fuzz-runs") + 1] == "256" for call in runner.tests(VARIANT_FILTER)
    )
    limits = {
        timeout
        for call, timeout in zip(runner.calls, runner.timeouts, strict=True)
        if call[1] == "test"
    }
    assert limits == {300}
    # Without an invariant in the PoC directory, the invariant mode runs once and stops.
    assert seeds_of(runner, INVARIANT_FILTER) == [SEEDS[0]]


# -- verdicts ----------------------------------------------------------------------------------


def test_found_on_the_vulnerable_revision_and_none_on_the_patched_one_passes(
    tmp_path: Path,
) -> None:
    outcome, runner = search(tmp_path, per_revision("found", "none"))
    result = outcome.result
    assert result.verdict is Verdict.PASS
    assert result.reasons == ()
    statement = outcome.statement
    assert statement.startswith(f"profile standard, base seed 0x1, seeds {', '.join(SEEDS)}")
    assert "fuzz: 3 of 3 seeds of 256 runs (768 runs), no variant found" in statement
    assert "invariant: no invariant in the PoC directory" in statement
    assert statement.endswith("no variant found within these runs; this is not a proof of absence")
    assert statement in result.summary
    vulnerable, patched = result.executions
    assert (vulnerable.verdict, patched.verdict) == (Verdict.PASS, Verdict.PASS)
    assert vulnerable.seed == patched.seed == 1
    assert [item.name for item in vulnerable.evidence] == [None, "sanity-counterexample.json"]
    assert [item.name for item in patched.evidence] == [None, None, None]
    bounds = outcome.bounds
    assert (bounds.profile, bounds.base_seed, bounds.seeds) == ("standard", "0x1", SEEDS)
    found = {(item.revision, item.mode): item for item in bounds.searches}
    assert found[(RevisionKind.VULNERABLE, "fuzz")].found_at_seed == 1
    assert found[(RevisionKind.PATCHED, "fuzz")].seeds_run == 3
    assert found[(RevisionKind.PATCHED, "fuzz")].runs == 768
    assert not found[(RevisionKind.PATCHED, "invariant")].available
    assert bounds.replays_reproduced is None
    assert len(runner.commands("build")) == 2


def test_a_confirmed_variant_fails_with_its_counterexample_and_test(tmp_path: Path) -> None:
    outcome, runner = search(tmp_path, per_revision("found", "found"))
    result = outcome.result
    assert result.verdict is Verdict.FAIL
    assert result.codes() == ["variant_found"]
    detail = result.reasons[0].detail
    assert "fuzz variant found with seed 1 and confirmed by 3 of 3 replays" in detail
    assert "knobs 7886, 3, 0, 0" in detail
    assert len(runner.tests(None)) == 0
    replays = [call for call in runner.commands("test") if REPLAY_CONTRACT_FILTER in call]
    assert len(replays) == 3
    patched = result.executions[1]
    names = [item.name for item in patched.evidence]
    assert COUNTEREXAMPLE_FILE in names
    assert VARIANT_POC_FILE in names
    (document,) = [
        json.loads(item.data) for item in patched.evidence if item.name == COUNTEREXAMPLE_FILE
    ]
    assert document["revision"] == "patched"
    assert (document["profile"], document["seed_index"], document["seed"]) == (
        "standard",
        1,
        SEEDS[0],
    )
    assert document["knobs"] == ["7886", "3", "0", "0"]
    assert document["confirmation"]["status"] == "confirmed"
    (source,) = [item.data.decode() for item in patched.evidence if item.name == VARIANT_POC_FILE]
    assert "contract AssayVariantPoC is ExploitPoC {" in source
    assert f"0x{11:064x}" in source
    assert "ASSAY_VARIANT_FOUND" not in source
    assert outcome.bounds.replays_reproduced == 3
    assert "variant found with seed 1 of 3" in outcome.statement
    assert "confirmed by 3 of 3 replays" in outcome.statement
    assert "this is not a proof of absence" not in outcome.statement


@pytest.mark.parametrize(
    "answers", [("reproduced", "blocked", "reproduced"), ("blocked", "blocked", "blocked")]
)
def test_replays_that_disagree_or_miss_are_a_flaky_counterexample(
    tmp_path: Path, answers: tuple[str, str, str]
) -> None:
    outcome, _ = search(
        tmp_path,
        per_revision("found", "found"),
        confirm=lambda tree, number: answers[number - 1],
    )
    result = outcome.result
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.codes() == ["flaky_counterexample"]
    reproduced = answers.count("reproduced")
    assert f"reproduced in {reproduced} of 3 replays" in result.reasons[0].detail
    names = [item.name for item in result.executions[1].evidence]
    assert COUNTEREXAMPLE_FILE in names
    assert VARIANT_POC_FILE in names
    assert outcome.bounds.replays_reproduced == reproduced


def test_a_counterexample_that_cannot_be_written_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fake_forge, "VARIANT_CALLDATA", "0xa167c778" + "00" * 31)
    outcome, runner = search(tmp_path, per_revision("found", "found"))
    assert outcome.result.verdict is Verdict.INCONCLUSIVE
    assert outcome.result.codes() == ["counterexample_rejected"]
    assert not [call for call in runner.commands("test") if REPLAY_CONTRACT_FILTER in call]
    names = [item.name for item in outcome.result.executions[1].evidence]
    assert COUNTEREXAMPLE_FILE in names
    assert VARIANT_POC_FILE not in names


def test_a_search_that_finds_nothing_on_the_vulnerable_revision_is_ineffective(
    tmp_path: Path,
) -> None:
    outcome, runner = search(tmp_path, per_revision("none", "none"))
    result = outcome.result
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.codes() == ["variant_search_ineffective"]
    assert result.executions[0].verdict is Verdict.INCONCLUSIVE
    assert result.executions[1].verdict is Verdict.PASS
    assert seeds_of(runner, VARIANT_FILTER) == [*SEEDS, *SEEDS]
    assert "not counted" in outcome.statement


def test_a_concrete_variant_fails_even_when_the_sanity_check_does_not_pass(
    tmp_path: Path,
) -> None:
    outcome, _ = search(tmp_path, per_revision("none", "found"))
    assert outcome.result.verdict is Verdict.FAIL
    assert outcome.result.codes() == ["variant_found"]


def test_the_search_stops_at_the_first_seed_that_finds_a_variant(tmp_path: Path) -> None:
    calls: dict[bool, int] = {True: 0, False: 0}

    def variant(tree: Path) -> str:
        vulnerable = vulnerable_tree(tree)
        if not vulnerable and "/confirm-" in str(tree):
            return "found"
        calls[vulnerable] += 1
        return "found" if vulnerable or calls[False] == 2 else "none"

    outcome, _ = search(tmp_path, variant)
    assert outcome.result.verdict is Verdict.FAIL
    patched = {
        item.mode: item for item in outcome.bounds.searches if item.revision.value == "patched"
    }
    assert patched["fuzz"].found_at_seed == 2
    assert patched["fuzz"].seeds_run == 2
    assert "variant found with seed 2 of 3" in outcome.statement


@pytest.mark.parametrize(
    ("patched", "code"),
    [
        ("incomplete", "variant_search_incomplete"),
        ("unconfirmed", "variant_unconfirmed"),
        ("other", "variant_search_failed"),
        ("setup", "poc_setup_failed"),
        ("missing", "poc_not_found"),
        ("timeout", "timeout"),
    ],
)
def test_anything_but_a_clean_search_is_never_a_pass(
    tmp_path: Path, patched: str, code: str
) -> None:
    outcome, _ = search(tmp_path, per_revision("found", patched))
    assert outcome.result.verdict is Verdict.INCONCLUSIVE
    assert outcome.result.codes() == [code]
    if code == "timeout":
        assert "exceeded the profile's limit of 300 s" in outcome.result.reasons[0].detail


def test_a_vulnerable_revision_that_does_not_compile_is_inconclusive(tmp_path: Path) -> None:
    outcome, _ = search(tmp_path, per_revision("found", "none"), build_fails=vulnerable_tree)
    assert outcome.result.verdict is Verdict.INCONCLUSIVE
    assert outcome.result.codes() == ["poc_build_failed"]


def test_out_of_memory_is_an_infrastructure_error(tmp_path: Path) -> None:
    with pytest.raises(ForgeOutOfMemory):
        search(tmp_path, per_revision("oom", "none"))


def test_the_quick_profile_and_a_base_seed_set_the_campaigns(tmp_path: Path) -> None:
    settings = VariantSettings(profile=profile("quick"), base_seed="0x2a", runs_per_seed=17)
    outcome, runner = search(tmp_path, per_revision("found", "none"), settings=settings)
    seeds = derive_seeds("0x2a", 1)
    assert outcome.result.verdict is Verdict.PASS
    assert seeds_of(runner, VARIANT_FILTER) == [seeds[0], seeds[0]]
    assert {call[-2:] for call in runner.tests(VARIANT_FILTER)} == {("--fuzz-runs", "17")}
    assert "fuzz: 1 of 1 seeds of 17 runs (17 runs), no variant found" in outcome.statement
    assert outcome.result.executions[0].seed == 42
    assert set(runner.timeouts) - {None} == {180}


# -- invariant mode ----------------------------------------------------------------------------


def test_an_invariant_variant_is_confirmed_through_a_replayed_sequence(tmp_path: Path) -> None:
    outcome, runner = search(
        tmp_path, per_revision("found", "none"), invariant=per_revision("found", "found")
    )
    result = outcome.result
    assert result.verdict is Verdict.FAIL
    assert "invariant variant found with seed 1" in result.reasons[0].detail
    assert "invariant vault_solvent broken by 2 calls (shrunk from 8)" in result.reasons[0].detail
    patched = result.executions[1]
    (source,) = [item.data.decode() for item in patched.evidence if item.name == VARIANT_POC_FILE]
    assert "contract AssayVariantPoC is SolvencyInvariant {" in source
    assert source.count("assayReplayCall(") == 2
    assert "assayCheckInvariant();" in source
    assert f"uint256(0x{63:064x})" in source
    assert "bytes4(uint32(0x76fcc654))" in source
    assert "attackerDeposit" not in source
    assert seeds_of(runner, INVARIANT_FILTER) == [SEEDS[0], SEEDS[0]]


def test_an_invariant_that_finds_nothing_on_the_vulnerable_revision_is_not_counted(
    tmp_path: Path,
) -> None:
    outcome, _ = search(
        tmp_path, per_revision("found", "none"), invariant=per_revision("none", "none")
    )
    result = outcome.result
    assert result.verdict is Verdict.PASS
    assert [item.code for item in result.warnings] == ["invariant_search_ineffective"]
    assert "invariant: 3 of 3 seeds of 64 sequences of up to 25 calls" in outcome.statement
    assert "not counted: this mode found nothing on the vulnerable revision" in outcome.statement


def test_an_effective_invariant_search_counts_towards_the_pass(tmp_path: Path) -> None:
    outcome, _ = search(
        tmp_path, per_revision("none", "none"), invariant=per_revision("found", "none")
    )
    assert outcome.result.verdict is Verdict.PASS
    assert [item.code for item in outcome.result.warnings] == ["fuzz_search_ineffective"]
    assert "invariant: 3 of 3 seeds of 64 sequences of up to 25 calls" in outcome.statement
    assert "(192 sequences, 1920 calls), no variant found" in outcome.statement


@pytest.mark.parametrize(
    ("patched", "code"),
    [
        ("incomplete", "invariant_search_incomplete"),
        ("unconfirmed", "invariant_unconfirmed"),
        ("other", "invariant_search_failed"),
        ("setup", "invariant_setup_failed"),
        ("missing", "invariant_not_found"),
        ("timeout", "timeout"),
    ],
)
def test_an_invariant_campaign_that_cannot_complete_is_never_a_pass(
    tmp_path: Path, patched: str, code: str
) -> None:
    outcome, _ = search(
        tmp_path, per_revision("found", "none"), invariant=per_revision("found", patched)
    )
    assert outcome.result.verdict is Verdict.INCONCLUSIVE
    assert outcome.result.codes() == [code]


def test_durations_are_measured_apart_from_the_bounds(tmp_path: Path) -> None:
    outcome, _ = search(tmp_path, per_revision("found", "found"))
    timing = outcome.timing
    assert timing.total_s >= 0
    kinds = [(item.revision.value, item.mode) for item in timing.campaigns]
    assert kinds == [("vulnerable", "fuzz"), ("patched", "fuzz"), ("patched", "confirmation")]
    assert "seconds" not in json.dumps(outcome.bounds.model_dump(mode="json"))
    for execution in outcome.result.executions:
        assert "seconds" not in json.dumps(execution.trace)


# -- classification of forge output -----------------------------------------------------------


def as_run(case: dict[str, object]) -> ForgeTestRun:
    text = json.dumps({"test/E.t.sol:E": {"test_results": {case.pop("name"): case}}})
    suites = parse_test_output(text)
    return ForgeTestRun(
        argv=("forge", "test"), exit_code=1, image_id="x", summary=summarize(suites), suites=suites
    )


def classify(case: dict[str, object], runs: int = 256) -> str:
    return classify_search(as_run(case), TOPIC, runs).outcome


def fuzz_case(**fields: object) -> dict[str, object]:
    return {
        "name": "testFuzz_variants(uint256)",
        "status": "Failure",
        "reason": "ASSAY_VARIANT_FOUND|attacker=0x" + "11" * 20 + "|balance=1|knobs=1,2,3,4",
        "counterexample": {"Single": {"calldata": "0x00"}},
        "logs": [
            {
                "address": "0x7fa9385be102ac3eac297483dd6233d62b3e1496",
                "topics": [TOPIC],
                "data": "0x"
                + "40".rjust(64, "0")
                + "80".rjust(64, "0")
                + "0f".rjust(64, "0")
                + b"attacker_profit".hex().ljust(64, "0")
                + "08".rjust(64, "0")
                + b"eth:1->2".hex().ljust(64, "0"),
            }
        ],
        "decoded_logs": [],
        "kind": {"Fuzz": {"runs": 4, "mean_gas": 1, "median_gas": 1}},
        **fields,
    }


def test_a_variant_needs_the_reason_the_counterexample_and_the_event() -> None:
    assert classify(fuzz_case()) == "found"
    assert classify(fuzz_case(counterexample=None)) == "unconfirmed"
    assert classify(fuzz_case(logs=[])) == "unconfirmed"
    other_address = fuzz_case()
    other_address["logs"][0]["address"] = "0x" + "12" * 20  # type: ignore[index]
    assert classify(other_address) == "unconfirmed"
    assert classify(fuzz_case(reason="ASSAY_VARIANT_FOUND|attacker=nobody")) == "unconfirmed"
    assert classify(fuzz_case(reason="panic")) == "failed"
    passing = fuzz_case(status="Success", reason=None)
    passing["kind"] = {"Fuzz": {"runs": 256, "mean_gas": 1, "median_gas": 1}}
    assert classify(dict(passing)) == "none"
    assert classify(dict(passing), runs=257) == "incomplete"


def invariant_case(**fields: object) -> dict[str, object]:
    return {
        "name": "invariant_assay()",
        "status": "Failure",
        "reason": None,
        "invariant_failures": [
            {
                "kind": "predicate",
                "name": "invariant_assay",
                "reason": fake_forge.INVARIANT_REASON,
                "counterexample": {"Sequence": [8, fake_forge.INVARIANT_CALLS]},
            }
        ],
        "logs": [],
        "decoded_logs": [],
        "kind": {"Invariant": {"runs": 4, "calls": 53, "reverts": 0}},
        **fields,
    }


def test_an_invariant_variant_needs_the_reason_and_the_sequence() -> None:
    found = classify_invariant(as_run(invariant_case()), 64)
    assert found.outcome == "found"
    assert found.counterexample is not None
    assert found.calls == 53
    failure = invariant_case()
    failure["invariant_failures"][0]["reason"] = "panic"  # type: ignore[index]
    assert classify_invariant(as_run(failure), 64).outcome == "failed"
    bad_name = invariant_case()
    bad_name["invariant_failures"][0]["reason"] = "ASSAY_INVARIANT_BROKEN|x y"  # type: ignore[index]
    assert classify_invariant(as_run(bad_name), 64).outcome == "unconfirmed"
    no_sequence = invariant_case()
    del no_sequence["invariant_failures"][0]["counterexample"]  # type: ignore[attr-defined]
    assert classify_invariant(as_run(no_sequence), 64).outcome == "unconfirmed"
    holding = invariant_case(status="Success", invariant_failures=[])
    holding["kind"] = {"Invariant": {"runs": 64, "calls": 640, "reverts": 0}}
    assert classify_invariant(as_run(dict(holding)), 64).outcome == "none"
    assert classify_invariant(as_run(dict(holding)), 65).outcome == "incomplete"
