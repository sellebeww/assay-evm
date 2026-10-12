"""Pure lifecycle rules: transition table, evidence levels, claim statuses."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from assay.ledger import (
    REQUIRED_ORACLES,
    STATE_LEVELS,
    TRANSITIONS,
    ClaimPromotionError,
    ClaimStatus,
    EvidenceLevel,
    FindingState,
    IllegalTransition,
    OracleName,
    RevisionKind,
    Verdict,
)
from assay.ledger.lifecycle import RunFacts, check_transition, claim_status_after

S = FindingState
V = Verdict


def exploit(verdict: Verdict, kind: RevisionKind = RevisionKind.VULNERABLE) -> RunFacts:
    return RunFacts(OracleName.EXPLOIT, verdict, 1, kind)


def patched(oracle: OracleName, verdict: Verdict, revision_id: int = 2) -> RunFacts:
    return RunFacts(oracle, verdict, revision_id, RevisionKind.PATCHED)


def all_required(verdict: Verdict = V.PASS) -> list[RunFacts]:
    return [patched(oracle, verdict) for oracle in sorted(REQUIRED_ORACLES)]


def test_transition_table_is_exactly_the_lifecycle() -> None:
    assert set(TRANSITIONS) == {
        (S.CANDIDATE, S.HYPOTHESIZED),
        (S.HYPOTHESIZED, S.POC_DRAFTED),
        (S.POC_DRAFTED, S.REPRODUCED),
        (S.POC_DRAFTED, S.NOT_REPRODUCED),
        (S.POC_DRAFTED, S.INCONCLUSIVE),
        (S.REPRODUCED, S.PATCH_PROPOSED),
        (S.PATCH_PROPOSED, S.VERIFIED_WITHIN_BOUNDS),
        (S.PATCH_PROPOSED, S.REJECTED),
        (S.PATCH_PROPOSED, S.INCONCLUSIVE),
    }


def test_every_state_has_evidence_levels_and_only_verified_reaches_e3() -> None:
    assert set(STATE_LEVELS) == set(FindingState)
    reaching_e3 = {state for state, levels in STATE_LEVELS.items() if EvidenceLevel.E3 in levels}
    assert reaching_e3 == {S.VERIFIED_WITHIN_BOUNDS}


def test_required_oracles_exclude_the_optional_symbolic_oracle() -> None:
    assert OracleName.SYMBOLIC not in REQUIRED_ORACLES
    assert set(REQUIRED_ORACLES) | {OracleName.SYMBOLIC} == set(OracleName)


@pytest.mark.parametrize(
    ("source", "target", "level"),
    [
        (S.CANDIDATE, S.HYPOTHESIZED, EvidenceLevel.E0),
        (S.HYPOTHESIZED, S.POC_DRAFTED, EvidenceLevel.E0),
    ],
)
def test_recorded_transitions_need_no_oracle_run(
    source: FindingState, target: FindingState, level: EvidenceLevel
) -> None:
    assert check_transition(source, target, runs=[], has_patch=False, reason=None) is level


def test_recorded_transitions_refuse_oracle_runs() -> None:
    with pytest.raises(IllegalTransition, match="not decided by oracle runs"):
        check_transition(
            S.CANDIDATE, S.HYPOTHESIZED, runs=[exploit(V.PASS)], has_patch=False, reason=None
        )


def test_patch_proposed_needs_a_patch() -> None:
    with pytest.raises(IllegalTransition, match="needs a patch"):
        check_transition(S.REPRODUCED, S.PATCH_PROPOSED, runs=[], has_patch=False, reason=None)
    level = check_transition(S.REPRODUCED, S.PATCH_PROPOSED, runs=[], has_patch=True, reason=None)
    assert level is EvidenceLevel.E1


@pytest.mark.parametrize(
    ("verdict", "target", "level"),
    [
        (V.PASS, S.REPRODUCED, EvidenceLevel.E1),
        (V.FAIL, S.NOT_REPRODUCED, EvidenceLevel.E0),
        (V.INCONCLUSIVE, S.INCONCLUSIVE, EvidenceLevel.E0),
    ],
)
def test_poc_outcome_follows_the_exploit_verdict(
    verdict: Verdict, target: FindingState, level: EvidenceLevel
) -> None:
    runs = [exploit(verdict)]
    assert check_transition(S.POC_DRAFTED, target, runs=runs, has_patch=False, reason=None) is level
    for other in set(Verdict) - {verdict}:
        with pytest.raises(IllegalTransition):
            check_transition(
                S.POC_DRAFTED, target, runs=[exploit(other)], has_patch=False, reason=None
            )


@pytest.mark.parametrize("target", [S.REPRODUCED, S.NOT_REPRODUCED, S.INCONCLUSIVE])
def test_poc_outcome_needs_at_least_one_run(target: FindingState) -> None:
    with pytest.raises(IllegalTransition, match="at least one oracle run"):
        check_transition(S.POC_DRAFTED, target, runs=[], has_patch=False, reason=None)


def test_reproduction_needs_exploit_runs_on_the_vulnerable_revision() -> None:
    wrong_oracle = RunFacts(OracleName.VARIANT, V.PASS, 1, RevisionKind.VULNERABLE)
    wrong_revision = exploit(V.PASS, RevisionKind.PATCHED)
    for run in (wrong_oracle, wrong_revision):
        with pytest.raises(IllegalTransition, match="exploit runs on a vulnerable revision"):
            check_transition(S.POC_DRAFTED, S.REPRODUCED, runs=[run], has_patch=False, reason=None)


def test_reproduction_refuses_disagreeing_runs() -> None:
    with pytest.raises(IllegalTransition):
        check_transition(
            S.POC_DRAFTED,
            S.REPRODUCED,
            runs=[exploit(V.PASS), exploit(V.INCONCLUSIVE)],
            has_patch=False,
            reason=None,
        )


def test_verified_needs_every_required_oracle_to_pass() -> None:
    level = check_transition(
        S.PATCH_PROPOSED, S.VERIFIED_WITHIN_BOUNDS, runs=all_required(), has_patch=True, reason=None
    )
    assert level is EvidenceLevel.E3
    for missing in REQUIRED_ORACLES:
        runs = [run for run in all_required() if run.oracle is not missing]
        with pytest.raises(IllegalTransition, match=str(missing)):
            check_transition(
                S.PATCH_PROPOSED, S.VERIFIED_WITHIN_BOUNDS, runs=runs, has_patch=True, reason=None
            )


@pytest.mark.parametrize("bad", [V.FAIL, V.INCONCLUSIVE])
def test_verified_refuses_a_required_oracle_that_did_not_pass(bad: Verdict) -> None:
    runs = [*all_required(), patched(OracleName.VARIANT, bad)]
    with pytest.raises(IllegalTransition):
        check_transition(
            S.PATCH_PROPOSED, S.VERIFIED_WITHIN_BOUNDS, runs=runs, has_patch=True, reason=None
        )


def test_verified_accepts_an_inconclusive_symbolic_run_but_not_a_failed_one() -> None:
    unknown = [*all_required(), patched(OracleName.SYMBOLIC, V.INCONCLUSIVE)]
    level = check_transition(
        S.PATCH_PROPOSED, S.VERIFIED_WITHIN_BOUNDS, runs=unknown, has_patch=True, reason=None
    )
    assert level is EvidenceLevel.E3
    with pytest.raises(IllegalTransition, match="after a FAIL"):
        check_transition(
            S.PATCH_PROPOSED,
            S.VERIFIED_WITHIN_BOUNDS,
            runs=[*all_required(), patched(OracleName.SYMBOLIC, V.FAIL)],
            has_patch=True,
            reason=None,
        )


def test_patch_outcomes_need_runs_on_one_patched_revision() -> None:
    split = [*all_required()[:-1], patched(sorted(REQUIRED_ORACLES)[-1], V.PASS, revision_id=3)]
    with pytest.raises(IllegalTransition, match="one patched revision"):
        check_transition(
            S.PATCH_PROPOSED, S.VERIFIED_WITHIN_BOUNDS, runs=split, has_patch=True, reason=None
        )
    with pytest.raises(IllegalTransition, match="only patched revisions"):
        check_transition(
            S.PATCH_PROPOSED, S.REJECTED, runs=[exploit(V.FAIL)], has_patch=True, reason="x"
        )


def test_rejected_needs_a_fail_and_a_reason() -> None:
    fail = [patched(OracleName.BEHAVIOR, V.FAIL)]
    assert (
        check_transition(S.PATCH_PROPOSED, S.REJECTED, runs=fail, has_patch=True, reason="b")
        is EvidenceLevel.E1
    )
    for reason in (None, "", "   "):
        with pytest.raises(IllegalTransition, match="needs a reason"):
            check_transition(S.PATCH_PROPOSED, S.REJECTED, runs=fail, has_patch=True, reason=reason)
    with pytest.raises(IllegalTransition, match="at least one FAIL"):
        check_transition(
            S.PATCH_PROPOSED, S.REJECTED, runs=all_required(), has_patch=True, reason="b"
        )


def test_inconclusive_after_a_patch_is_e2_only_when_the_e2_oracles_passed() -> None:
    e2 = [
        *[run for run in all_required() if run.oracle is not OracleName.VARIANT],
        patched(OracleName.VARIANT, V.INCONCLUSIVE),
    ]
    assert (
        check_transition(S.PATCH_PROPOSED, S.INCONCLUSIVE, runs=e2, has_patch=True, reason=None)
        is EvidenceLevel.E2
    )
    e1 = [patched(OracleName.INTEGRITY, V.PASS), patched(OracleName.EXPLOIT, V.INCONCLUSIVE)]
    assert (
        check_transition(S.PATCH_PROPOSED, S.INCONCLUSIVE, runs=e1, has_patch=True, reason=None)
        is EvidenceLevel.E1
    )
    with pytest.raises(IllegalTransition, match="after a FAIL"):
        check_transition(
            S.PATCH_PROPOSED,
            S.INCONCLUSIVE,
            runs=[patched(OracleName.INTEGRITY, V.FAIL)],
            has_patch=True,
            reason=None,
        )


run_facts = st.builds(
    RunFacts,
    st.sampled_from(OracleName),
    st.sampled_from(Verdict),
    st.integers(min_value=1, max_value=3),
    st.sampled_from(RevisionKind),
)


@given(
    source=st.sampled_from(FindingState),
    target=st.sampled_from(FindingState),
    runs=st.lists(run_facts, max_size=8),
    has_patch=st.booleans(),
    reason=st.none() | st.text(max_size=5),
)
def test_check_transition_never_allows_a_pair_outside_the_table(
    source: FindingState,
    target: FindingState,
    runs: list[RunFacts],
    has_patch: bool,
    reason: str | None,
) -> None:
    try:
        level = check_transition(source, target, runs=runs, has_patch=has_patch, reason=reason)
    except IllegalTransition:
        return
    assert (source, target) in TRANSITIONS
    assert level in STATE_LEVELS[target]
    if target is S.VERIFIED_WITHIN_BOUNDS:
        assert {run.oracle for run in runs if run.verdict is V.PASS} >= REQUIRED_ORACLES
    if target is S.REPRODUCED:
        assert runs
        assert all(run.verdict is V.PASS for run in runs)


@pytest.mark.parametrize(
    ("verdict", "status"),
    [
        (V.PASS, ClaimStatus.TRUSTED),
        (V.FAIL, ClaimStatus.REFUTED),
        (V.INCONCLUSIVE, ClaimStatus.INCONCLUSIVE),
    ],
)
def test_an_asserted_claim_takes_the_status_of_the_verdict(
    verdict: Verdict, status: ClaimStatus
) -> None:
    assert claim_status_after(ClaimStatus.ASSERTED, verdict) is status


def test_trusted_and_refuted_claims_are_final() -> None:
    for status in (ClaimStatus.TRUSTED, ClaimStatus.REFUTED):
        for verdict in Verdict:
            with pytest.raises(ClaimPromotionError):
                claim_status_after(status, verdict)


def test_an_inconclusive_claim_can_still_be_decided() -> None:
    assert claim_status_after(ClaimStatus.INCONCLUSIVE, V.PASS) is ClaimStatus.TRUSTED
    assert claim_status_after(ClaimStatus.INCONCLUSIVE, V.FAIL) is ClaimStatus.REFUTED
    with pytest.raises(ClaimPromotionError):
        claim_status_after(ClaimStatus.INCONCLUSIVE, V.INCONCLUSIVE)
