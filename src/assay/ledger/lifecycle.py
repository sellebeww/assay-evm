"""Finding lifecycle, evidence levels and claim statuses.

The transition table below is the application-side rule. Migration 1 holds the same pairs and
the minimal evidence for each target state in triggers, so a direct `UPDATE` through `sqlite3`
is rejected as well; tests keep the two in step.

Evidence rules for transitions that an oracle result causes:

- From `POC_DRAFTED`, every referenced run is an `exploit` run on a vulnerable revision, and all
  of them have the verdict of the target: `PASS` for `REPRODUCED`, `FAIL` for `NOT_REPRODUCED`,
  `INCONCLUSIVE` for `INCONCLUSIVE`.
- From `PATCH_PROPOSED`, every referenced run is on one patched revision of the finding.
  `VERIFIED_WITHIN_BOUNDS` needs no `FAIL` and a `PASS` from every required oracle, with no other
  verdict from a required oracle. `REJECTED` needs at least one `FAIL`. `INCONCLUSIVE` needs no
  `FAIL`; it is at evidence level E2 when integrity, exploit, behavior and regression all passed,
  otherwise at E1.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum, StrEnum
from typing import Final

from assay.ledger.errors import ClaimPromotionError, IllegalTransition


class FindingState(StrEnum):
    CANDIDATE = "CANDIDATE"
    HYPOTHESIZED = "HYPOTHESIZED"
    POC_DRAFTED = "POC_DRAFTED"
    REPRODUCED = "REPRODUCED"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    INCONCLUSIVE = "INCONCLUSIVE"
    PATCH_PROPOSED = "PATCH_PROPOSED"
    VERIFIED_WITHIN_BOUNDS = "VERIFIED_WITHIN_BOUNDS"
    REJECTED = "REJECTED"


class EvidenceLevel(StrEnum):
    E0 = "E0"
    """Unverified signal: analyzer output or a hypothesis."""
    E1 = "E1"
    """Exploit reproduced on the vulnerable revision."""
    E2 = "E2"
    """Patch blocks the PoC without detected regression; variant search not conclusive."""
    E3 = "E3"
    """All required oracles passed within recorded bounds."""


class ClaimStatus(StrEnum):
    ASSERTED = "asserted"
    TRUSTED = "trusted"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class Verdict(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


class FinalVerdict(StrEnum):
    """Final verdict of a verification (table `verification`)."""

    VERIFIED_WITHIN_BOUNDS = "VERIFIED_WITHIN_BOUNDS"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class OracleName(StrEnum):
    INTEGRITY = "integrity"
    EXPLOIT = "exploit"
    VARIANT = "variant"
    BEHAVIOR = "behavior"
    REGRESSION = "regression"
    SYMBOLIC = "symbolic"


class RevisionKind(StrEnum):
    VULNERABLE = "vulnerable"
    PATCHED = "patched"


class ScanTool(StrEnum):
    """Static analyzers whose output a `scan` records (unverified, evidence level E0)."""

    SLITHER = "slither"
    ADERYN = "aderyn"


class CassetteMode(StrEnum):
    """How a model call was answered: from a cassette, recorded to one, or live."""

    REPLAY = "replay"
    RECORD = "record"
    LIVE = "live"


class PatchSource(StrEnum):
    HUMAN = "human"
    MODEL = "model"
    FIXTURE = "fixture"


REQUIRED_ORACLES: Final = frozenset(
    {
        OracleName.INTEGRITY,
        OracleName.EXPLOIT,
        OracleName.VARIANT,
        OracleName.BEHAVIOR,
        OracleName.REGRESSION,
    }
)
"""Oracles that must all pass for `VERIFIED_WITHIN_BOUNDS`. The symbolic oracle is optional."""

E2_ORACLES: Final = frozenset(
    {OracleName.INTEGRITY, OracleName.EXPLOIT, OracleName.BEHAVIOR, OracleName.REGRESSION}
)

STATE_LEVELS: Final[Mapping[FindingState, frozenset[EvidenceLevel]]] = {
    FindingState.CANDIDATE: frozenset({EvidenceLevel.E0}),
    FindingState.HYPOTHESIZED: frozenset({EvidenceLevel.E0}),
    FindingState.POC_DRAFTED: frozenset({EvidenceLevel.E0}),
    FindingState.REPRODUCED: frozenset({EvidenceLevel.E1}),
    FindingState.NOT_REPRODUCED: frozenset({EvidenceLevel.E0}),
    FindingState.INCONCLUSIVE: frozenset({EvidenceLevel.E0, EvidenceLevel.E1, EvidenceLevel.E2}),
    FindingState.PATCH_PROPOSED: frozenset({EvidenceLevel.E1}),
    FindingState.VERIFIED_WITHIN_BOUNDS: frozenset({EvidenceLevel.E3}),
    FindingState.REJECTED: frozenset({EvidenceLevel.E1}),
}
"""Evidence levels a finding may hold in each state (also a CHECK constraint in the schema)."""


class Evidence(Enum):
    """What a transition must be backed by."""

    RECORDED = "recorded"
    """A record kept outside the oracles (structured hypothesis, PoC checker result)."""
    PATCH = "patch"
    """A patch exists for the finding."""
    ORACLE = "oracle"
    """One or more oracle runs, checked by the rules in the module docstring."""


@dataclass(frozen=True, slots=True)
class Transition:
    source: FindingState
    target: FindingState
    evidence: Evidence
    because: str


def _table(*rows: Transition) -> Mapping[tuple[FindingState, FindingState], Transition]:
    return {(row.source, row.target): row for row in rows}


_S = FindingState

TRANSITIONS: Final = _table(
    Transition(_S.CANDIDATE, _S.HYPOTHESIZED, Evidence.RECORDED, "a hypothesis was recorded"),
    Transition(_S.HYPOTHESIZED, _S.POC_DRAFTED, Evidence.RECORDED, "a PoC passed the checker"),
    Transition(_S.POC_DRAFTED, _S.REPRODUCED, Evidence.ORACLE, "ExploitOracle PASS"),
    Transition(_S.POC_DRAFTED, _S.NOT_REPRODUCED, Evidence.ORACLE, "ExploitOracle FAIL"),
    Transition(_S.POC_DRAFTED, _S.INCONCLUSIVE, Evidence.ORACLE, "ExploitOracle INCONCLUSIVE"),
    Transition(_S.REPRODUCED, _S.PATCH_PROPOSED, Evidence.PATCH, "a patch exists"),
    Transition(
        _S.PATCH_PROPOSED,
        _S.VERIFIED_WITHIN_BOUNDS,
        Evidence.ORACLE,
        "every required oracle PASS",
    ),
    Transition(_S.PATCH_PROPOSED, _S.REJECTED, Evidence.ORACLE, "at least one oracle FAIL"),
    Transition(_S.PATCH_PROPOSED, _S.INCONCLUSIVE, Evidence.ORACLE, "no FAIL, not all PASS"),
)
"""Every legal finding transition. A new finding always starts as `CANDIDATE` at E0."""

_FIXED_LEVEL: Final[Mapping[FindingState, EvidenceLevel]] = {
    FindingState.HYPOTHESIZED: EvidenceLevel.E0,
    FindingState.POC_DRAFTED: EvidenceLevel.E0,
    FindingState.REPRODUCED: EvidenceLevel.E1,
    FindingState.NOT_REPRODUCED: EvidenceLevel.E0,
    FindingState.PATCH_PROPOSED: EvidenceLevel.E1,
    FindingState.VERIFIED_WITHIN_BOUNDS: EvidenceLevel.E3,
    FindingState.REJECTED: EvidenceLevel.E1,
}

_POC_VERDICT: Final[Mapping[FindingState, Verdict]] = {
    FindingState.REPRODUCED: Verdict.PASS,
    FindingState.NOT_REPRODUCED: Verdict.FAIL,
    FindingState.INCONCLUSIVE: Verdict.INCONCLUSIVE,
}


@dataclass(frozen=True, slots=True)
class RunFacts:
    """What a transition check needs to know about one referenced oracle run."""

    oracle: OracleName
    verdict: Verdict
    revision_id: int
    revision_kind: RevisionKind


def check_transition(
    source: FindingState,
    target: FindingState,
    *,
    runs: Sequence[RunFacts],
    has_patch: bool,
    reason: str | None,
) -> EvidenceLevel:
    """Return the evidence level after `source -> target`, or raise `IllegalTransition`.

    `runs` must already be known to belong to the finding; this function checks only what the
    runs say. `reason` is required for `REJECTED`.
    """
    rule = TRANSITIONS.get((source, target))
    if rule is None:
        raise IllegalTransition(f"{source} -> {target} is not in the transition table")
    if target is FindingState.REJECTED and not (reason and reason.strip()):
        raise IllegalTransition(f"{source} -> {target} needs a reason")
    if rule.evidence is not Evidence.ORACLE:
        if runs:
            raise IllegalTransition(f"{source} -> {target} is not decided by oracle runs")
        if rule.evidence is Evidence.PATCH and not has_patch:
            raise IllegalTransition(f"{source} -> {target} needs a patch for the finding")
        return _FIXED_LEVEL[target]
    if not runs:
        raise IllegalTransition(f"{source} -> {target} needs at least one oracle run")
    if source is FindingState.POC_DRAFTED:
        return _check_poc_outcome(target, runs)
    return _check_patch_outcome(target, runs)


def _check_poc_outcome(target: FindingState, runs: Sequence[RunFacts]) -> EvidenceLevel:
    expected = _POC_VERDICT[target]
    for run in runs:
        if run.oracle is not OracleName.EXPLOIT or run.revision_kind is not RevisionKind.VULNERABLE:
            raise IllegalTransition(
                f"POC_DRAFTED -> {target} accepts only exploit runs on a vulnerable revision"
            )
        if run.verdict is not expected:
            raise IllegalTransition(
                f"POC_DRAFTED -> {target} needs every exploit run to be {expected}, "
                f"got {run.verdict}"
            )
    return EvidenceLevel.E1 if target is FindingState.REPRODUCED else EvidenceLevel.E0


def _check_patch_outcome(target: FindingState, runs: Sequence[RunFacts]) -> EvidenceLevel:
    if any(run.revision_kind is not RevisionKind.PATCHED for run in runs):
        raise IllegalTransition(f"PATCH_PROPOSED -> {target} accepts only patched revisions")
    if len({run.revision_id for run in runs}) != 1:
        raise IllegalTransition(f"PATCH_PROPOSED -> {target} needs runs on one patched revision")
    failed = any(run.verdict is Verdict.FAIL for run in runs)
    if target is FindingState.REJECTED:
        if not failed:
            raise IllegalTransition("PATCH_PROPOSED -> REJECTED needs at least one FAIL")
        return EvidenceLevel.E1
    if failed:
        raise IllegalTransition(f"PATCH_PROPOSED -> {target} is not allowed after a FAIL")
    if target is FindingState.VERIFIED_WITHIN_BOUNDS:
        missing = sorted(oracle for oracle in REQUIRED_ORACLES if not _all_pass(runs, oracle))
        if missing:
            raise IllegalTransition(
                "PATCH_PROPOSED -> VERIFIED_WITHIN_BOUNDS needs PASS from every required "
                f"oracle; not all PASS: {', '.join(missing)}"
            )
        return EvidenceLevel.E3
    if all(_all_pass(runs, oracle) for oracle in E2_ORACLES):
        return EvidenceLevel.E2
    return EvidenceLevel.E1


def _all_pass(runs: Sequence[RunFacts], oracle: OracleName) -> bool:
    """True when `oracle` has at least one run and every run of it passed."""
    verdicts = [run.verdict for run in runs if run.oracle is oracle]
    return bool(verdicts) and all(verdict is Verdict.PASS for verdict in verdicts)


CLAIM_STATUS_FOR_VERDICT: Final[Mapping[Verdict, ClaimStatus]] = {
    Verdict.PASS: ClaimStatus.TRUSTED,
    Verdict.FAIL: ClaimStatus.REFUTED,
    Verdict.INCONCLUSIVE: ClaimStatus.INCONCLUSIVE,
}

CLAIM_TRANSITIONS: Final[Mapping[ClaimStatus, frozenset[ClaimStatus]]] = {
    ClaimStatus.ASSERTED: frozenset(
        {ClaimStatus.TRUSTED, ClaimStatus.REFUTED, ClaimStatus.INCONCLUSIVE}
    ),
    ClaimStatus.INCONCLUSIVE: frozenset({ClaimStatus.TRUSTED, ClaimStatus.REFUTED}),
    ClaimStatus.TRUSTED: frozenset(),
    ClaimStatus.REFUTED: frozenset(),
}
"""Status changes a claim may make. `trusted` and `refuted` are final."""


def claim_status_after(current: ClaimStatus, verdict: Verdict) -> ClaimStatus:
    """Return the status an oracle run with `verdict` gives a claim, or raise.

    `PASS` makes a claim `trusted`, `FAIL` makes it `refuted`, `INCONCLUSIVE` makes it
    `inconclusive`.
    """
    target = CLAIM_STATUS_FOR_VERDICT[verdict]
    if target not in CLAIM_TRANSITIONS[current]:
        raise ClaimPromotionError(f"a {current} claim cannot become {target}")
    return target
