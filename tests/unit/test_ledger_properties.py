"""Property tests: random operation sequences never break the ledger invariants.

The expected rules are written out again here, independent of `assay.ledger.lifecycle`, so a
change to the rules in the code shows up as a failure instead of being mirrored.
"""

import sqlite3
import tempfile
from contextlib import ExitStack, closing
from pathlib import Path

import pytest
from hypothesis import assume, event, given, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule
from ledger_scenario import Scenario

from assay.ledger import (
    ClaimId,
    FindingId,
    FindingState,
    IllegalTransition,
    LedgerError,
    OracleName,
    OracleRunId,
    RevisionId,
    Verdict,
)

S = FindingState

LEGAL = {
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
STATUS_FOR_VERDICT = {"PASS": "trusted", "FAIL": "refuted", "INCONCLUSIVE": "inconclusive"}
NEXT_STATUS = {
    "asserted": {"trusted", "refuted", "inconclusive"},
    "inconclusive": {"trusted", "refuted"},
    "trusted": set(),
    "refuted": set(),
}
REQUIRED = {"integrity", "exploit", "variant", "behavior", "regression"}


class LedgerMachine(RuleBasedStateMachine):
    """Mixes API calls, raw SQL updates and helper-built findings at random."""

    def __init__(self) -> None:
        super().__init__()
        self._stack = ExitStack()
        directory = Path(self._stack.enter_context(tempfile.TemporaryDirectory()))
        self.s = self._stack.enter_context(Scenario.create(directory))
        self.raw = self._stack.enter_context(closing(self.s.raw()))

    def teardown(self) -> None:
        self._stack.close()

    # Facts read back from the database; ids and links of rows never change.

    def findings(self) -> dict[int, str]:
        return dict(self.raw.execute("SELECT id, state FROM finding").fetchall())

    def claims(self) -> dict[int, tuple[int, str]]:
        rows = self.raw.execute("SELECT id, finding_id, status FROM claim").fetchall()
        return {claim: (finding, status) for claim, finding, status in rows}

    def runs(self) -> dict[int, tuple[int | None, str, str, int]]:
        rows = self.raw.execute(
            "SELECT id, claim_id, verdict, oracle, revision_id FROM oracle_run"
        ).fetchall()
        return {run: (claim, verdict, oracle, rev) for run, claim, verdict, oracle, rev in rows}

    def revisions(self) -> dict[int, tuple[str, int | None]]:
        rows = self.raw.execute(
            "SELECT r.id, r.kind, p.finding_id FROM revision AS r "
            "LEFT JOIN patch AS p ON p.id = r.patch_id"
        ).fetchall()
        return {rev: (kind, finding) for rev, kind, finding in rows}

    # Rules

    @initialize()
    def seed_material(self) -> None:
        """Start with findings whose claims have runs of every verdict, before and after a patch."""
        poc = self.s.drive_to(S.POC_DRAFTED)
        claim = self.s.claim(poc)
        for verdict in Verdict:
            self.s.run(claim, verdict)
        patched = self.s.drive_to(S.PATCH_PROPOSED)
        self.s.patch_runs(patched, dict.fromkeys(OracleName, Verdict.PASS))
        self.s.patch_runs(patched, {OracleName.BEHAVIOR: Verdict.FAIL})

    @rule()
    def add_finding(self) -> None:
        self.s.finding()

    @rule(state=st.sampled_from(FindingState))
    def add_finding_in_state(self, state: FindingState) -> None:
        self.s.drive_to(state)

    @rule(data=st.data())
    def add_claim(self, data: st.DataObject) -> None:
        finding = data.draw(st.sampled_from(sorted(self.findings())))
        self.s.claim(FindingId(finding))

    @rule(data=st.data())
    def add_patched_revision(self, data: st.DataObject) -> None:
        finding = FindingId(data.draw(st.sampled_from(sorted(self.findings()))))
        attempts = self.raw.execute(
            "SELECT count(*) FROM patch WHERE finding_id = ?", (finding,)
        ).fetchone()[0]
        self.s.patched_revision(finding, attempts + 1)

    @rule(
        data=st.data(),
        verdict=st.sampled_from(Verdict),
        oracle=st.sampled_from(OracleName),
    )
    def record_run(self, data: st.DataObject, verdict: Verdict, oracle: OracleName) -> None:
        claim = data.draw(st.none() | st.sampled_from(sorted(self.claims())))
        revision = data.draw(st.sampled_from(sorted(self.revisions())))
        self.s.run(None if claim is None else ClaimId(claim), verdict, oracle, RevisionId(revision))

    @rule(data=st.data())
    def promote(self, data: st.DataObject) -> None:
        claims, runs = self.claims(), self.runs()
        linked = sorted((c, r) for r, (c, *_) in runs.items() if c is not None)
        anything = st.tuples(
            st.integers(min_value=0, max_value=len(claims) + 2),
            st.integers(min_value=0, max_value=len(runs) + 2),
        )
        claim, run = data.draw(st.sampled_from(linked) | anything)
        allowed = (
            claim in claims
            and run in runs
            and runs[run][0] == claim
            and STATUS_FOR_VERDICT[runs[run][1]] in NEXT_STATUS[claims[claim][1]]
        )
        try:
            status = self.s.ledger.promote_claim(ClaimId(claim), OracleRunId(run))
        except LedgerError:
            event("promote_claim: refused")
            assert not allowed
            assert self.claims() == claims
            return
        event(f"promote_claim: {status}")
        assert allowed
        assert status.value == STATUS_FOR_VERDICT[runs[run][1]]

    @rule(
        data=st.data(),
        reason=st.none() | st.sampled_from(["variant_found", "missing_oracles"]),
    )
    def transition(self, data: st.DataObject, reason: str | None) -> None:
        findings, claims, runs = self.findings(), self.claims(), self.runs()
        finding = data.draw(st.sampled_from(sorted(findings)))
        source = S(findings[finding])
        onward = sorted(goal for start, goal in LEGAL if start is source)
        goal = data.draw(
            (st.sampled_from(onward) if onward else st.nothing()) | st.sampled_from(FindingState)
        )
        own = sorted(r for r, (c, *_) in runs.items() if c is not None and claims[c][0] == finding)
        pool = own if own and data.draw(st.booleans()) else sorted(runs)
        chosen = data.draw(st.lists(st.sampled_from(pool), unique=True, max_size=7))
        try:
            moved = self.s.ledger.transition_finding(
                FindingId(finding),
                goal,
                oracle_run_ids=[OracleRunId(run) for run in chosen],
                reason=reason,
            )
        except LedgerError:
            event("transition_finding: refused")
            assert self.findings()[finding] == source.value
            return
        event(f"transition_finding: {goal}")
        assert (source, goal) in LEGAL
        assert moved.state is goal

    @rule(data=st.data(), status=st.sampled_from(sorted(NEXT_STATUS)))
    def raw_claim_update(self, data: st.DataObject, status: str) -> None:
        claims, runs = self.claims(), self.runs()
        claim = data.draw(st.sampled_from(sorted(claims)))
        before = claims[claim][1]
        try:
            self.raw.execute("UPDATE claim SET status = ? WHERE id = ?", (status, claim))
        except sqlite3.IntegrityError:
            event("raw claim update: rejected")
            return
        event("raw claim update: accepted")
        if status != before:
            assert status in NEXT_STATUS[before]
            assert any(
                c == claim and STATUS_FOR_VERDICT[verdict] == status
                for c, verdict, *_ in runs.values()
            )

    @rule(data=st.data(), goal=st.sampled_from(FindingState))
    def raw_finding_update(self, data: st.DataObject, goal: FindingState) -> None:
        findings = self.findings()
        finding = data.draw(st.sampled_from(sorted(findings)))
        level = data.draw(st.sampled_from(["E0", "E1", "E2", "E3"]))
        try:
            self.raw.execute(
                "UPDATE finding SET state = ?, evidence_level = ?, reason = 'raw' WHERE id = ?",
                (goal.value, level, finding),
            )
        except sqlite3.IntegrityError:
            event("raw finding update: rejected")
            return
        event("raw finding update: accepted")
        if goal.value != findings[finding]:
            assert (S(findings[finding]), goal) in LEGAL

    # Invariants

    @invariant()
    def decided_claims_have_a_matching_run(self) -> None:
        runs = self.runs()
        for claim, (_, status) in self.claims().items():
            if status == "asserted":
                continue
            assert any(
                c == claim and STATUS_FOR_VERDICT[verdict] == status
                for c, verdict, *_ in runs.values()
            ), (claim, status)

    @invariant()
    def advanced_findings_have_oracle_evidence(self) -> None:
        claims, runs, revisions = self.claims(), self.runs(), self.revisions()

        def evidence(finding: int) -> list[tuple[str, str, str, int | None]]:
            return [
                (verdict, oracle, revisions[rev][0], revisions[rev][1])
                for claim, verdict, oracle, rev in runs.values()
                if claim is not None and claims[claim][0] == finding
            ]

        for finding, state in self.findings().items():
            facts = evidence(finding)
            if state == "REPRODUCED":
                assert ("PASS", "exploit", "vulnerable", None) in facts
            if state == "VERIFIED_WITHIN_BOUNDS":
                passed = {
                    oracle
                    for verdict, oracle, kind, owner in facts
                    if verdict == "PASS" and kind == "patched" and owner == finding
                }
                assert passed >= REQUIRED

    @invariant()
    def audit_chain_is_intact(self) -> None:
        assert self.s.ledger.verify_chain().ok


LedgerMachine.TestCase.settings = settings(max_examples=75, stateful_step_count=30, deadline=None)
TestLedgerMachine = LedgerMachine.TestCase


@settings(max_examples=80, deadline=None)
@given(
    source=st.sampled_from(FindingState),
    target=st.sampled_from(FindingState),
    with_runs=st.booleans(),
    reason=st.none() | st.just("reason"),
)
def test_illegal_transitions_are_always_rejected(
    source: FindingState, target: FindingState, with_runs: bool, reason: str | None
) -> None:
    assume((source, target) not in LEGAL)
    with tempfile.TemporaryDirectory() as tmp, Scenario.create(Path(tmp)) as s:
        finding = s.drive_to(source)
        runs: list[OracleRunId] = []
        if with_runs:
            # The strongest evidence there is: every oracle passes everywhere.
            claim = s.claim(finding)
            runs = [s.run(claim, Verdict.PASS, oracle) for oracle in OracleName]
            runs += s.patch_runs(finding, dict.fromkeys(OracleName, Verdict.PASS))
        rows_before = s.ledger.verify_chain().rows
        with pytest.raises(IllegalTransition):
            s.ledger.transition_finding(finding, target, oracle_run_ids=runs, reason=reason)
        assert s.ledger.get_finding(finding).state is source
        assert s.ledger.verify_chain().rows == rows_before
