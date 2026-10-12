"""Builds ledgers with findings in a chosen state, for the ledger tests."""

import hashlib
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path

from assay.ledger import (
    REQUIRED_ORACLES,
    ClaimId,
    FindingId,
    FindingState,
    Ledger,
    OracleName,
    OracleRunId,
    OracleRunInput,
    PatchSource,
    RevisionId,
    RevisionKind,
    Verdict,
)

IMAGE_DIGEST = "sha256:" + "ab" * 32


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class Scenario:
    """One project with a vulnerable revision and a trace blob, plus helpers."""

    def __init__(self, ledger: Ledger, db_path: Path) -> None:
        self.ledger = ledger
        self.db_path = db_path
        self.project = ledger.add_project("project", "project")
        self.vulnerable = ledger.add_revision(self.project, RevisionKind.VULNERABLE, sha("v"))
        self.trace = ledger.store_blob(b'{"trace":1}', media_type="application/json", label="t")
        self._next = 0

    @classmethod
    @contextmanager
    def create(cls, directory: Path) -> Iterator["Scenario"]:
        db_path = directory / "ledger.db"
        with Ledger.open(db_path) as ledger:
            yield cls(ledger, db_path)

    def raw(self) -> sqlite3.Connection:
        """A plain connection, as the sqlite3 shell would open it (autocommit)."""
        return sqlite3.connect(self.db_path, isolation_level=None)

    def finding(self) -> FindingId:
        self._next += 1
        return self.ledger.add_finding(self.project, f"finding-{self._next}", "reentrancy")

    def claim(self, finding: FindingId, text: str = "the exploit reproduces") -> ClaimId:
        return self.ledger.add_claim(finding, text)

    def run(
        self,
        claim: ClaimId | None,
        verdict: Verdict,
        oracle: OracleName = OracleName.EXPLOIT,
        revision: RevisionId | None = None,
    ) -> OracleRunId:
        return self.ledger.record_oracle_run(
            OracleRunInput(
                claim_id=claim,
                revision_id=self.vulnerable if revision is None else revision,
                oracle=oracle,
                argv=("forge", "test"),
                image_digest=IMAGE_DIGEST,
                seed=1,
                exit_code=0,
                verdict=verdict,
                reason=f"{oracle} {verdict}",
                trace_blob_sha256=self.trace,
            )
        )

    def patched_revision(self, finding: FindingId, attempt_no: int = 1) -> RevisionId:
        patch = self.ledger.add_patch(
            finding, PatchSource.HUMAN, f"--- a\n+++ b\n# {attempt_no}\n".encode(), attempt_no
        )
        return self.ledger.add_revision(
            self.project, RevisionKind.PATCHED, sha(f"patched {finding} {attempt_no}"), patch
        )

    def patch_runs(
        self, finding: FindingId, verdicts: dict[OracleName, Verdict]
    ) -> list[OracleRunId]:
        """Record runs on a new patched revision, one per oracle, for a new claim."""
        attempt = 1 + self._patch_count(finding)
        revision = self.patched_revision(finding, attempt)
        claim = self.claim(finding, f"patch attempt {attempt} closes the exploit")
        return [self.run(claim, verdict, oracle, revision) for oracle, verdict in verdicts.items()]

    def _patch_count(self, finding: FindingId) -> int:
        with closing(self.raw()) as conn:
            row = conn.execute("SELECT count(*) FROM patch WHERE finding_id = ?", (finding,))
            return int(row.fetchone()[0])

    def drive_to(self, state: FindingState) -> FindingId:
        """Return a new finding moved to `state` along legal transitions with real evidence."""
        finding = self.finding()
        if state is FindingState.CANDIDATE:
            return finding
        self.ledger.transition_finding(finding, FindingState.HYPOTHESIZED)
        if state is FindingState.HYPOTHESIZED:
            return finding
        self.ledger.transition_finding(finding, FindingState.POC_DRAFTED)
        if state is FindingState.POC_DRAFTED:
            return finding
        poc_verdict = {
            FindingState.NOT_REPRODUCED: Verdict.FAIL,
            FindingState.INCONCLUSIVE: Verdict.INCONCLUSIVE,
        }.get(state, Verdict.PASS)
        poc_state = {
            Verdict.PASS: FindingState.REPRODUCED,
            Verdict.FAIL: FindingState.NOT_REPRODUCED,
            Verdict.INCONCLUSIVE: FindingState.INCONCLUSIVE,
        }[poc_verdict]
        run = self.run(self.claim(finding), poc_verdict)
        self.ledger.transition_finding(finding, poc_state, oracle_run_ids=[run])
        if state is poc_state:
            return finding
        self.patched_revision(finding)
        self.ledger.transition_finding(finding, FindingState.PATCH_PROPOSED)
        if state is FindingState.PATCH_PROPOSED:
            return finding
        if state is FindingState.VERIFIED_WITHIN_BOUNDS:
            runs = self.patch_runs(finding, dict.fromkeys(REQUIRED_ORACLES, Verdict.PASS))
            self.ledger.transition_finding(finding, state, oracle_run_ids=runs)
            return finding
        assert state is FindingState.REJECTED, state
        runs = self.patch_runs(finding, {OracleName.INTEGRITY: Verdict.FAIL})
        self.ledger.transition_finding(finding, state, oracle_run_ids=runs, reason="vacuous_patch")
        return finding
