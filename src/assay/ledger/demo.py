"""A small, synthetic ledger for `assay dev ledger-demo`.

The demo records one finding and two claims. Claim 1 stays `asserted` on purpose, so that a
direct `UPDATE claim SET status = 'trusted' WHERE id = 1` can be tried against the database and
seen to fail. Claim 2 is promoted through an oracle run, and the finding moves to `REPRODUCED`
on that run. No project is built and no oracle is executed: the oracle run is a synthetic
record that says so in its reason.
"""

import hashlib
from typing import Final

from pydantic import BaseModel, ConfigDict

from assay.ledger.audit import canonical_json
from assay.ledger.ledger import ClaimId, FindingId, Ledger, OracleRunId, OracleRunInput
from assay.ledger.lifecycle import (
    ClaimStatus,
    EvidenceLevel,
    FindingState,
    OracleName,
    RevisionKind,
    Verdict,
)

DEMO_NOTE: Final = "synthetic demo record: no project was built and no oracle was executed"


def _placeholder_sha256(what: str) -> str:
    return hashlib.sha256(f"assay ledger demo: {what}".encode()).hexdigest()


class DemoSummary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: FindingId
    stable_id: str
    state: FindingState
    evidence_level: EvidenceLevel
    asserted_claim_id: ClaimId
    trusted_claim_id: ClaimId
    trusted_claim_status: ClaimStatus
    oracle_run_id: OracleRunId
    audit_rows: int


def populate_demo(ledger: Ledger) -> DemoSummary:
    """Fill an empty ledger with the demo records and return what was created."""
    project = ledger.add_project("demo", "demo-project")
    vulnerable = ledger.add_revision(
        project, RevisionKind.VULNERABLE, _placeholder_sha256("vulnerable tree")
    )
    finding = ledger.add_finding(project, "demo-reentrancy-1", "reentrancy")
    unpromoted = ledger.add_claim(
        finding,
        "A variant of the PoC with another attacker balance also reproduces the exploit.",
    )
    reproduced = ledger.add_claim(
        finding, "The PoC reproduces the exploit on the vulnerable revision."
    )
    trace = ledger.store_blob(
        canonical_json(
            {"note": DEMO_NOTE, "oracle": "exploit", "predicate": "attacker_profit"}
        ).encode("ascii"),
        media_type="application/json",
        label="demo exploit trace",
    )
    run = ledger.record_oracle_run(
        OracleRunInput(
            claim_id=reproduced,
            revision_id=vulnerable,
            oracle=OracleName.EXPLOIT,
            argv=("forge", "test", "--match-test", "test_replay"),
            image_digest="sha256:" + _placeholder_sha256("runner image"),
            seed=None,
            exit_code=0,
            verdict=Verdict.PASS,
            reason=DEMO_NOTE,
            trace_blob_sha256=trace,
        )
    )
    status = ledger.promote_claim(reproduced, run)
    ledger.transition_finding(finding, FindingState.HYPOTHESIZED)
    ledger.transition_finding(finding, FindingState.POC_DRAFTED)
    final = ledger.transition_finding(finding, FindingState.REPRODUCED, oracle_run_ids=[run])
    return DemoSummary(
        finding_id=final.id,
        stable_id=final.stable_id,
        state=final.state,
        evidence_level=final.evidence_level,
        asserted_claim_id=unpromoted,
        trusted_claim_id=reproduced,
        trusted_claim_status=status,
        oracle_run_id=run,
        audit_rows=ledger.verify_chain().rows,
    )
