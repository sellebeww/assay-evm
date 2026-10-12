"""Global invariants of a ledger, checked by `assay dev ledger-audit` (read-only).

1. No claim is `trusted`, `refuted` or `inconclusive` without an `oracle_run` of that claim with
   the matching verdict.
2. No finding is `REPRODUCED` without an exploit `PASS` on a vulnerable revision, none is
   `VERIFIED_WITHIN_BOUNDS` without a `PASS` of every required oracle on a patched revision of
   its own, and no finding at a later state (`NOT_REPRODUCED`, `PATCH_PROPOSED`, `REJECTED`)
   lacks every oracle run.
3. No status was raised by a model run: every audit event that changed a claim or a finding
   state through an oracle names oracle runs that exist and belong to that claim or finding,
   and no `model_run` row is the only record behind a status.
4. The audit chain is intact.
"""

import json
import sqlite3
from dataclasses import dataclass
from typing import Final

from assay.ledger import audit
from assay.ledger.lifecycle import REQUIRED_ORACLES, FindingState, Verdict

_CLAIM_VERDICT: Final = {"trusted": "PASS", "refuted": "FAIL", "inconclusive": "INCONCLUSIVE"}
_RECORDED_ONLY: Final = frozenset({"HYPOTHESIZED", "POC_DRAFTED"})
_PATCH_STEP: Final = "PATCH_PROPOSED"
_NEEDS_A_RUN: Final = ("NOT_REPRODUCED", "PATCH_PROPOSED", "REJECTED", "INCONCLUSIVE")


@dataclass(frozen=True, slots=True)
class Violation:
    invariant: str
    detail: str


def check_invariants(conn: sqlite3.Connection) -> list[Violation]:
    """Return every violation found; an empty list means all invariants hold."""
    found: list[Violation] = []
    for claim_id, status in conn.execute(
        "SELECT id, status FROM claim WHERE status <> 'asserted'"
    ).fetchall():
        verdict = _CLAIM_VERDICT[status]
        if not conn.execute(
            "SELECT 1 FROM oracle_run WHERE claim_id = ? AND verdict = ?", (claim_id, verdict)
        ).fetchone():
            found.append(
                Violation("claim_without_oracle_run", f"claim {claim_id} is {status} without a run")
            )
    found += _finding_violations(conn)
    found += _event_violations(conn)
    report = audit.verify_chain(conn)
    if report.violation is not None:
        found.append(
            Violation(
                "audit_chain",
                f"audit_log seq {report.violation.seq}: {report.violation.problem}",
            )
        )
    return found


def _finding_violations(conn: sqlite3.Connection) -> list[Violation]:
    found: list[Violation] = []
    for finding_id, state in conn.execute("SELECT id, state FROM finding").fetchall():
        runs = conn.execute(
            "SELECT oracle, verdict, revision_kind, patch_finding_id "
            "FROM finding_oracle_run WHERE finding_id = ?",
            (finding_id,),
        ).fetchall()
        if state == FindingState.REPRODUCED and not any(
            o == "exploit" and v == Verdict.PASS and k == "vulnerable" for o, v, k, _ in runs
        ):
            found.append(
                Violation("finding_without_oracle_run", f"finding {finding_id} REPRODUCED")
            )
        elif state == FindingState.VERIFIED_WITHIN_BOUNDS:
            passed = {
                o
                for o, v, k, owner in runs
                if v == Verdict.PASS and k == "patched" and owner == finding_id
            }
            if not {r.value for r in REQUIRED_ORACLES} <= passed:
                found.append(
                    Violation(
                        "finding_without_oracle_run",
                        f"finding {finding_id} VERIFIED_WITHIN_BOUNDS lacks required PASS runs",
                    )
                )
        elif state in _NEEDS_A_RUN and not runs:
            found.append(
                Violation("finding_without_oracle_run", f"finding {finding_id} is {state}")
            )
    return found


def _event_violations(conn: sqlite3.Connection) -> list[Violation]:
    """Status-changing events must rest on oracle runs; recorded-only steps never raise a level."""
    found: list[Violation] = []
    rows = conn.execute(
        "SELECT seq, event, payload_json FROM audit_log "
        "WHERE event IN ('claim.promoted', 'finding.transitioned') ORDER BY seq"
    ).fetchall()
    for seq, event, payload_json in rows:
        try:
            payload = json.loads(payload_json)
        except ValueError:
            continue  # reported by the chain check
        if any(key.startswith("model_run") for key in payload):
            found.append(Violation("status_from_model_run", f"audit seq {seq} names a model run"))
        if event == "claim.promoted":
            ids = [payload.get("oracle_run_id")]
        else:
            ids = list(payload.get("oracle_run_ids", []))
            if payload.get("to") in _RECORDED_ONLY:
                if ids or payload.get("evidence_level") != "E0":
                    found.append(
                        Violation("status_without_oracle", f"audit seq {seq}: {payload.get('to')}")
                    )
                continue
        for run_id in ids:
            if (
                not isinstance(run_id, int)
                or not conn.execute("SELECT 1 FROM oracle_run WHERE id = ?", (run_id,)).fetchone()
            ):
                found.append(
                    Violation("status_without_oracle", f"audit seq {seq}: no oracle_run {run_id}")
                )
        if event == "finding.transitioned" and not ids and payload.get("to") != _PATCH_STEP:
            found.append(Violation("status_without_oracle", f"audit seq {seq}: no oracle run"))
    return found
