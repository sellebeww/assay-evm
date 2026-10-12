"""The common contract of every oracle and the recording of its runs in the ledger.

An oracle is a deterministic check. It returns an `OracleResult`: a verdict (`PASS`, `FAIL` or
`INCONCLUSIVE`), structured reasons, warnings that do not affect the verdict, and the executions
it made. An execution is one check of
one revision (the vulnerable or the patched one); `record_result` stores each execution as an
immutable `oracle_run` with its argv, image digest, seed, exit code, verdict and trace blob,
together with a claim that the run decides. Evidence artifacts are stored as blobs and listed
in the trace.

Oracles never decide a claim's status themselves: `record_result` asks the ledger to promote
each claim from the verdict of its run, and the ledger enforces the rule again.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Annotated, Final, Protocol

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StringConstraints

from assay.ledger import (
    ClaimId,
    FindingId,
    Ledger,
    OracleName,
    OracleRunId,
    OracleRunInput,
    RevisionId,
    RevisionKind,
    Verdict,
    canonical_json,
)

MAX_DETAIL_CHARS: Final = 500
MAX_LEDGER_REASON_CHARS: Final = 2000

ReasonCode = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
Detail = Annotated[str, StringConstraints(max_length=MAX_DETAIL_CHARS)]


def clip(text: str, limit: int = MAX_DETAIL_CHARS) -> str:
    """Cut `text` to at most `limit` characters, marking the cut."""
    return text if len(text) <= limit else text[: limit - 3] + "..."


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Reason(_Model):
    """A structured reason: a stable code, a human-readable detail and an optional location.

    `detail` may quote untrusted text (file names, identifiers, revert reasons); it is data and
    must be escaped before it is printed.
    """

    code: ReasonCode
    detail: Detail
    path: str | None = None
    line: int | None = None


def reason(code: str, detail: str, *, path: str | None = None, line: int | None = None) -> Reason:
    return Reason(code=code, detail=clip(detail), path=path, line=line)


class Evidence(_Model):
    """An artifact that backs a verdict, stored as a content-addressed blob.

    `name` is a file name for the artifact in an evidence bundle, for artifacts that have a
    well-known name (for example `counterexample.json`).
    """

    label: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    media_type: Annotated[str, StringConstraints(pattern=r"^[a-z]+/[a-z0-9.+-]+$")]
    data: bytes
    name: Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9_.-]{0,79}$")] | None = None


class Execution(_Model):
    """One check of one revision, recorded as one `oracle_run`.

    `claim` is the statement the run decides: `PASS` makes it trusted, `FAIL` refuted,
    `INCONCLUSIVE` inconclusive. `warnings` are observations that do not affect the verdict.
    `trace` is canonical JSON data (no floats); it never contains durations, timestamps or host
    paths.
    """

    revision: RevisionKind
    claim: Annotated[str, StringConstraints(min_length=1, max_length=2000)]
    argv: tuple[str, ...]
    seed: int | None
    exit_code: int | None
    verdict: Verdict
    reasons: tuple[Reason, ...]
    summary: Annotated[str, StringConstraints(min_length=1, max_length=MAX_DETAIL_CHARS)]
    trace: dict[str, JsonValue]
    evidence: tuple[Evidence, ...] = ()
    warnings: tuple[Reason, ...] = ()


class OracleResult(_Model):
    """The verdict of one oracle for one verification.

    `warnings` are reported but never change the verdict (for example an additive interface
    change found by the RegressionOracle).
    """

    oracle: OracleName
    verdict: Verdict
    reasons: tuple[Reason, ...]
    summary: Annotated[str, StringConstraints(min_length=1, max_length=MAX_DETAIL_CHARS)]
    executions: tuple[Execution, ...] = Field(min_length=1)
    warnings: tuple[Reason, ...] = ()

    def codes(self) -> list[str]:
        return list(dict.fromkeys(item.code for item in self.reasons))


class Oracle[C](Protocol):
    """An oracle checks one verification context `C` and returns its result."""

    name: OracleName

    def run(self, context: C) -> OracleResult: ...


@dataclass(frozen=True, slots=True)
class RecordedRun:
    oracle_run_id: OracleRunId
    claim_id: ClaimId
    revision: RevisionKind
    verdict: Verdict


def ledger_reason(reasons: tuple[Reason, ...], summary: str) -> str:
    """The `reason` column of an `oracle_run`: the summary, then each reason with its code."""
    parts = [summary, *(f"{item.code}: {item.detail}" for item in reasons)]
    return clip(" | ".join(parts), MAX_LEDGER_REASON_CHARS)


def record_result(
    ledger: Ledger,
    result: OracleResult,
    *,
    finding_id: FindingId,
    revisions: Mapping[RevisionKind, RevisionId],
    image_digest: str,
) -> list[RecordedRun]:
    """Store every execution of `result` as an `oracle_run` and promote the claim it decides.

    Evidence goes to the blob store first; the trace blob lists each artifact by label and
    sha256, so the run refers to all of them.
    """
    recorded: list[RecordedRun] = []
    for execution in result.executions:
        evidence: list[JsonValue] = [
            {
                "label": item.label,
                "media_type": item.media_type,
                "sha256": ledger.store_blob(
                    item.data, media_type=item.media_type, label=item.label
                ),
            }
            for item in execution.evidence
        ]
        trace: dict[str, JsonValue] = {
            "oracle": result.oracle.value,
            "revision": execution.revision.value,
            "verdict": execution.verdict.value,
            "summary": execution.summary,
            "reasons": [item.model_dump(mode="json") for item in execution.reasons],
            "warnings": [item.model_dump(mode="json") for item in execution.warnings],
            "evidence": evidence,
            "detail": execution.trace,
        }
        trace_blob = ledger.store_blob(
            canonical_json(trace).encode("ascii"),
            media_type="application/json",
            label=f"{result.oracle.value} trace ({execution.revision.value} revision)",
        )
        claim_id = ledger.add_claim(finding_id, execution.claim)
        run_id = ledger.record_oracle_run(
            OracleRunInput(
                claim_id=claim_id,
                revision_id=revisions[execution.revision],
                oracle=result.oracle,
                argv=execution.argv,
                image_digest=image_digest,
                seed=execution.seed,
                exit_code=execution.exit_code,
                verdict=execution.verdict,
                reason=ledger_reason(execution.reasons, execution.summary),
                trace_blob_sha256=trace_blob,
            )
        )
        ledger.promote_claim(claim_id, run_id)
        recorded.append(RecordedRun(run_id, claim_id, execution.revision, execution.verdict))
    return recorded
