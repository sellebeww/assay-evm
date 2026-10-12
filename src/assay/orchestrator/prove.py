"""`assay prove`: hypothesis, PoC and a bounded repair loop for one candidate finding.

Order: snapshot the project; find the finding (a candidate that `assay scan` recorded for this
very tree); refuse a target that reads the test environment; ask the model for a hypothesis
(`CANDIDATE -> HYPOTHESIZED`); then, per attempt, ask for a PoC, run the static checker, and
only when it accepts the file write it to the PoC directory and run it on the vulnerable
revision through the ExploitOracle in the sandbox. The first attempt whose PoC passes the checker
moves the finding to `POC_DRAFTED`.

The model proposes and the harness decides. Statuses change only through the ledger and only on
oracle evidence: `POC_DRAFTED -> REPRODUCED` needs an exploit `PASS` of a recorded `oracle_run`;
when the attempts run out, the verdict of the last recorded run gives `NOT_REPRODUCED` (`FAIL`)
or `INCONCLUSIVE`. A PoC the checker rejects never runs and has no oracle run; a finding for
which no PoC ever passed the checker stays `HYPOTHESIZED`. Every model call is a `model_run`,
every execution an `oracle_run`. Nothing in this module reads a model reply as a verdict.
"""

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Final

from assay.ingest import IngestError, Snapshot, create_snapshot
from assay.ledger import (
    EvidenceLevel,
    Finding,
    FindingId,
    FindingState,
    Ledger,
    OracleRunId,
    RevisionId,
    RevisionKind,
    Verdict,
)
from assay.llm import (
    BudgetExceeded,
    LlmClient,
    StructuredOutputError,
)
from assay.llm.client import Recorder
from assay.llm.context import related_code
from assay.llm.hypothesize import (
    CandidateContext,
    Hypothesis,
    ObservationNote,
    propose_hypothesis,
)
from assay.llm.poc_checker import check_poc
from assay.llm.poc_writer import (
    POC_FILE,
    Feedback,
    feedback_from_check,
    request_poc,
    write_poc,
)
from assay.llm.recording import ledger_recorder
from assay.oracles.base import record_result
from assay.oracles.exploit import ExploitOracle
from assay.oracles.integrity.checks import sniffing_reasons
from assay.oracles.runtree import HARNESS_MOUNT, SOURCE_DIR, Harness, load_harness
from assay.orchestrator.scan import ledger_key
from assay.sandbox import SandboxRunner

HYPOTHESIS_REASON: Final = "hypothesis recorded, sha256 "
"""Start of the reason of the transition to HYPOTHESIZED; the blob's sha256 follows."""
MAX_ATTEMPTS_CAP: Final = 5
DEFAULT_ATTEMPTS: Final = 3
_MAX_SOURCE_BYTES: Final = 1024 * 1024


class ProveInputError(Exception):
    """The inputs cannot be proved. `usage` inputs are not what the command expects; `rejected`
    inputs broke an ingest rule or a rule of the target (it reads the test environment)."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True, slots=True)
class ProveRequest:
    project: Path
    poc_dir: Path
    finding_id: int | None
    vuln_class: str | None
    max_attempts: int = DEFAULT_ATTEMPTS


@dataclass(frozen=True, slots=True)
class AttemptLog:
    number: int
    outcome: str
    """`model_output_invalid`, `static_check_rejected`, `poc_rejected_at_ingest`, or the verdict of
    the exploit run (`PASS`, `FAIL`, `INCONCLUSIVE`)."""
    codes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ProveOutcome:
    finding_id: FindingId
    stable_id: str
    vuln_class: str
    state: FindingState
    evidence_level: EvidenceLevel
    attempts: tuple[AttemptLog, ...]
    max_attempts: int
    hypothesis: Hypothesis
    stopped: str | None = None
    """`budget` when a model budget ended the loop early."""
    notes: list[str] = field(default_factory=list)


ClientFactory = Callable[[Recorder], LlmClient]


def resolve_finding(ledger: Ledger, request: ProveRequest, tree_sha256: str) -> Finding:
    """The candidate finding to prove: the one named, or the first of the class."""
    if (request.finding_id is None) == (request.vuln_class is None):
        raise ProveInputError("usage", "give exactly one of --finding and --class")
    suffix = ledger_key("", tree_sha256).rsplit(":", 1)[1]
    if request.finding_id is not None:
        try:
            finding = ledger.get_finding(FindingId(request.finding_id))
        except Exception as exc:  # NotFound or a bad id
            raise ProveInputError("usage", f"finding {request.finding_id} does not exist") from exc
    else:
        assert request.vuln_class is not None
        matching = [
            item
            for item in ledger.findings(vuln_class=request.vuln_class, state=FindingState.CANDIDATE)
            if item.stable_id.endswith(f":{suffix}")
        ]
        if not matching:
            raise ProveInputError(
                "usage",
                f"no candidate finding of class {request.vuln_class} for this project; "
                "run `assay scan` on it first",
            )
        finding = matching[0]
    if not finding.stable_id.endswith(f":{suffix}"):
        raise ProveInputError(
            "usage", "the finding was recorded for another version of the project"
        )
    if finding.state is not FindingState.CANDIDATE:
        raise ProveInputError(
            "usage",
            f"finding {finding.id} is already {finding.state.value}; only a candidate is proved",
        )
    return finding


def _target_sources(snapshot: Snapshot) -> dict[str, str]:
    sources: dict[str, str] = {}
    for item in snapshot.files:
        path = PurePosixPath(item.path)
        if path.parts[:1] == (SOURCE_DIR,) and path.suffix == ".sol":
            data = (snapshot.tree_dir / item.path).read_bytes()[:_MAX_SOURCE_BYTES]
            sources[item.path] = data.decode("utf-8", "replace")
    return sources


def check_target(snapshot: Snapshot) -> None:
    if any(PurePosixPath(i.path).parts[:1] == (HARNESS_MOUNT,) for i in snapshot.files):
        raise ProveInputError(
            "rejected", f"the project has a top-level {HARNESS_MOUNT}/ directory (reserved)"
        )
    sources = _target_sources(snapshot)
    if not sources:
        raise ProveInputError("usage", f"the project has no .sol files under {SOURCE_DIR}/")
    problems = sniffing_reasons(sources)
    if problems:
        first = problems[0]
        raise ProveInputError(
            "rejected",
            f"the target reads the test environment ({first.detail} in {first.path}); "
            "nothing was run",
        )


def candidate_context(ledger: Ledger, finding: Finding, snapshot: Snapshot) -> CandidateContext:
    observations = ledger.finding_observations(finding.id)
    notes = tuple(
        ObservationNote(
            rule_id=item.rule_id,
            severity=item.severity_reported,
            message=item.message,
            path=place.path,
            start_line=place.start_line,
            end_line=place.end_line,
        )
        for item in observations
        for place in item.locations[:1]
    )
    code = related_code(snapshot.tree_dir, [(n.path, n.start_line, n.end_line) for n in notes])
    if not code:
        raise ProveInputError("usage", "the finding points at no readable .sol file under src/")
    return CandidateContext(vuln_class=finding.vuln_class, observations=notes, code=code)


def prepare_poc_dir(poc_dir: Path, project: Path) -> None:
    """Create the PoC directory, or accept one that holds nothing but our own file."""
    resolved = poc_dir.resolve()
    if resolved == project.resolve() or resolved.is_relative_to(project.resolve()):
        raise ProveInputError(
            "usage", "the PoC directory must lie outside the project (it would change its hash)"
        )
    if poc_dir.is_symlink():
        raise ProveInputError("usage", "the PoC directory must not be a symbolic link")
    if poc_dir.exists():
        if not poc_dir.is_dir() or any(entry.name != POC_FILE for entry in poc_dir.iterdir()):
            raise ProveInputError(
                "usage", f"the PoC directory must be empty or hold only {POC_FILE}"
            )
        return
    poc_dir.mkdir(parents=True)


def _feedback_from_result(attempt: int, reasons: list[tuple[str, str]], summary: str) -> Feedback:
    items = tuple(reasons) or (("not_reproduced", summary),)
    return Feedback(attempt, "exploit_run", items)


def run_prove(
    request: ProveRequest,
    *,
    ledger: Ledger,
    make_client: ClientFactory,
    runner: SandboxRunner,
    work_dir: Path,
    harness: Harness | None = None,
    dry_run: bool = False,
) -> ProveOutcome | CandidateContext:
    """Prove one finding; `work_dir` must be an existing empty directory.

    Returns the outcome, or, with `dry_run`, only the candidate context that would be sent.
    Lets `LlmError`, sandbox, ledger and file errors through: they are not verdicts.
    """
    if not 1 <= request.max_attempts <= MAX_ATTEMPTS_CAP:
        raise ProveInputError("usage", f"--max-attempts must be between 1 and {MAX_ATTEMPTS_CAP}")
    try:
        base = create_snapshot(request.project, work_dir / "base")
    except IngestError as exc:
        raise ProveInputError("rejected", f"project rejected: {exc}") from exc
    finding = resolve_finding(ledger, request, base.tree_sha256)
    check_target(base)
    context = candidate_context(ledger, finding, base)
    if dry_run:
        return context
    prepare_poc_dir(request.poc_dir, request.project)
    client = make_client(ledger_recorder(ledger, finding.id))

    hypothesis = propose_hypothesis(client, context).value
    blob = ledger.store_blob(
        json.dumps(hypothesis.model_dump(mode="json"), sort_keys=True).encode("ascii"),
        media_type="application/json",
        label="hypothesis (model proposal, unverified)",
    )
    ledger.transition_finding(
        finding.id, FindingState.HYPOTHESIZED, reason=f"{HYPOTHESIS_REASON}{blob}"
    )
    revision = ledger.add_revision(finding.project_id, RevisionKind.VULNERABLE, base.tree_sha256)
    return _repair_loop(
        request, ledger, client, runner, work_dir, harness or load_harness(),
        finding, base, context, hypothesis, revision,
    )  # fmt: skip


def _repair_loop(
    request: ProveRequest,
    ledger: Ledger,
    client: LlmClient,
    runner: SandboxRunner,
    work_dir: Path,
    harness: Harness,
    finding: Finding,
    base: Snapshot,
    context: CandidateContext,
    hypothesis: Hypothesis,
    revision: RevisionId,
) -> ProveOutcome:
    image_digest: str | None = None  # read lazily: a rejected PoC never touches the runner
    attempts: list[AttemptLog] = []
    feedback: list[Feedback] = []
    last_run: tuple[int, Verdict] | None = None
    drafted = False
    stopped: str | None = None
    for number in range(1, request.max_attempts + 1):
        try:
            answer = request_poc(client, hypothesis, context, feedback).value
        except StructuredOutputError as exc:
            attempts.append(AttemptLog(number, "model_output_invalid", (exc.code,)))
            feedback.append(Feedback(number, "model_output", ((exc.code, exc.detail),)))
            continue
        except BudgetExceeded:
            stopped = "budget"
            break
        check = check_poc(answer.solidity)
        if not check.ok:
            attempts.append(AttemptLog(number, "static_check_rejected", tuple(check.codes())))
            feedback.append(feedback_from_check(number, check))
            continue
        write_poc(request.poc_dir, answer.solidity)
        if not drafted:
            ledger.transition_finding(
                finding.id,
                FindingState.POC_DRAFTED,
                reason=f"a PoC passed the static checker (attempt {number})",
            )
            drafted = True
        try:
            poc = create_snapshot(request.poc_dir, work_dir / f"poc-{number}")
        except IngestError as exc:
            attempts.append(AttemptLog(number, "poc_rejected_at_ingest"))
            feedback.append(Feedback(number, "ingest", (("poc_rejected_at_ingest", str(exc)),)))
            continue
        image_digest = image_digest or runner.image_id()
        run_dir = work_dir / f"exploit-{number}"
        run_dir.mkdir(mode=0o700)
        result = ExploitOracle().reproduce(runner, base, poc, harness, run_dir)
        recorded = record_result(
            ledger,
            result,
            finding_id=finding.id,
            revisions={RevisionKind.VULNERABLE: revision},
            image_digest=image_digest,
        )[0]
        last_run = (int(recorded.oracle_run_id), result.verdict)
        attempts.append(AttemptLog(number, result.verdict.value, tuple(result.codes())))
        if result.verdict is Verdict.PASS:
            break
        feedback.append(
            _feedback_from_result(
                number, [(r.code, r.detail) for r in result.reasons], result.summary
            )
        )
    return _finish(request, ledger, finding, attempts, last_run, hypothesis, stopped)


def _finish(
    request: ProveRequest,
    ledger: Ledger,
    finding: Finding,
    attempts: list[AttemptLog],
    last_run: tuple[int, Verdict] | None,
    hypothesis: Hypothesis,
    stopped: str | None,
) -> ProveOutcome:
    if last_run is not None:
        run_id, verdict = last_run
        target = {
            Verdict.PASS: FindingState.REPRODUCED,
            Verdict.FAIL: FindingState.NOT_REPRODUCED,
            Verdict.INCONCLUSIVE: FindingState.INCONCLUSIVE,
        }[verdict]
        ledger.transition_finding(
            finding.id,
            target,
            oracle_run_ids=[OracleRunId(run_id)],
            reason=None if target is FindingState.REPRODUCED else f"last exploit run: {verdict}",
        )
    final = ledger.get_finding(finding.id)
    return ProveOutcome(
        finding_id=final.id,
        stable_id=final.stable_id,
        vuln_class=final.vuln_class,
        state=final.state,
        evidence_level=final.evidence_level,
        attempts=tuple(attempts),
        max_attempts=request.max_attempts,
        hypothesis=hypothesis,
        stopped=stopped,
    )
