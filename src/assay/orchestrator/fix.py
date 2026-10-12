"""`assay fix`: a bounded loop that asks a model for a patch and lets the oracles decide.

Order: snapshot the project; find the finding (it must be REPRODUCED for this very tree, by
`assay prove`); refuse a target that reads the test environment; read the hypothesis that `prove`
recorded, the redacted source of the files the finding points at and the PoC. Then, per attempt
(3 by default, `--max-attempts` 1 to 5):

1. the model returns one unified diff (strict JSON, one repair of the format);
2. `run_verification` judges it. The IntegrityOracle runs first and is a gate: a patch that is not
   accepted by ingest (traversal, protected path, out of scope, too large, does not apply) or
   that shows a vacuous change, special-casing or environment sniffing is rejected there, and
   nothing from it runs in the sandbox. Otherwise the exploit, variant, behavior and regression
   oracles (and the symbolic oracle with `--symbolic`) run with the loop's seed;
3. a patch that did not pass becomes structured, bounded, redacted feedback (`fix_feedback`),
   quoted as data in the next prompt.

The first attempt that passes every oracle ends the loop and is verified again with a HELD-OUT
seed family: the seed that every campaign of that run derives from comes from the loop's seed
through a different seed family, so the final run searches seeds that no attempt and no prompt
has seen. That final run decides: its verdict is the verdict of the loop, and when it differs
from the in-loop verdict the result says so. Its findings are never fed back. A patch that did
not pass in the loop is rejected on evidence a held-out run could only repeat, so the last
evaluated attempt stands when the attempts run out.

Statuses move only on oracle evidence recorded in the ledger. The finding goes
`REPRODUCED -> PATCH_PROPOSED` once a patch was judged, then to `VERIFIED_WITHIN_BOUNDS`,
`REJECTED` or `INCONCLUSIVE` on the runs of the deciding verification, on its patched revision.
When no patched revision carries the evidence (every patch was refused before it could be applied)
the finding stays `PATCH_PROPOSED` and the result says so (ADR 0019). A model reply is never read
as a verdict, and nothing in this module reads, or sends, a seed.
"""

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints

from assay.ingest import IngestError, Snapshot, create_snapshot
from assay.ingest.patch import DEFAULT_PROTECTED, PatchPolicy
from assay.ledger import (
    EvidenceLevel,
    FinalVerdict,
    Finding,
    FindingId,
    FindingState,
    IllegalTransition,
    Ledger,
    OracleRunId,
    PatchSource,
)
from assay.llm import BudgetExceeded, LlmClient, SourceNotAllowed, StructuredOutputError
from assay.llm.client import Recorder
from assay.llm.hypothesize import (
    CandidateContext,
    Hypothesis,
    ObservationNote,
)
from assay.llm.messages import Message
from assay.llm.patcher import (
    PatchConfig,
    PatchFeedback,
    diff_bytes,
    patch_messages,
    request_patch,
)
from assay.llm.recording import ledger_recorder
from assay.llm.redact import SourceFile, read_source
from assay.oracles.base import Reason
from assay.oracles.runtree import Harness, load_harness
from assay.oracles.variant import derive_seeds
from assay.orchestrator.fix_feedback import feedback_from_outcome
from assay.orchestrator.models import VerifyReport, VerifySettings
from assay.orchestrator.prove import (
    HYPOTHESIS_REASON,
    MAX_ATTEMPTS_CAP,
    ProveInputError,
    check_target,
)
from assay.orchestrator.scan import ledger_key
from assay.orchestrator.verify import (
    VERIFIED_REASON,
    BundleRequest,
    FindingTarget,
    VerifyInputError,
    VerifyOutcome,
    VerifyRequest,
    run_verification,
)
from assay.report.bundle import HISTORY_FILE, BundleContents, write_bundle
from assay.sandbox import SandboxRunner

DEFAULT_ATTEMPTS: Final = 3
HELD_OUT_FAMILY: Final = "held-out"
"""The seed family of the final decision. The loop's campaigns use the family `search`."""
HELD_OUT_ATTEMPT_BASE: Final = 100
"""The held-out verification of attempt `n` is recorded as patch `HELD_OUT_ATTEMPT_BASE + n`."""
HISTORY_FORMAT: Final = "assay-fix-history"
MAX_CONTEXT_FILES: Final = 3
_HYPOTHESIS_SHA: Final = re.compile(re.escape(HYPOTHESIS_REASON) + r"([0-9a-f]{64})$")

Decision = Literal["held_out_run", "last_attempt", "none"]


def held_out_seed(base_seed: str) -> str:
    """The base seed of the final decision: the first seed of the held-out family of `base_seed`."""
    return derive_seeds(base_seed, 1, HELD_OUT_FAMILY)[0]


def campaign_seeds(settings: VerifySettings) -> tuple[str, ...]:
    """Every seed of the loop and of the held-out run: base seeds and the seeds derived from them.

    Used only to keep them out of prompts; nothing here sends them.
    """
    held = held_out_seed(settings.fuzz_seed)
    count = max(settings.variant().profile.seeds, 1)
    return tuple(
        dict.fromkeys(
            (
                settings.fuzz_seed,
                *derive_seeds(settings.fuzz_seed, count),
                held,
                *derive_seeds(held, count),
            )
        )
    )


def held_out_settings(settings: VerifySettings) -> VerifySettings:
    """The settings of the final decision: the loop's settings with the held-out base seed."""
    return VerifySettings(
        **{**settings.model_dump(), "fuzz_seed": held_out_seed(settings.fuzz_seed)}
    )


@dataclass(frozen=True, slots=True)
class FixRequest:
    project: Path
    poc_dir: Path
    finding_id: int
    max_attempts: int = DEFAULT_ATTEMPTS
    settings: VerifySettings = field(default_factory=VerifySettings)
    patch: PatchConfig = field(default_factory=PatchConfig)


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class HistoryOracle(_Model):
    oracle: str
    status: str
    verdict: str | None
    reasons: tuple[Reason, ...]


class HistoryAttempt(_Model):
    number: int
    outcome: Literal["evaluated", "model_output_invalid"]
    diff_sha256: str | None
    in_loop_verdict: FinalVerdict | None
    integrity_violation: bool = False
    oracles: tuple[HistoryOracle, ...] = ()
    problems: tuple[Reason, ...] = ()
    """Why a reply was not usable (a reason code and a short detail), without the reply."""


class HistoryLimits(_Model):
    max_attempts: int
    max_changed_lines: int
    max_files: int
    max_diff_bytes: int
    scope: tuple[str, ...]


class HistoryBounds(_Model):
    profile: str
    fuzz_seed: str
    fuzz_runs: int
    symbolic: bool


class HistoryFinal(_Model):
    decision: Decision
    verdict: FinalVerdict
    in_loop_verdict: FinalVerdict | None
    differs_from_in_loop: bool
    decisive_attempt: int | None
    diff_sha256: str | None
    reasons: tuple[str, ...]
    stopped: str | None
    attempts_used: int
    statement: Annotated[str, StringConstraints(max_length=1000)]


class FixHistory(_Model):
    """`fix/history.json` of the bundle of a fix loop.

    It holds the diff hashes, the verdict of every oracle with its reasons, the limits and the
    bounds. It holds no prompt, no model reply, no credential, no timestamp and no host path.
    """

    format: Literal["assay-fix-history"] = HISTORY_FORMAT
    schema_version: Literal[1] = 1
    vuln_class: str
    limits: HistoryLimits
    loop_bounds: HistoryBounds
    held_out_bounds: HistoryBounds
    attempts: tuple[HistoryAttempt, ...]
    final: HistoryFinal

    def to_bytes(self) -> bytes:
        text = json.dumps(self.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=True)
        return (text + "\n").encode("ascii")


@dataclass(frozen=True, slots=True)
class FixOutcome:
    finding_id: FindingId
    stable_id: str
    vuln_class: str
    verdict: FinalVerdict
    reasons: tuple[str, ...]
    history: FixHistory
    report: VerifyReport | None
    """The report of the deciding verification; `None` when no patch was judged."""
    state: FindingState
    evidence_level: EvidenceLevel
    manifest_sha256: str | None = None
    notes: tuple[str, ...] = ()

    @property
    def integrity_violation(self) -> bool:
        return self.report is not None and self.report.integrity_violation


def _resolve(ledger: Ledger, finding_id: int, tree_sha256: str) -> Finding:
    suffix = ledger_key("", tree_sha256).rsplit(":", 1)[1]
    try:
        finding = ledger.get_finding(FindingId(finding_id))
    except Exception as exc:  # NotFound or a bad id
        raise ProveInputError("usage", f"finding {finding_id} does not exist") from exc
    if not finding.stable_id.endswith(f":{suffix}"):
        raise ProveInputError(
            "usage", "the finding was recorded for another version of the project"
        )
    if finding.state is not FindingState.REPRODUCED:
        raise ProveInputError(
            "usage",
            f"finding {finding.id} is {finding.state.value}; only a REPRODUCED finding is fixed "
            "(run `assay prove` first)",
        )
    return finding


def load_hypothesis(ledger: Ledger, finding: Finding) -> Hypothesis:
    """The hypothesis that `assay prove` recorded for the finding (a model proposal at E0)."""
    for change in reversed(ledger.finding_transitions(finding.id)):
        found = _HYPOTHESIS_SHA.search(change.reason or "")
        if found is not None:
            try:
                return Hypothesis.model_validate_json(ledger.read_blob(found.group(1)), strict=True)
            except Exception as exc:
                raise ProveInputError(
                    "usage", f"the hypothesis of finding {finding.id} cannot be read: {exc}"
                ) from exc
    raise ProveInputError("usage", f"finding {finding.id} has no recorded hypothesis")


def patch_context(
    ledger: Ledger, finding: Finding, base: Snapshot, config: PatchConfig
) -> CandidateContext:
    """The finding's analyzer notes and the whole redacted source of the files they point at.

    Whole files, so that the model can write context lines that match exactly.
    """
    notes: list[ObservationNote] = []
    code: dict[str, SourceFile] = {}
    for item in ledger.finding_observations(finding.id):
        for place in item.locations[:1]:
            notes.append(
                ObservationNote(
                    rule_id=item.rule_id,
                    severity=item.severity_reported,
                    message=item.message,
                    path=place.path,
                    start_line=place.start_line,
                    end_line=place.end_line,
                )
            )
            if place.path in code or len(code) >= MAX_CONTEXT_FILES:
                continue
            try:
                code[place.path] = read_source(base.tree_dir, place.path, scope=config.scope)
            except SourceNotAllowed:
                continue
    if not code:
        raise ProveInputError("usage", "the finding points at no readable .sol file in the scope")
    return CandidateContext(
        vuln_class=finding.vuln_class, observations=tuple(notes), code=tuple(code.values())
    )


def read_poc(poc: Snapshot) -> str:
    """The `.sol` files of the PoC snapshot as one text, each under a header line."""
    parts = []
    for item in sorted(poc.files, key=lambda entry: entry.path):
        if PurePosixPath(item.path).suffix == ".sol":
            text = (poc.tree_dir / item.path).read_bytes().decode("utf-8", errors="replace")
            parts.append(f"// file: {item.path}\n{text}")
    return "\n".join(parts)


def _policy(project: Path, poc_dir: Path, config: PatchConfig) -> PatchPolicy:
    """The scope, and the default protected paths plus a PoC directory inside the project."""
    protected = list(DEFAULT_PROTECTED)
    project_dir, poc_path = project.resolve(), poc_dir.resolve()
    if poc_path == project_dir or poc_path in project_dir.parents:
        raise ProveInputError("usage", "the PoC directory must not contain the project")
    if project_dir in poc_path.parents:
        protected.append(poc_path.relative_to(project_dir).as_posix())
    return PatchPolicy(scope=config.scope, protected=tuple(protected))


def _summaries(report: VerifyReport) -> tuple[HistoryOracle, ...]:
    return tuple(
        HistoryOracle(
            oracle=row.oracle.value,
            status=row.status,
            verdict=None if row.verdict is None else row.verdict.value,
            reasons=row.reasons,
        )
        for row in report.oracles
    )


def _bounds(settings: VerifySettings) -> HistoryBounds:
    return HistoryBounds(
        profile=settings.profile,
        fuzz_seed=settings.fuzz_seed,
        fuzz_runs=settings.runs,
        symbolic=settings.symbolic,
    )


def _patch_ids(outcome: VerifyOutcome) -> list[OracleRunId]:
    return [OracleRunId(int(run.oracle_run_id)) for run in outcome.patched_runs]


def _statement(
    decision: Decision, verdict: FinalVerdict, in_loop: FinalVerdict | None, seed: str | None
) -> str:
    if decision == "none":
        return "no patch was judged; the loop ended without a verdict on a patch"
    if decision == "held_out_run":
        base = f"the final verdict comes from a verification with the held-out seed {seed}"
        if in_loop is verdict:
            return f"{base}: {verdict.value}; the in-loop verdict was the same"
        return (
            f"{base}: {verdict.value}; it differs from the in-loop verdict "
            f"{in_loop.value if in_loop else '-'}, and the final verdict applies"
        )
    return f"the last judged attempt stands: {verdict.value}; it was not verified in the loop"


def _finish_ledger(
    ledger: Ledger,
    finding: Finding,
    decisive: VerifyOutcome | None,
    reasons: tuple[str, ...],
    notes: list[str],
) -> None:
    """Move the finding on the runs of the deciding verification, when they allow it."""
    if decisive is None:
        return
    target = {
        FinalVerdict.VERIFIED_WITHIN_BOUNDS: FindingState.VERIFIED_WITHIN_BOUNDS,
        FinalVerdict.REJECTED: FindingState.REJECTED,
        FinalVerdict.INCONCLUSIVE: FindingState.INCONCLUSIVE,
    }[decisive.report.final_verdict]
    runs = _patch_ids(decisive)
    reason = "; ".join(reasons) or None
    try:
        ledger.transition_finding(
            finding.id,
            target,
            oracle_run_ids=runs,
            reason=reason if target is FindingState.REJECTED else None,
        )
    except IllegalTransition as exc:
        notes.append(
            f"the finding stays PATCH_PROPOSED: no patched revision holds the evidence for "
            f"{target.value} ({exc})"
        )


def run_fix(
    request: FixRequest,
    *,
    ledger: Ledger,
    make_client: Callable[[Recorder], LlmClient],
    runner: SandboxRunner,
    work_dir: Path,
    symbolic_runner: SandboxRunner | None = None,
    bundle: BundleRequest | None = None,
    harness: Harness | None = None,
    hypothesis: Hypothesis | None = None,
    dry_run: bool = False,
) -> FixOutcome | list[Message]:
    """Fix one REPRODUCED finding; `work_dir` must be an existing empty directory.

    Returns the outcome, or, with `dry_run`, the first request that would be sent. `bundle`
    names where the bundle of the deciding verification goes and how to describe the
    environment; it is written once, at the end, with the attempt history. Lets `LlmError`,
    sandbox, ledger and file errors through: they are not verdicts.
    """
    if not 1 <= request.max_attempts <= MAX_ATTEMPTS_CAP:
        raise ProveInputError("usage", f"--max-attempts must be between 1 and {MAX_ATTEMPTS_CAP}")
    config, settings = request.patch, request.settings
    try:
        base = create_snapshot(request.project, work_dir / "base")
        poc = create_snapshot(request.poc_dir, work_dir / "poc")
    except IngestError as exc:
        raise ProveInputError("rejected", f"input rejected at ingest: {exc}") from exc
    finding = _resolve(ledger, request.finding_id, base.tree_sha256)
    check_target(base)
    policy = _policy(request.project, request.poc_dir, config)
    proposal = hypothesis if hypothesis is not None else load_hypothesis(ledger, finding)
    context = patch_context(ledger, finding, base, config)
    poc_source = read_poc(poc)
    if dry_run:
        return patch_messages(proposal, context, poc_source, config)
    seeds = campaign_seeds(settings)
    held_settings = held_out_settings(settings)
    harness = harness if harness is not None else load_harness()
    client = make_client(ledger_recorder(ledger, finding.id))
    inner = None if bundle is None else replace(bundle, write=False)

    def verify(
        patch_file: Path, directory: Path, number: int, used: VerifySettings
    ) -> VerifyOutcome:
        directory.mkdir(mode=0o700)
        return run_verification(
            VerifyRequest(request.project, patch_file, request.poc_dir),
            runner=runner,
            ledger=ledger,
            work_dir=directory,
            settings=used,
            harness=harness,
            policy=policy,
            limits=config.limits(),
            bundle=inner,
            symbolic_runner=symbolic_runner,
            target=FindingTarget(finding.id, finding.project_id, PatchSource.MODEL, number),
            integrity_gate=True,
        )

    attempts: list[HistoryAttempt] = []
    feedback: list[PatchFeedback] = []
    last: tuple[int, str, VerifyOutcome] | None = None
    stopped: str | None = None
    notes: list[str] = []
    passed: tuple[int, str, VerifyOutcome] | None = None
    for number in range(1, request.max_attempts + 1):
        try:
            answer = request_patch(
                client, proposal, context, poc_source, config, feedback, seeds=seeds
            ).value
        except StructuredOutputError as exc:
            attempts.append(
                HistoryAttempt(
                    number=number,
                    outcome="model_output_invalid",
                    diff_sha256=None,
                    in_loop_verdict=None,
                    problems=(Reason(code=exc.code, detail=exc.detail[:200]),),
                )
            )
            feedback.append(
                PatchFeedback(number, "model_output", None, problems=((exc.code, exc.detail),))
            )
            continue
        except BudgetExceeded:
            stopped = "budget"
            break
        data = diff_bytes(answer)
        digest = hashlib.sha256(data).hexdigest()
        patch_file = work_dir / f"attempt-{number}.diff"
        patch_file.write_bytes(data)
        try:
            outcome = verify(patch_file, work_dir / f"attempt-{number}", number, settings)
        except VerifyInputError as exc:
            raise ProveInputError(
                "rejected" if exc.kind == "rejected" else "usage", str(exc)
            ) from exc
        judged = outcome.report
        attempts.append(
            HistoryAttempt(
                number=number,
                outcome="evaluated",
                diff_sha256=digest,
                in_loop_verdict=judged.final_verdict,
                integrity_violation=judged.integrity_violation,
                oracles=_summaries(judged),
            )
        )
        if last is None:
            ledger.transition_finding(
                finding.id,
                FindingState.PATCH_PROPOSED,
                reason=f"a patch was proposed (attempt {number})",
            )
        last = (number, digest, outcome)
        if judged.final_verdict is FinalVerdict.VERIFIED_WITHIN_BOUNDS:
            passed = last
            break
        feedback.append(feedback_from_outcome(number, outcome, digest, seeds))

    decision: Decision = "none"
    decisive: VerifyOutcome | None = None
    in_loop: FinalVerdict | None = None
    decisive_attempt: int | None = None
    diff_hash: str | None = None
    if passed is not None:
        number, diff_hash, first = passed
        in_loop, decisive_attempt = first.report.final_verdict, number
        final_dir = work_dir / f"held-out-{number}"
        try:
            decisive = verify(
                work_dir / f"attempt-{number}.diff",
                final_dir,
                HELD_OUT_ATTEMPT_BASE + number,
                held_settings,
            )
        except VerifyInputError as exc:
            raise ProveInputError(
                "rejected" if exc.kind == "rejected" else "usage", str(exc)
            ) from exc
        decision = "held_out_run"
    elif last is not None:
        decisive_attempt, diff_hash, decisive = last
        in_loop = decisive.report.final_verdict
        decision = "last_attempt"

    if decisive is None:
        verdict = FinalVerdict.INCONCLUSIVE
        why = "the model budget ended the loop" if stopped else "no usable reply"
        reasons: tuple[str, ...] = (f"no_patch_judged: {why}",)
        final_report: VerifyReport | None = None
    else:
        final_report = decisive.report
        verdict = final_report.final_verdict
        reasons = final_report.reasons or (VERIFIED_REASON,)
        if verdict is not FinalVerdict.VERIFIED_WITHIN_BOUNDS and stopped is None:
            used = len(attempts)
            if used >= request.max_attempts:
                reasons = (*reasons, f"attempts exhausted ({used} of {request.max_attempts})")
    if stopped is not None and verdict is not FinalVerdict.VERIFIED_WITHIN_BOUNDS:
        reasons = (*reasons, "stopped early: the model budget is used up")
    _finish_ledger(ledger, finding, decisive, reasons, notes)
    final = HistoryFinal(
        decision=decision,
        verdict=verdict,
        in_loop_verdict=in_loop,
        differs_from_in_loop=in_loop is not None and in_loop is not verdict,
        decisive_attempt=decisive_attempt,
        diff_sha256=diff_hash,
        reasons=reasons,
        stopped=stopped,
        attempts_used=len(attempts),
        statement=_statement(decision, verdict, in_loop, held_settings.fuzz_seed),
    )
    history = FixHistory(
        vuln_class=finding.vuln_class,
        limits=HistoryLimits(
            max_attempts=request.max_attempts,
            max_changed_lines=config.max_changed_lines,
            max_files=config.max_files,
            max_diff_bytes=config.max_diff_bytes,
            scope=config.scope,
        ),
        loop_bounds=_bounds(settings),
        held_out_bounds=_bounds(held_settings),
        attempts=tuple(attempts),
        final=final,
    )
    manifest: str | None = None
    if bundle is not None and decisive is not None and decisive.contents is not None:
        contents: BundleContents = replace(
            decisive.contents, extra=((HISTORY_FILE, history.to_bytes()),)
        )
        manifest = write_bundle(bundle.dest, contents, bundle.sanitizer)
    elif bundle is not None:
        notes.append("no bundle was written: no patch was judged")
    stored = ledger.get_finding(finding.id)
    return FixOutcome(
        finding_id=finding.id,
        stable_id=finding.stable_id,
        vuln_class=finding.vuln_class,
        verdict=verdict,
        reasons=reasons,
        history=history,
        report=final_report,
        state=stored.state,
        evidence_level=stored.evidence_level,
        manifest_sha256=manifest,
        notes=tuple(notes),
    )


__all__ = [
    "DEFAULT_ATTEMPTS",
    "HELD_OUT_ATTEMPT_BASE",
    "HELD_OUT_FAMILY",
    "FixHistory",
    "FixOutcome",
    "FixRequest",
    "campaign_seeds",
    "held_out_seed",
    "held_out_settings",
    "load_hypothesis",
    "run_fix",
]
