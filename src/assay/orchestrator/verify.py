"""`assay verify`: run the oracles on one patch, decide the final verdict, record everything.

Order: integrity, exploit, variant, then symbolic when asked for (`VerifySettings.symbolic`),
behavior, regression. The integrity oracle runs first. When
the patch was not applied, or the integrity oracle found an integrity violation
(`HARD_REASONS`), verification stops: nothing from the patch runs and the remaining oracles are
reported as skipped. Any other failure does not stop verification, so that the report is
complete.

Final verdict: `VERIFIED_WITHIN_BOUNDS` only when all five required oracles ran and passed, and
the symbolic oracle, when it ran, passed too; `REJECTED` when any oracle failed; otherwise
`INCONCLUSIVE`. A symbolic timeout or unknown result is never a pass. Bounded equivalence never
changes the verdict; it is an annotation of the report.

Every oracle execution is recorded in the ledger as an `oracle_run` with a claim that the run
decides; the claim's status follows from the run's verdict through `promote_claim`. The
verification row holds the final verdict, its reasons, the bounds that ran and, when a bundle
was written, the sha256 of its manifest. The finding of a verification stays `CANDIDATE`: the
lifecycle steps before a reproduction need a recorded hypothesis and a PoC checker, which
`assay verify` does not have.
"""

import hashlib
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from assay.ingest import IngestError, Snapshot, create_snapshot
from assay.ingest.patch import (
    DEFAULT_PROTECTED,
    PatchLimits,
    PatchPolicy,
    prepare_patched_revision,
)
from assay.ledger import (
    REQUIRED_ORACLES,
    FinalVerdict,
    FindingId,
    Ledger,
    OracleName,
    PatchId,
    PatchSource,
    ProjectId,
    RevisionId,
    RevisionKind,
    Verdict,
)
from assay.ledger.ledger import MAX_PATCH_BYTES
from assay.oracles.base import OracleResult, RecordedRun, record_result
from assay.oracles.behavior import BehaviorContext, BehaviorOracle
from assay.oracles.exploit import ExploitContext, ExploitOracle
from assay.oracles.integrity import IntegrityContext, IntegrityOracle, is_hard
from assay.oracles.regression import RegressionContext, RegressionOracle, target_contracts
from assay.oracles.runtree import HARNESS_MOUNT, SOURCE_DIR, Harness, load_harness
from assay.oracles.symbolic import SymbolicContext, SymbolicOracle, SymbolicOutcome
from assay.oracles.variant import VariantContext, VariantOracle, VariantOutcome
from assay.orchestrator.models import (
    ORACLE_ORDER,
    REPORT_ORDER,
    Bounds,
    EvidenceLevel,
    Inputs,
    OracleRow,
    OracleStatus,
    Timing,
    VerifyReport,
    VerifySettings,
)
from assay.report.bundle import BundleContents, Environment, ManifestSettings, Sanitizer
from assay.report.bundle import write_bundle as _write_bundle
from assay.sandbox import SandboxRunner

__all__ = [
    "ORACLE_ORDER",
    "REPORT_ORDER",
    "VERIFIED_REASON",
    "BundleRequest",
    "FindingTarget",
    "Inputs",
    "OracleRow",
    "OracleStatus",
    "VerifyInputError",
    "VerifyOutcome",
    "VerifyReport",
    "VerifyRequest",
    "VerifySettings",
    "decide",
    "run_verification",
]

VERIFIED_REASON: Final = "every required oracle passed within the recorded bounds"
HALMOS_LABEL: Final = "assay.halmos.version"
FINDING_CLASS: Final = "other"
PROJECT_NAME: Final = "verify"


class VerifyInputError(Exception):
    """The inputs cannot be verified. `rejected` inputs broke an ingest rule; `usage` inputs
    are not what the command expects."""

    def __init__(self, kind: Literal["rejected", "usage"], message: str) -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True, slots=True)
class VerifyRequest:
    base: Path
    patch: Path
    poc: Path


@dataclass(frozen=True, slots=True)
class BundleRequest:
    """Where to write the evidence bundle, and what to record about the environment."""

    dest: Path
    environment: Callable[[], Environment]
    """Called once the oracles ran; reads the runner image digest, labels and versions.lock."""
    sanitizer: Sanitizer
    symbolic_environment: Callable[[], Environment] | None = None
    """The same for the symbolic runner image, when the symbolic oracle ran."""
    write: bool = True
    """`False` assembles the contents of the bundle (`VerifyOutcome.contents`) without writing
    it, for a caller that adds files and writes the bundle itself (the fix loop)."""


@dataclass(frozen=True, slots=True)
class FindingTarget:
    """An existing finding that a verification is recorded for, instead of a new one.

    The fix loop verifies the patches of a finding that `assay prove` reproduced: the oracle runs
    belong to that finding's claims, so the finding can move on the evidence of the runs. The
    patch row is the attempt `attempt_no` of the finding.
    """

    finding_id: FindingId
    project_id: ProjectId
    source: PatchSource
    attempt_no: int


@dataclass(frozen=True, slots=True)
class VerifyOutcome:
    report: VerifyReport
    verification_id: int
    manifest_sha256: str | None = None
    results: tuple[OracleResult, ...] = ()
    """The results of the oracles that ran, with their evidence, in the order they ran."""
    patch_id: PatchId | None = None
    patched_runs: tuple[RecordedRun, ...] = ()
    """The recorded runs on the patched revision: the evidence a finding can move on."""
    contents: BundleContents | None = None
    """The bundle contents, when the bundle was requested and not written (`write=False`)."""


def decide(rows: Sequence[OracleRow]) -> tuple[FinalVerdict, tuple[str, ...]]:
    """Final verdict from the oracle rows.

    `REJECTED` if any oracle failed; otherwise `INCONCLUSIVE` if any oracle was inconclusive,
    skipped or missing; `VERIFIED_WITHIN_BOUNDS` only when every required oracle ran and passed.
    """
    by_oracle = {row.oracle: row for row in rows}
    failed = [row for row in rows if row.status == "ran" and row.verdict is Verdict.FAIL]
    if failed:
        codes = [item.code for row in failed for item in row.reasons]
        return FinalVerdict.REJECTED, tuple(dict.fromkeys(codes)) or ("oracle_failed",)
    reasons = [
        item.code
        for row in rows
        if row.status == "ran" and row.verdict is Verdict.INCONCLUSIVE
        for item in row.reasons
    ]
    skipped = [row.oracle.value for row in rows if row.status == "skipped"]
    missing = [
        oracle.value
        for oracle in ORACLE_ORDER
        if oracle in REQUIRED_ORACLES
        and (oracle not in by_oracle or by_oracle[oracle].status == "missing")
    ]
    if skipped:
        reasons.append(f"skipped_oracles: {', '.join(skipped)}")
    if missing:
        reasons.append(f"missing_oracles: {', '.join(missing)}")
    not_passed = [
        row
        for row in rows
        if row.oracle in REQUIRED_ORACLES
        and row.status == "ran"
        and row.verdict is not Verdict.PASS
    ]
    if reasons or not_passed:
        return FinalVerdict.INCONCLUSIVE, tuple(dict.fromkeys(reasons)) or ("not_all_passed",)
    return FinalVerdict.VERIFIED_WITHIN_BOUNDS, ()


def _row(result: OracleResult) -> OracleRow:
    return OracleRow(
        oracle=result.oracle,
        status="ran",
        verdict=result.verdict,
        reasons=result.reasons,
        summary=result.summary,
        warnings=result.warnings,
    )


def _bounds_statement(
    rows: Sequence[OracleRow],
    settings: VerifySettings,
    contracts: Sequence[str],
    variant: VariantOutcome | None,
    symbolic: SymbolicOutcome | None = None,
) -> str:
    ran = {row.oracle: row for row in rows if row.status == "ran"}
    parts: list[str] = []
    if OracleName.INTEGRITY in ran:
        parts.append("integrity: static checks of the patch and the patched sources")
    if OracleName.EXPLOIT in ran:
        parts.append(
            f"exploit: test_replay up to {settings.replays} times per revision, "
            f"fuzz seed {settings.fuzz_seed}"
        )
    if OracleName.VARIANT in ran and variant is not None:
        parts.append(f"variant: {variant.statement}")
    if OracleName.SYMBOLIC in ran and symbolic is not None:
        parts.append(symbolic.statement)
    if OracleName.BEHAVIOR in ran:
        parts.append(
            f"behavior: benign tests and their records on both revisions, fuzz seed "
            f"{settings.fuzz_seed}, {settings.runs} fuzz runs"
        )
        if symbolic is not None and symbolic.bounds.equivalence != "none":
            parts.append(symbolic.equivalence_statement)
    if OracleName.REGRESSION in ran:
        targets = ", ".join(contracts) or "none"
        parts.append(
            f"regression: storage layout, ABI and events of {targets}; the whole test suite on "
            "the patched revision"
        )
    not_run = [row.oracle.value for row in rows if row.status != "ran"]
    if not_run:
        parts.append(f"not run: {', '.join(not_run)}")
    return "; ".join(parts)


def evidence_level(rows: Sequence[OracleRow], final: FinalVerdict) -> EvidenceLevel:
    """The evidence level of the patch's finding that the oracle results support.

    A symbolic result never creates a level of its own; it is an annotation of the bounds.
    """
    if final is FinalVerdict.VERIFIED_WITHIN_BOUNDS:
        return "E3"
    ran = {row.oracle: row for row in rows if row.status == "ran"}
    failed = any(row.verdict is Verdict.FAIL for row in ran.values())
    e2 = (OracleName.INTEGRITY, OracleName.EXPLOIT, OracleName.BEHAVIOR, OracleName.REGRESSION)
    if not failed and all(oracle in ran and ran[oracle].verdict is Verdict.PASS for oracle in e2):
        return "E2"
    exploit = ran.get(OracleName.EXPLOIT)
    if exploit is not None and (
        exploit.verdict is Verdict.PASS or "exploit_still_reproducible" in exploit.codes()
    ):
        return "E1"
    return "E0"


def _annotations(symbolic: SymbolicOutcome | None) -> tuple[str, ...]:
    if symbolic is None:
        return ()
    return (symbolic.statement, symbolic.equivalence_statement)


def _snapshot(source: Path, dest: Path, what: str) -> Snapshot:
    try:
        return create_snapshot(source, dest)
    except IngestError as exc:
        raise VerifyInputError("rejected", f"{what} rejected at ingest: {exc}") from exc


def _read_patch(path: Path) -> bytes:
    with path.open("rb") as handle:
        data = handle.read(MAX_PATCH_BYTES + 1)
    if len(data) > MAX_PATCH_BYTES:
        raise VerifyInputError("usage", f"the patch is larger than {MAX_PATCH_BYTES} bytes")
    return data


def _policy(base: Path, poc: Path, override: PatchPolicy | None) -> PatchPolicy:
    """The default policy; a PoC directory inside the base project is protected as well."""
    base_dir, poc_dir = base.resolve(), poc.resolve()
    if poc_dir == base_dir or poc_dir in base_dir.parents:
        raise VerifyInputError("usage", "the PoC directory must not contain the base project")
    if override is not None:
        return override
    protected = list(DEFAULT_PROTECTED)
    if base_dir in poc_dir.parents:
        relative = poc_dir.relative_to(base_dir).as_posix()
        if relative not in protected:
            protected.append(relative)
    return PatchPolicy(protected=tuple(protected))


def _stable_id(ledger: Ledger, *digests: str) -> str:
    stem = "verify-" + hashlib.sha256("\n".join(digests).encode("ascii")).hexdigest()[:20]
    candidate, number = stem, 1
    while ledger.find_finding(candidate) is not None:
        number += 1
        candidate = f"{stem}.{number}"
    return candidate


def _milliseconds(timing: Timing) -> dict[str, object]:
    """The durations as whole milliseconds, for the ledger (its canonical JSON has no floats)."""
    return {
        "total": round(timing.total_s * 1000),
        "oracles": {oracle.value: round(value * 1000) for oracle, value in timing.oracles.items()},
    }


def _oracle_dir(work_dir: Path, name: str) -> Path:
    path = work_dir / name
    path.mkdir()
    return path


def run_verification(
    request: VerifyRequest,
    *,
    runner: SandboxRunner,
    ledger: Ledger,
    work_dir: Path,
    settings: VerifySettings | None = None,
    harness: Harness | None = None,
    policy: PatchPolicy | None = None,
    bundle: BundleRequest | None = None,
    symbolic_runner: SandboxRunner | None = None,
    target: FindingTarget | None = None,
    limits: PatchLimits | None = None,
    integrity_gate: bool = False,
) -> VerifyOutcome:
    """Verify one patch and record the result in `ledger`. `work_dir` must be empty.

    `symbolic_runner` runs Halmos in the symbolic runner image; it is needed when
    `settings.symbolic` is set.

    `policy` replaces the patch policy derived from the inputs (used by `assay replay`, which
    applies the policy recorded in a bundle). `target` records the verification for an existing
    finding (the fix loop), `limits` replaces the default size limits of the patch, and
    `integrity_gate` stops verification after any failure of the IntegrityOracle, so that nothing
    else runs for a patch that is already known to be rejected. Raises `VerifyInputError` for
    inputs that cannot be verified, and lets sandbox, harness, ledger and file errors through:
    those are infrastructure problems, not verdicts.
    """
    started = time.monotonic()
    settings = settings if settings is not None else VerifySettings()
    if settings.symbolic and symbolic_runner is None:
        raise VerifyInputError("usage", "the symbolic oracle needs the symbolic runner image")
    policy = _policy(request.base, request.poc, policy)
    data = _read_patch(request.patch)
    base = _snapshot(request.base, work_dir / "base", "the base project")
    paths = [item.path for item in base.files]
    if any(path.split("/", 1)[0] == HARNESS_MOUNT for path in paths):
        raise VerifyInputError(
            "rejected",
            f"the base project has a top-level {HARNESS_MOUNT}/ directory, which is reserved "
            "for the shared harness",
        )
    if not any(path.startswith(f"{SOURCE_DIR}/") for path in paths):
        raise VerifyInputError("usage", f"the base project has no {SOURCE_DIR}/ directory")
    poc = _snapshot(request.poc, work_dir / "poc", "the PoC directory")
    image_digest = runner.image_id()
    symbolic_digest: str | None = None
    halmos_version: str | None = None
    if settings.symbolic and symbolic_runner is not None:
        symbolic_digest = symbolic_runner.image_id()
        halmos_version = symbolic_runner.image_labels().get(HALMOS_LABEL)
    harness = harness if harness is not None else load_harness()
    prepared = prepare_patched_revision(
        base, data, work_dir / "patched", policy=policy, limits=limits
    )
    contracts = target_contracts(base)

    if target is None:
        project = ledger.add_project(PROJECT_NAME, f"tree:{base.tree_sha256[:16]}")
        finding = ledger.add_finding(
            project,
            _stable_id(ledger, base.tree_sha256, poc.tree_sha256, prepared.sha256),
            FINDING_CLASS,
        )
        source, attempt_no = PatchSource.HUMAN, 1
    else:
        project, finding = target.project_id, target.finding_id
        source, attempt_no = target.source, target.attempt_no
    revisions: dict[RevisionKind, RevisionId] = {
        RevisionKind.VULNERABLE: ledger.add_revision(
            project, RevisionKind.VULNERABLE, base.tree_sha256
        )
    }
    patch_id = ledger.add_patch(finding, source, data, attempt_no=attempt_no)
    if prepared.snapshot is not None:
        revisions[RevisionKind.PATCHED] = ledger.add_revision(
            project, RevisionKind.PATCHED, prepared.snapshot.tree_sha256, patch_id
        )

    results: list[OracleResult] = []
    patched_runs: list[RecordedRun] = []
    seconds: dict[OracleName, float] = {}
    clock = time.monotonic()

    def record(result: OracleResult, digest: str = image_digest) -> None:
        nonlocal clock
        now = time.monotonic()
        seconds[result.oracle] = round(now - clock, 1)
        recorded = record_result(
            ledger, result, finding_id=finding, revisions=revisions, image_digest=digest
        )
        patched_runs.extend(item for item in recorded if item.revision is RevisionKind.PATCHED)
        results.append(result)
        clock = time.monotonic()

    integrity = IntegrityOracle().run(
        IntegrityContext(base=base, poc=poc, prepared=prepared, policy=policy, harness=harness)
    )
    record(integrity)
    variant: VariantOutcome | None = None
    symbolic: SymbolicOutcome | None = None
    order = REPORT_ORDER if settings.symbolic else ORACLE_ORDER
    rows = [_row(integrity)]
    violation = is_hard(integrity)
    patched = prepared.snapshot
    gated = integrity_gate and integrity.verdict is Verdict.FAIL
    if patched is None or violation or gated:
        if violation:
            why = "integrity violation"
        elif patched is None:
            why = "the patch was not applied"
        else:
            why = "the integrity check failed"
        rows += [
            OracleRow(
                oracle=oracle,
                status="skipped",
                verdict=None,
                reasons=(),
                summary=f"not run: {why}",
            )
            for oracle in order[1:]
        ]
    else:
        record(
            ExploitOracle(settings.exploit()).run(
                ExploitContext(
                    runner=runner,
                    vulnerable=base,
                    patched=patched,
                    poc=poc,
                    harness=harness,
                    work_dir=_oracle_dir(work_dir, "exploit"),
                )
            )
        )
        variant = VariantOracle(settings.variant()).search(
            VariantContext(
                runner=runner,
                vulnerable=base,
                patched=patched,
                poc=poc,
                harness=harness,
                work_dir=_oracle_dir(work_dir, "variant"),
            )
        )
        record(variant.result)
        if settings.symbolic and symbolic_runner is not None and symbolic_digest is not None:
            symbolic = SymbolicOracle(settings.symbolic_settings(), halmos_version).search(
                SymbolicContext(
                    runner=runner,
                    symbolic_runner=symbolic_runner,
                    vulnerable=base,
                    patched=patched,
                    poc=poc,
                    harness=harness,
                    work_dir=_oracle_dir(work_dir, "symbolic"),
                )
            )
            record(symbolic.result, symbolic_digest)
        record(
            BehaviorOracle(settings.suite()).run(
                BehaviorContext(
                    runner=runner,
                    vulnerable=base,
                    patched=patched,
                    harness=harness,
                    work_dir=_oracle_dir(work_dir, "behavior"),
                )
            )
        )
        record(
            RegressionOracle(settings.suite()).run(
                RegressionContext(
                    runner=runner,
                    vulnerable=base,
                    patched=patched,
                    harness=harness,
                    work_dir=_oracle_dir(work_dir, "regression"),
                    targets=contracts,
                )
            )
        )
        rows += [_row(result) for result in results[1:]]

    final_verdict, reasons = decide(rows)
    bounds = Bounds(
        exploit_replays_per_revision=settings.replays,
        profile=settings.profile,
        fuzz_seed=settings.fuzz_seed,
        fuzz_runs=settings.runs,
        interface_contracts=contracts,
        oracles_run=tuple(row.oracle for row in rows if row.status == "ran"),
        oracles_not_run=tuple(row.oracle for row in rows if row.status != "ran"),
        variant=None if variant is None else variant.bounds,
        symbolic=None if symbolic is None else symbolic.bounds,
    )
    timing = Timing(
        total_s=round(time.monotonic() - started, 1),
        oracles=seconds,
        variant=None if variant is None else variant.timing,
        symbolic=None if symbolic is None else symbolic.timing,
    )
    report = VerifyReport(
        inputs=Inputs(
            base_tree_sha256=base.tree_sha256,
            poc_tree_sha256=poc.tree_sha256,
            patch_sha256=prepared.sha256,
            patched_tree_sha256=None if patched is None else patched.tree_sha256,
            harness_sha256=harness.sha256,
        ),
        oracles=tuple(rows),
        final_verdict=final_verdict,
        reasons=reasons,
        integrity_violation=violation,
        bounds=bounds,
        bounds_statement=_bounds_statement(rows, settings, contracts, variant, symbolic),
        timing=timing,
        evidence_level=evidence_level(rows, final_verdict),
        annotations=_annotations(symbolic),
    )
    manifest_sha256: str | None = None
    contents: BundleContents | None = None
    if bundle is not None:
        contents = BundleContents(
            base=base,
            poc=poc,
            patch=data,
            harness=harness,
            results=tuple(results),
            report=report,
            environment=bundle.environment(),
            symbolic_environment=None
            if symbolic is None or bundle.symbolic_environment is None
            else bundle.symbolic_environment(),
            settings=ManifestSettings(
                exploit_replays=settings.replays,
                profile=settings.profile,
                fuzz_seed=settings.fuzz_seed,
                fuzz_runs=settings.fuzz_runs,
                symbolic=settings.symbolic,
                scope=policy.scope,
                protected=policy.protected,
            ),
        )
        if bundle.write:
            manifest_sha256 = _write_bundle(bundle.dest, contents, bundle.sanitizer)
            contents = None
    verification_id = ledger.add_verification(
        patch_id,
        final_verdict,
        "; ".join(reasons) or VERIFIED_REASON,
        {**bounds.model_dump(mode="json"), "timing_ms": _milliseconds(timing)},
        bundle_manifest_sha256=manifest_sha256,
    )
    return VerifyOutcome(
        report=report,
        verification_id=verification_id,
        manifest_sha256=manifest_sha256,
        results=tuple(results),
        patch_id=patch_id,
        patched_runs=tuple(patched_runs),
        contents=contents,
    )
