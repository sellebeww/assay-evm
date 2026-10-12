"""The benchmark runner: `assay verify` on every patch of a split, results stored as files.

The runner reuses `run_verification`, so it counts exactly what `assay verify` decides. Each case
gets its own ledger in a temporary directory. A case whose inputs are rejected is recorded with
its error; an infrastructure problem (Docker, runner image, memory) stops the run.
"""

import json
import platform
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from assay import __version__
from assay.bench.freeze import tree_hash
from assay.bench.models import (
    CaseResult,
    OracleOutcome,
    RunInfo,
    Split,
    SplitName,
)
from assay.bench.splits import (
    Expectation,
    fixtures_tree_sha256,
    load_expectations,
    load_split,
    split_file_sha256,
)
from assay.ledger import FinalVerdict, Ledger
from assay.oracles.symbolic import symbolic_runner
from assay.oracles.variant import profile
from assay.orchestrator.verify import (
    VerifyInputError,
    VerifyReport,
    VerifyRequest,
    VerifySettings,
    run_verification,
)
from assay.report.bundle import environment, read_versions_lock
from assay.sandbox import SandboxRunner

RESULTS_DIR: Final = Path("bench") / "results"
RUN_FILE: Final = "run.json"
CASES_DIR: Final = "cases"
EXIT_CODES: Final = {
    FinalVerdict.VERIFIED_WITHIN_BOUNDS: 0,
    FinalVerdict.REJECTED: 1,
    FinalVerdict.INCONCLUSIVE: 3,
}


class RunExists(Exception):
    """The result folder of this run already exists and is complete."""


@dataclass(frozen=True, slots=True)
class RunSettings:
    profile: str = "standard"
    fuzz_seed: str = "0x1"
    symbolic: bool = False
    resume: bool = False


def run_id(split: SplitName, settings: RunSettings, oracle_hash: str, fixtures_hash: str) -> str:
    """A name that identifies the split, the bounds, the oracles and the fixtures of a run."""
    symbolic = "-symbolic" if settings.symbolic else ""
    return f"{split}-{settings.profile}{symbolic}-{oracle_hash[:10]}-{fixtures_hash[:10]}"


def case_file_name(fixture: str, label: str) -> str:
    return f"{fixture.replace('/', '__')}__{label}.json"


def case_from_report(
    item: Expectation, report: VerifyReport, seconds: float, *, symbolic_ran: bool
) -> CaseResult:
    rows = tuple(
        OracleOutcome(
            oracle=row.oracle.value,
            status=row.status,
            verdict=None if row.verdict is None else row.verdict.value,
            codes=row.codes(),
        )
        for row in report.oracles
        if symbolic_ran or row.oracle.value != "symbolic"
    )
    return CaseResult(
        fixture=item.fixture,
        label=item.label,  # type: ignore[arg-type]
        expected_verdict=item.verdict,  # type: ignore[arg-type]
        expected_reason=item.reason,
        exit_code=5 if report.integrity_violation else EXIT_CODES[report.final_verdict],
        final_verdict=report.final_verdict.value,
        reasons=report.reasons,
        evidence_level=report.evidence_level,
        oracles=rows,
        base_tree_sha256=report.inputs.base_tree_sha256,
        poc_tree_sha256=report.inputs.poc_tree_sha256,
        patch_sha256=report.inputs.patch_sha256,
        seconds=round(seconds, 1),
    )


def case_from_error(item: Expectation, exit_code: int, error: str, seconds: float) -> CaseResult:
    return CaseResult(
        fixture=item.fixture,
        label=item.label,  # type: ignore[arg-type]
        expected_verdict=item.verdict,  # type: ignore[arg-type]
        expected_reason=item.reason,
        exit_code=exit_code,
        final_verdict=None,
        reasons=(),
        evidence_level=None,
        oracles=(),
        base_tree_sha256=None,
        poc_tree_sha256=None,
        patch_sha256=None,
        seconds=round(seconds, 1),
        error=error,
    )


def git_commit(root: Path) -> str | None:
    """The commit of the checkout, or `None` when there is none (or git is unavailable)."""
    try:
        done = subprocess.run(
            ["git", "rev-parse", "--verify", "-q", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    text = done.stdout.strip()
    return text if done.returncode == 0 and len(text) == 40 else None


def verify_case(
    root: Path,
    split: Split,
    item: Expectation,
    settings: VerifySettings,
    runner: SandboxRunner,
    halmos: SandboxRunner | None,
) -> CaseResult:
    base = root / split.root / item.fixture
    request = VerifyRequest(
        base=base, patch=base / "patches" / f"{item.label}.diff", poc=base / "poc"
    )
    start = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="assay-bench-", ignore_cleanup_errors=True) as tmp:
            work = Path(tmp) / "work"
            work.mkdir()
            with Ledger.open(Path(tmp) / "ledger.db") as ledger:
                outcome = run_verification(
                    request,
                    runner=runner,
                    ledger=ledger,
                    work_dir=work,
                    settings=settings,
                    symbolic_runner=halmos,
                )
    except VerifyInputError as exc:
        code = 5 if exc.kind == "rejected" else 2
        return case_from_error(item, code, str(exc), time.monotonic() - start)
    return case_from_report(
        item, outcome.report, time.monotonic() - start, symbolic_ran=settings.symbolic
    )


def run_split(
    root: Path,
    name: SplitName,
    settings: RunSettings,
    *,
    runner: SandboxRunner,
    progress: Callable[[str], None] = lambda _line: None,
) -> tuple[Path, RunInfo]:
    """Run every case of the split and write `bench/results/<run-id>/`. Infrastructure problems
    (sandbox, ledger, harness, memory) propagate and stop the run."""
    split = load_split(root, name)
    expectations = load_expectations(root, split)
    oracle_hash = tree_hash(root)
    fixtures_hash = fixtures_tree_sha256(root, split)
    identifier = run_id(name, settings, oracle_hash, fixtures_hash)
    out = root / RESULTS_DIR / identifier
    if (out / RUN_FILE).exists():
        raise RunExists(f"{out.relative_to(root).as_posix()} already holds a complete run")
    if out.exists() and not settings.resume:
        raise RunExists(
            f"{out.relative_to(root).as_posix()} holds an interrupted run; use --resume or "
            "remove the folder"
        )
    (out / CASES_DIR).mkdir(parents=True, exist_ok=True)

    verify_settings = VerifySettings(
        profile=settings.profile,  # type: ignore[arg-type]
        fuzz_seed=settings.fuzz_seed,
        symbolic=settings.symbolic,
    )
    halmos = symbolic_runner() if settings.symbolic else None
    env = environment(runner.image_id(), runner.image_labels(), read_versions_lock())
    chosen = profile(settings.profile)
    started = time.monotonic()
    done_before = 0.0
    results: list[CaseResult] = []
    for index, item in enumerate(expectations, 1):
        path = out / CASES_DIR / case_file_name(item.fixture, item.label)
        if settings.resume and path.is_file():
            case = CaseResult.model_validate_json(path.read_bytes())
            done_before += case.seconds
            progress(f"[{index:2d}/{len(expectations)}] {item.fixture} {item.label}: resumed")
        else:
            case = verify_case(root, split, item, verify_settings, runner, halmos)
            path.write_text(case.model_dump_json(indent=2) + "\n", encoding="utf-8")
            progress(
                f"[{index:2d}/{len(expectations)}] {item.fixture} {item.label}: "
                f"{case.final_verdict or case.error} ({round(case.seconds)} s)"
            )
        results.append(case)

    info = RunInfo(
        run_id=identifier,
        split=name,
        split_file_sha256=split_file_sha256(root, name),
        fixtures_tree_sha256=fixtures_hash,
        cases=len(results),
        assay_version=__version__,
        git_commit=git_commit(root),
        oracle_tree_sha256=tree_hash(root),
        image_digest=env.image_digest,
        tool_versions=env.tool_versions,
        versions_lock_sha256=env.versions_lock_sha256,
        machine=platform.machine(),
        profile=chosen.name,
        fuzz_seed=verify_settings.fuzz_seed,
        fuzz_runs=verify_settings.runs,
        variant_seeds=chosen.seeds,
        invariant_runs=chosen.invariant_runs,
        invariant_depth=chosen.invariant_depth,
        exploit_replays=verify_settings.replays,
        symbolic=settings.symbolic,
        total_seconds=round(done_before + time.monotonic() - started, 1),
    )
    if info.oracle_tree_sha256 != oracle_hash:
        raise RuntimeError("the frozen paths changed while the benchmark was running")
    (out / RUN_FILE).write_text(
        json.dumps(info.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return out, info
