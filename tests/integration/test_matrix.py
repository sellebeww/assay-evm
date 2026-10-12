"""Classification matrix: `assay verify` on every patch of every development fixture.

Each final verdict and its reasons are compared with the fixture's `expected.json`, which
`make fixtures-check` establishes with plain Foundry, independently of the oracles. The results
are written to `build/matrix/results.json` for `tools/matrix_report.py`, which renders
`docs/classification-matrix.md`. Run with `make matrix`; it takes between half an hour and two
hours, depending on the machine.

A verification that ends with exit code 4 (an infrastructure problem, for example Docker out of
memory) stops the whole run with exit code 4, since the remaining results would say nothing
about the oracles.
"""

import json
import os
import time
from pathlib import Path
from typing import Final

import pytest
from typer.testing import CliRunner

import matrix_report as mr
from assay import __version__
from assay.cli.exit_codes import ExitCode
from assay.cli.main import app
from assay.oracles.variant import PROFILE_NAMES, profile
from assay.orchestrator.models import VerifySettings
from assay.report.bundle import environment, read_versions_lock, without_timing
from assay.sandbox import SandboxRunner

pytestmark = [pytest.mark.matrix, pytest.mark.usefixtures("runner")]

ROOT: Final = Path(__file__).resolve().parents[2]
FIXTURES: Final = ROOT / "fixtures"
RESULTS: Final = ROOT / "build" / "matrix" / "results.json"
# Verified a second time and compared with the first run. Between them, the three cases store a
# counterexample (overfit), pass every oracle (good) and record a changed interface (regressing).
DETERMINISM_CASES: Final = (
    ("oracle_manipulation/spot_price", "overfit"),
    ("dos/payout_loop", "good"),
    ("rounding/share_inflation", "regressing"),
)
# Exit codes that come with a report; an integrity violation (5) has one unless ingest rejected
# the inputs.
REPORT_EXIT_CODES: Final = (
    ExitCode.SUCCESS,
    ExitCode.NEGATIVE,
    ExitCode.INCONCLUSIVE,
    ExitCode.INTEGRITY,
)

# The campaign profile of the variant search (`make matrix PROFILE=...`, default standard).
PROFILE: Final = os.environ.get("ASSAY_MATRIX_PROFILE", "standard")

cli = CliRunner()


def verify(fixture: str, label: str, run_dir: Path) -> tuple[mr.CaseResult, Path]:
    """Run `assay verify` with its own ledger and bundle directory under `run_dir`."""
    base = FIXTURES / fixture
    bundle = run_dir / "bundle"
    start = time.monotonic()
    result = cli.invoke(
        app,
        [
            "verify",
            "--base",
            str(base),
            "--patch",
            str(base / "patches" / f"{label}.diff"),
            "--poc",
            str(base / "poc"),
            "--ledger",
            str(run_dir / "ledger.db"),
            "--bundle-out",
            str(bundle),
            "--profile",
            PROFILE,
            "--json",
        ],
    )
    seconds = time.monotonic() - start
    if result.exit_code == ExitCode.INFRASTRUCTURE:
        pytest.exit(
            f"{fixture} {label}: infrastructure problem (exit code 4), for example Docker out "
            f"of memory: {result.stderr.strip()}",
            returncode=int(ExitCode.INFRASTRUCTURE),
        )
    verdict: str | None = None
    reasons: tuple[str, ...] = ()
    error = None
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        error = f"{type(result.exception).__name__}: {result.exception}"
    elif result.exit_code in REPORT_EXIT_CODES and result.stdout.strip():
        report = json.loads(result.stdout)
        verdict, reasons = report["final_verdict"], tuple(report["reasons"])
    else:
        error = (result.stderr.strip().splitlines() or [f"exit code {result.exit_code}"])[0]
    case = mr.CaseResult(
        fixture=fixture,
        label=label,
        exit_code=result.exit_code,
        final_verdict=verdict,
        reasons=reasons,
        seconds=round(seconds, 1),
        error=error,
    )
    return case, bundle


@pytest.fixture(scope="module")
def matrix(
    tmp_path_factory: pytest.TempPathFactory, runner: SandboxRunner
) -> tuple[mr.MatrixResults, list[mr.Row], dict[tuple[str, str], Path]]:
    RESULTS.unlink(missing_ok=True)
    if PROFILE not in PROFILE_NAMES:
        pytest.exit(f"unknown profile {PROFILE!r}; known: {', '.join(PROFILE_NAMES)}", returncode=2)
    expectations = mr.load_expectations(FIXTURES)
    workspace = tmp_path_factory.mktemp("matrix")
    cases: list[mr.CaseResult] = []
    bundles: dict[tuple[str, str], Path] = {}
    start = time.monotonic()
    for index, item in enumerate(expectations, 1):
        run_dir = workspace / item.fixture.replace("/", "-") / item.label
        run_dir.mkdir(parents=True)
        case, bundle = verify(item.fixture, item.label, run_dir)
        cases.append(case)
        bundles[(item.fixture, item.label)] = bundle
        ok = mr.matches(case.final_verdict, case.reasons, item.verdict, item.reason)
        print(
            f"[{index:2d}/{len(expectations)}] {item.fixture} {item.label}: "
            f"{case.final_verdict or case.error} ({round(case.seconds)} s) "
            f"{'match' if ok else 'MISMATCH'}",
            flush=True,
        )
    settings = VerifySettings(profile=PROFILE)  # type: ignore[arg-type]
    chosen = profile(PROFILE)
    image = environment(runner.image_id(), runner.image_labels(), read_versions_lock())
    results = mr.MatrixResults(
        assay_version=__version__,
        image_digest=image.image_digest,
        tool_versions=image.tool_versions,
        versions_lock_sha256=image.versions_lock_sha256,
        profile=chosen.name,
        fuzz_seed=settings.fuzz_seed,
        fuzz_runs=settings.runs,
        variant_seeds=chosen.seeds,
        invariant_runs=chosen.invariant_runs,
        invariant_depth=chosen.invariant_depth,
        exploit_replays=settings.replays,
        total_seconds=round(time.monotonic() - start, 1),
        cases=tuple(cases),
    )
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(results.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return results, mr.compare(expectations, results), bundles


def test_every_patch_gets_the_verdict_of_its_label(
    matrix: tuple[mr.MatrixResults, list[mr.Row], dict[tuple[str, str], Path]],
) -> None:
    _, rows, _ = matrix
    print()
    print("\n".join(mr.table_lines(rows)))
    print(mr.result_line(rows), flush=True)
    assert len(rows) == len(mr.PATCH_LABELS) * len(mr.CLASS_IDS)
    mismatches = [f"{row.fixture} {row.label}: {row.actual}" for row in rows if not row.matches]
    assert mismatches == []


@pytest.mark.parametrize(("fixture", "label"), DETERMINISM_CASES)
def test_a_second_verification_gives_the_same_verdict_and_manifest(
    matrix: tuple[mr.MatrixResults, list[mr.Row], dict[tuple[str, str], Path]],
    tmp_path: Path,
    fixture: str,
    label: str,
) -> None:
    results, _, bundles = matrix
    (first,) = [case for case in results.cases if (case.fixture, case.label) == (fixture, label)]
    second, bundle = verify(fixture, label, tmp_path)
    assert (second.exit_code, second.final_verdict, second.reasons) == (
        first.exit_code,
        first.final_verdict,
        first.reasons,
    )
    # Only the durations in `timing` may differ between the two manifests (ADR 0017).
    manifest = without_timing((bundle / "manifest.json").read_bytes())
    assert manifest == without_timing((bundles[(fixture, label)] / "manifest.json").read_bytes())
