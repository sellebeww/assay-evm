"""`assay verify`: check whether a patch closes the exploit of a PoC, within recorded bounds."""

import json
import re
import tempfile
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Final, NoReturn

import typer

from assay.analyzers.foundry import ForgeOutOfMemory
from assay.cli.exit_codes import ExitCode
from assay.cli.text import printable
from assay.ledger import FinalVerdict, Ledger, LedgerError, OracleName
from assay.oracles.runtree import HarnessUnavailable
from assay.oracles.symbolic import symbolic_runner
from assay.oracles.variant import DEFAULT_BASE_SEED, MAX_FUZZ_RUNS
from assay.orchestrator.verify import (
    BundleRequest,
    VerifyInputError,
    VerifyReport,
    VerifyRequest,
    VerifySettings,
    run_verification,
)
from assay.report.bundle import (
    BundleError,
    Environment,
    EnvironmentUnavailable,
    Sanitizer,
    check_bundle_dir,
    environment,
    read_versions_lock,
)
from assay.sandbox import SandboxError, SandboxRunner

DEFAULT_LEDGER: Final = Path(".assay") / "ledger.db"
_SEED: Final = re.compile(r"0x[0-9a-f]{1,16}")


class ProfileChoice(StrEnum):
    QUICK = "quick"
    STANDARD = "standard"
    THOROUGH = "thorough"


LIMITS: Final = (
    "a verdict covers only the checks and bounds listed here; VERIFIED_WITHIN_BOUNDS means "
    "that nothing was found within them, and is not a proof of absence"
)
_EXIT_CODES: Final = {
    FinalVerdict.VERIFIED_WITHIN_BOUNDS: ExitCode.SUCCESS,
    FinalVerdict.REJECTED: ExitCode.NEGATIVE,
    FinalVerdict.INCONCLUSIVE: ExitCode.INCONCLUSIVE,
}


def exit_code(report: VerifyReport) -> ExitCode:
    """5 for an integrity violation, otherwise 0, 1 or 3 by the final verdict."""
    if report.integrity_violation:
        return ExitCode.INTEGRITY
    return _EXIT_CODES[report.final_verdict]


def _table(rows: list[tuple[str, str, str]]) -> list[str]:
    widths = [max(len(row[index]) for row in rows) for index in range(3)]
    return [
        "  ".join(cell.ljust(width) for cell, width in zip(row, widths, strict=True)).rstrip()
        for row in rows
    ]


def _time(report: VerifyReport) -> str:
    """The measured durations; they are not part of the bounds and differ between runs."""
    timing = report.timing
    parts = [f"{timing.total_s} s in total"]
    if OracleName.VARIANT in timing.oracles:
        parts.append(f"variant search {timing.oracles[OracleName.VARIANT]} s")
    if OracleName.SYMBOLIC in timing.oracles:
        parts.append(f"symbolic {timing.oracles[OracleName.SYMBOLIC]} s")
    if timing.variant is not None:
        campaigns = [item for item in timing.variant.campaigns if item.mode != "confirmation"]
        confirmations = [item for item in timing.variant.campaigns if item.mode == "confirmation"]
        parts.append(
            f"{len(campaigns)} campaigns, {round(sum(item.seconds for item in campaigns), 1)} s"
        )
        if confirmations:
            parts.append(
                f"counterexample replays {round(sum(item.seconds for item in confirmations), 1)} s"
            )
    return ", ".join(parts)


def render(report: VerifyReport) -> str:
    """The verdict table, the final verdict, the bounds, warnings and details, as plain text."""
    inputs = report.inputs
    lines = [
        f"base tree {inputs.base_tree_sha256[:12]}  poc tree {inputs.poc_tree_sha256[:12]}  "
        f"patch sha256 {inputs.patch_sha256[:12]}",
        "",
    ]
    rows = [("oracle", "verdict", "reason")]
    for row in report.oracles:
        if row.status == "ran":
            codes = ", ".join(row.codes()) or "-"
            rows.append((row.oracle.value, row.verdict.value if row.verdict else "-", codes))
        else:
            rows.append((row.oracle.value, "-", row.status))
    lines += _table(rows)
    lines += [
        "",
        f"final verdict: {report.final_verdict.value}",
        f"reason: {'; '.join(report.reasons) or 'every required oracle passed'}",
        f"bounds: {report.bounds_statement}",
    ]
    if report.evidence_level is not None:
        lines.append(f"evidence level: {report.evidence_level}")
    lines += [f"{item}" for item in report.annotations]
    lines += [
        f"time: {_time(report)}",
        f"limits: {LIMITS}",
    ]
    warnings = [(row.oracle.value, item) for row in report.oracles for item in row.warnings]
    if warnings:
        lines += ["", "warnings (they do not change the verdict):"]
        lines += [f"  {oracle}: {item.code}: {item.detail}" for oracle, item in warnings]
    lines += ["", "details:"]
    for row in report.oracles:
        lines.append(f"  {row.oracle.value}: {row.summary}")
        for item in row.reasons:
            where = ""
            if item.path is not None:
                where = f" [{item.path}{'' if item.line is None else f':{item.line}'}]"
            lines.append(f"    {item.code}: {item.detail}{where}")
    return printable("\n".join(lines))


def _fail(code: ExitCode, message: str) -> NoReturn:
    typer.echo(printable(message), err=True)
    raise typer.Exit(int(code))


def bundle_sanitizer(
    work_dir: Path, request: VerifyRequest, bundle: Path, ledger: Path
) -> Sanitizer:
    return Sanitizer(
        [
            (work_dir, "<work>"),
            (request.base.resolve(), "<base>"),
            (request.poc.resolve(), "<poc>"),
            (request.patch.resolve().parent, "<patch-dir>"),
            (bundle.resolve(), "<bundle>"),
            (ledger.resolve().parent, "<ledger-dir>"),
            (Path.cwd(), "<cwd>"),
            (Path(tempfile.gettempdir()), "<tmp>"),
            (Path.home(), "<home>"),
        ]
    )


def verify_command(
    base: Annotated[
        Path,
        typer.Option(
            "--base",
            help="Directory of the vulnerable Foundry project (its src/ is patched).",
            exists=True,
            file_okay=False,
        ),
    ],
    patch: Annotated[
        Path,
        typer.Option(
            "--patch",
            help="Unified diff to verify, with a/ and b/ path prefixes as git writes them.",
            exists=True,
            dir_okay=False,
        ),
    ],
    poc: Annotated[
        Path,
        typer.Option(
            "--poc",
            help="Directory with the PoC: one contract deriving from AssayPoC.",
            exists=True,
            file_okay=False,
        ),
    ],
    profile: Annotated[
        ProfileChoice,
        typer.Option(
            "--profile",
            help="Campaign profile of the variant search: seeds, runs per seed, invariant runs "
            "and depth, time limit per campaign (see docs/oracles.md).",
        ),
    ] = ProfileChoice.STANDARD,
    seed: Annotated[
        str,
        typer.Option(
            "--seed",
            help="Base seed (0x and 1 to 16 hex digits). Every campaign seed is derived from it.",
        ),
    ] = DEFAULT_BASE_SEED,
    fuzz_runs: Annotated[
        int | None,
        typer.Option(
            "--fuzz-runs",
            help="Runs of every fuzz campaign (variant search, fuzz tests of the project); "
            "replaces the profile's runs per seed.",
            min=1,
            max=MAX_FUZZ_RUNS,
        ),
    ] = None,
    symbolic: Annotated[
        bool,
        typer.Option(
            "--symbolic",
            help="Also run the symbolic oracle (Halmos) on the properties in the PoC directory's "
            "symbolic/ subdirectory, after the variant search; needs the symbolic runner image "
            "(see docs/symbolic.md).",
        ),
    ] = False,
    bundle_out: Annotated[
        Path | None,
        typer.Option(
            "--bundle-out",
            help="Write an evidence bundle into this directory, which must be empty or absent.",
        ),
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Print the report as JSON instead of a table.")
    ] = False,
    ledger_path: Annotated[
        Path,
        typer.Option("--ledger", help="Ledger database; created if missing.", dir_okay=False),
    ] = DEFAULT_LEDGER,
) -> None:
    """Check whether PATCH closes the exploit of POC on BASE, within recorded bounds.

    Runs the oracles integrity, exploit, variant, behavior and regression, prints a verdict per
    oracle, the final verdict and the bounds that ran, and records every oracle run in the
    ledger. VERIFIED_WITHIN_BOUNDS needs a PASS from all five oracles and is not a proof of
    absence. With --symbolic the symbolic oracle (Halmos) runs after the variant search and must
    pass as well; a symbolic timeout or unknown result makes the verdict INCONCLUSIVE. The
    variant search runs the campaigns of --profile (quick, standard or thorough),
    with seeds derived from --seed, and fails a patch only for a variant that a generated test
    reproduced three times. With --bundle-out, the inputs, the evidence and a manifest are
    written so that `assay replay` can re-check them offline.

    \b
    Example:
      assay verify --base fixtures/reentrancy/single_function \\
        --patch fixtures/reentrancy/single_function/patches/good.diff \\
        --poc fixtures/reentrancy/single_function/poc --profile quick --bundle-out out/good

    Exit codes: 0 VERIFIED_WITHIN_BOUNDS; 1 REJECTED; 2 usage error; 3 INCONCLUSIVE;
    4 infrastructure problem (Docker, runner image, harness, ledger, out of memory);
    5 integrity violation (traversal, symlink, binary file, protected or out-of-scope path,
    or inputs rejected at ingest).
    """
    request = VerifyRequest(base=base, patch=patch, poc=poc)
    if _SEED.fullmatch(seed) is None:
        _fail(ExitCode.USAGE, f"error: --seed must be 0x and 1 to 16 lowercase hex digits: {seed}")
    settings = VerifySettings(
        profile=profile.value, fuzz_seed=seed, fuzz_runs=fuzz_runs, symbolic=symbolic
    )
    if bundle_out is not None:
        try:
            check_bundle_dir(bundle_out, inputs=(base, poc))
        except BundleError as exc:
            _fail(ExitCode.USAGE, f"error: {exc}")
    runner = SandboxRunner()
    halmos = symbolic_runner() if symbolic else None
    try:
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with (
            tempfile.TemporaryDirectory(prefix="assay-verify-", ignore_cleanup_errors=True) as tmp,
            Ledger.open(ledger_path) as ledger,
        ):
            bundle: BundleRequest | None = None
            if bundle_out is not None:

                def record_environment() -> Environment:
                    return environment(
                        runner.image_id(), runner.image_labels(), read_versions_lock()
                    )

                def record_symbolic_environment() -> Environment:
                    assert halmos is not None
                    return environment(
                        halmos.image_id(), halmos.image_labels(), read_versions_lock()
                    )

                bundle = BundleRequest(
                    dest=bundle_out,
                    environment=record_environment,
                    sanitizer=bundle_sanitizer(Path(tmp), request, bundle_out, ledger_path),
                    symbolic_environment=None if halmos is None else record_symbolic_environment,
                )
            outcome = run_verification(
                request,
                runner=runner,
                ledger=ledger,
                work_dir=Path(tmp),
                settings=settings,
                bundle=bundle,
                symbolic_runner=halmos,
            )
    except VerifyInputError as exc:
        code = ExitCode.INTEGRITY if exc.kind == "rejected" else ExitCode.USAGE
        _fail(code, f"error: {exc}")
    except BundleError as exc:
        _fail(ExitCode.USAGE, f"error: {exc}")
    except ForgeOutOfMemory as exc:
        _fail(ExitCode.INFRASTRUCTURE, f"error: {exc}")
    except (
        SandboxError,
        HarnessUnavailable,
        EnvironmentUnavailable,
        LedgerError,
        OSError,
    ) as exc:
        _fail(ExitCode.INFRASTRUCTURE, f"error: {exc}")

    report = outcome.report
    if json_output:
        typer.echo(json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True))
    else:
        typer.echo(render(report))
        typer.echo(f"ledger: verification {outcome.verification_id} recorded")
        if outcome.manifest_sha256 is not None:
            typer.echo(f"bundle: written, manifest sha256 {outcome.manifest_sha256}")
    raise typer.Exit(int(exit_code(report)))
