"""`assay bench`: run the oracle benchmark, freeze the oracles and write the report."""

from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from assay.analyzers.foundry import ForgeOutOfMemory
from assay.bench.freeze import FROZEN_FILE, FreezeError, read_frozen, tree_hash, write_frozen
from assay.bench.report import RESULTS_JSON, RESULTS_PAGE, ReportError, build_report
from assay.bench.run import RunExists, RunSettings, run_split
from assay.bench.splits import SplitError
from assay.cli.exit_codes import ExitCode
from assay.cli.text import printable
from assay.ingest.config import DEFAULT_FUZZ_SEED
from assay.oracles.runtree import HarnessUnavailable
from assay.report.bundle import EnvironmentUnavailable
from assay.sandbox import SandboxError, SandboxRunner

bench_app = typer.Typer(
    name="bench",
    help="Benchmark of the oracles on the development and held-out fixtures.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)


class SplitChoice(StrEnum):
    DEV = "dev"
    HELDOUT = "heldout"


class ProfileChoice(StrEnum):
    QUICK = "quick"
    STANDARD = "standard"
    THOROUGH = "thorough"


def _fail(code: ExitCode, message: str) -> NoReturn:
    typer.echo(printable(message), err=True)
    raise typer.Exit(int(code))


@bench_app.command("run")
def run_command(
    split: Annotated[
        SplitChoice, typer.Option("--split", help="Split to run: dev or heldout.")
    ] = SplitChoice.DEV,
    profile: Annotated[
        ProfileChoice, typer.Option("--profile", help="Campaign profile of the variant search.")
    ] = ProfileChoice.STANDARD,
    seed: Annotated[str, typer.Option("--seed", help="Base seed (0x and hex digits).")] = (
        DEFAULT_FUZZ_SEED
    ),
    symbolic: Annotated[
        bool, typer.Option("--symbolic", help="Also run the symbolic oracle (needs its image).")
    ] = False,
    resume: Annotated[
        bool, typer.Option("--resume", help="Continue an interrupted run of the same identity.")
    ] = False,
    root: Annotated[
        Path, typer.Option("--root", help="Repository root.", exists=True, file_okay=False)
    ] = Path("."),
) -> None:
    """Run `assay verify` on every patch of a split and store the results in bench/results/.

    The run folder name identifies the split, the profile, the oracles and the fixtures. The
    results of the held-out split are marked held-out only if the oracle hash equals
    bench/FROZEN_HASH (see bench/PROTOCOL.md).

    Exit codes: 0 the run is complete; 2 usage error; 4 infrastructure problem.
    """
    root = root.resolve()
    settings = RunSettings(profile=profile.value, fuzz_seed=seed, symbolic=symbolic, resume=resume)
    try:
        folder, info = run_split(
            root,
            split.value,
            settings,
            runner=SandboxRunner(),
            progress=lambda line: typer.echo(printable(line)),
        )
    except (SplitError, RunExists, FreezeError) as exc:
        _fail(ExitCode.USAGE, f"error: {exc}")
    except (
        ForgeOutOfMemory,
        SandboxError,
        HarnessUnavailable,
        EnvironmentUnavailable,
        OSError,
    ) as exc:
        _fail(ExitCode.INFRASTRUCTURE, f"error: {exc}")
    typer.echo(f"run complete: {info.cases} cases in {folder.relative_to(root).as_posix()}")


@bench_app.command("freeze")
def freeze_command(
    root: Annotated[
        Path, typer.Option("--root", help="Repository root.", exists=True, file_okay=False)
    ] = Path("."),
    force: Annotated[
        bool, typer.Option("--force", help="Replace an existing bench/FROZEN_HASH.")
    ] = False,
) -> None:
    """Record the hash of src/assay/oracles, solidity/ and versions.lock in bench/FROZEN_HASH.

    After the freeze, nothing in those paths may change until the benchmark is finished.
    """
    root = root.resolve()
    try:
        existing = read_frozen(root)
        if existing is not None and not force:
            current = tree_hash(root)
            state = "equals" if current == existing else "DIFFERS from"
            _fail(
                ExitCode.USAGE,
                f"error: {FROZEN_FILE.as_posix()} exists; the current hash {state} it; "
                "use --force to replace it",
            )
        value = write_frozen(root)
    except FreezeError as exc:
        _fail(ExitCode.USAGE, f"error: {exc}")
    typer.echo(f"frozen: {value}")


@bench_app.command("report")
def report_command(
    results: Annotated[list[Path], typer.Argument(help="Result folders, at most one per split.")],
    root: Annotated[
        Path, typer.Option("--root", help="Repository root.", exists=True, file_okay=False)
    ] = Path("."),
) -> None:
    """Write docs/results.md and docs/results.json from stored result folders.

    Held-out results are marked held-out only if the oracle hash recorded in the run equals
    bench/FROZEN_HASH. Mismatches between verdicts and labels are listed under "Findings" with
    the causes recorded in bench/findings.json.
    """
    root = root.resolve()
    try:
        markdown, data, warnings = build_report(
            root, [item if item.is_absolute() else Path.cwd() / item for item in results]
        )
    except ReportError as exc:
        _fail(ExitCode.USAGE, f"error: {exc}")
    for item in warnings:
        typer.echo(printable(f"warning: {item}"), err=True)
    page, data_file = root / RESULTS_PAGE, root / RESULTS_JSON
    page.write_text(markdown, encoding="utf-8")
    data_file.write_text(data, encoding="utf-8")
    typer.echo(f"wrote {RESULTS_PAGE.as_posix()} and {RESULTS_JSON.as_posix()}")
