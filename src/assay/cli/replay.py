"""`assay replay`: re-check an evidence bundle offline and compare its verdicts."""

import json
import tempfile
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from assay.analyzers.foundry import ForgeOutOfMemory
from assay.cli.documents import ReplayDocument
from assay.cli.exit_codes import ExitCode
from assay.cli.text import printable
from assay.ledger import LedgerError
from assay.oracles.runtree import HarnessUnavailable
from assay.oracles.symbolic import symbolic_runner
from assay.orchestrator.verify import VerifyInputError
from assay.report.bundle import EnvironmentUnavailable, read_versions_lock
from assay.report.replay import (
    ReplayError,
    load_bundle,
    replay_bundle,
    select_runner,
    select_symbolic_runner,
)
from assay.sandbox import SandboxError, SandboxRunner


def _fail(code: ExitCode, message: str, details: tuple[str, ...] = ()) -> NoReturn:
    typer.echo(printable(message), err=True)
    for line in details:
        typer.echo(printable(f"  {line}"), err=True)
    raise typer.Exit(int(code))


def _versions_lock() -> str | None:
    try:
        return read_versions_lock()
    except EnvironmentUnavailable:
        return None


def _runner(image: str) -> SandboxRunner:
    return SandboxRunner(image=image)


def _symbolic_runner(image: str) -> SandboxRunner:
    return symbolic_runner(image=image)


def replay_command(
    bundle: Annotated[
        Path,
        typer.Argument(help="Evidence bundle written by `assay verify --bundle-out`.", exists=True),
    ],
    json_output: Annotated[
        bool, typer.Option("--json", help="Print the comparison as JSON.")
    ] = False,
) -> None:
    """Re-check the evidence bundle BUNDLE offline and compare its verdicts.

    Checks the sha256 of every file against manifest.json (nothing runs when one differs),
    checks the runner image, runs every oracle again in the sandbox without network, and
    compares the verdicts with the manifest. Prints REPLAY MATCH when they are equal.

    \b
    Example:
      assay replay out/good
      assay replay out/good --json

    Exit codes: 0 REPLAY MATCH; 1 the verdicts differ; 2 usage error, or a bundle of another
    format version; 4 infrastructure problem (Docker or the runner image missing: run make
    image); 5 the bundle does not match its manifest.
    """
    try:
        manifest = load_bundle(bundle)
    except ReplayError as exc:
        if exc.kind == "format":
            _fail(ExitCode.USAGE, f"error: {exc}; nothing was run")
        _fail(ExitCode.INTEGRITY, f"error: {exc}; nothing was run", exc.details)
    try:
        runner, notes = select_runner(manifest, make_runner=_runner, versions_lock=_versions_lock())
        symbolic, symbolic_notes = select_symbolic_runner(
            manifest, make_runner=_symbolic_runner, versions_lock=_versions_lock()
        )
    except ReplayError as exc:
        if exc.kind == "tampered":
            _fail(ExitCode.INTEGRITY, f"error: {exc}; nothing was run")
        _fail(ExitCode.INFRASTRUCTURE, f"error: {exc}")
    try:
        with tempfile.TemporaryDirectory(prefix="assay-replay-", ignore_cleanup_errors=True) as tmp:
            outcome = replay_bundle(
                bundle,
                manifest,
                runner=runner,
                work_dir=Path(tmp),
                notes=(*notes, *symbolic_notes),
                symbolic_runner=symbolic,
            )
    except VerifyInputError as exc:
        _fail(ExitCode.INTEGRITY, f"error: the inputs of the bundle cannot be verified: {exc}")
    except ForgeOutOfMemory as exc:
        _fail(ExitCode.INFRASTRUCTURE, f"error: {exc}")
    except (SandboxError, HarnessUnavailable, LedgerError, OSError) as exc:
        _fail(ExitCode.INFRASTRUCTURE, f"error: {exc}")

    if json_output:
        document = ReplayDocument(
            match=outcome.matches,
            differences=outcome.differences,
            notes=outcome.notes,
            bundle_final_verdict=manifest.final_verdict.value,
            replay_final_verdict=outcome.report.final_verdict.value,
        )
        typer.echo(json.dumps(document.model_dump(mode="json"), indent=2, sort_keys=True))
    else:
        lines = list(outcome.notes)
        if outcome.matches:
            lines += [
                "REPLAY MATCH",
                f"final verdict: {manifest.final_verdict.value} (recorded and replayed)",
                f"bounds: {manifest.bounds_statement}",
                f"time: replay {outcome.report.timing.total_s} s, recorded run "
                f"{manifest.timing.total_s} s (durations differ between runs)",
            ]
        else:
            lines += ["REPLAY MISMATCH: the replay differs from the bundle"]
            lines += [f"  {line}" for line in outcome.differences]
        typer.echo(printable("\n".join(lines)))
    raise typer.Exit(int(ExitCode.SUCCESS if outcome.matches else ExitCode.NEGATIVE))
