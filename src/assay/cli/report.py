"""`assay report`: a self-contained HTML report of an evidence bundle."""

import os
import tempfile
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from assay.cli.exit_codes import ExitCode
from assay.cli.text import printable
from assay.report.bundle import MANIFEST_FILE
from assay.report.html import render_report
from assay.report.replay import ReplayError, load_bundle


def _fail(code: ExitCode, message: str, details: tuple[str, ...] = ()) -> NoReturn:
    typer.echo(printable(message), err=True)
    for line in details:
        typer.echo(printable(f"  {line}"), err=True)
    raise typer.Exit(int(code))


def _write(path: Path, text: str) -> None:
    """Write `text` to `path` through a temporary file in the same directory."""
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def report_command(
    bundle: Annotated[
        Path,
        typer.Argument(help="Evidence bundle written by `assay verify --bundle-out`."),
    ],
    out: Annotated[
        Path,
        typer.Option("--out", help="HTML file to write; an existing file is replaced."),
    ],
) -> None:
    """Write a self-contained HTML report of the evidence bundle BUNDLE.

    Checks the sha256 of every file against manifest.json first; a bundle that does not match is
    refused and no report is written. The report is one file with inline CSS, no JavaScript and
    no external resource, and the same bundle always gives the same bytes. It shows the verdict,
    what the result does and does not mean, the verdict and reasons of every oracle, the PoC, the
    patch, the attempt history of a fix loop, the manifest hash and how to replay the bundle.

    \b
    Example:
      assay verify --base fixtures/reentrancy/single_function \\
        --patch fixtures/reentrancy/single_function/patches/good.diff \\
        --poc fixtures/reentrancy/single_function/poc --bundle-out out/good
      assay report out/good --out out/good.html

    Exit codes: 0 report written; 2 usage error, or a bundle of another format version;
    4 the report cannot be written; 5 the bundle does not match its manifest.
    """
    if not bundle.is_dir():
        _fail(ExitCode.USAGE, f"error: not a bundle directory: {bundle}")
    if out.is_dir():
        _fail(ExitCode.USAGE, f"error: --out names a directory: {out}")
    if not out.parent.is_dir():
        _fail(ExitCode.USAGE, f"error: directory does not exist: {out.parent}")
    resolved = out.resolve()
    if resolved.parent == bundle.resolve() or bundle.resolve() in resolved.parents:
        _fail(ExitCode.USAGE, "error: --out must lie outside the bundle directory")
    try:
        manifest = load_bundle(bundle)
    except ReplayError as exc:
        if exc.kind == "format":
            _fail(ExitCode.USAGE, f"error: {exc}; no report was written")
        _fail(ExitCode.INTEGRITY, f"error: {exc}; no report was written", exc.details)
    try:
        text = render_report(bundle, manifest)
        _write(out, text)
    except OSError as exc:
        _fail(ExitCode.INFRASTRUCTURE, f"error: cannot write the report: {exc}")
    typer.echo(printable(f"report written to {out} ({manifest.final_verdict.value})"))
    typer.echo(f"bundle: {MANIFEST_FILE} checked, {len(manifest.files)} files match")
