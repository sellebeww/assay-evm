"""`assay doctor`: check Docker, the runner image, disk space and the model variables."""

import json
import os
import sys
from typing import Annotated, Final

import typer

from assay.cli.console import color_enabled
from assay.cli.exit_codes import ExitCode
from assay.cli.text import printable
from assay.doctor import Check, DoctorReport, real_probes, run_doctor

_LABEL: Final = {"ok": "ok", "problem": "PROBLEM", "info": "info", "skipped": "skipped"}
_COLOR: Final = {"ok": "green", "problem": "red", "info": "cyan", "skipped": "yellow"}


def render(report: DoctorReport, *, color: bool = False) -> str:
    """The checks as plain text: one line per check, a `fix:` line under each problem."""
    width = max(len(item.title) for item in report.checks)

    def label(item: Check) -> str:
        text = _LABEL[item.status].ljust(len("PROBLEM"))
        return typer.style(text, fg=_COLOR[item.status]) if color else text

    lines: list[str] = []
    for item in report.checks:
        lines.append(
            f"{label(item)}  {printable(item.title.ljust(width))}  {printable(item.detail)}"
        )
        if item.fix is not None and item.status in ("problem", "info"):
            lines.append(f"{' ' * len('PROBLEM')}  {' ' * width}  fix: {printable(item.fix)}")
    problems = sum(1 for item in report.checks if item.status == "problem")
    lines.append("")
    lines.append(
        "all checks passed"
        if report.ok
        else f"{problems} problem(s) found; exit code {int(ExitCode.INFRASTRUCTURE)}"
    )
    return "\n".join(lines)


def doctor_command(
    json_output: Annotated[
        bool, typer.Option("--json", help="Print the report as JSON instead of text.")
    ] = False,
) -> None:
    """Check that this machine can run Assay.

    Checks that the docker command exists and the daemon answers, that the runner image (and the
    optional symbolic image) exists and declares the tool versions pinned in versions.lock, the
    platform of the image and whether it runs natively or under emulation, free disk space, and
    whether the model variables ASSAY_LLM_* are set. Variables show only as SET or NOT SET,
    never their values. Every problem comes with a one-line fix. Nothing is built or changed.

    \b
    Example:
      assay doctor
      assay doctor --json

    Exit codes: 0 every check passed; 4 infrastructure problem (Docker, image, disk space).
    """
    report = run_doctor(real_probes(os.environ))
    if json_output:
        typer.echo(json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True))
    else:
        typer.echo(render(report, color=color_enabled(sys.stdout)))
    raise typer.Exit(int(ExitCode.SUCCESS if report.ok else ExitCode.INFRASTRUCTURE))
