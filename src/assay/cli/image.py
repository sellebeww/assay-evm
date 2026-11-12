"""`assay image build`: build the runner images from the pinned Dockerfile.

A source checkout builds them with `make image`; an installed package has no Makefile, so this
command does the same from the build context that the package carries (`docker/runner` in a
checkout, `assay/_data/runner` in a wheel). Every `KEY=VALUE` line of `versions.lock` becomes a
build argument, as in the Makefile. The command runs `docker build` and nothing else.
"""

import re
import shutil
import subprocess
from pathlib import Path
from typing import Annotated, Final

import typer

from assay.cli.exit_codes import ExitCode
from assay.report.bundle import default_versions_lock
from assay.sandbox.runner import DEFAULT_IMAGE, DEFAULT_SYMBOLIC_IMAGE

SYMBOLIC_PLATFORM: Final = "linux/amd64"
_LOCK_LINE: Final = re.compile(r"^([A-Z0-9_]+)=(.*)$")

image_app = typer.Typer(
    name="image",
    help="Build the runner images that the oracles run in.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)


def build_context() -> Path:
    """The directory with the Dockerfile: the checkout's `docker/runner` or the packaged copy."""
    packaged = Path(__file__).resolve().parents[1] / "_data" / "runner"
    if (packaged / "Dockerfile").is_file():
        return packaged
    return default_versions_lock().parent


def build_args(lock_text: str) -> list[str]:
    """The `--build-arg KEY=VALUE` words for every pinned line of versions.lock."""
    words: list[str] = []
    for line in lock_text.splitlines():
        match = _LOCK_LINE.match(line)
        if match:
            words += ["--build-arg", f"{match.group(1)}={match.group(2)}"]
    return words


def docker_commands(
    context: Path, lock_text: str, *, symbolic: bool, platform: str | None = None
) -> list[list[str]]:
    """The `docker build` argument lists to run, runner image first."""
    args = build_args(lock_text)
    dockerfile = str(context / "Dockerfile")
    platform_flags = ["--platform", platform] if platform else []
    commands = [
        [
            "docker",
            "build",
            *platform_flags,
            *["--target", "runner", *args, "--tag", DEFAULT_IMAGE],
            *["--file", dockerfile, str(context)],
        ]
    ]
    if symbolic:
        commands.append(
            [
                "docker",
                "build",
                *["--platform", SYMBOLIC_PLATFORM, "--target", "runner-symbolic", *args],
                *["--tag", DEFAULT_SYMBOLIC_IMAGE, "--file", dockerfile, str(context)],
            ]
        )
    return commands


@image_app.command("build")
def build_command(
    symbolic: Annotated[
        bool,
        typer.Option(
            "--symbolic/--no-symbolic",
            help="Also build the symbolic image (linux/amd64) that `--symbolic` needs.",
        ),
    ] = True,
    platform: Annotated[
        str | None,
        typer.Option("--platform", help="Platform of the runner image, for example linux/amd64."),
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Print the docker commands without running them.")
    ] = False,
) -> None:
    """Build the runner image (and the symbolic one) from the pinned Dockerfile.

    Needs Docker and network access, once. The images are built locally and never downloaded
    from a registry. The pinned tool versions come from versions.lock. The same result as
    `make image` in a source checkout.

    \b
    Example:
      assay image build --no-symbolic

    Exit codes: 0 built; 2 usage error; 4 Docker missing or the build failed.
    """
    context = build_context()
    if not (context / "Dockerfile").is_file():
        typer.echo("error: the Dockerfile of the runner image was not found", err=True)
        raise typer.Exit(int(ExitCode.INFRASTRUCTURE))
    commands = docker_commands(
        context,
        default_versions_lock().read_text(encoding="utf-8"),
        symbolic=symbolic,
        platform=platform,
    )
    if dry_run:
        for command in commands:
            typer.echo(" ".join(command))
        raise typer.Exit(0)
    if shutil.which("docker") is None:
        typer.echo("error: the docker command was not found; install Docker first", err=True)
        raise typer.Exit(int(ExitCode.INFRASTRUCTURE))
    for command in commands:
        typer.echo(f"building {command[command.index('--tag') + 1]} ...")
        if subprocess.run(command, check=False).returncode != 0:
            typer.echo("error: docker build failed (see its output above)", err=True)
            raise typer.Exit(int(ExitCode.INFRASTRUCTURE))
    typer.echo("done: run `assay doctor` to check the result")
