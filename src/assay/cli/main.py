"""Command-line entry point for Assay."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as distribution_version
from typing import Annotated

import typer

from assay import __version__
from assay.cli import dev
from assay.cli.bench import bench_app
from assay.cli.ci import ci_app
from assay.cli.doctor import doctor_command
from assay.cli.fix import fix_command
from assay.cli.prove import prove_command
from assay.cli.replay import replay_command
from assay.cli.report import report_command
from assay.cli.run import run_command
from assay.cli.scan import scan_command
from assay.cli.verify import verify_command

DISTRIBUTION = "assay-evm"
HELP = """Check whether a Solidity patch closes an exploit, within recorded bounds.

\b
Typical flow:
  assay scan PROJECT                  candidate findings from static analysis
  assay prove PROJECT --class CLASS   reproduce a candidate with a PoC
  assay verify --base DIR --patch FILE --poc DIR --bundle-out OUT
  assay report OUT --out report.html  self-contained HTML report of a bundle
  assay replay OUT                    re-check a bundle offline
  assay ci verify --project DIR --poc-dir DIR --base REF --head REF
                                      verify a pull request without a model or secrets
  assay doctor                        check Docker, the runner image and the disk

Output is plain text without color when it is not a terminal or NO_COLOR is set. scan, verify,
prove, fix, run, replay and doctor print stable JSON with --json. Exit codes are listed in
docs/cli.md: 0 success, 1 negative result, 2 usage error, 3 INCONCLUSIVE, 4 infrastructure
problem, 5 integrity violation."""

app = typer.Typer(
    name="assay",
    help=HELP,
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)
app.add_typer(dev.app, name="dev", hidden=True)
app.add_typer(ci_app, name="ci")
app.add_typer(bench_app, name="bench", hidden=True)


def package_version() -> str:
    """The version from the package metadata, or the source tree's value if not installed."""
    try:
        return distribution_version(DISTRIBUTION)
    except PackageNotFoundError:
        return __version__


def _show_version(value: bool) -> None:
    if value:
        typer.echo(package_version())
        raise typer.Exit()


@app.callback()
def main(
    version_flag: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Print the Assay version and exit.",
            callback=_show_version,
            is_eager=True,
        ),
    ] = False,
) -> None:
    # A callback keeps Typer in multi-command mode, so `assay version` stays a subcommand.
    pass


app.command("verify")(verify_command)
app.command("replay")(replay_command)
app.command("scan")(scan_command)
app.command("prove")(prove_command)
app.command("fix")(fix_command)
app.command("run")(run_command)
app.command("report")(report_command)
app.command("doctor")(doctor_command)


@app.command()
def version() -> None:
    """Print the Assay version (the same as `assay --version`).

    \b
    Example:
      assay version
    """
    typer.echo(package_version())
