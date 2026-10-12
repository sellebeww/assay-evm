"""CLI polish: `--version`, `--help` snapshots with examples, colors, exit codes, JSON schemas."""

import os
import re
import sys
from importlib.metadata import version as distribution_version
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay import __version__
from assay.cli.documents import SCHEMAS
from assay.cli.exit_codes import ExitCode
from assay.cli.main import app

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOTS = Path(__file__).parent / "snapshots"
sys.path.insert(0, str(ROOT / "tools"))
import export_schemas  # noqa: E402

PUBLIC = ("verify", "replay", "scan", "prove", "fix", "run", "report", "doctor", "version")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
cli = CliRunner(env={"COLUMNS": "100", "LINES": "50", "TERM": "dumb"})


def help_text(*command: str, env: dict[str, str] | None = None) -> str:
    result = CliRunner(env={"COLUMNS": "100", "TERM": "dumb", **(env or {})}).invoke(
        app, [*command, "--help"]
    )
    assert result.exit_code == 0, result.output
    return result.output


def check_snapshot(name: str, text: str) -> None:
    path = SNAPSHOTS / name
    if os.environ.get("ASSAY_UPDATE_GOLDEN") == "1":
        path.write_text(text, encoding="utf-8")
    assert text == path.read_text(encoding="utf-8"), (
        f"{name} differs; if the change is intended, run with ASSAY_UPDATE_GOLDEN=1"
    )


# -- version ------------------------------------------------------------------------------------


def test_version_flag_prints_the_package_metadata_version() -> None:
    result = cli.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == distribution_version("assay-evm") == __version__


def test_version_flag_works_without_a_command_and_the_command_agrees() -> None:
    assert cli.invoke(app, ["version"]).stdout == cli.invoke(app, ["--version"]).stdout


# -- help ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("command", PUBLIC)
def test_every_public_command_has_a_help_with_an_example(command: str) -> None:
    text = help_text(command)
    assert "Example" in text, command
    assert f"assay {command}" in text, command
    assert "Exit codes" in text or command == "version", command


def test_the_top_level_help_lists_every_public_command_and_hides_dev() -> None:
    text = help_text()
    for command in PUBLIC:
        assert re.search(rf"^\s*│?\s*{command}\b", text, re.MULTILINE), command
    assert not re.search(r"^\s*│?\s*dev\b", text, re.MULTILINE)
    assert "--version" in text


@pytest.mark.parametrize("command", PUBLIC)
def test_help_snapshots(command: str) -> None:
    check_snapshot(f"help_{command}.txt", help_text(command))


def test_top_level_help_snapshot() -> None:
    check_snapshot("help.txt", help_text())


@pytest.mark.parametrize("command", ["scan", "verify", "prove", "fix", "run", "replay", "doctor"])
def test_json_commands_document_the_json_option(command: str) -> None:
    assert "--json" in help_text(command)


# -- color --------------------------------------------------------------------------------------


@pytest.mark.parametrize("command", [(), *[(name,) for name in PUBLIC]])
def test_help_has_no_color_when_it_is_not_a_terminal(command: tuple[str, ...]) -> None:
    assert ANSI.search(help_text(*command)) is None


@pytest.mark.parametrize("command", [(), ("verify",), ("doctor",)])
def test_help_has_no_color_with_no_color_even_if_color_is_forced(command: tuple[str, ...]) -> None:
    text = help_text(*command, env={"NO_COLOR": "1", "FORCE_COLOR": "1"})
    colors = [code for code in ANSI.findall(text) if re.search(r"\[(3[0-7]|9[0-7]|38;)", code)]
    assert colors == []


# -- exit codes ---------------------------------------------------------------------------------


def test_the_exit_codes_are_the_documented_ones() -> None:
    assert {item.name: int(item) for item in ExitCode} == {
        "SUCCESS": 0,
        "NEGATIVE": 1,
        "USAGE": 2,
        "INCONCLUSIVE": 3,
        "INFRASTRUCTURE": 4,
        "INTEGRITY": 5,
    }


def test_docs_cli_lists_every_exit_code_and_every_command() -> None:
    text = (ROOT / "docs" / "cli.md").read_text(encoding="utf-8")
    for item in ExitCode:
        assert re.search(rf"^\| {int(item)} \|", text, re.MULTILINE), item
    for command in PUBLIC:
        assert f"`assay {command}" in text, command
    for command in SCHEMAS:
        assert f"docs/schemas/{command}.schema.json" in text, command


def test_a_missing_argument_is_a_usage_error() -> None:
    assert cli.invoke(app, ["replay"]).exit_code == int(ExitCode.USAGE)
    assert cli.invoke(app, ["no-such-command"]).exit_code == int(ExitCode.USAGE)


# -- schemas ------------------------------------------------------------------------------------


def test_the_checked_in_schemas_are_what_the_models_give() -> None:
    assert export_schemas.main(["--check"]) == 0


def test_every_json_command_has_a_schema_file() -> None:
    names = {path.name for path in (ROOT / "docs" / "schemas").glob("*.json")}
    assert names == {f"{command}.schema.json" for command in SCHEMAS}
    assert set(SCHEMAS) == {"scan", "verify", "prove", "fix", "run", "replay", "doctor"}


def test_the_schemas_hold_no_host_path_or_time() -> None:
    for path in (ROOT / "docs" / "schemas").glob("*.json"):
        text = path.read_text(encoding="utf-8")
        assert str(ROOT) not in text
        assert os.path.expanduser("~") not in text
