from importlib.metadata import version as distribution_version
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay import __version__
from assay.cli.dev import _printable
from assay.cli.main import app
from assay.sandbox import runner as runner_module

runner = CliRunner()


def test_version_prints_package_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == __version__


def test_package_version_matches_distribution_metadata() -> None:
    assert distribution_version("assay-evm") == __version__


def test_help_lists_version_command() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "version" in result.stdout


def test_dev_commands_are_hidden_from_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "dev" not in result.stdout
    dev_help = runner.invoke(app, ["dev", "--help"])
    assert dev_help.exit_code == 0
    assert "forge-test" in dev_help.stdout


@pytest.fixture
def no_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner_module, "find_docker", lambda: None)


def make_project(root: Path) -> Path:
    (root / "src").mkdir(parents=True)
    (root / "src" / "Counter.sol").write_text("contract Counter {}\n")
    return root


def test_forge_test_requires_an_existing_directory(tmp_path: Path) -> None:
    result = runner.invoke(app, ["dev", "forge-test", str(tmp_path / "missing")])
    assert result.exit_code == 2


@pytest.mark.usefixtures("no_docker")
def test_forge_test_rejects_an_unsafe_project_before_docker(tmp_path: Path) -> None:
    project = make_project(tmp_path / "project")
    (project / "src" / "Link.sol").symlink_to("/etc/hosts")
    result = runner.invoke(app, ["dev", "forge-test", str(project)])
    assert result.exit_code == 5
    assert "symlink_outside_tree" in result.stderr
    assert result.stdout == ""


@pytest.mark.usefixtures("no_docker")
def test_forge_test_without_docker_is_an_infrastructure_error(tmp_path: Path) -> None:
    project = make_project(tmp_path / "project")
    result = runner.invoke(app, ["dev", "forge-test", str(project)])
    assert result.exit_code == 4
    assert "docker CLI not found" in result.stderr


def test_untrusted_text_is_escaped_before_printing() -> None:
    assert _printable("ok\tline\nnext") == "ok\tline\nnext"
    assert _printable("a\x1b[31mb") == "a\\u001b[31mb"
    assert _printable("x‮y​z") == "x\\u202ey\\u200bz"
