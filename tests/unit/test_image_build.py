"""`assay image build`: the docker commands that it runs, without running Docker."""

from pathlib import Path

from typer.testing import CliRunner

from assay.cli.image import build_args, build_context, docker_commands
from assay.cli.main import app

LOCK = "# comment\nSOLC_VERSION=0.8.36\nNOT A LINE\nFOUNDRY_VERSION=v1.0.0\n"


def test_every_key_value_line_of_the_lock_becomes_a_build_argument() -> None:
    assert build_args(LOCK) == [
        "--build-arg",
        "SOLC_VERSION=0.8.36",
        "--build-arg",
        "FOUNDRY_VERSION=v1.0.0",
    ]


def test_the_runner_image_comes_first_and_the_symbolic_one_is_amd64() -> None:
    first, second = docker_commands(Path("/ctx"), LOCK, symbolic=True)
    assert first[:2] == ["docker", "build"]
    assert first[first.index("--target") + 1] == "runner"
    assert first[first.index("--tag") + 1] == "assay-runner:dev"
    assert second[second.index("--platform") + 1] == "linux/amd64"
    assert second[second.index("--target") + 1] == "runner-symbolic"
    assert first[-1] == "/ctx"


def test_without_symbolic_only_one_build_runs() -> None:
    assert len(docker_commands(Path("/ctx"), LOCK, symbolic=False, platform="linux/arm64")) == 1


def test_the_build_context_has_the_dockerfile() -> None:
    assert (build_context() / "Dockerfile").is_file()


def test_dry_run_prints_the_commands_and_runs_nothing() -> None:
    result = CliRunner().invoke(app, ["image", "build", "--dry-run", "--no-symbolic"])
    assert result.exit_code == 0, result.output
    assert result.output.startswith("docker build ")
    assert "--tag assay-runner:dev" in result.output
