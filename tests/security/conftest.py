import subprocess
from pathlib import Path
from typing import Any

import pytest

import assay.sandbox.runner as runner_module


class _RecordingSubprocess:
    """Stand-in for the `subprocess` module of the runner that records each docker call.

    Calls are forwarded to the real module, so the runner still talks to the real Docker.
    """

    def __init__(self, calls: list[str]) -> None:
        self._calls = calls

    def __getattr__(self, name: str) -> Any:
        return getattr(subprocess, name)

    def run(self, args: list[str], **kwargs: Any) -> Any:
        self._calls.append(args[1])
        return subprocess.run(args, **kwargs)

    def Popen(self, args: list[str], **kwargs: Any) -> Any:
        self._calls.append(args[1])
        return subprocess.Popen(args, **kwargs)


@pytest.fixture
def docker_calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Return the list of docker subcommands that the sandbox runner executes during the test."""
    calls: list[str] = []
    monkeypatch.setattr(runner_module, "subprocess", _RecordingSubprocess(calls))
    return calls


# The Python of the runner image, which exists for Slither. The policy tests below run it
# directly: the argv allowlist would refuse it, and that allowlist is the one layer these tests
# remove, so that every observation comes from the container policy itself.
IMAGE_PYTHON = "/opt/assay/python/bin/python3"


def run_policy_probe(
    runner: Any,
    code: str,
    tmp_path: Path,
    *,
    timeout_s: float = 60.0,
) -> Any:
    """Run `code` with the image's Python under the runner's complete container policy.

    The container gets exactly the arguments of `SandboxRunner.docker_run_args` (network, mounts,
    user, capabilities, limits, environment) and is removed like every sandbox run; only the
    argv check of `SandboxRunner.run` is skipped.
    """
    from assay.sandbox import make_scratch_dir
    from assay.sandbox.runner import new_container_name

    project = tmp_path / "project"
    project.mkdir()
    scratch = make_scratch_dir(tmp_path)
    command = (IMAGE_PYTHON, "-I", "-S", "-c", code)
    name = new_container_name()
    image_id = runner.image_id()
    args = runner.docker_run_args(
        command,
        project_dir=project.resolve(),
        scratch_dir=scratch.resolve(),
        name=name,
        image_id=image_id,
    )
    return runner._execute(args, command=command, name=name, image_id=image_id, timeout_s=timeout_s)


@pytest.fixture
def policy_probe() -> Any:
    """`run_policy_probe`, for the tests of the container policy."""
    return run_policy_probe
