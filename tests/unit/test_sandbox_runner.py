"""SandboxRunner without Docker.

The run tests use a stand-in `docker` executable (a small Python script) that records every
call and imitates the behavior of the real CLI for the commands the runner uses.
"""

import json
import stat
import subprocess
import sys
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path
from typing import Any

import pytest

from assay.sandbox import (
    CLEANUP_LABEL,
    CONTAINER_ENV,
    ArgvRejected,
    SandboxLimits,
    SandboxRunner,
    SandboxUnavailable,
    make_scratch_dir,
)
from assay.sandbox import runner as runner_module

IMAGE_ID = "sha256:" + "ab" * 32

FAKE_DOCKER = """\
import json, os, signal, sys, time

IMAGE_ID = "sha256:" + "ab" * 32
state = os.environ["DOCKER_CONFIG"]
args = sys.argv[1:]
with open(os.path.join(state, "calls.jsonl"), "a") as log:
    log.write(json.dumps({"args": args, "env": sorted(os.environ)}) + "\\n")

if args[:2] == ["image", "inspect"]:
    print(IMAGE_ID)
elif args[:1] == ["run"]:
    name = args[args.index("--name") + 1]
    with open(os.path.join(state, name + ".pid"), "w") as handle:
        handle.write(str(os.getpid()))
    with open(os.path.join(state, "behavior")) as handle:
        behavior = handle.read().strip()
    if behavior == "sleep":
        time.sleep(120)
    elif behavior == "flood":
        for _ in range(8):
            sys.stdout.buffer.write(b"o" * (1 << 20))
        sys.stderr.buffer.write(b"e" * (3 << 20))
    elif behavior == "oom":
        open(os.path.join(state, name + ".oom"), "w").close()
        sys.exit(137)
    else:
        sys.stdout.write("argv=" + " ".join(args[args.index(IMAGE_ID) + 1:]))
        sys.stderr.write("warning")
        sys.exit(int(behavior))
elif args[:1] == ["kill"]:
    with open(os.path.join(state, args[-1] + ".pid")) as handle:
        os.kill(int(handle.read()), signal.SIGKILL)
elif args[:1] == ["events"]:
    name = next(arg for arg in args if arg.startswith("container=")).split("=", 1)[1]
    if os.path.exists(os.path.join(state, name + ".oom")):
        print("oom")
elif args[:1] in (["ps"], ["rm"]):
    pass
else:
    sys.exit(2)
"""


@dataclass
class FakeDocker:
    path: str
    state: Path

    def behave(self, behavior: str) -> None:
        (self.state / "behavior").write_text(behavior)

    def calls(self) -> list[dict[str, Any]]:
        log = self.state / "calls.jsonl"
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text().splitlines()]

    def commands(self) -> list[str]:
        return [call["args"][0] for call in self.calls()]


@pytest.fixture
def fake_docker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeDocker:
    state = tmp_path / "docker-state"
    state.mkdir()
    script = tmp_path / "bin" / "docker"
    script.parent.mkdir()
    script.write_text(f"#!{sys.executable}\n{FAKE_DOCKER}")
    script.chmod(0o755)
    monkeypatch.setenv("DOCKER_CONFIG", str(state))
    monkeypatch.setenv("ASSAY_LLM_API_KEY", "must-not-reach-docker")
    return FakeDocker(path=str(script), state=state)


@pytest.fixture
def dirs(tmp_path: Path) -> tuple[Path, Path]:
    project = tmp_path / "project"
    project.mkdir()
    return project.resolve(), make_scratch_dir(tmp_path).resolve()


def _pairs(args: list[str]) -> set[tuple[str, str]]:
    return set(pairwise(args))


def test_docker_run_args_apply_the_container_policy(dirs: tuple[Path, Path]) -> None:
    project, scratch = dirs
    args = SandboxRunner(docker="docker").docker_run_args(
        ("forge", "test"),
        project_dir=project,
        scratch_dir=scratch,
        name="assay-0",
        image_id=IMAGE_ID,
    )

    assert args[0] == "run"
    assert args[-3:] == [IMAGE_ID, "forge", "test"]
    options = args[1:-3]
    assert "--rm" in options
    assert "--read-only" in options
    assert {
        ("--pull", "never"),
        ("--name", "assay-0"),
        ("--label", CLEANUP_LABEL),
        ("--network", "none"),
        ("--cap-drop", "ALL"),
        ("--security-opt", "no-new-privileges"),
        ("--pids-limit", "256"),
        ("--memory", "2048m"),
        ("--memory-swap", "2048m"),
        ("--cpus", "2"),
        ("--user", "10001:10001"),
        ("--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m"),
        ("--log-driver", "none"),
        ("--mount", f"type=bind,source={project},target=/work/project,readonly"),
        ("--mount", f"type=bind,source={scratch},target=/work/scratch"),
        ("--workdir", "/work/project"),
    } <= _pairs(options)
    env = [value for flag, value in pairwise(options) if flag == "--env"]
    assert env == [f"{key}={value}" for key, value in CONTAINER_ENV.items()]
    for unwanted in ("--privileged", "--env-file", "--volume", "-v", "--network=host", "sh", "-c"):
        assert unwanted not in args


def test_docker_run_args_follow_the_limits(dirs: tuple[Path, Path]) -> None:
    project, scratch = dirs
    limits = SandboxLimits(memory_mib=512, cpus=0.5, pids=64, tmpfs_mib=8)
    args = SandboxRunner(docker="docker", limits=limits).docker_run_args(
        ("forge", "build"),
        project_dir=project,
        scratch_dir=scratch,
        name="assay-1",
        image_id=IMAGE_ID,
    )
    assert {
        ("--memory", "512m"),
        ("--memory-swap", "512m"),
        ("--cpus", "0.5"),
        ("--pids-limit", "64"),
        ("--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=8m"),
    } <= _pairs(args)


def test_container_environment_is_fixed() -> None:
    assert dict(CONTAINER_ENV) == {
        "FOUNDRY_OFFLINE": "true",
        "FOUNDRY_SOLC": "/opt/assay/bin/solc",
        "HOME": "/tmp",
        "NO_COLOR": "1",
    }


def test_rejected_argv_never_starts_a_process(
    dirs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("no process may start for a rejected argv")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    project, scratch = dirs
    with pytest.raises(ArgvRejected):
        SandboxRunner(docker="docker").run(
            ["sh", "-c", "id"], project_dir=project, scratch_dir=scratch
        )


@pytest.mark.parametrize("bad_name", ["with,comma", 'with"quote', "with\nnewline"])
def test_mount_paths_with_unsupported_characters_are_rejected(
    tmp_path: Path, bad_name: str
) -> None:
    project = tmp_path / bad_name
    project.mkdir()
    scratch = make_scratch_dir(tmp_path)
    with pytest.raises(ValueError, match="unsupported character"):
        SandboxRunner(docker="docker").run(
            ["forge", "build"], project_dir=project, scratch_dir=scratch
        )


def test_missing_mount_directory_is_rejected(tmp_path: Path) -> None:
    scratch = make_scratch_dir(tmp_path)
    with pytest.raises(ValueError, match="does not exist"):
        SandboxRunner(docker="docker").run(
            ["forge", "build"], project_dir=tmp_path / "missing", scratch_dir=scratch
        )


def test_scratch_inside_project_is_rejected(tmp_path: Path) -> None:
    scratch = make_scratch_dir(tmp_path)
    with pytest.raises(ValueError, match="must not contain"):
        SandboxRunner(docker="docker").run(
            ["forge", "build"], project_dir=tmp_path, scratch_dir=scratch
        )


def test_scratch_dir_is_writable_by_the_container_user(tmp_path: Path) -> None:
    scratch = make_scratch_dir(tmp_path)
    assert stat.S_IMODE(scratch.stat().st_mode) == 0o777
    assert list(scratch.iterdir()) == []


def test_missing_docker_cli_is_an_infrastructure_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner_module, "find_docker", lambda: None)
    with pytest.raises(SandboxUnavailable, match="docker CLI not found"):
        SandboxRunner().image_id()


def test_run_returns_the_result_and_removes_the_container(
    fake_docker: FakeDocker, dirs: tuple[Path, Path]
) -> None:
    fake_docker.behave("3")
    project, scratch = dirs
    result = SandboxRunner(docker=fake_docker.path).run(
        ["forge", "test", "--json"], project_dir=project, scratch_dir=scratch
    )

    assert result.argv == ("forge", "test", "--json")
    assert result.exit_code == 3
    assert result.stdout == "argv=forge test --json"
    assert result.stderr == "warning"
    assert not result.truncated
    assert not result.timed_out
    assert not result.oom_killed
    assert result.image_id == IMAGE_ID
    assert result.duration_s >= 0
    assert fake_docker.commands() == ["image", "run", "ps", "events"]
    run_args = fake_docker.calls()[1]["args"]
    name = run_args[run_args.index("--name") + 1]
    assert name.startswith("assay-")
    assert fake_docker.calls()[2]["args"][-1] == f"name=^{name}$"


def test_container_names_are_unique(fake_docker: FakeDocker, dirs: tuple[Path, Path]) -> None:
    fake_docker.behave("0")
    project, scratch = dirs
    runner = SandboxRunner(docker=fake_docker.path)
    for _ in range(3):
        runner.run(["forge", "build"], project_dir=project, scratch_dir=scratch)
    names = [
        call["args"][call["args"].index("--name") + 1]
        for call in fake_docker.calls()
        if call["args"][0] == "run"
    ]
    assert len(set(names)) == 3


def test_host_environment_does_not_reach_docker(
    fake_docker: FakeDocker, dirs: tuple[Path, Path]
) -> None:
    fake_docker.behave("0")
    project, scratch = dirs
    SandboxRunner(docker=fake_docker.path).run(
        ["forge", "build"], project_dir=project, scratch_dir=scratch
    )
    for call in fake_docker.calls():
        assert "ASSAY_LLM_API_KEY" not in call["env"]
        assert "DOCKER_CONFIG" in call["env"]
    assert all("--env-file" not in call["args"] for call in fake_docker.calls())


def test_timeout_kills_the_container(fake_docker: FakeDocker, dirs: tuple[Path, Path]) -> None:
    fake_docker.behave("sleep")
    project, scratch = dirs
    runner = SandboxRunner(docker=fake_docker.path, limits=SandboxLimits(timeout_s=1.0))
    result = runner.run(["forge", "test"], project_dir=project, scratch_dir=scratch)

    assert result.timed_out
    assert result.exit_code != 0
    assert 1.0 <= result.duration_s < 30
    assert "kill" in fake_docker.commands()
    kill = next(call["args"] for call in fake_docker.calls() if call["args"][0] == "kill")
    assert kill[1:3] == ["--signal", "KILL"]
    assert kill[-1].startswith("assay-")


def test_output_is_cut_at_the_limit(fake_docker: FakeDocker, dirs: tuple[Path, Path]) -> None:
    fake_docker.behave("flood")
    project, scratch = dirs
    limit = 1 << 20
    runner = SandboxRunner(docker=fake_docker.path, limits=SandboxLimits(output_limit_bytes=limit))
    result = runner.run(["forge", "test"], project_dir=project, scratch_dir=scratch)

    assert result.truncated
    assert result.stdout == "o" * limit
    assert result.stderr == "e" * limit
    assert result.exit_code == 0


def test_out_of_memory_kill_is_reported(fake_docker: FakeDocker, dirs: tuple[Path, Path]) -> None:
    fake_docker.behave("oom")
    project, scratch = dirs
    result = SandboxRunner(docker=fake_docker.path).run(
        ["forge", "test"], project_dir=project, scratch_dir=scratch
    )
    assert result.oom_killed
    assert result.exit_code == 137
    assert not result.timed_out


def test_rejected_argv_makes_no_docker_call(
    fake_docker: FakeDocker, dirs: tuple[Path, Path]
) -> None:
    fake_docker.behave("0")
    project, scratch = dirs
    with pytest.raises(ArgvRejected):
        SandboxRunner(docker=fake_docker.path).run(
            ["forge", "script", "Deploy"], project_dir=project, scratch_dir=scratch
        )
    assert fake_docker.calls() == []


def test_image_lookup_failure_is_an_infrastructure_error(tmp_path: Path) -> None:
    script = tmp_path / "docker"
    script.write_text(
        f"#!{sys.executable}\nimport sys\nsys.stderr.write('No such image')\nsys.exit(1)\n"
    )
    script.chmod(0o755)
    with pytest.raises(SandboxUnavailable, match="make image"):
        SandboxRunner(docker=str(script)).image_id()


def docker_printing(tmp_path: Path, stdout: str, exit_code: int = 0) -> str:
    script = tmp_path / "docker"
    script.write_text(
        f"#!{sys.executable}\nimport sys\nsys.stdout.write({stdout!r})\nsys.exit({exit_code})\n"
    )
    script.chmod(0o755)
    return str(script)


def test_image_labels_are_read_from_the_image(tmp_path: Path) -> None:
    labels = {"assay.solc.version": "0.8.36", "assay.foundry.version": "v1.8.4"}
    runner = SandboxRunner(docker=docker_printing(tmp_path, json.dumps(labels) + "\n"))
    assert runner.image_labels() == dict(sorted(labels.items()))
    assert SandboxRunner(docker=docker_printing(tmp_path, "null\n")).image_labels() == {}


@pytest.mark.parametrize(
    ("stdout", "exit_code"),
    [("", 1), ("[1, 2]", 0), ('{"a": 1}', 0), ("not json", 0)],
)
def test_unusable_image_labels_are_an_infrastructure_error(
    tmp_path: Path, stdout: str, exit_code: int
) -> None:
    with pytest.raises(SandboxUnavailable):
        SandboxRunner(docker=docker_printing(tmp_path, stdout, exit_code)).image_labels()
