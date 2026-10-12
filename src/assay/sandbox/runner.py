"""Run one allowlisted command inside the runner image.

`SandboxRunner` is the only component that starts untrusted code. It calls `docker run` with an
argument vector, never through a shell, and applies the container policy described in
docs/sandbox.md on every run.
"""

import os
import re
import secrets
import shutil
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import IO, Annotated, Final

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, TypeAdapter, ValidationError

from assay.sandbox.allowlist import check_argv
from assay.sandbox.layout import CONTAINER_USER, PROJECT_MOUNT, SCRATCH_MOUNT, SOLC_PATH

DEFAULT_IMAGE: Final = "assay-runner:dev"
DEFAULT_SYMBOLIC_IMAGE: Final = "assay-runner-symbolic:dev"
"""The runner plus Halmos, built for linux/amd64 only (ADR 0018)."""
CONTAINER_PREFIX: Final = "assay-"
CLEANUP_LABEL: Final = "assay.role=sandbox"
MAX_TIMEOUT_S: Final = 86_400

# The complete environment set for the container. Docker passes nothing from the host unless it
# is named here; the image sets the same values, and these take precedence over it.
CONTAINER_ENV: Final[Mapping[str, str]] = {
    "FOUNDRY_OFFLINE": "true",
    "FOUNDRY_SOLC": SOLC_PATH,
    "HOME": "/tmp",
    "NO_COLOR": "1",
}

# Host variables the docker CLI itself may need (context, socket, TLS). Nothing else from the
# host environment reaches the docker process.
_HOST_ENV_PASSTHROUGH: Final = (
    "HOME",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY",
)
_DOCKER_DESKTOP_CLI: Final = Path("/Applications/Docker.app/Contents/Resources/bin/docker")

_IMAGE_ID: Final = re.compile(r"sha256:[0-9a-f]{64}")
_PLATFORM: Final = re.compile(r"[a-z]{3,10}/[a-z0-9]{3,10}")
_Label = Annotated[str, StringConstraints(max_length=1024)]
_LABELS: Final[TypeAdapter[dict[str, str] | None]] = TypeAdapter(
    Annotated[dict[_Label, _Label], Field(max_length=256)] | None
)
_READ_CHUNK: Final = 64 * 1024
_CONTROL_TIMEOUT_S: Final = 30.0
_KILL_GRACE_S: Final = 10.0
_REMOVAL_TIMEOUT_S: Final = 15.0
_READER_JOIN_S: Final = 10.0
# Margin for clock differences between the host and the Docker daemon when querying events.
_EVENTS_MARGIN_S: Final = 5.0


class SandboxError(Exception):
    """The sandbox could not complete a run."""


class SandboxUnavailable(SandboxError):
    """Docker or the runner image cannot be used."""


class SandboxLimits(BaseModel):
    """Resource limits applied to every container."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    timeout_s: float = Field(default=600.0, gt=0, le=MAX_TIMEOUT_S)
    memory_mib: int = Field(default=2048, ge=64)
    cpus: float = Field(default=2.0, gt=0, le=64)
    pids: int = Field(default=256, ge=16)
    tmpfs_mib: int = Field(default=64, ge=1)
    output_limit_bytes: int = Field(default=16 * 1024 * 1024, ge=1024)


class SandboxResult(BaseModel):
    """Outcome of one sandboxed command.

    `stdout` and `stderr` are decoded as UTF-8 (invalid bytes replaced) and cut at
    `SandboxLimits.output_limit_bytes` each; `truncated` is set when either stream was cut.
    `exit_code` is the exit status of `docker run`, or a negative signal number if the docker
    client itself had to be killed.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    argv: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    truncated: bool
    timed_out: bool
    oom_killed: bool
    duration_s: float
    image_id: str


def find_docker() -> str | None:
    """Return the docker CLI from PATH, or from the Docker Desktop default location."""
    found = shutil.which("docker")
    if found is not None:
        return found
    if _DOCKER_DESKTOP_CLI.is_file() and os.access(_DOCKER_DESKTOP_CLI, os.X_OK):
        return str(_DOCKER_DESKTOP_CLI)
    return None


def new_container_name() -> str:
    """Return a unique container name with the `assay-` prefix."""
    return f"{CONTAINER_PREFIX}{secrets.token_hex(8)}"


def make_scratch_dir(parent: Path) -> Path:
    """Create an empty scratch directory under `parent` that the container user can write.

    The directory is world-writable because the container runs as uid 10001; keep `parent`
    private (for example a fresh temporary directory).
    """
    scratch = parent / "scratch"
    scratch.mkdir()
    scratch.chmod(0o777)
    return scratch


def _mount_source(path: Path, what: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{what} directory does not exist: {path}") from exc
    if not resolved.is_dir():
        raise ValueError(f"{what} is not a directory: {path}")
    text = str(resolved)
    # `--mount` values are comma-separated and may be quoted; refuse paths that could change
    # their meaning.
    if any(ch in ',"' or not ch.isprintable() for ch in text):
        raise ValueError(f"{what} path contains an unsupported character: {text!r}")
    return resolved


def _host_env(docker: str) -> dict[str, str]:
    env = {key: os.environ[key] for key in _HOST_ENV_PASSTHROUGH if key in os.environ}
    search = [str(Path(docker).parent), "/usr/local/bin", "/usr/bin", "/bin"]
    env["PATH"] = os.pathsep.join(dict.fromkeys(search))
    return env


class _CappedReader(threading.Thread):
    """Drain a stream completely, keeping at most `limit` bytes."""

    def __init__(self, stream: IO[bytes], limit: int) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self._limit = limit
        self._chunks: list[bytes] = []
        self._kept = 0
        self.truncated = False

    def run(self) -> None:
        fd = self._stream.fileno()
        while True:
            try:
                chunk = os.read(fd, _READ_CHUNK)
            except OSError:
                # The pipe was closed after the run ended; what was read so far is kept.
                return
            if not chunk:
                return
            room = self._limit - self._kept
            if len(chunk) > room:
                self.truncated = True
                chunk = chunk[:room]
            if chunk:
                self._chunks.append(chunk)
                self._kept += len(chunk)

    def text(self) -> str:
        return b"".join(self._chunks).decode("utf-8", errors="replace")


class SandboxRunner:
    """Run exactly one allowlisted command in a locked-down container.

    Every run uses a fresh container (`--rm`) with no network, a read-only root filesystem, no
    capabilities, no privilege gain, a non-root user, pids, memory and CPU limits, a small
    tmpfs for `/tmp`, the project mounted read-only and one scratch directory mounted writable.
    """

    def __init__(
        self,
        *,
        image: str = DEFAULT_IMAGE,
        limits: SandboxLimits | None = None,
        docker: str | None = None,
    ) -> None:
        self.image = image
        self.limits = limits if limits is not None else SandboxLimits()
        self._docker = docker

    # -- public API --------------------------------------------------------------------------

    def run(
        self,
        argv: Sequence[str],
        *,
        project_dir: Path,
        scratch_dir: Path,
        timeout_s: float | None = None,
    ) -> SandboxResult:
        """Run `argv` with `project_dir` read-only at /work/project and `scratch_dir` writable.

        The argv is checked against the allowlist before Docker is called. A wall-clock timeout
        (`timeout_s`, or `limits.timeout_s` when it is not given) kills the container; the
        container is removed before this method returns.
        """
        if timeout_s is not None and not 0 < timeout_s <= MAX_TIMEOUT_S:
            raise ValueError(f"timeout_s must be in (0, {MAX_TIMEOUT_S}]")
        command = check_argv(argv)
        project = _mount_source(project_dir, "project")
        scratch = _mount_source(scratch_dir, "scratch")
        if project == scratch or project in scratch.parents or scratch in project.parents:
            raise ValueError("project and scratch directories must not contain each other")
        image_id = self.image_id()
        name = new_container_name()
        run_args = self.docker_run_args(
            command, project_dir=project, scratch_dir=scratch, name=name, image_id=image_id
        )
        return self._execute(
            run_args,
            command=command,
            name=name,
            image_id=image_id,
            timeout_s=self.limits.timeout_s if timeout_s is None else timeout_s,
        )

    def image_id(self) -> str:
        """Return the content-addressed id of the runner image."""
        proc = self._control(["image", "inspect", "--format", "{{.Id}}", self.image])
        if proc.returncode != 0:
            detail = proc.stderr.strip().splitlines()[-1:] or ["no detail"]
            raise SandboxUnavailable(
                f"runner image {self.image} is not available (build it with `make image`): "
                f"{detail[0]}"
            )
        ident = proc.stdout.strip()
        if _IMAGE_ID.fullmatch(ident) is None:
            raise SandboxUnavailable(f"unexpected image id for {self.image}: {ident!r}")
        return ident

    def image_labels(self) -> dict[str, str]:
        """Return the labels of the runner image (for example the pinned tool versions)."""
        proc = self._control(
            ["image", "inspect", "--format", "{{json .Config.Labels}}", self.image]
        )
        if proc.returncode != 0:
            raise SandboxUnavailable(
                f"runner image {self.image} is not available (build it with `make image`)"
            )
        try:
            labels = _LABELS.validate_json(proc.stdout.strip() or "null")
        except ValidationError as exc:
            raise SandboxUnavailable(f"unexpected labels for {self.image}") from exc
        return dict(sorted((labels or {}).items()))

    def daemon_platform(self) -> str:
        """Return `os/arch` of the Docker daemon, for example `linux/arm64`.

        Raises `SandboxUnavailable` when the daemon does not answer.
        """
        proc = self._control(["version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"])
        platform = proc.stdout.strip()
        if proc.returncode != 0 or _PLATFORM.fullmatch(platform) is None:
            detail = proc.stderr.strip().splitlines()[-1:] or ["no detail"]
            raise SandboxUnavailable(f"docker daemon is not reachable: {detail[0]}")
        return platform

    def image_platform(self) -> str:
        """Return `os/arch` the runner image was built for, for example `linux/amd64`."""
        proc = self._control(
            ["image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", self.image]
        )
        platform = proc.stdout.strip()
        if proc.returncode != 0 or _PLATFORM.fullmatch(platform) is None:
            raise SandboxUnavailable(
                f"runner image {self.image} is not available (build it with `make image`)"
            )
        return platform

    def docker_run_args(
        self,
        command: Sequence[str],
        *,
        project_dir: Path,
        scratch_dir: Path,
        name: str,
        image_id: str,
    ) -> list[str]:
        """Return the arguments of `docker run` (without the docker executable)."""
        limits = self.limits
        options: list[tuple[str, ...]] = [
            ("--rm",),
            ("--pull", "never"),
            ("--name", name),
            ("--label", CLEANUP_LABEL),
            ("--network", "none"),
            ("--read-only",),
            ("--cap-drop", "ALL"),
            ("--security-opt", "no-new-privileges"),
            ("--pids-limit", str(limits.pids)),
            ("--memory", f"{limits.memory_mib}m"),
            ("--memory-swap", f"{limits.memory_mib}m"),
            ("--cpus", f"{limits.cpus:g}"),
            ("--user", CONTAINER_USER),
            ("--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={limits.tmpfs_mib}m"),
            ("--log-driver", "none"),
            ("--mount", f"type=bind,source={project_dir},target={PROJECT_MOUNT},readonly"),
            ("--mount", f"type=bind,source={scratch_dir},target={SCRATCH_MOUNT}"),
            ("--workdir", PROJECT_MOUNT),
        ]
        options += [("--env", f"{key}={value}") for key, value in CONTAINER_ENV.items()]
        return ["run", *(item for option in options for item in option), image_id, *command]

    def list_containers(self) -> list[str]:
        """Return the names of existing containers that carry the sandbox label."""
        proc = self._control(
            ["ps", "--all", "--filter", f"label={CLEANUP_LABEL}", "--format", "{{.Names}}"]
        )
        if proc.returncode != 0:
            raise SandboxUnavailable("cannot list containers")
        return sorted(line for line in proc.stdout.split() if line)

    def remove_containers(self) -> list[str]:
        """Force-remove every container that carries the sandbox label; return their names."""
        names = self.list_containers()
        for name in names:
            self._control(["rm", "--force", name])
        return names

    # -- internals ---------------------------------------------------------------------------

    def _docker_cli(self) -> str:
        docker = self._docker if self._docker is not None else find_docker()
        if docker is None:
            raise SandboxUnavailable("docker CLI not found; install Docker and start it")
        return docker

    def _control(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        """Run a short docker CLI command that does not execute untrusted code."""
        docker = self._docker_cli()
        try:
            return subprocess.run(
                [docker, *args],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                errors="replace",
                env=_host_env(docker),
                timeout=_CONTROL_TIMEOUT_S,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SandboxUnavailable(f"docker {args[0]} did not answer in time") from exc
        except OSError as exc:
            raise SandboxUnavailable(f"cannot execute docker: {exc}") from exc

    def _execute(
        self,
        run_args: list[str],
        *,
        command: tuple[str, ...],
        name: str,
        image_id: str,
        timeout_s: float,
    ) -> SandboxResult:
        docker = self._docker_cli()
        limit = self.limits.output_limit_bytes
        since = time.time() - _EVENTS_MARGIN_S
        started = time.monotonic()
        try:
            proc = subprocess.Popen(
                [docker, *run_args],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_host_env(docker),
                close_fds=True,
            )
        except OSError as exc:
            raise SandboxUnavailable(f"cannot execute docker: {exc}") from exc
        assert proc.stdout is not None
        assert proc.stderr is not None
        out = _CappedReader(proc.stdout, limit)
        err = _CappedReader(proc.stderr, limit)
        out.start()
        err.start()
        timed_out = False
        try:
            try:
                proc.wait(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                timed_out = True
                self._kill(name)
                try:
                    proc.wait(timeout=_KILL_GRACE_S)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        finally:
            if proc.poll() is None:
                # Interrupted (for example by KeyboardInterrupt): stop the container as well.
                self._kill(name)
                proc.kill()
                proc.wait()
            out.join(_READER_JOIN_S)
            err.join(_READER_JOIN_S)
            proc.stdout.close()
            proc.stderr.close()
            self._ensure_removed(name)
        duration = time.monotonic() - started
        return SandboxResult(
            argv=command,
            exit_code=proc.returncode,
            stdout=out.text(),
            stderr=err.text(),
            truncated=out.truncated or err.truncated,
            timed_out=timed_out,
            oom_killed=self._oom_killed(name, since),
            duration_s=round(duration, 3),
            image_id=image_id,
        )

    def _kill(self, name: str) -> None:
        # Errors are expected when the container has already stopped or was never created.
        self._control(["kill", "--signal", "KILL", name])

    def _exists(self, name: str) -> bool:
        proc = self._control(["ps", "--all", "--quiet", "--filter", f"name=^{name}$"])
        if proc.returncode != 0:
            raise SandboxError(f"cannot check whether container {name} still exists")
        return bool(proc.stdout.strip())

    def _ensure_removed(self, name: str) -> None:
        deadline = time.monotonic() + _REMOVAL_TIMEOUT_S
        while self._exists(name):
            if time.monotonic() > deadline:
                raise SandboxError(f"container {name} could not be removed")
            self._control(["rm", "--force", name])
            time.sleep(0.2)

    def _oom_killed(self, name: str, since: float) -> bool:
        # With --rm the container is gone before it could be inspected, so the out-of-memory
        # kill is read from the daemon's event log instead of the container state.
        window = ["--since", f"{since:.3f}", "--until", f"{time.time():.3f}"]
        filters = ["--filter", f"container={name}", "--filter", "event=oom"]
        proc = self._control(["events", *window, *filters, "--format", "{{.Action}}"])
        if proc.returncode != 0:
            raise SandboxError(f"cannot read the event log for container {name}")
        return "oom" in proc.stdout.split()
