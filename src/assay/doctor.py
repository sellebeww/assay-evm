"""`assay doctor`: check the machine for what Assay needs, with a one-line fix per problem.

Everything that touches the machine is passed in (`Probes`), so the checks run against a stand-in
in tests. The report never contains the value of an environment variable: a variable is `SET` or
`NOT SET`, nothing else. A tool version is the one the image declares in its labels, which the
Dockerfile writes from `versions.lock`; the binaries themselves are run by `make image-check`.
The image id is not compared with anything: it differs between builds and platforms (ADR 0008,
ADR 0013), so the image is matched to `versions.lock` by the pinned tool versions (ADR 0020).
"""

import platform
import shutil
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Final, Literal, Protocol

from pydantic import BaseModel, ConfigDict

from assay.llm.config import ENV_API_KEY, ENV_BASE_URL, ENV_MAX_TOKENS, ENV_MODEL, ENV_TIMEOUT
from assay.report.bundle import EnvironmentUnavailable, read_versions_lock, tool_versions
from assay.sandbox import (
    DEFAULT_IMAGE,
    DEFAULT_SYMBOLIC_IMAGE,
    SandboxRunner,
    SandboxUnavailable,
    find_docker,
)

DOCTOR_FORMAT: Final = "assay-doctor/1"
MIN_FREE_BYTES: Final = 5 * 1024**3
"""Free space below which the check fails: the images, the forge caches and the work trees."""

CheckStatus = Literal["ok", "problem", "info", "skipped"]

RUNNER_TOOLS: Final = {
    "foundry": "FOUNDRY_VERSION",
    "solc": "SOLC_VERSION",
    "forge-std": "FORGE_STD_VERSION",
    "python": "PYTHON_VERSION",
    "slither": "SLITHER_VERSION",
    "aderyn": "ADERYN_VERSION",
}
SYMBOLIC_TOOLS: Final = {**RUNNER_TOOLS, "halmos": "HALMOS_VERSION", "z3": "Z3_SOLVER_VERSION"}
LLM_VARIABLES: Final = (ENV_BASE_URL, ENV_API_KEY, ENV_MODEL, ENV_TIMEOUT, ENV_MAX_TOKENS)

FIX_INSTALL: Final = "install Docker and make sure the docker command is on PATH"
FIX_START: Final = "start Docker (Docker Desktop or the docker service) and run assay doctor again"
FIX_IMAGE: Final = "run make image"
FIX_REBUILD: Final = "run make image to rebuild the image from versions.lock"
FIX_LOCK: Final = "run assay from a source checkout, which holds docker/runner/versions.lock"


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Check(_Model):
    """One line of the report. `fix` is set for a problem and for an optional part to set up."""

    id: str
    title: str
    status: CheckStatus
    detail: str
    fix: str | None = None


class DoctorReport(_Model):
    """Result of `assay doctor`. `ok` is true when no check is a problem; the exit code is then
    0, otherwise 4."""

    format: Literal["assay-doctor/1"] = DOCTOR_FORMAT
    ok: bool
    checks: tuple[Check, ...]


class ImageProbe(Protocol):
    image: str

    def image_id(self) -> str: ...

    def image_labels(self) -> dict[str, str]: ...

    def image_platform(self) -> str: ...

    def daemon_platform(self) -> str: ...


@dataclass(frozen=True, slots=True)
class Probes:
    """The machine, as `run_doctor` sees it."""

    docker_path: Callable[[], str | None]
    make_image: Callable[[str], ImageProbe]
    versions_lock: Callable[[], str]
    free_bytes: Callable[[], int]
    host_machine: Callable[[], str]
    environ: Mapping[str, str]


def real_probes(environ: Mapping[str, str]) -> Probes:
    return Probes(
        docker_path=find_docker,
        make_image=lambda image: SandboxRunner(image=image),
        versions_lock=read_versions_lock,
        free_bytes=lambda: shutil.disk_usage(tempfile.gettempdir()).free,
        host_machine=platform.machine,
        environ=environ,
    )


def parse_versions_lock(text: str) -> dict[str, str]:
    """`KEY=VALUE` lines of `versions.lock`; comments and blank lines are skipped."""
    found: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        found[key.strip()] = value.strip()
    return found


def normalize_arch(machine: str) -> str:
    """`arm64` or `amd64` for the names the platforms use; anything else unchanged, lowercased."""
    lowered = machine.lower()
    return {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64", "amd64": "amd64"}.get(
        lowered, lowered
    )


def _check(id_: str, title: str, status: CheckStatus, detail: str, fix: str | None = None) -> Check:
    return Check(id=id_, title=title, status=status, detail=detail, fix=fix)


def _gib(value: int) -> str:
    return f"{value / 1024**3:.1f} GiB"


def _expected_versions(lock: Mapping[str, str], tools: Mapping[str, str]) -> dict[str, str]:
    # The lock pins Foundry and Aderyn with a leading `v`; the labels carry the value as written.
    return {tool: lock[key] for tool, key in tools.items() if key in lock}


def _image_checks(
    *,
    prefix: str,
    name: str,
    image: str,
    probe: ImageProbe,
    lock: Mapping[str, str] | None,
    tools: Mapping[str, str],
    daemon: str,
    optional: bool,
    lock_problem: str | None,
) -> list[Check]:
    unavailable = f"{image} is not built; it is needed only for --symbolic" if optional else None
    try:
        image_id = probe.image_id()
    except SandboxUnavailable as exc:
        status: CheckStatus = "info" if optional else "problem"
        return [
            _check(prefix, f"{name} image", status, unavailable or str(exc), FIX_IMAGE),
            _check(f"{prefix}_tools", f"{name} tool versions", "skipped", "image not available"),
            _check(f"{prefix}_platform", f"{name} platform", "skipped", "image not available"),
        ]
    checks = [_check(prefix, f"{name} image", "ok", f"{image} present, id {image_id}")]
    try:
        labels = probe.image_labels()
    except SandboxUnavailable as exc:
        labels = {}
        checks.append(
            _check(f"{prefix}_tools", f"{name} tool versions", "problem", str(exc), FIX_IMAGE)
        )
    else:
        declared = tool_versions(labels)
        if lock is None:
            checks.append(
                _check(
                    f"{prefix}_tools",
                    f"{name} tool versions",
                    "problem",
                    lock_problem or "versions.lock cannot be read",
                    FIX_LOCK,
                )
            )
        else:
            expected = _expected_versions(lock, tools)
            wrong = [
                f"{tool} {declared.get(tool, 'missing')} (versions.lock: {version})"
                for tool, version in expected.items()
                if declared.get(tool) != version
            ]
            listing = ", ".join(f"{tool} {declared[tool]}" for tool in sorted(declared))
            if wrong:
                checks.append(
                    _check(
                        f"{prefix}_tools",
                        f"{name} tool versions",
                        "problem",
                        "differs from versions.lock: " + "; ".join(wrong),
                        FIX_REBUILD,
                    )
                )
            else:
                checks.append(
                    _check(
                        f"{prefix}_tools",
                        f"{name} tool versions",
                        "ok",
                        f"match versions.lock (as declared by the image labels): {listing}",
                    )
                )
    try:
        built = probe.image_platform()
    except SandboxUnavailable as exc:
        checks.append(
            _check(f"{prefix}_platform", f"{name} platform", "problem", str(exc), FIX_IMAGE)
        )
        return checks
    same = normalize_arch(built.partition("/")[2]) == normalize_arch(daemon.partition("/")[2])
    mode = "native" if same else "emulated"
    note = "" if same else " (slower; ADR 0018 explains why the symbolic image is amd64 only)"
    checks.append(
        _check(
            f"{prefix}_platform",
            f"{name} platform",
            "ok",
            f"image {built} on daemon {daemon}: {mode}{note}",
        )
    )
    return checks


def run_doctor(probes: Probes) -> DoctorReport:
    """Run every check. A check that cannot run because Docker is missing is `skipped`."""
    checks: list[Check] = []
    docker = probes.docker_path()
    if docker is None:
        checks.append(_check("docker_cli", "docker command", "problem", "not found", FIX_INSTALL))
    else:
        checks.append(_check("docker_cli", "docker command", "ok", "found"))
    daemon: str | None = None
    daemon_error = ""
    if docker is not None:
        try:
            daemon = probes.make_image(DEFAULT_IMAGE).daemon_platform()
        except SandboxUnavailable as exc:
            daemon_error = str(exc)
    if daemon is not None:
        host = normalize_arch(probes.host_machine())
        checks.append(
            _check(
                "docker_daemon",
                "docker daemon",
                "ok",
                f"running, {daemon}; host architecture {host}",
            )
        )
    elif docker is not None:
        checks.append(_check("docker_daemon", "docker daemon", "problem", daemon_error, FIX_START))
    else:
        checks.append(_check("docker_daemon", "docker daemon", "skipped", "no docker command"))

    lock: dict[str, str] | None = None
    lock_problem: str | None = None
    try:
        lock = parse_versions_lock(probes.versions_lock())
    except EnvironmentUnavailable as exc:
        lock_problem = str(exc)
    for prefix, name, image, tools, optional in (
        ("runner", "runner", DEFAULT_IMAGE, RUNNER_TOOLS, False),
        ("symbolic", "symbolic runner", DEFAULT_SYMBOLIC_IMAGE, SYMBOLIC_TOOLS, True),
    ):
        if daemon is None:
            checks += [
                _check(prefix, f"{name} image", "skipped", "docker daemon not available"),
                _check(f"{prefix}_tools", f"{name} tool versions", "skipped", "no image"),
                _check(f"{prefix}_platform", f"{name} platform", "skipped", "no image"),
            ]
            continue
        checks += _image_checks(
            prefix=prefix,
            name=name,
            image=image,
            probe=probes.make_image(image),
            lock=lock,
            tools=tools,
            daemon=daemon,
            optional=optional,
            lock_problem=lock_problem,
        )

    free = probes.free_bytes()
    if free < MIN_FREE_BYTES:
        checks.append(
            _check(
                "disk",
                "disk space",
                "problem",
                f"{_gib(free)} free, at least {_gib(MIN_FREE_BYTES)} needed",
                "free disk space, for example with docker system prune and by deleting old bundles",
            )
        )
    else:
        checks.append(_check("disk", "disk space", "ok", f"{_gib(free)} free"))

    states = ", ".join(
        f"{name} {'SET' if probes.environ.get(name) else 'NOT SET'}" for name in LLM_VARIABLES
    )
    checks.append(
        _check(
            "llm",
            "model endpoint",
            "info",
            f"{states}; only the modes record and live need it, replay and verify do not",
        )
    )
    return DoctorReport(ok=all(item.status != "problem" for item in checks), checks=tuple(checks))
