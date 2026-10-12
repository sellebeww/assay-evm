"""Static analyzers: the common interface, the raw result and the parsed observations.

An analyzer runs inside the sandbox runner like any other untrusted program (argv only, no
network, the project read-only, one writable scratch directory, a wall-clock limit and capped
output). Its output is untrusted input (threat T13): it is parsed by `assay.analysis.limits`
and strict models, and a malformed document becomes `AnalyzerOutputError`, never a crash and
never an action. Nothing here creates a claim or changes a finding: analyzer output is an
unverified hint (evidence level E0), and only oracle runs change a status.
"""

import os
import stat
from abc import ABC, abstractmethod
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Annotated, ClassVar, Final

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
)

from assay.analysis.limits import AnalyzerOutputError, OutputLimits
from assay.ingest.paths import UnsafePathError, safe_relative_path
from assay.sandbox import SandboxResult, SandboxRunner
from assay.sandbox.layout import PROJECT_MOUNT

LABEL_PREFIX: Final = "assay."
LABEL_SUFFIX: Final = ".version"
STDERR_EXCERPT_CHARS: Final = 4000


class AnalyzerName(StrEnum):
    SLITHER = "slither"
    ADERYN = "aderyn"


class AnalyzerError(Exception):
    """An analyzer run produced no usable result."""

    def __init__(self, message: str, raw: "RawAnalysis | None" = None) -> None:
        super().__init__(message)
        self.raw = raw


class AnalyzerTimeout(AnalyzerError):
    """The wall-clock limit was reached; the outcome is unknown."""


class AnalyzerOutOfMemory(AnalyzerError):
    """The container was killed for exceeding its memory limit."""


class AnalyzerFailed(AnalyzerError):
    """The tool exited with an error, or wrote no output to parse."""


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class RawAnalysis(_Model):
    """One analyzer run as it happened: the tool, the command and its raw output.

    `output` holds the bytes of the tool's JSON document exactly as written (standard output
    for Slither, the report file for Aderyn), at most the size limit of the run. `stderr` is an
    excerpt of the end of the error stream. No field holds a host path.
    """

    tool: AnalyzerName
    tool_version: str
    argv: tuple[str, ...]
    image_id: str
    duration_s: float
    exit_code: int
    timed_out: bool
    oom_killed: bool
    truncated: bool
    output: bytes
    stderr: str


def _relative(value: str) -> str:
    try:
        return str(safe_relative_path(value))
    except UnsafePathError as exc:
        raise ValueError(str(exc)) from exc


RelativePath = Annotated[str, StringConstraints(max_length=1024), AfterValidator(_relative)]
RuleId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,199}$")]
Severity = Annotated[str, StringConstraints(pattern=r"^[A-Za-z][A-Za-z0-9 _()-]{0,63}$")]
Message = Annotated[str, StringConstraints(min_length=1, max_length=4000)]


class Location(_Model):
    """A place in the project: a path relative to the project root and a line range."""

    path: RelativePath
    start_line: int = Field(ge=1, le=10_000_000)
    end_line: int = Field(ge=1, le=10_000_000)


class Observation(_Model):
    """One result of an analyzer, as the tool reported it. Unverified (evidence level E0)."""

    rule_id: RuleId
    severity_reported: Severity
    message: Message
    locations: tuple[Location, ...] = Field(max_length=64)


class Analysis(_Model):
    """A parsed analyzer run."""

    raw: RawAnalysis
    observations: tuple[Observation, ...]


def check_target(target: str) -> str:
    """Return `target` if it names the project root (`.`) or a path inside it.

    Absolute paths, `..` components, backslashes and control characters are rejected, so a
    tool is never pointed outside the mounted project.
    """
    if target == ".":
        return target
    try:
        return str(safe_relative_path(target))
    except UnsafePathError as exc:
        raise ValueError(f"analysis target outside the project: {exc}") from exc


def project_relative(path: str) -> str:
    """Map a path reported by a tool to a path relative to the project root.

    A path under the project mount is made relative; any other absolute path, and any relative
    path that leaves the root, is outside the project and rejected.
    """
    posix = PurePosixPath(path)
    if posix.is_absolute():
        root = PurePosixPath(PROJECT_MOUNT)
        if posix != root and root in posix.parents:
            path = str(posix.relative_to(root))
        else:
            raise AnalyzerOutputError("path_outside_project", f"{path[:200]!r}")
    try:
        return str(safe_relative_path(path))
    except UnsafePathError as exc:
        raise AnalyzerOutputError("path_outside_project", str(exc)[:200]) from exc


def read_report(path: Path, limit: int) -> bytes:
    """Read a report file that a tool wrote into the scratch directory.

    The file belongs to the container: it is opened without following a symlink, must be a
    regular file, and is read only up to `limit` bytes. A larger file is an error.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError as exc:
        raise AnalyzerOutputError("malformed_json", "the tool wrote no report") from exc
    except OSError as exc:
        raise AnalyzerOutputError("malformed_json", f"the report cannot be opened: {exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise AnalyzerOutputError("malformed_json", "the report is not a regular file")
        if info.st_size > limit:
            raise AnalyzerOutputError(
                "output_too_large", f"report of {info.st_size} bytes, limit {limit}"
            )
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise AnalyzerOutputError("output_too_large", f"report larger than {limit} bytes")
    return data


def validate[M: BaseModel](model: type[M], document: object) -> M:
    """Validate a parsed document against a strict model; errors name fields, not values."""
    try:
        return model.model_validate(document)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in exc.errors(include_url=False, include_input=False)[:5]
        )
        raise AnalyzerOutputError("schema_mismatch", problems[:1000]) from exc


class Analyzer(ABC):
    """A static analyzer that runs in the sandbox and reports JSON."""

    name: ClassVar[AnalyzerName]

    def __init__(self, limits: OutputLimits | None = None) -> None:
        self.limits = limits if limits is not None else OutputLimits()

    @abstractmethod
    def argv(self, target: str) -> tuple[str, ...]:
        """The command for `target` (already checked by `check_target`)."""

    @abstractmethod
    def collect_output(self, result: SandboxResult, scratch_dir: Path) -> bytes:
        """The raw JSON document of a finished run."""

    @abstractmethod
    def failure(self, raw: RawAnalysis) -> str | None:
        """Why a finished run has no usable result, or `None` if its output can be parsed."""

    @abstractmethod
    def parse(self, output: bytes) -> tuple[Observation, ...]:
        """Parse a raw JSON document, or raise `AnalyzerOutputError`."""

    def tool_version(self, runner: SandboxRunner) -> str:
        """The version that the runner image declares for this tool."""
        labels = runner.image_labels()
        version = labels.get(f"{LABEL_PREFIX}{self.name.value}{LABEL_SUFFIX}")
        if not version:
            raise AnalyzerFailed(
                f"the runner image declares no {self.name.value} version; rebuild it with "
                "`make image`"
            )
        return version

    def run(
        self, runner: SandboxRunner, project_dir: Path, scratch_dir: Path, *, target: str = "."
    ) -> RawAnalysis:
        """Run the tool on `project_dir` (a snapshot) and return the raw result.

        Raises `AnalyzerTimeout`, `AnalyzerOutOfMemory` or `AnalyzerFailed` when the run gave no
        output to parse; the raw result is attached to the error.
        """
        command = self.argv(check_target(target))
        version = self.tool_version(runner)
        result = runner.run(command, project_dir=project_dir, scratch_dir=scratch_dir)
        output = b""
        problem: str | None = None
        if not (result.timed_out or result.oom_killed):
            try:
                output = self.collect_output(result, scratch_dir)
            except AnalyzerOutputError as exc:
                problem = str(exc)
        raw = RawAnalysis(
            tool=self.name,
            tool_version=version,
            argv=result.argv,
            image_id=result.image_id,
            duration_s=result.duration_s,
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            oom_killed=result.oom_killed,
            truncated=result.truncated,
            output=output,
            stderr=result.stderr[-STDERR_EXCERPT_CHARS:],
        )
        if result.timed_out:
            raise AnalyzerTimeout(f"{self.name.value} reached the time limit", raw)
        if result.oom_killed:
            raise AnalyzerOutOfMemory(f"{self.name.value} ran out of memory", raw)
        if problem is None:
            problem = self.failure(raw)
        if problem is not None:
            raise AnalyzerFailed(f"{self.name.value} failed: {problem}", raw)
        return raw

    def analyze(
        self, runner: SandboxRunner, project_dir: Path, scratch_dir: Path, *, target: str = "."
    ) -> Analysis:
        """Run the tool and parse its output (`AnalyzerError` or `AnalyzerOutputError`)."""
        raw = self.run(runner, project_dir, scratch_dir, target=target)
        return Analysis(raw=raw, observations=self.parse(raw.output))

    def check_count(self, count: int) -> None:
        """Refuse a report with more results than `OutputLimits.max_results`."""
        if count > self.limits.max_results:
            raise AnalyzerOutputError(
                "too_many_results", f"{count} results, more than {self.limits.max_results}"
            )
