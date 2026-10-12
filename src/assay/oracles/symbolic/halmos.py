"""Halmos through the sandbox runner: the argument vector, the run, and the strict parsing of its
JSON report (ADR 0018).

Halmos runs in the symbolic runner image like every other tool: one allowlisted argument
vector, the run tree mounted read-only, one writable scratch directory, no network, a wall-clock
limit and a memory limit. It compiles the tree itself (`forge build` inside the same container)
into `/work/scratch/out` and writes its report to `/work/scratch/halmos.json`.

The report is untrusted input. It is read from the host side of the scratch directory without
following a symlink, bounded before parsing (`assay.analysis.limits`), and validated by strict
models that keep only what Assay uses: per property its contract, signature, Halmos's result
code, path counts, the number of loops cut at the unrolling bound, and the counterexample models
(parameter names, Solidity types and values). Everything else is ignored and never interpreted.

Result codes of Halmos 0.3 per property: 0 no counterexample on any explored path, 1 a
counterexample, 2 a solver timeout (`unknown`), 3 a path that could not be explored, 4 every path
reverted, 5 a solver or internal error. Only 0 can lead to a pass; see `CheckOutcome`.
"""

import os
import re
import stat
from pathlib import Path
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from assay.analysis.limits import AnalyzerOutputError, OutputLimits, load_json
from assay.sandbox import DEFAULT_SYMBOLIC_IMAGE, SandboxLimits, SandboxResult, SandboxRunner

REPORT_NAME: Final = "halmos.json"
REPORT_PATH: Final = f"/work/scratch/{REPORT_NAME}"
BUILD_OUT: Final = "/work/scratch/out"
PROJECT_ROOT: Final = "/work/project"
SOLVER: Final = "z3"
"""z3 4.12.6.0 from the pinned z3-solver wheel; Halmos's default, Yices, is not in the image
(ADR 0018)."""
MAX_REPORT_BYTES: Final = 16 * 1024 * 1024
MAX_CHECKS: Final = 1000
MAX_MODELS: Final = 64
MAX_VARIABLES: Final = 256

# Static Solidity types: the only parameter types a property may have, so that its calldata is
# 4 + 32 * (number of parameters) bytes.
_BITS: Final = "|".join(str(bits) for bits in range(256, 0, -8))
STATIC_TYPE: Final = re.compile(rf"address|bool|u?int(?:{_BITS})?|bytes(?:3[0-2]|[12][0-9]|[1-9])")
SIGNATURE: Final = re.compile(r"(check_[A-Za-z0-9_]{1,64})\(([a-z0-9,]{0,512})\)")
CONTRACT_KEY: Final = re.compile(
    r"test/[A-Za-z0-9_][A-Za-z0-9_.\-/]{0,200}\.sol:[A-Za-z_][A-Za-z0-9_]{0,63}"
)

HalmosCode = Literal[0, 1, 2, 3, 4, 5]
CheckOutcome = Literal["no_counterexample", "counterexample", "unknown"]
_OUTCOMES: Final[dict[int, CheckOutcome]] = {
    0: "no_counterexample",
    1: "counterexample",
    2: "unknown",
    3: "unknown",
    4: "unknown",
    5: "unknown",
}
_CODE_TEXT: Final = {
    0: "no counterexample",
    1: "counterexample",
    2: "solver timeout (unknown)",
    3: "a path could not be explored",
    4: "every path reverted",
    5: "solver or internal error",
}

_Name = Annotated[str, StringConstraints(max_length=200)]


class HalmosOutputError(Exception):
    """The Halmos report is unusable; `code` names the problem."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class _Strict(BaseModel):
    """Only the fields Assay reads; any other field of the report is ignored."""

    model_config = ConfigDict(frozen=True, extra="ignore", strict=True)


class _Variable(_Strict):
    variable_name: _Name
    solidity_type: _Name
    size_bits: int = Field(ge=1, le=256)
    value: int = Field(ge=0)


class _Model(_Strict):
    model: dict[_Name, _Variable] = Field(max_length=MAX_VARIABLES)
    is_valid: bool


class _Test(_Strict):
    name: Annotated[str, StringConstraints(max_length=600)]
    exitcode: int = Field(ge=0, le=5)
    num_models: int | None = Field(default=None, ge=0)
    models: list[_Model] | None = Field(default=None, max_length=MAX_MODELS)
    num_paths: list[int] | None = Field(default=None, min_length=3, max_length=3)
    num_bounded_loops: int | None = Field(default=None, ge=0)


class _Report(_Strict):
    exitcode: int
    test_results: dict[Annotated[str, StringConstraints(max_length=300)], list[_Test]] = Field(
        max_length=MAX_CHECKS
    )


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Witness(_Frozen):
    """A counterexample model: the value of each named parameter, and whether Halmos checked
    the model against the path condition (`valid`)."""

    valid: bool
    values: tuple[tuple[str, str, int], ...]
    """`(parameter name, Solidity type, value)`, sorted by name."""

    def value_of(self, name: str) -> int | None:
        for item, _, value in self.values:
            if item == name:
                return value
        return None


class CheckResult(_Frozen):
    """The result of one property."""

    contract: str
    """`test/<path>.sol:<Name>`, as Halmos reports it."""
    signature: str
    code: int = Field(ge=0, le=5)
    paths: int | None
    bounded_loops: int | None
    witnesses: tuple[Witness, ...]

    @property
    def name(self) -> str:
        return self.signature.split("(", 1)[0]

    @property
    def parameter_types(self) -> tuple[str, ...]:
        inner = self.signature.split("(", 1)[1][:-1]
        return tuple(inner.split(",")) if inner else ()

    @property
    def outcome(self) -> CheckOutcome:
        return _OUTCOMES[self.code]

    @property
    def calldata_bytes(self) -> int:
        return 4 + 32 * len(self.parameter_types)

    def describe(self) -> str:
        return _CODE_TEXT[self.code]


def parse_report(data: bytes) -> tuple[CheckResult, ...]:
    """The properties of a Halmos JSON report, sorted by contract and signature.

    Raises `HalmosOutputError` for a report that is too large, malformed, or does not fit the
    expected shape, and for a property whose signature has a parameter type other than a
    static one.
    """
    try:
        document = load_json(data, OutputLimits(max_bytes=MAX_REPORT_BYTES))
        report = _Report.model_validate(document)
    except AnalyzerOutputError as exc:
        raise HalmosOutputError(exc.code, exc.detail) from exc
    except ValidationError as exc:
        raise HalmosOutputError("schema_mismatch", _first_error(exc)) from exc
    found: list[CheckResult] = []
    for contract, tests in sorted(report.test_results.items()):
        if CONTRACT_KEY.fullmatch(contract) is None or ".." in contract.split("/"):
            raise HalmosOutputError("schema_mismatch", f"unexpected contract {contract[:80]!r}")
        for test in tests:
            match = SIGNATURE.fullmatch(test.name)
            if match is None:
                raise HalmosOutputError("schema_mismatch", f"unexpected test {test.name[:80]!r}")
            types = match.group(2).split(",") if match.group(2) else []
            if any(STATIC_TYPE.fullmatch(item) is None for item in types):
                raise HalmosOutputError(
                    "unsupported_signature",
                    f"{test.name[:120]} has a parameter that is not of a static type",
                )
            witnesses = tuple(_witness(item) for item in test.models or ())
            if test.exitcode == 1 and not witnesses:
                raise HalmosOutputError(
                    "schema_mismatch", f"{test.name[:120]} has a counterexample without a model"
                )
            found.append(
                CheckResult(
                    contract=contract,
                    signature=test.name,
                    code=test.exitcode,
                    paths=None if test.num_paths is None else test.num_paths[0],
                    bounded_loops=test.num_bounded_loops,
                    witnesses=witnesses,
                )
            )
    found.sort(key=lambda item: (item.contract, item.signature))
    keys = [(item.contract, item.signature) for item in found]
    if len(set(keys)) != len(keys):
        raise HalmosOutputError("duplicate_key", "a property is reported twice")
    return tuple(found)


_PARAMETER_NAME: Final = re.compile(r"[A-Za-z][A-Za-z0-9]{0,63}")


def _witness(model: _Model) -> Witness:
    values: dict[str, tuple[str, int]] = {}
    for full_name, variable in model.model.items():
        # Parameters are `p_<name>_<type>_...`; other symbols (for example the bytes of a
        # hash) are not inputs and are not replayed.
        if not full_name.startswith("p_"):
            continue
        name, kind = variable.variable_name, variable.solidity_type
        if _PARAMETER_NAME.fullmatch(name) is None or STATIC_TYPE.fullmatch(kind) is None:
            raise HalmosOutputError("schema_mismatch", f"unexpected model variable {name[:40]!r}")
        if variable.value >= 2**variable.size_bits:
            raise HalmosOutputError("schema_mismatch", f"value of {name} exceeds its size")
        if name in values:
            raise HalmosOutputError("duplicate_key", f"model variable {name} appears twice")
        values[name] = (kind, variable.value)
    return Witness(
        valid=model.is_valid,
        values=tuple((name, kind, value) for name, (kind, value) in sorted(values.items())),
    )


def _first_error(exc: ValidationError) -> str:
    error = exc.errors()[0]
    where = ".".join(str(item) for item in error["loc"][:6])
    return f"{where}: {error['msg']}"[:200]


class HalmosSettings(_Frozen):
    """The bounds and limits of one Halmos run."""

    loop: int = Field(default=3, ge=1, le=99)
    """Loop unrolling bound: iterations explored per loop; deeper paths are cut."""
    solver_timeout_s: int = Field(default=60, ge=1, le=9999)
    """Time the solver gets per assertion query; a query that runs out is `unknown`."""
    timeout_s: int = Field(default=900, ge=10, le=86_400)
    """Wall-clock limit of the whole run, compilation included."""
    memory_mib: int = Field(default=4096, ge=512)
    solver_threads: int = Field(default=1, ge=1, le=4)
    """One thread, so that the order in which paths are solved, and so the reported
    counterexamples, repeat."""


SYMBOLIC_TMPFS_MIB: Final = 256
"""Halmos writes its solver queries to /tmp, so the symbolic runner gets a larger tmpfs."""


def symbolic_runner(
    settings: HalmosSettings | None = None, image: str = DEFAULT_SYMBOLIC_IMAGE
) -> SandboxRunner:
    """A runner of the symbolic image with the memory and time limits of `settings`."""
    settings = settings if settings is not None else HalmosSettings()
    limits = SandboxLimits(
        timeout_s=settings.timeout_s, memory_mib=settings.memory_mib, tmpfs_mib=SYMBOLIC_TMPFS_MIB
    )
    return SandboxRunner(image=image, limits=limits)


def halmos_argv(prefix: str, settings: HalmosSettings) -> tuple[str, ...]:
    return (
        "halmos",
        "--root",
        PROJECT_ROOT,
        "--forge-build-out",
        BUILD_OUT,
        "--function",
        prefix,
        "--loop",
        str(settings.loop),
        "--solver",
        SOLVER,
        "--solver-timeout-assertion",
        f"{settings.solver_timeout_s}s",
        "--solver-threads",
        str(settings.solver_threads),
        "--json-output",
        REPORT_PATH,
        "--no-status",
    )


RunProblem = Literal["timeout", "out_of_memory", "build_failed", "no_report", "unusable_report"]


class HalmosRun(_Frozen):
    """One Halmos run: what ran, how it ended, and the properties it reported."""

    argv: tuple[str, ...]
    exit_code: int
    problem: RunProblem | None
    detail: str
    checks: tuple[CheckResult, ...]
    seconds: float


def run_halmos(
    runner: SandboxRunner, tree: Path, scratch: Path, prefix: str, settings: HalmosSettings
) -> HalmosRun:
    """Run the properties of `tree` whose names start with `prefix`.

    A timeout, an out-of-memory kill, a failed build or a missing or unusable report is a
    `problem`, never a result: no property of such a run counts as passed.
    """
    argv = halmos_argv(prefix, settings)
    result = runner.run(argv, project_dir=tree, scratch_dir=scratch, timeout_s=settings.timeout_s)
    return interpret(result, _read_report(scratch / REPORT_NAME), settings)


def interpret(result: SandboxResult, report: bytes | None, settings: HalmosSettings) -> HalmosRun:
    """Classify a finished Halmos container run and its report bytes (or `None`)."""

    def ended(
        problem: RunProblem | None, detail: str, checks: tuple[CheckResult, ...] = ()
    ) -> HalmosRun:
        return HalmosRun(
            argv=result.argv,
            exit_code=result.exit_code,
            problem=problem,
            detail=detail,
            checks=checks,
            seconds=round(result.duration_s, 1),
        )

    if result.timed_out:
        return ended("timeout", f"Halmos exceeded the wall-clock limit of {settings.timeout_s} s")
    if result.oom_killed:
        return ended(
            "out_of_memory", f"Halmos exceeded the memory limit of {settings.memory_mib} MiB"
        )
    if report is None:
        output = f"{result.stdout}\n{result.stderr}"
        if "Build failed" in output or "Compiler run failed" in output:
            return ended("build_failed", "the symbolic tree does not compile")
        return ended("no_report", f"Halmos exited with code {result.exit_code} without a report")
    try:
        checks = parse_report(report)
    except HalmosOutputError as exc:
        return ended("unusable_report", str(exc))
    return ended(None, f"Halmos exited with code {result.exit_code}", checks)


def _read_report(path: Path) -> bytes | None:
    """The report from the host side of the scratch directory: a regular file, not followed
    through a symlink, at most `MAX_REPORT_BYTES` (plus one byte, so that a larger file fails
    the size check)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            return None
        return handle.read(MAX_REPORT_BYTES + 1)
