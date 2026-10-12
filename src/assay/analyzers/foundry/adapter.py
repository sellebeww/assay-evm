"""`forge build` and `forge test` through the sandbox runner."""

import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Final, Literal, TypedDict, Unpack

from assay.analyzers.foundry.models import ForgeBuildRun, ForgeTestRun, ForgeTestSuite
from assay.analyzers.foundry.parser import (
    ForgeParseError,
    parse_build_errors,
    parse_test_output,
    summarize,
)
from assay.sandbox import SandboxResult, SandboxRunner, check_argv, make_scratch_dir

BUILD_ARGV: Final = ("forge", "build", "--json")
# `-vv` makes forge include the decoded console.log lines in its JSON output. One thread keeps
# fuzz campaigns deterministic: with several, forge runs a campaign on parallel workers and the
# reported runs, gas figures and counterexamples depend on scheduling.
TEST_ARGV: Final = ("forge", "test", "--json", "-vv", "--threads", "1")

OutputProblem = Literal["failed", "truncated", "invalid"]


class ForgeError(Exception):
    """A forge run did not produce a usable result."""

    def __init__(self, message: str, result: SandboxResult) -> None:
        super().__init__(message)
        self.result = result


class ForgeTimeout(ForgeError):
    """The wall-clock limit was reached. The outcome is unknown, never a pass."""


class ForgeOutOfMemory(ForgeError):
    """The container was killed for exceeding its memory limit."""


class ForgeOutputError(ForgeError):
    """Forge produced no usable output.

    `problem` is `failed` when forge exited with an error before producing results (for
    example a compilation error), `truncated` when the output exceeded the size limit, and
    `invalid` when the output did not match the expected structure.
    """

    def __init__(self, message: str, result: SandboxResult, problem: OutputProblem) -> None:
        super().__init__(message, result)
        self.problem: OutputProblem = problem


def forge_test_argv(
    *,
    match_test: str | None = None,
    match_contract: str | None = None,
    match_path: str | None = None,
    fuzz_seed: str | None = None,
    fuzz_runs: int | None = None,
) -> tuple[str, ...]:
    """Return the argv of `forge test`, checked against the sandbox allowlist."""
    argv = list(TEST_ARGV)
    for flag, value in (
        ("--match-test", match_test),
        ("--match-contract", match_contract),
        ("--match-path", match_path),
        ("--fuzz-seed", fuzz_seed),
        ("--fuzz-runs", None if fuzz_runs is None else str(fuzz_runs)),
    ):
        if value is not None:
            argv += [flag, value]
    return check_argv(argv)


def forge_inspect_argv(contract: str, field_name: str) -> tuple[str, ...]:
    """Return the argv of `forge inspect <contract> <field> --json`, checked as well."""
    return check_argv(["forge", "inspect", contract, field_name, "--json"])


def build(
    runner: SandboxRunner, project_dir: Path, *, scratch_dir: Path | None = None
) -> ForgeBuildRun:
    """Compile the project. Compiler errors are returned; warnings are not reported."""
    result = _run(runner, BUILD_ARGV, project_dir, scratch_dir)
    _check_completed(result)
    errors = () if result.exit_code == 0 else _parse(parse_build_errors, result)
    return ForgeBuildRun(
        argv=result.argv,
        exit_code=result.exit_code,
        image_id=result.image_id,
        succeeded=result.exit_code == 0,
        errors=errors,
    )


class ForgeTestOptions(TypedDict, total=False):
    """Optional arguments of `test`: forge's filters, fuzz settings and a scratch directory."""

    match_test: str
    match_contract: str
    match_path: str
    fuzz_seed: str
    fuzz_runs: int
    scratch_dir: Path
    timeout_s: float


def test(
    runner: SandboxRunner, project_dir: Path, **options: Unpack[ForgeTestOptions]
) -> ForgeTestRun:
    """Run the project's tests and return the normalized results.

    Failing tests are a result, not an error: they appear in the summary and `exit_code` is
    forge's (non-zero). Errors are raised only when no usable result exists.
    """
    argv = forge_test_argv(
        match_test=options.get("match_test"),
        match_contract=options.get("match_contract"),
        match_path=options.get("match_path"),
        fuzz_seed=options.get("fuzz_seed"),
        fuzz_runs=options.get("fuzz_runs"),
    )
    result = _run(runner, argv, project_dir, options.get("scratch_dir"), options.get("timeout_s"))
    _check_completed(result)
    suites: tuple[ForgeTestSuite, ...]
    if result.exit_code == 0 and not result.truncated and not result.stdout.strip():
        suites = ()  # forge prints nothing when no test matches the filters
    else:
        suites = _parse(parse_test_output, result)
    return ForgeTestRun(
        argv=result.argv,
        exit_code=result.exit_code,
        image_id=result.image_id,
        summary=summarize(suites),
        suites=suites,
    )


def inspect(
    runner: SandboxRunner,
    project_dir: Path,
    contract: str,
    field_name: str,
    *,
    scratch_dir: Path | None = None,
) -> str:
    """Return the JSON text printed by `forge inspect <contract> <field> --json`.

    The text is untrusted and returned unparsed; the caller parses it strictly.
    """
    result = _run(runner, forge_inspect_argv(contract, field_name), project_dir, scratch_dir)
    _check_completed(result)
    if result.exit_code != 0:
        message = f"forge inspect exited with code {result.exit_code}"
        raise ForgeOutputError(message, result, "failed")
    if result.truncated:
        raise ForgeOutputError("forge inspect output exceeded the size limit", result, "truncated")
    return result.stdout


def _run(
    runner: SandboxRunner,
    argv: tuple[str, ...],
    project_dir: Path,
    scratch_dir: Path | None,
    timeout_s: float | None = None,
) -> SandboxResult:
    # The timeout is passed only when one was asked for, so that the runner's own limit applies
    # otherwise.
    extra = {} if timeout_s is None else {"timeout_s": timeout_s}
    if scratch_dir is not None:
        return runner.run(argv, project_dir=project_dir, scratch_dir=scratch_dir, **extra)
    # Files written by the container user may not be removable on Linux hosts; a leftover
    # temporary directory must not turn a finished run into an error.
    with tempfile.TemporaryDirectory(prefix="assay-", ignore_cleanup_errors=True) as tmp:
        return runner.run(
            argv, project_dir=project_dir, scratch_dir=make_scratch_dir(Path(tmp)), **extra
        )


def _check_completed(result: SandboxResult) -> None:
    command = " ".join(result.argv[:2])
    if result.timed_out:
        raise ForgeTimeout(f"{command} exceeded the wall-clock limit", result)
    if result.oom_killed:
        raise ForgeOutOfMemory(f"{command} exceeded the memory limit", result)


def _parse[T](parser: Callable[[str], T], result: SandboxResult) -> T:
    command = " ".join(result.argv[:2])
    if result.truncated:
        raise ForgeOutputError(f"{command} output exceeded the size limit", result, "truncated")
    if not result.stdout.strip():
        message = f"{command} exited with code {result.exit_code} without results"
        raise ForgeOutputError(message, result, "failed")
    try:
        return parser(result.stdout)
    except ForgeParseError as exc:
        raise ForgeOutputError(f"unexpected {command} output: {exc}", result, "invalid") from exc
