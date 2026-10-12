"""Normalized results of forge runs.

These models contain no durations, timestamps or host paths, so the same project, image and
arguments give byte-identical JSON.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict

TestStatus = Literal["success", "failure", "skipped"]
TestKind = Literal["unit", "fuzz", "invariant", "table"]


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ForgeEvent(_Model):
    """One raw log entry recorded during a test, in lowercase hex.

    Forge reports the logs of every contract, so a consumer must check `address` before it
    trusts an event.
    """

    address: str
    topics: tuple[str, ...]
    data: str


class ForgeCall(_Model):
    """One call of a counterexample: its calldata in lowercase hex, forge's rendering of the
    decoded arguments (`raw_args`), and for a fuzz test the 1-based index of the failing run,
    when forge printed them. A call of an invariant sequence also names its sender and target
    address, and any time (`warp`) or block (`roll`) shift forge applied before it."""

    calldata: str
    args: str | None
    run: int | None = None
    sender: str | None = None
    target: str | None = None
    warp: str | None = None
    roll: str | None = None


class ForgeCounterexample(_Model):
    """The input that made a fuzz or invariant test fail.

    `single` is one call (fuzz tests); `sequence` is a list of calls (invariant tests), shrunk
    by forge from a sequence of `unshrunk_length` calls.
    """

    kind: Literal["single", "sequence"]
    calls: tuple[ForgeCall, ...]
    unshrunk_length: int | None = None


class ForgeInvariantFailure(_Model):
    """An invariant that broke during an invariant test, with the sequence that broke it."""

    name: str
    kind: str
    reason: str | None
    counterexample: ForgeCounterexample | None


class ForgeTestCase(_Model):
    """One test function.

    `gas` is set for unit tests; `mean_gas` and `median_gas` for fuzz and table tests; `runs`
    for fuzz, invariant and table tests; `calls` and `reverts` for invariant tests.
    `logs` are the decoded `console.log` lines; `events` are the raw logs; `counterexample`
    is set for a failing fuzz test when forge reported the failing input; `invariant_failures`
    lists the invariants that broke in an invariant test, each with its shrunk sequence.
    """

    name: str
    status: TestStatus
    reason: str | None
    kind: TestKind
    gas: int | None = None
    mean_gas: int | None = None
    median_gas: int | None = None
    runs: int | None = None
    calls: int | None = None
    reverts: int | None = None
    logs: tuple[str, ...]
    events: tuple[ForgeEvent, ...] = ()
    counterexample: ForgeCounterexample | None = None
    invariant_failures: tuple[ForgeInvariantFailure, ...] = ()


class ForgeTestSuite(_Model):
    """One test contract, named `<path>:<contract>`."""

    name: str
    tests: tuple[ForgeTestCase, ...]
    warnings: tuple[str, ...]


class ForgeTestSummary(_Model):
    passed: int
    failed: int
    skipped: int


class ForgeTestRun(_Model):
    argv: tuple[str, ...]
    exit_code: int
    image_id: str
    summary: ForgeTestSummary
    suites: tuple[ForgeTestSuite, ...]


class ForgeDiagnostic(_Model):
    """A compiler error reported by `forge build --json`."""

    type: str
    code: str | None
    message: str
    file: str | None
    start: int | None
    end: int | None


class ForgeBuildRun(_Model):
    argv: tuple[str, ...]
    exit_code: int
    image_id: str
    succeeded: bool
    errors: tuple[ForgeDiagnostic, ...]
