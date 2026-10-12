"""Strict parsing of forge JSON output.

Forge output is untrusted: test names, revert reasons and log lines come from the project under
test. Parsing uses strict Pydantic models with limits on counts and string lengths; anything
unexpected raises `ForgeParseError` and is never executed or interpreted further. Fields that
vary between identical runs (durations) and fields that Assay does not use (traces, labels,
raw logs) are dropped.
"""

from typing import Annotated, Final, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    NonNegativeInt,
    StringConstraints,
    TypeAdapter,
    ValidationError,
    model_validator,
)

from assay.analyzers.foundry.models import (
    ForgeCall,
    ForgeCounterexample,
    ForgeDiagnostic,
    ForgeEvent,
    ForgeInvariantFailure,
    ForgeTestCase,
    ForgeTestSuite,
    ForgeTestSummary,
    TestKind,
    TestStatus,
)

MAX_NAME_CHARS: Final = 1024
MAX_TEXT_CHARS: Final = 64 * 1024
MAX_SUITES: Final = 10_000
MAX_TESTS_PER_SUITE: Final = 10_000
MAX_LINES: Final = 10_000
MAX_EVENTS: Final = 10_000
MAX_EVENT_DATA_BYTES: Final = 64 * 1024
MAX_TOPICS: Final = 4
MAX_CALLDATA_BYTES: Final = 64 * 1024
MAX_SEQUENCE_CALLS: Final = 10_000
MAX_INVARIANT_FAILURES: Final = 100

_Name = Annotated[str, StringConstraints(min_length=1, max_length=MAX_NAME_CHARS)]
_Text = Annotated[str, StringConstraints(max_length=MAX_TEXT_CHARS)]
_Lines = Annotated[list[_Text], Field(max_length=MAX_LINES)]
_Address = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-fA-F]{40}$")]
_Topic = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-fA-F]{64}$")]
_EventData = Annotated[
    str,
    StringConstraints(pattern=r"^0x(?:[0-9a-fA-F]{2})*$", max_length=2 + 2 * MAX_EVENT_DATA_BYTES),
]
_Calldata = Annotated[
    str,
    StringConstraints(pattern=r"^0x(?:[0-9a-fA-F]{2})*$", max_length=2 + 2 * MAX_CALLDATA_BYTES),
]


class ForgeParseError(ValueError):
    """Forge output does not match the expected structure or exceeds a limit."""


class _Raw(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="ignore")


class _RawUnit(_Raw):
    gas: NonNegativeInt


class _RawFuzz(_Raw):
    runs: NonNegativeInt
    mean_gas: NonNegativeInt
    median_gas: NonNegativeInt


class _RawInvariant(_Raw):
    runs: NonNegativeInt
    calls: NonNegativeInt
    reverts: NonNegativeInt


class _RawKind(BaseModel):
    # Unknown kinds are rejected rather than ignored.
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    Unit: _RawUnit | None = None
    Fuzz: _RawFuzz | None = None
    Invariant: _RawInvariant | None = None
    Table: _RawFuzz | None = None

    @model_validator(mode="after")
    def _exactly_one_kind(self) -> Self:
        kinds = (self.Unit, self.Fuzz, self.Invariant, self.Table)
        if sum(kind is not None for kind in kinds) != 1:
            raise ValueError("expected exactly one test kind")
        return self


class _RawLog(_Raw):
    address: _Address
    topics: Annotated[list[_Topic], Field(max_length=MAX_TOPICS)]
    data: _EventData


class _RawCall(_Raw):
    calldata: _Calldata
    raw_args: _Text | None = None
    fuzz_run: NonNegativeInt | None = None


class _RawCounterexample(BaseModel):
    # Unknown shapes are rejected rather than ignored.
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    Single: _RawCall | None = None
    Sequence: Annotated[list[_RawCall], Field(max_length=MAX_SEQUENCE_CALLS)] | None = None

    @model_validator(mode="after")
    def _exactly_one_shape(self) -> Self:
        if (self.Single is None) == (self.Sequence is None):
            raise ValueError("expected exactly one counterexample shape")
        return self


class _RawSequenceCall(_Raw):
    """One call of an invariant counterexample: who called which address with what data."""

    calldata: _Calldata
    sender: _Address | None = None
    addr: _Address | None = None
    raw_args: _Text | None = None
    # A time or block shift before the call; forge sets them only when configured to.
    warp: _Text | NonNegativeInt | None = None
    roll: _Text | NonNegativeInt | None = None


class _RawInvariantCounterexample(BaseModel):
    # Unknown shapes are rejected rather than ignored. Forge writes the sequence as a pair: the
    # length of the sequence before shrinking, and the shrunk calls.
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    Sequence: tuple[
        NonNegativeInt, Annotated[list[_RawSequenceCall], Field(max_length=MAX_SEQUENCE_CALLS)]
    ]


class _RawInvariantFailure(_Raw):
    kind: _Name
    name: _Name
    reason: _Text | None = None
    counterexample: _RawInvariantCounterexample | None = None


class _RawTest(_Raw):
    status: Literal["Success", "Failure", "Skipped"]
    reason: _Text | None = None
    counterexample: _RawCounterexample | None = None
    invariant_failures: Annotated[
        list[_RawInvariantFailure], Field(max_length=MAX_INVARIANT_FAILURES)
    ] = []
    decoded_logs: _Lines = []
    logs: Annotated[list[_RawLog], Field(max_length=MAX_EVENTS)] = []
    kind: _RawKind


class _RawSuite(_Raw):
    test_results: Annotated[dict[_Name, _RawTest], Field(max_length=MAX_TESTS_PER_SUITE)]
    warnings: _Lines = []


class _RawLocation(_Raw):
    file: _Name
    start: int
    end: int


class _RawCompilerMessage(_Raw):
    severity: _Name
    type: _Name
    errorCode: _Name | None = None
    message: _Text
    sourceLocation: _RawLocation | None = None


class _RawBuild(_Raw):
    errors: Annotated[list[_RawCompilerMessage], Field(max_length=MAX_LINES)] = []


_TestOutput = Annotated[dict[_Name, _RawSuite], Field(max_length=MAX_SUITES)]
_TEST_OUTPUT: Final[TypeAdapter[dict[str, _RawSuite]]] = TypeAdapter(_TestOutput)
_BUILD_OUTPUT: Final = TypeAdapter(_RawBuild)

_STATUS: Final[dict[str, TestStatus]] = {
    "Success": "success",
    "Failure": "failure",
    "Skipped": "skipped",
}


def _describe(exc: ValidationError) -> str:
    first = exc.errors(include_input=False, include_url=False)[0]
    location = ".".join(repr(part) if isinstance(part, str) else str(part) for part in first["loc"])
    return f"{exc.error_count()} validation error(s); first at {location[:200]}: {first['msg']}"


def _utf8(text: str) -> bytes:
    return text.encode("utf-8")


def _counterexample(raw: _RawCounterexample | None) -> ForgeCounterexample | None:
    if raw is None:
        return None
    calls = [raw.Single] if raw.Single is not None else list(raw.Sequence or [])
    return ForgeCounterexample(
        kind="single" if raw.Single is not None else "sequence",
        calls=tuple(
            ForgeCall(
                calldata=call.calldata.lower(),
                args=call.raw_args,
                run=call.fuzz_run,
            )
            for call in calls
        ),
    )


def _shift(value: str | int | None) -> str | None:
    return None if value is None else str(value)


def _invariant_failure(raw: _RawInvariantFailure) -> ForgeInvariantFailure:
    counterexample = None
    if raw.counterexample is not None:
        length, calls = raw.counterexample.Sequence
        counterexample = ForgeCounterexample(
            kind="sequence",
            calls=tuple(
                ForgeCall(
                    calldata=call.calldata.lower(),
                    args=call.raw_args,
                    sender=None if call.sender is None else call.sender.lower(),
                    target=None if call.addr is None else call.addr.lower(),
                    warp=_shift(call.warp),
                    roll=_shift(call.roll),
                )
                for call in calls
            ),
            unshrunk_length=length,
        )
    return ForgeInvariantFailure(
        name=raw.name, kind=raw.kind, reason=raw.reason, counterexample=counterexample
    )


def _normalize_test(name: str, raw: _RawTest) -> ForgeTestCase:
    kind: TestKind
    metrics: dict[str, int]
    if raw.kind.Unit is not None:
        kind, metrics = "unit", {"gas": raw.kind.Unit.gas}
    elif raw.kind.Invariant is not None:
        invariant = raw.kind.Invariant
        kind = "invariant"
        metrics = {"runs": invariant.runs, "calls": invariant.calls, "reverts": invariant.reverts}
    else:
        sampled = raw.kind.Fuzz or raw.kind.Table
        assert sampled is not None
        kind = "fuzz" if raw.kind.Fuzz is not None else "table"
        metrics = {
            "runs": sampled.runs,
            "mean_gas": sampled.mean_gas,
            "median_gas": sampled.median_gas,
        }
    return ForgeTestCase.model_validate(
        {
            "name": name,
            "status": _STATUS[raw.status],
            "reason": raw.reason,
            "kind": kind,
            "logs": tuple(raw.decoded_logs),
            "events": tuple(
                ForgeEvent(
                    address=log.address.lower(),
                    topics=tuple(topic.lower() for topic in log.topics),
                    data=log.data.lower(),
                )
                for log in raw.logs
            ),
            "counterexample": _counterexample(raw.counterexample),
            "invariant_failures": tuple(
                _invariant_failure(item) for item in raw.invariant_failures
            ),
            **metrics,
        }
    )


def parse_test_output(text: str) -> tuple[ForgeTestSuite, ...]:
    """Parse the stdout of `forge test --json` into suites sorted by name."""
    try:
        raw = _TEST_OUTPUT.validate_json(text, strict=True)
    except ValidationError as exc:
        raise ForgeParseError(_describe(exc)) from exc
    suites = []
    for suite_name in sorted(raw, key=_utf8):
        suite = raw[suite_name]
        tests = tuple(
            _normalize_test(name, suite.test_results[name])
            for name in sorted(suite.test_results, key=_utf8)
        )
        suites.append(ForgeTestSuite(name=suite_name, tests=tests, warnings=tuple(suite.warnings)))
    return tuple(suites)


def summarize(suites: tuple[ForgeTestSuite, ...]) -> ForgeTestSummary:
    statuses = [test.status for suite in suites for test in suite.tests]
    return ForgeTestSummary(
        passed=statuses.count("success"),
        failed=statuses.count("failure"),
        skipped=statuses.count("skipped"),
    )


def parse_build_errors(text: str) -> tuple[ForgeDiagnostic, ...]:
    """Return the compiler errors (severity `error`) from the stdout of `forge build --json`."""
    try:
        raw = _BUILD_OUTPUT.validate_json(text, strict=True)
    except ValidationError as exc:
        raise ForgeParseError(_describe(exc)) from exc
    return tuple(
        ForgeDiagnostic(
            type=message.type,
            code=message.errorCode,
            message=message.message,
            file=message.sourceLocation.file if message.sourceLocation else None,
            start=message.sourceLocation.start if message.sourceLocation else None,
            end=message.sourceLocation.end if message.sourceLocation else None,
        )
        for message in raw.errors
        if message.severity == "error"
    )
