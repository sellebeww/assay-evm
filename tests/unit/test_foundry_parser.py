import json
from pathlib import Path
from typing import Any

import pytest

from assay.analyzers.foundry import (
    ForgeDiagnostic,
    ForgeEvent,
    ForgeParseError,
    ForgeTestSummary,
    parse_build_errors,
    parse_test_output,
    summarize,
)

DATA = Path(__file__).resolve().parents[1] / "data" / "forge"


def probe_text() -> str:
    return (DATA / "probe-test.json").read_text(encoding="utf-8")


def unit_test(**overrides: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "Success",
        "reason": None,
        "decoded_logs": [],
        "kind": {"Unit": {"gas": 100}},
    }
    result.update(overrides)
    return result


def output(tests: dict[str, Any], suite: str = "test/A.t.sol:A") -> str:
    return json.dumps({suite: {"duration": "1ms", "test_results": tests, "warnings": []}})


def test_probe_output_is_normalized() -> None:
    suites = parse_test_output(probe_text())

    assert [suite.name for suite in suites] == [
        "test/Probe.t.sol:ProbeInvariantTest",
        "test/Probe.t.sol:ProbeTest",
    ]
    (invariant,) = suites[0].tests
    assert invariant.name == "invariant_CountStaysSmall()"
    assert (invariant.kind, invariant.status) == ("invariant", "success")
    assert (invariant.runs, invariant.calls, invariant.reverts) == (256, 128000, 0)
    assert invariant.gas is None

    tests = {test.name: test for test in suites[1].tests}
    assert list(tests) == [
        "tableAmount(uint256)",
        "testFuzz_Fails(uint256)",
        "testFuzz_Passes(uint256)",
        "test_Fails()",
        "test_Passes()",
        "test_Skipped()",
    ]
    passes = tests["test_Passes()"]
    assert (passes.kind, passes.status, passes.reason) == ("unit", "success", None)
    assert passes.logs == ("probe log 7",)
    assert isinstance(passes.gas, int)
    assert passes.gas > 0

    assert tests["test_Fails()"].status == "failure"
    assert tests["test_Fails()"].reason == "one is not two: 1 != 2"
    assert tests["test_Skipped()"].status == "skipped"
    assert tests["test_Skipped()"].reason == "not applicable"

    fuzz = tests["testFuzz_Passes(uint256)"]
    assert (fuzz.kind, fuzz.status, fuzz.runs, fuzz.gas) == ("fuzz", "success", 256, None)
    assert fuzz.mean_gas is not None
    assert fuzz.median_gas is not None
    fuzz_failure = tests["testFuzz_Fails(uint256)"]
    assert fuzz_failure.status == "failure"
    assert fuzz_failure.reason is not None
    assert fuzz_failure.reason.startswith("assertion failed:")

    table = tests["tableAmount(uint256)"]
    assert (table.kind, table.status, table.runs) == ("table", "success", 3)

    assert summarize(suites) == ForgeTestSummary(passed=4, failed=2, skipped=1)


def test_durations_and_unused_fields_are_dropped() -> None:
    normalized = json.dumps(
        [suite.model_dump(mode="json") for suite in parse_test_output(probe_text())]
    )
    for dropped in ("duration", "µs", "traces", "labeled_addresses", "first_case", "metrics"):
        assert dropped not in normalized


def test_normalization_does_not_depend_on_input_order() -> None:
    raw = json.loads(probe_text())
    reordered = {
        name: {**suite, "test_results": dict(reversed(list(suite["test_results"].items())))}
        for name, suite in reversed(list(raw.items()))
    }
    assert parse_test_output(json.dumps(reordered)) == parse_test_output(probe_text())


def test_empty_object_means_no_suites() -> None:
    assert parse_test_output("{}") == ()
    assert summarize(()) == ForgeTestSummary(passed=0, failed=0, skipped=0)


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("", id="empty"),
        pytest.param("Error: Compiler run failed", id="not-json"),
        pytest.param("[]", id="array"),
        pytest.param(output({"t()": unit_test(status="Passed")}), id="unknown-status"),
        pytest.param(output({"t()": unit_test(kind={"Mystery": {}})}), id="unknown-kind"),
        pytest.param(
            output({"t()": unit_test(kind={"Unit": {"gas": 1}, "Fuzz": {}})}), id="two-kinds"
        ),
        pytest.param(output({"t()": unit_test(kind={})}), id="no-kind"),
        pytest.param(output({"t()": unit_test(kind={"Unit": {"gas": -1}})}), id="negative-gas"),
        pytest.param(output({"t()": unit_test(kind={"Unit": {"gas": "1"}})}), id="string-gas"),
        pytest.param(output({"t()": unit_test(reason=7)}), id="number-reason"),
        pytest.param(output({"t" * 2000: unit_test()}), id="long-name"),
        pytest.param(output({"t()": unit_test(reason="r" * 70_000)}), id="long-reason"),
        pytest.param(output({"t()": unit_test(decoded_logs=["l"] * 10_001)}), id="many-logs"),
        pytest.param(output({"t()": {"reason": None}}), id="missing-fields"),
        pytest.param("[" * 100_000 + "]" * 100_000, id="deep-nesting"),
    ],
)
def test_malformed_output_is_a_structured_error(text: str) -> None:
    with pytest.raises(ForgeParseError):
        parse_test_output(text)


def test_error_message_does_not_echo_input_values() -> None:
    with pytest.raises(ForgeParseError) as info:
        parse_test_output(
            output({"t()": unit_test(reason="\x1b[31msecret-value")}).replace(
                '"Success"', '"Bogus"'
            )
        )
    assert "secret-value" not in str(info.value)


def test_compiler_errors_are_extracted() -> None:
    errors = parse_build_errors((DATA / "broken-build.json").read_text(encoding="utf-8"))
    assert errors == (
        ForgeDiagnostic(
            type="DeclarationError",
            code="7576",
            message="Undeclared identifier.",
            file="test/Broken.t.sol",
            start=196,
            end=203,
        ),
    )


def test_compiler_warnings_are_not_reported() -> None:
    warning = {
        "severity": "warning",
        "type": "Warning",
        "errorCode": "2018",
        "message": "Function state mutability can be restricted to pure",
    }
    assert parse_build_errors(json.dumps({"errors": [warning], "contracts": {}})) == ()


@pytest.mark.parametrize(
    "text",
    ["", "{", '{"errors": "none"}', '{"errors": [{"severity": "error"}]}'],
)
def test_malformed_build_output_is_a_structured_error(text: str) -> None:
    with pytest.raises(ForgeParseError):
        parse_build_errors(text)


def test_raw_logs_are_kept_as_lowercase_events() -> None:
    log = {"address": "0x" + "AB" * 20, "topics": ["0x" + "CD" * 32], "data": "0x0A"}
    (suite,) = parse_test_output(output({"t()": unit_test(logs=[log])}))
    assert suite.tests[0].events == (
        ForgeEvent(address="0x" + "ab" * 20, topics=("0x" + "cd" * 32,), data="0x0a"),
    )


def test_probe_console_log_is_an_event_of_the_console_address() -> None:
    tests = {test.name: test for test in parse_test_output(probe_text())[1].tests}
    (event,) = tests["test_Passes()"].events
    assert event.address == "0x000000000000000000636f6e736f6c652e6c6f67"


@pytest.mark.parametrize(
    "log",
    [
        {"address": "0x12", "topics": [], "data": "0x"},
        {"address": "0x" + "ab" * 20, "topics": ["0x12"], "data": "0x"},
        {"address": "0x" + "ab" * 20, "topics": ["0x" + "cd" * 32] * 5, "data": "0x"},
        {"address": "0x" + "ab" * 20, "topics": [], "data": "0x123"},
        {"address": "0x" + "ab" * 20, "topics": [], "data": "0x" + "00" * 70_000},
        {"address": "0x" + "ab" * 20, "topics": []},
    ],
)
def test_malformed_events_are_a_structured_error(log: dict[str, Any]) -> None:
    with pytest.raises(ForgeParseError):
        parse_test_output(output({"t()": unit_test(logs=[log])}))


def test_counterexamples_are_kept_with_their_calldata() -> None:
    tests = {case.name: case for suite in parse_test_output(probe_text()) for case in suite.tests}
    counterexample = tests["testFuzz_Fails(uint256)"].counterexample
    assert counterexample is not None
    assert counterexample.kind == "single"
    (call,) = counterexample.calls
    assert call.calldata.startswith("0xfbd9e9b2")
    assert call.args == "742886487892369547698386939959150855759913659"
    assert call.run == 1
    assert tests["testFuzz_Passes(uint256)"].counterexample is None


def _with_counterexample(value: object) -> str:
    case = {
        "status": "Failure",
        "reason": "x",
        "counterexample": value,
        "logs": [],
        "decoded_logs": [],
        "kind": {"Invariant": {"runs": 1, "calls": 2, "reverts": 0}},
    }
    return json.dumps({"test/A.t.sol:A": {"test_results": {"invariant_x()": case}}})


def test_sequence_counterexamples_are_parsed() -> None:
    steps = [{"calldata": "0xAB", "sender": "0x00"}, {"calldata": "0x", "raw_args": "1"}]
    (suite,) = parse_test_output(_with_counterexample({"Sequence": steps}))
    counterexample = suite.tests[0].counterexample
    assert counterexample is not None
    assert counterexample.kind == "sequence"
    assert [(call.calldata, call.args) for call in counterexample.calls] == [
        ("0xab", None),
        ("0x", "1"),
    ]


@pytest.mark.parametrize(
    "value",
    [
        {},
        {"Single": {"calldata": "0x00"}, "Sequence": []},
        {"Other": {}},
        {"Single": {"calldata": "zz"}},
        {"Single": {}},
        "0x00",
    ],
)
def test_malformed_counterexamples_are_rejected(value: object) -> None:
    with pytest.raises(ForgeParseError):
        parse_test_output(_with_counterexample(value))
