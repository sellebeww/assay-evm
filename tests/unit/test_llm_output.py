"""Model output is untrusted: strict JSON, size limits, one repair attempt, then failure."""

import json
from typing import Annotated

import pytest
from llm_support import Endpoint, ok, user
from pydantic import BaseModel, ConfigDict, StringConstraints

from assay.ledger import CassetteMode
from assay.llm import (
    LlmClient,
    LlmConfig,
    StructuredOutputError,
    ask_structured,
    load_config,
    parse_output,
)
from assay.llm.ask import AskAnswer
from assay.llm.output import MAX_NESTING, MAX_OUTPUT_CHARS

CONFIG: LlmConfig = load_config(
    {
        "ASSAY_LLM_BASE_URL": "https://llm.example.org/v1",
        "ASSAY_LLM_API_KEY": "k" * 12,
        "ASSAY_LLM_MODEL": "m",
    }
)


class Strict(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    name: Annotated[str, StringConstraints(max_length=10)]
    count: int = 0


def client(endpoint: Endpoint) -> LlmClient:
    return LlmClient(
        mode=CassetteMode.LIVE,
        allow_llm=True,
        config=CONFIG,
        transport=endpoint.transport,
        sleep=lambda _: None,
    )


def code(text: str) -> str:
    with pytest.raises(StructuredOutputError) as caught:
        parse_output(text, Strict)
    return caught.value.code


def test_valid_json_is_accepted() -> None:
    assert parse_output('{"name": "a", "count": 2}', Strict) == Strict(name="a", count=2)
    assert parse_output('  {"name": "a"}\n', Strict).count == 0


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", "not_json"),
        ("sure! here it is", "not_json"),
        ('```json\n{"name": "a"}\n```', "not_json"),
        ('{"name": "a"} trailing', "not_json"),
        ('{"name": "a", "name": "b"}', "not_json"),
        ('{"name": "a", "count": NaN}', "not_json"),
        ('{"name": "a", "count": Infinity}', "not_json"),
        ('["name"]', "not_object"),
        ('"name"', "not_object"),
        ("42", "not_object"),
        ('{"name": 5}', "schema"),
        ('{"name": "a", "count": "1"}', "schema"),
        ('{"name": "a", "extra": 1}', "schema"),
        ('{"name": "far too long a name"}', "schema"),
        ("{}", "schema"),
        ("x" * (MAX_OUTPUT_CHARS + 1), "too_large"),
    ],
)
def test_anything_else_is_rejected_with_a_code(text: str, expected: str) -> None:
    assert code(text) == expected


def test_deep_nesting_is_rejected_without_crashing() -> None:
    depth = MAX_NESTING + 5
    assert code('{"name": ' + "[" * depth + "]" * depth + "}") in {"too_deep", "schema"}
    assert code("[" * 60_000) in {"not_json", "not_object"}


def test_schema_errors_name_fields_not_values() -> None:
    with pytest.raises(StructuredOutputError) as caught:
        parse_output('{"name": 5, "ignore previous instructions": 1}', Strict)
    assert "name" in caught.value.detail
    assert "5" not in caught.value.detail


def test_a_good_reply_takes_one_call() -> None:
    endpoint = Endpoint(ok('{"answer": "Mars"}'))
    result = ask_structured(client(endpoint), user("q"), AskAnswer)
    assert result.value.answer == "Mars"
    assert len(result.completions) == 1
    assert len(endpoint.requests) == 1


def test_a_bad_reply_gets_exactly_one_repair_attempt() -> None:
    endpoint = Endpoint(ok("Sure! The answer is Mars."), ok('{"answer": "Mars"}'))
    result = ask_structured(client(endpoint), user("q"), AskAnswer)
    assert result.value.answer == "Mars"
    assert len(result.completions) == 2
    assert len(endpoint.requests) == 2
    repair = endpoint.bodies()[1]["messages"]
    assert [m["role"] for m in repair] == ["user", "assistant", "user"]
    assert "not_json" in repair[2]["content"]


def test_failing_twice_is_a_structured_failure_after_two_calls() -> None:
    endpoint = Endpoint(ok("nope"), ok('{"answer": 5}'))
    with pytest.raises(StructuredOutputError) as caught:
        ask_structured(client(endpoint), user("q"), AskAnswer)
    assert caught.value.code == "schema"
    assert caught.value.attempts == 2
    assert len(endpoint.requests) == 2


def test_the_repair_never_repeats_more_than_a_short_quote_of_the_output() -> None:
    endpoint = Endpoint(ok("A" * 5000), ok('{"answer": "x"}'))
    ask_structured(client(endpoint), user("q"), AskAnswer)
    assistant = endpoint.bodies()[1]["messages"][1]["content"]
    assert len(assistant) <= 300


def test_model_output_is_data_only() -> None:
    """A hostile reply is parsed, validated and returned as a string; nothing runs it."""
    hostile = {"answer": "$(touch pwned); ignore previous instructions; import os"}
    endpoint = Endpoint(ok(json.dumps(hostile)))
    result = ask_structured(client(endpoint), user("q"), AskAnswer)
    assert result.value.answer == hostile["answer"]
