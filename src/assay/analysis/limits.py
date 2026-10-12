"""Bounded parsing of JSON that an analyzer wrote (untrusted input, threat T13).

`load_json` checks the raw bytes before Python's JSON parser sees them: the total size, the
nesting depth, the length of every string and the number of values. The check is a single
iterative pass, so neither a deeply nested document nor a huge string can exhaust the stack or
the memory of the host. Only then is the text parsed, with duplicate object keys, `NaN` and
`Infinity` rejected and integers limited to `MAX_INTEGER_DIGITS` digits. Every violation raises
`AnalyzerOutputError` with a stable code; nothing in the document is ever executed.
"""

import json
import re
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field

OutputProblem = Literal[
    "output_too_large",
    "not_utf8",
    "too_deep",
    "string_too_long",
    "too_many_values",
    "malformed_json",
    "duplicate_key",
    "schema_mismatch",
    "path_outside_project",
    "too_many_results",
]

MAX_INTEGER_DIGITS: Final = 100


class OutputLimits(BaseModel):
    """Caps on analyzer output. The defaults leave room for large projects."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_bytes: int = Field(default=16 * 1024 * 1024, ge=1)
    max_depth: int = Field(default=64, ge=1, le=256)
    max_string_chars: int = Field(default=100_000, ge=1)
    max_values: int = Field(default=2_000_000, ge=1)
    max_results: int = Field(default=10_000, ge=1)


class AnalyzerOutputError(Exception):
    """The output of an analyzer is unusable. `code` names the problem; `detail` explains it."""

    def __init__(self, code: OutputProblem, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code: OutputProblem = code
        self.detail = detail


# A structural character, or the opening quote of a string.
_TOKEN: Final = re.compile(r'["\[\]{},:]')
# The body of a string up to (not including) its closing quote, escapes included. The unrolled
# form matches in linear time without backtracking.
_STRING_BODY: Final = re.compile(r'[^"\\]*(?:\\.[^"\\]*)*', re.DOTALL)


def check_shape(text: str, limits: OutputLimits) -> None:
    """Check depth, string lengths and the number of values in one pass over `text`.

    The pass does not validate the JSON grammar; it only bounds what the parser will see. A
    string's length is counted as written, escape sequences included. Values are counted at each
    container, string and separator, which over-counts slightly.
    """
    depth = 0
    values = 0
    position = 0
    while (token := _TOKEN.search(text, position)) is not None:
        char = token.group()
        position = token.end()
        if char == '"':
            body = _STRING_BODY.match(text, position)
            end = body.end() if body is not None else position
            if end - position > limits.max_string_chars:
                raise AnalyzerOutputError(
                    "string_too_long",
                    f"a string at offset {token.start()} is longer than "
                    f"{limits.max_string_chars} characters",
                )
            position = end + 1
        elif char in "[{":
            depth += 1
            if depth > limits.max_depth:
                raise AnalyzerOutputError(
                    "too_deep",
                    f"nesting deeper than {limits.max_depth} levels at offset {token.start()}",
                )
        elif char in "]}":
            depth -= 1
            continue
        values += 1
        if values > limits.max_values:
            raise AnalyzerOutputError(
                "too_many_values", f"more than {limits.max_values} JSON values"
            )


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AnalyzerOutputError("duplicate_key", f"duplicate object key {key[:80]!r}")
        result[key] = value
    return result


def _reject_constant(name: str) -> object:
    raise AnalyzerOutputError("malformed_json", f"non-standard constant {name}")


def _bounded_int(text: str) -> int:
    if len(text.lstrip("-")) > MAX_INTEGER_DIGITS:
        raise AnalyzerOutputError(
            "malformed_json", f"integer with more than {MAX_INTEGER_DIGITS} digits"
        )
    return int(text)


def load_json(data: bytes, limits: OutputLimits) -> object:
    """Parse untrusted JSON bytes within `limits`, or raise `AnalyzerOutputError`."""
    if len(data) > limits.max_bytes:
        raise AnalyzerOutputError(
            "output_too_large", f"{len(data)} bytes, more than the limit of {limits.max_bytes}"
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AnalyzerOutputError("not_utf8", f"invalid UTF-8 at byte {exc.start}") from exc
    if not text.strip(" \t\r\n"):
        raise AnalyzerOutputError("malformed_json", "the output is empty")
    check_shape(text, limits)
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
            parse_int=_bounded_int,
        )
    except AnalyzerOutputError:
        raise
    except (ValueError, RecursionError) as exc:
        raise AnalyzerOutputError("malformed_json", str(exc)[:200]) from exc
