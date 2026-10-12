"""Model output is untrusted input: JSON only, validated by a strict model, one repair attempt.

Nothing here executes the output or passes it to a shell. A reply that is not one JSON object
that the expected model accepts is repaired once (the model sees the problem code and the
field names, never more of its own text than a short quote), then fails with a structured error.
"""

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Protocol

from pydantic import BaseModel, ValidationError

from assay.llm.client import Completion
from assay.llm.errors import StructuredOutputError
from assay.llm.messages import Message

MAX_OUTPUT_CHARS: Final = 64 * 1024
MAX_NESTING: Final = 32
_QUOTE_CHARS: Final = 300
_FIELD = re.compile(r"[^A-Za-z0-9_.\[\]-]")


class Completer(Protocol):
    def complete(self, messages: Sequence[Message]) -> Completion: ...


@dataclass(frozen=True)
class Structured[M: BaseModel]:
    value: M
    completions: tuple[Completion, ...]


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def _reject_constant(name: str) -> object:
    raise ValueError(f"{name} is not valid JSON")


def _depth(value: object, level: int = 0) -> int:
    if level > MAX_NESTING:
        return level
    if isinstance(value, dict):
        return max((_depth(item, level + 1) for item in value.values()), default=level + 1)
    if isinstance(value, list):
        return max((_depth(item, level + 1) for item in value), default=level + 1)
    return level


def parse_output[M: BaseModel](text: str, model: type[M]) -> M:
    """Parse `text` as one JSON object and validate it with `model`.

    Raises `StructuredOutputError` with attempts=1; `ask_structured` sets the real count.
    """
    if len(text) > MAX_OUTPUT_CHARS:
        raise StructuredOutputError("too_large", f"more than {MAX_OUTPUT_CHARS} characters", 1)
    try:
        data = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        raise StructuredOutputError("not_json", "the reply is not a single JSON value", 1) from exc
    if not isinstance(data, dict):
        raise StructuredOutputError("not_object", "the reply is not a JSON object", 1)
    if _depth(data) > MAX_NESTING:
        raise StructuredOutputError("too_deep", f"nesting deeper than {MAX_NESTING}", 1)
    try:
        return model.model_validate(data, strict=True)
    except ValidationError as exc:
        fields = sorted(
            {
                _FIELD.sub("?", ".".join(str(part) for part in error["loc"]))[:60] or "(root)"
                for error in exc.errors(include_url=False, include_input=False)
            }
        )[:8]
        raise StructuredOutputError("schema", "invalid fields: " + ", ".join(fields), 1) from exc


def _repair_messages(
    messages: Sequence[Message], bad: str, error: StructuredOutputError
) -> list[Message]:
    return [
        *messages,
        Message(role="assistant", content=bad[:_QUOTE_CHARS]),
        Message(
            role="user",
            content=(
                f"Your previous reply was rejected ({error.code}: {error.detail}). "
                "Reply again with only one JSON object that matches the requested format, "
                "with no text around it."
            ),
        ),
    ]


def ask_structured[M: BaseModel](
    client: Completer, messages: Sequence[Message], model: type[M]
) -> Structured[M]:
    """Ask for JSON matching `model`; repair the format once; then fail with a structured error."""
    first = client.complete(messages)
    try:
        return Structured(parse_output(first.content, model), (first,))
    except StructuredOutputError as error:
        problem = error
    second = client.complete(_repair_messages(messages, first.content, problem))
    try:
        return Structured(parse_output(second.content, model), (first, second))
    except StructuredOutputError as error:
        raise StructuredOutputError(error.code, error.detail, 2) from error
