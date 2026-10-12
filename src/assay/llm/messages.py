"""The request model: chat messages, limits and the canonical form that cassette keys hash."""

import hashlib
import json
from collections.abc import Sequence
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from assay.llm.errors import PayloadError

MAX_MESSAGES: Final = 32
MAX_MESSAGE_CHARS: Final = 200_000
MAX_PAYLOAD_BYTES: Final = 256 * 1024
REQUEST_FORMAT: Final = 1


class Message(BaseModel):
    """One chat message."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    role: Literal["system", "user", "assistant"]
    content: Annotated[str, StringConstraints(max_length=MAX_MESSAGE_CHARS)]


def check_messages(messages: Sequence[Message]) -> tuple[Message, ...]:
    """Validate a conversation: 1 to `MAX_MESSAGES` messages, no NUL characters."""
    try:
        checked = tuple(Message.model_validate(m.model_dump()) for m in messages)
    except ValidationError as exc:
        raise PayloadError("a message is malformed") from exc
    if not 1 <= len(checked) <= MAX_MESSAGES:
        raise PayloadError(f"a request needs 1 to {MAX_MESSAGES} messages")
    if any("\x00" in m.content for m in checked):
        raise PayloadError("a message contains a NUL character")
    return checked


def canonical_request(messages: Sequence[Message], temperature: float) -> bytes:
    """The bytes that identify a request: messages and parameters, no environment values.

    The model name, the endpoint and the per-call token limit come from the environment and
    are left out on purpose, so a cassette recorded on one machine replays on another.
    """
    body = {
        "format": REQUEST_FORMAT,
        "messages": [{"role": m.role, "content": m.content} for m in messages],
        "temperature": float(temperature),
    }
    data = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    if len(data) > MAX_PAYLOAD_BYTES:
        raise PayloadError(f"the request is larger than {MAX_PAYLOAD_BYTES} bytes")
    return data


def request_sha256(messages: Sequence[Message], temperature: float) -> str:
    return hashlib.sha256(canonical_request(messages, temperature)).hexdigest()


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


Temperature = Annotated[float, Field(ge=0.0, le=2.0)]
