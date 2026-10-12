"""Cassettes: recorded model exchanges stored as JSON files, one per request key.

A cassette holds the redacted request, the reply and the provenance of the reply (the model name
the endpoint returned, as it came). It holds no header, no API key and no absolute host path;
`write_cassette` refuses to write a cassette that still looks like it does.
"""

import json
import os
import re
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from assay.llm.errors import CassetteError, CassetteMissing
from assay.llm.messages import Message, Temperature, request_sha256
from assay.llm.redact import redact_message_text

DEFAULT_CASSETTE_DIR: Final = Path("tests") / "data" / "cassettes"
MAX_CASSETTE_BYTES: Final = 1024 * 1024
_KEY: Final = re.compile(r"^[0-9a-f]{64}$")

Hex64 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Host = Annotated[
    str, StringConstraints(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9.:\[\]_-]+$")
]
TokenCount = Annotated[int, Field(ge=0, le=10**9)]


class _Strict(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")


class CassetteRequest(_Strict):
    messages: tuple[Message, ...]
    temperature: Temperature


class CassetteResponse(_Strict):
    content: Annotated[str, StringConstraints(max_length=200_000)]
    model: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    """The model name exactly as the endpoint returned it (provenance)."""
    finish_reason: Annotated[str, StringConstraints(max_length=64)] | None
    prompt_tokens: TokenCount
    completion_tokens: TokenCount


class Cassette(_Strict):
    format: Literal[1]
    synthetic: bool
    note: Annotated[str, StringConstraints(max_length=300)] | None
    key: Hex64
    endpoint_host: Host
    request: CassetteRequest
    response: CassetteResponse

    def strings(self) -> Iterable[str]:
        """Every free-text value, for the final cleanliness check."""
        yield from (m.content for m in self.request.messages)
        yield self.response.content
        yield self.response.model
        yield self.endpoint_host
        if self.note is not None:
            yield self.note


def cassette_key(messages: tuple[Message, ...], temperature: float) -> str:
    return request_sha256(messages, temperature)


def cassette_path(directory: Path, key: str) -> Path:
    if not _KEY.fullmatch(key):
        raise CassetteError("a cassette key is 64 lowercase hex characters")
    return directory / f"{key}.json"


def load_cassette(directory: Path, key: str) -> Cassette:
    """Read the cassette for `key`; a missing file is `CassetteMissing`, never a network call."""
    path = cassette_path(directory, key)
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise CassetteMissing(
            f"no cassette for this request (key {key[:16]}) in {directory}; "
            "replay mode never contacts the network"
        ) from None
    except OSError as exc:
        raise CassetteError(f"cassette {key[:16]} cannot be read") from exc
    if path.is_symlink() or not path.is_file() or info.st_size > MAX_CASSETTE_BYTES:
        raise CassetteError(f"cassette {key[:16]} is not a regular file of acceptable size")
    try:
        cassette = Cassette.model_validate_json(path.read_bytes())
    except (ValidationError, OSError, ValueError) as exc:
        raise CassetteError(f"cassette {key[:16]} is malformed") from exc
    if (
        cassette.key != key
        or cassette_key(cassette.request.messages, cassette.request.temperature) != key
    ):
        raise CassetteError(f"cassette {key[:16]} does not match its own request hash")
    return cassette


def check_clean(cassette: Cassette, secrets: Iterable[str] = ()) -> None:
    """Raise when a cassette still holds a secret, a secret-like pattern or a host path."""
    known = [s for s in secrets if s]
    for text in cassette.strings():
        if any(secret in text for secret in known) or redact_message_text(text).total:
            raise CassetteError(
                "refusing to write a cassette that still holds a secret-like value or a path"
            )


def write_cassette(directory: Path, cassette: Cassette, secrets: Iterable[str] = ()) -> Path:
    """Write `cassette` atomically as `<key>.json`, after the cleanliness check."""
    check_clean(cassette, secrets)
    path = cassette_path(directory, cassette.key)
    text = json.dumps(cassette.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=True)
    try:
        directory.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(dir=directory, prefix=".cassette-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                handle.write(text + "\n")
            os.replace(temp, path)
        except BaseException:
            Path(temp).unlink(missing_ok=True)
            raise
    except OSError as exc:
        raise CassetteError(f"cassette {cassette.key[:16]} cannot be written") from exc
    return path
