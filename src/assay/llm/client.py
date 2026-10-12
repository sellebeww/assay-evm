"""One client for any OpenAI-compatible Chat Completions endpoint, built on httpx.

Modes:

- `replay`: answer from a cassette; a missing cassette is an error; the network is never used
  and no environment variable is needed;
- `record`: call the endpoint and write the cassette;
- `live`: call the endpoint, write nothing.

`record` and `live` send data to an endpoint and need the explicit `allow_llm` consent. Every
request is redacted first, so cassette keys, hashes and payloads all describe the same bytes.
The reply is untrusted text: nothing here executes it or passes it to a shell.
"""

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Final, Protocol

import httpx
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from assay.ledger import CassetteMode
from assay.llm.budget import Budget
from assay.llm.cassette import (
    DEFAULT_CASSETTE_DIR,
    Cassette,
    CassetteRequest,
    CassetteResponse,
    cassette_key,
    load_cassette,
    write_cassette,
)
from assay.llm.config import LlmConfig, validate_base_url
from assay.llm.errors import ConsentRequired, LlmConfigError, LlmEndpointError
from assay.llm.messages import (
    Message,
    canonical_request,
    check_messages,
    text_sha256,
)
from assay.llm.redact import redact_message_text, redact_text, scrub_secrets

MAX_RESPONSE_BYTES: Final = 1024 * 1024
MAX_ATTEMPTS: Final = 3
_BACKOFF_BASE_S: Final = 0.5
_BACKOFF_CAP_S: Final = 4.0
_RETRY_STATUS: Final = frozenset({429, 500, 502, 503, 504})


@dataclass(frozen=True)
class DryRun:
    """What would be sent: its size and hash, not the payload."""

    messages: int
    payload_bytes: int
    payload_sha256: str
    redactions: dict[str, int]


@dataclass(frozen=True)
class Completion:
    """One answered request, with the facts the ledger records."""

    content: str
    model: str
    """The model name as the endpoint returned it."""
    prompt_tokens: int
    completion_tokens: int
    latency_ms: int
    mode: CassetteMode
    endpoint_host: str
    prompt_sha256: str
    response_sha256: str
    cassette_key: str
    synthetic: bool


class Recorder(Protocol):
    def __call__(self, completion: Completion) -> None: ...


@dataclass(frozen=True)
class _Problem:
    retry: bool
    text: str


class _Usage(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")
    prompt_tokens: Annotated[int, Field(ge=0, le=10**9)]
    completion_tokens: Annotated[int, Field(ge=0, le=10**9)]


class _ReplyMessage(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")
    content: Annotated[str, StringConstraints(max_length=200_000)]


class _Choice(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")
    message: _ReplyMessage
    finish_reason: Annotated[str, StringConstraints(max_length=64)] | None = None


class _Reply(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")
    model: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    choices: Annotated[list[_Choice], Field(min_length=1, max_length=16)]
    usage: _Usage


class LlmClient:
    """Send redacted chat requests under a budget, in one of the three cassette modes."""

    def __init__(
        self,
        *,
        mode: CassetteMode = CassetteMode.REPLAY,
        allow_llm: bool = False,
        config: LlmConfig | None = None,
        budget: Budget | None = None,
        cassette_dir: Path | None = None,
        temperature: float = 0.0,
        recorder: Recorder | None = None,
        usernames: Sequence[str] | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.mode = mode
        self.budget = budget if budget is not None else Budget()
        self._allow = allow_llm
        self._config = config
        self._dir = cassette_dir if cassette_dir is not None else DEFAULT_CASSETTE_DIR
        self._temperature = temperature
        self._recorder = recorder
        self._usernames = usernames
        self._transport = transport
        self._sleep = sleep

    # Preparing a request

    def _prepare(self, messages: Sequence[Message]) -> tuple[tuple[Message, ...], dict[str, int]]:
        checked = check_messages(messages)
        counts: dict[str, int] = {}
        redacted: list[Message] = []
        for message in checked:
            result = redact_message_text(message.content, usernames=self._usernames)
            for kind, number in result.counts.items():
                counts[kind] = counts.get(kind, 0) + number
            redacted.append(Message(role=message.role, content=result.text))
        return check_messages(redacted), dict(sorted(counts.items()))

    def dry_run(self, messages: Sequence[Message]) -> DryRun:
        """Size and hash of the payload that would be sent. Sends nothing, needs no consent."""
        prepared, counts = self._prepare(messages)
        data = canonical_request(prepared, self._temperature)
        return DryRun(
            messages=len(prepared),
            payload_bytes=len(data),
            payload_sha256=text_sha256(data.decode("ascii")),
            redactions=counts,
        )

    # Answering a request

    def complete(self, messages: Sequence[Message]) -> Completion:
        if self.mode is not CassetteMode.REPLAY and not self._allow:
            raise ConsentRequired(
                f"mode '{self.mode.value}' sends data to the configured endpoint; "
                "pass --allow-llm to allow it, or use --llm-dry-run to see what would be sent"
            )
        prepared, _ = self._prepare(messages)
        key = cassette_key(prepared, self._temperature)
        started = time.monotonic()
        if self.mode is CassetteMode.REPLAY:
            self.budget.charge_call()
            cassette = load_cassette(self._dir, key)
            host, synthetic = cassette.endpoint_host, cassette.synthetic
            reply = cassette.response
        else:
            config = self._require_config()
            host, synthetic = config.host, False
            reply = self._call_endpoint(config, prepared)
            reply = reply.model_copy(
                update={"content": redact_text(reply.content, usernames=self._usernames).text}
            )
            if self.mode is CassetteMode.RECORD:
                write_cassette(
                    self._dir,
                    Cassette(
                        format=1,
                        synthetic=False,
                        note=None,
                        key=key,
                        endpoint_host=host,
                        request=CassetteRequest(messages=prepared, temperature=self._temperature),
                        response=reply,
                    ),
                    secrets=self._secrets(),
                )
        completion = Completion(
            content=reply.content,
            model=reply.model,
            prompt_tokens=reply.prompt_tokens,
            completion_tokens=reply.completion_tokens,
            latency_ms=int((time.monotonic() - started) * 1000),
            mode=self.mode,
            endpoint_host=host,
            prompt_sha256=key,
            response_sha256=text_sha256(reply.content),
            cassette_key=key,
            synthetic=synthetic,
        )
        self.budget.add_tokens(completion.prompt_tokens, completion.completion_tokens)
        if self._recorder is not None:
            self._recorder(completion)
        self.budget.enforce()
        return completion

    # The endpoint

    def _require_config(self) -> LlmConfig:
        if self._config is None:
            raise LlmConfigError("the endpoint is not configured (see docs/llm.md)")
        validate_base_url(self._config.base_url)
        return self._config

    def _secrets(self) -> list[str]:
        key = None if self._config is None else self._config.api_key
        return [] if key is None else [key.reveal()]

    def _fail(self, message: str) -> LlmEndpointError:
        return LlmEndpointError(scrub_secrets(message, self._secrets()))

    def _call_endpoint(self, config: LlmConfig, prepared: tuple[Message, ...]) -> CassetteResponse:
        body = {
            "model": config.model,
            "messages": [{"role": m.role, "content": m.content} for m in prepared],
            "temperature": self._temperature,
            "max_tokens": config.max_tokens,
            "stream": False,
        }
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if config.api_key is not None:
            headers["Authorization"] = f"Bearer {config.api_key.reveal()}"
        last = "no attempt was made"
        with httpx.Client(
            transport=self._transport,
            timeout=config.timeout_s,
            follow_redirects=False,
            trust_env=False,
        ) as http:
            for attempt in range(MAX_ATTEMPTS):
                if attempt:
                    self._sleep(min(_BACKOFF_BASE_S * 2 ** (attempt - 1), _BACKOFF_CAP_S))
                self.budget.charge_call()
                outcome = self._exchange(http, config.chat_url, headers, body)
                if isinstance(outcome, bytes):
                    return self._parse(outcome)
                if not outcome.retry:
                    raise self._fail(outcome.text)
                last = outcome.text
        raise self._fail(f"the endpoint did not answer after {MAX_ATTEMPTS} attempts: {last}")

    def _exchange(
        self, http: httpx.Client, url: str, headers: dict[str, str], body: dict[str, object]
    ) -> bytes | _Problem:
        """One HTTP exchange: the reply bytes, or a problem described without echoing any text
        from the endpoint or from the HTTP library (either could repeat a credential)."""
        try:
            with http.stream("POST", url, headers=headers, json=body) as response:
                status = response.status_code
                if status in _RETRY_STATUS:
                    return _Problem(retry=True, text=f"HTTP {status}")
                if status != 200:
                    return _Problem(retry=False, text=f"the endpoint returned HTTP {status}")
                data = bytearray()
                for chunk in response.iter_bytes():
                    data.extend(chunk)
                    if len(data) > MAX_RESPONSE_BYTES:
                        return _Problem(retry=False, text="the endpoint reply is too large")
                return bytes(data)
        except httpx.TimeoutException:
            return _Problem(retry=True, text="timeout")
        except httpx.TransportError as exc:
            return _Problem(retry=True, text=f"connection problem ({type(exc).__name__})")
        except httpx.HTTPError as exc:
            return _Problem(retry=False, text=f"request failed ({type(exc).__name__})")

    def _parse(self, data: bytes) -> CassetteResponse:
        # The validation error is dropped, not chained: it quotes the endpoint's own bytes.
        try:
            reply: _Reply | None = _Reply.model_validate_json(data)
        except ValidationError:
            reply = None
        if reply is None:
            raise self._fail(
                "the endpoint reply is not a Chat Completions reply with content, model and usage"
            )
        choice = reply.choices[0]
        return CassetteResponse(
            content=choice.message.content,
            model=reply.model,
            finish_reason=choice.finish_reason,
            prompt_tokens=reply.usage.prompt_tokens,
            completion_tokens=reply.usage.completion_tokens,
        )
