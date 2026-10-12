"""Helpers for the LLM tests: a network blocker, fake secrets and a scripted endpoint."""

import json
import socket
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from assay.llm import Message

# Obviously fake values, assembled at run time so that no scanner mistakes them for real ones.
FAKE_API_KEY = "sk-" + "FAKEKEY0" * 4
FAKE_BEARER_SECRET = "FAKE" + "0123456789abcdef" * 2
FAKE_HEX_KEY = "ab" * 32
FAKE_MNEMONIC = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima"


def user(text: str) -> list[Message]:
    return [Message(role="user", content=text)]


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any attempt to open a socket or resolve a name fail the test."""

    def refuse(*_: Any, **__: Any) -> Any:
        raise AssertionError("the test tried to use the network")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def reply_body(
    content: str,
    *,
    model: str = "test-model-1",
    prompt_tokens: int = 10,
    completion_tokens: int = 5,
    usage: bool = True,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "id": "x",
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}}],
    }
    body["choices"][0]["finish_reason"] = "stop"
    if usage:
        body["usage"] = {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens}
    return body


class Endpoint:
    """A scripted endpoint: each request gets the next scripted answer (the last one repeats)."""

    def __init__(self, *answers: httpx.Response | Exception | Callable[[], httpx.Response]) -> None:
        self.answers = list(answers)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, Exception):
            raise answer
        return answer() if callable(answer) else answer

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)

    def bodies(self) -> list[dict[str, Any]]:
        return [json.loads(r.content) for r in self.requests]


def ok(content: str = '{"answer": "Mars"}', **kwargs: Any) -> httpx.Response:
    return httpx.Response(200, json=reply_body(content, **kwargs))
