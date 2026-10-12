"""The client: consent, dry run, budgets, retries, modes and redaction before sending."""

from pathlib import Path

import httpx
import pytest
from llm_support import FAKE_API_KEY, FAKE_HEX_KEY, Endpoint, no_network, ok, reply_body, user

from assay.ledger import CassetteMode
from assay.llm import (
    Budget,
    BudgetExceeded,
    CassetteMissing,
    ConsentRequired,
    LlmClient,
    LlmConfigError,
    LlmEndpointError,
    PayloadError,
    load_config,
)
from assay.llm.cassette import cassette_key, cassette_path, load_cassette
from assay.llm.messages import MAX_MESSAGES, Message

CONFIG = load_config(
    {
        "ASSAY_LLM_BASE_URL": "https://llm.example.org/v1",
        "ASSAY_LLM_API_KEY": FAKE_API_KEY,
        "ASSAY_LLM_MODEL": "configured-model",
    }
)
__all__ = ["no_network"]


def live(endpoint: Endpoint, **kwargs: object) -> LlmClient:
    options: dict[str, object] = {
        "mode": CassetteMode.LIVE,
        "allow_llm": True,
        "config": CONFIG,
        "transport": endpoint.transport,
        "sleep": lambda _: None,
        "usernames": (),
    }
    return LlmClient(**{**options, **kwargs})  # type: ignore[arg-type]


# Consent and dry run


@pytest.mark.parametrize("mode", [CassetteMode.RECORD, CassetteMode.LIVE])
def test_sending_modes_need_the_explicit_consent(mode: CassetteMode, tmp_path: Path) -> None:
    endpoint = Endpoint(ok())
    client = LlmClient(
        mode=mode, config=CONFIG, transport=endpoint.transport, cassette_dir=tmp_path
    )
    with pytest.raises(ConsentRequired, match="--allow-llm"):
        client.complete(user("hello"))
    assert endpoint.requests == []
    assert list(tmp_path.iterdir()) == []


def test_dry_run_reports_size_and_hash_and_sends_nothing(no_network: None) -> None:
    client = LlmClient(mode=CassetteMode.LIVE, usernames=())
    plan = client.dry_run(user(f"look at 0x{FAKE_HEX_KEY} and /Users/someone/a/b"))
    again = client.dry_run(user(f"look at 0x{FAKE_HEX_KEY} and /Users/someone/a/b"))
    assert plan == again
    assert plan.messages == 1
    assert plan.payload_bytes > 0
    assert len(plan.payload_sha256) == 64
    assert plan.redactions == {"path": 1}
    other = client.dry_run(user("another question"))
    assert other.payload_sha256 != plan.payload_sha256


def test_dry_run_hashes_the_redacted_payload() -> None:
    client = LlmClient(usernames=("someone",))
    a = client.dry_run(user("hello someone"))
    b = client.dry_run(user("hello <user>"))
    assert a.payload_sha256 == b.payload_sha256


# Redaction before sending


def test_the_endpoint_receives_only_redacted_text() -> None:
    endpoint = Endpoint(ok())
    live(endpoint, usernames=("someone",)).complete(
        user(f"key {FAKE_API_KEY} at /Users/someone/project/src/A.sol by someone")
    )
    body = endpoint.bodies()[0]
    sent = body["messages"][0]["content"]
    assert FAKE_API_KEY not in sent
    assert "/Users" not in sent
    assert "someone" not in sent
    assert body["temperature"] == 0.0
    assert body["model"] == "configured-model"
    assert body["max_tokens"] == CONFIG.max_tokens
    assert body["stream"] is False
    assert str(endpoint.requests[0].url) == "https://llm.example.org/v1/chat/completions"


def test_a_reply_is_redacted_before_it_is_returned() -> None:
    endpoint = Endpoint(ok(f"use /Users/someone/x/y and {FAKE_API_KEY}"))
    result = live(endpoint).complete(user("hi"))
    assert FAKE_API_KEY not in result.content
    assert "/Users" not in result.content


def test_payload_limits() -> None:
    client = LlmClient()
    with pytest.raises(PayloadError):
        client.complete([])
    with pytest.raises(PayloadError):
        client.complete([Message(role="user", content="a")] * (MAX_MESSAGES + 1))
    with pytest.raises(PayloadError):
        client.dry_run([Message(role="user", content="a" * 150_000)] * 2)
    with pytest.raises(PayloadError):
        client.dry_run(user("nul\x00byte"))


# Budgets


def test_call_budget_stops_with_a_clear_error() -> None:
    endpoint = Endpoint(ok())
    client = live(endpoint, budget=Budget(max_calls=2, max_tokens=1000))
    client.complete(user("one"))
    client.complete(user("two"))
    with pytest.raises(BudgetExceeded, match="call budget exhausted: 2 of 2"):
        client.complete(user("three"))
    assert len(endpoint.requests) == 2


def test_token_budget_uses_the_usage_the_endpoint_reports() -> None:
    endpoint = Endpoint(ok(prompt_tokens=60, completion_tokens=50))
    client = live(endpoint, budget=Budget(max_calls=5, max_tokens=100))
    with pytest.raises(BudgetExceeded, match="token budget exceeded: 110 tokens used, limit 100"):
        client.complete(user("one"))
    with pytest.raises(BudgetExceeded, match="token budget exhausted"):
        client.complete(user("two"))
    assert len(endpoint.requests) == 1


def test_the_over_budget_call_is_still_recorded() -> None:
    seen: list[int] = []
    client = live(
        Endpoint(ok(prompt_tokens=90, completion_tokens=90)),
        budget=Budget(max_calls=5, max_tokens=100),
        recorder=lambda completion: seen.append(completion.prompt_tokens),
    )
    with pytest.raises(BudgetExceeded):
        client.complete(user("one"))
    assert seen == [90]


def test_missing_usage_fails_instead_of_counting_nothing() -> None:
    client = live(Endpoint(httpx.Response(200, json=reply_body("{}", usage=False))))
    with pytest.raises(LlmEndpointError, match="usage"):
        client.complete(user("one"))


@pytest.mark.parametrize(("calls", "tokens"), [(0, 10), (-1, 10), (1, 0), (1001, 10), (1, 10**8)])
def test_budget_values_are_bounded(calls: int, tokens: int) -> None:
    with pytest.raises(Exception, match="budget must be between"):
        Budget(max_calls=calls, max_tokens=tokens)


def test_each_http_attempt_counts_as_a_call() -> None:
    endpoint = Endpoint(httpx.Response(503), ok())
    client = live(endpoint, budget=Budget(max_calls=1, max_tokens=1000))
    with pytest.raises(BudgetExceeded, match="call budget exhausted"):
        client.complete(user("one"))
    assert len(endpoint.requests) == 1


# Retries


def test_transient_failures_are_retried_with_a_bounded_backoff() -> None:
    sleeps: list[float] = []
    endpoint = Endpoint(httpx.Response(429), httpx.ConnectError("x"), ok())
    client = live(endpoint, sleep=sleeps.append)
    assert client.complete(user("one")).content == '{"answer": "Mars"}'
    assert len(endpoint.requests) == 3
    assert sleeps == [0.5, 1.0]
    assert client.budget.calls == 3


def test_retries_are_limited_and_then_fail_clearly() -> None:
    endpoint = Endpoint(httpx.Response(500))
    with pytest.raises(LlmEndpointError, match="did not answer after 3 attempts: HTTP 500"):
        live(endpoint).complete(user("one"))
    assert len(endpoint.requests) == 3


def test_a_client_error_is_not_retried() -> None:
    endpoint = Endpoint(httpx.Response(400, text="bad"))
    with pytest.raises(LlmEndpointError, match="HTTP 400"):
        live(endpoint).complete(user("one"))
    assert len(endpoint.requests) == 1


def test_redirects_are_not_followed() -> None:
    endpoint = Endpoint(httpx.Response(302, headers={"location": "https://elsewhere.example/x"}))
    with pytest.raises(LlmEndpointError, match="HTTP 302"):
        live(endpoint).complete(user("one"))
    assert len(endpoint.requests) == 1


@pytest.mark.parametrize(
    "answer",
    [
        httpx.Response(200, text="not json"),
        httpx.Response(200, json={"choices": []}),
        httpx.Response(200, json={"model": "m", "choices": [{"message": {"content": None}}]}),
        httpx.Response(200, json=reply_body("x", prompt_tokens=-1)),
        httpx.Response(200, json={**reply_body("x"), "usage": {"prompt_tokens": "1"}}),
    ],
)
def test_malformed_replies_are_endpoint_errors(answer: httpx.Response) -> None:
    with pytest.raises(LlmEndpointError):
        live(Endpoint(answer)).complete(user("one"))


def test_an_oversized_reply_is_refused() -> None:
    big = httpx.Response(200, content=b"x" * (1024 * 1024 + 10))
    with pytest.raises(LlmEndpointError, match="too large"):
        live(Endpoint(big)).complete(user("one"))


def test_live_mode_without_a_configuration_is_a_config_error() -> None:
    client = LlmClient(mode=CassetteMode.LIVE, allow_llm=True)
    with pytest.raises(LlmConfigError):
        client.complete(user("one"))


# Modes and provenance


def test_record_writes_a_cassette_that_replay_then_uses(tmp_path: Path, no_network: None) -> None:
    del no_network
    endpoint = Endpoint(ok(model="returned-model-7"))
    recorded = live(endpoint, mode=CassetteMode.RECORD, cassette_dir=tmp_path).complete(
        user("a neutral question")
    )
    key = cassette_key((Message(role="user", content="a neutral question"),), 0.0)
    assert cassette_path(tmp_path, key).is_file()
    assert recorded.cassette_key == key
    stored = load_cassette(tmp_path, key)
    assert stored.response.model == "returned-model-7"
    assert not stored.synthetic
    assert stored.endpoint_host == "llm.example.org"
    text = cassette_path(tmp_path, key).read_text()
    assert FAKE_API_KEY not in text
    assert "authorization" not in text.lower()
    assert "bearer" not in text.lower()

    replayed = LlmClient(cassette_dir=tmp_path, usernames=()).complete(user("a neutral question"))
    assert replayed.content == recorded.content
    assert replayed.mode is CassetteMode.REPLAY
    assert replayed.model == "returned-model-7"
    assert replayed.prompt_sha256 == recorded.prompt_sha256
    assert replayed.response_sha256 == recorded.response_sha256
    assert len(endpoint.requests) == 1


def test_live_mode_writes_no_cassette(tmp_path: Path) -> None:
    live(Endpoint(ok()), cassette_dir=tmp_path).complete(user("one"))
    assert list(tmp_path.iterdir()) == []


def test_replay_without_a_cassette_is_an_error_and_never_uses_the_network(
    tmp_path: Path, no_network: None
) -> None:
    del no_network
    with pytest.raises(CassetteMissing, match="never contacts the network"):
        LlmClient(cassette_dir=tmp_path).complete(user("nobody recorded this"))


def test_replay_ignores_the_environment_and_a_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_network: None
) -> None:
    del no_network
    for name in ("ASSAY_LLM_BASE_URL", "ASSAY_LLM_API_KEY", "ASSAY_LLM_MODEL"):
        monkeypatch.delenv(name, raising=False)
    live(Endpoint(ok()), mode=CassetteMode.RECORD, cassette_dir=tmp_path).complete(user("q"))
    client = LlmClient(mode=CassetteMode.REPLAY, config=CONFIG, cassette_dir=tmp_path)
    assert client.complete(user("q")).endpoint_host == "llm.example.org"
