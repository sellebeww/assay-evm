"""Endpoint configuration: environment only, https or localhost, and the key never leaks."""

import logging
import pickle

import httpx
import pytest
from llm_support import FAKE_API_KEY, Endpoint, ok, user

from assay.ledger import CassetteMode
from assay.llm import ApiKey, LlmClient, LlmConfigError, LlmEndpointError, load_config
from assay.llm.config import ENV_NAMES, env_status, validate_base_url

GOOD = {
    "ASSAY_LLM_BASE_URL": "https://llm.example.org/v1",
    "ASSAY_LLM_API_KEY": FAKE_API_KEY,
    "ASSAY_LLM_MODEL": "some-model",
}


def test_config_comes_only_from_the_given_environment() -> None:
    config = load_config(GOOD)
    assert config.base_url == "https://llm.example.org/v1"
    assert config.model == "some-model"
    assert config.timeout_s == 60.0
    assert config.max_tokens == 1024
    assert config.host == "llm.example.org"
    assert config.chat_url == "https://llm.example.org/v1/chat/completions"


def test_optional_timeout_and_max_tokens() -> None:
    config = load_config({**GOOD, "ASSAY_LLM_TIMEOUT_S": "5", "ASSAY_LLM_MAX_TOKENS": "256"})
    assert config.timeout_s == 5.0
    assert config.max_tokens == 256


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("ASSAY_LLM_TIMEOUT_S", "0"),
        ("ASSAY_LLM_TIMEOUT_S", "abc"),
        ("ASSAY_LLM_TIMEOUT_S", "100000"),
        ("ASSAY_LLM_MAX_TOKENS", "0"),
        ("ASSAY_LLM_MAX_TOKENS", "1.5"),
        ("ASSAY_LLM_MAX_TOKENS", "99999999"),
        ("ASSAY_LLM_MODEL", "x" * 201),
    ],
)
def test_out_of_range_options_are_rejected(name: str, value: str) -> None:
    with pytest.raises(LlmConfigError):
        load_config({**GOOD, name: value})


def test_missing_variables_are_named_without_values() -> None:
    with pytest.raises(LlmConfigError, match="ASSAY_LLM_BASE_URL, ASSAY_LLM_MODEL"):
        load_config({})
    with pytest.raises(LlmConfigError, match="ASSAY_LLM_API_KEY"):
        load_config({**GOOD, "ASSAY_LLM_API_KEY": ""})


def test_a_localhost_endpoint_may_omit_the_key() -> None:
    config = load_config(
        {"ASSAY_LLM_BASE_URL": "http://localhost:11434/v1", "ASSAY_LLM_MODEL": "local"}
    )
    assert config.api_key is None
    assert config.host == "localhost:11434"


@pytest.mark.parametrize(
    "url",
    [
        "http://llm.example.org/v1",
        "http://10.0.0.5:8000/v1",
        "http://localhost.example.org/v1",
        "ftp://llm.example.org",
        "file:///etc/passwd",
        "llm.example.org/v1",
        "https://",
        "https://user:pass@llm.example.org/v1",
        "https://user@llm.example.org/v1",
        "https://llm.example.org/v1?key=abc",
        "https://llm.example.org/v1#frag",
        "https://llm.example.org:99999/v1",
        "https://llm.example.org/v1 ",
        "https://llm.example.org/\nv1",
        "https://llm\u2024example.org/v1",
        "",
    ],
)
def test_unsafe_base_urls_are_refused(url: str) -> None:
    with pytest.raises(LlmConfigError):
        validate_base_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://llm.example.org",
        "https://llm.example.org:8443/v1/",
        "https://localhost/v1",
        "http://localhost:8080/v1",
        "http://127.0.0.1:8080/v1",
        "http://[::1]:8080/v1",
    ],
)
def test_https_and_localhost_urls_are_accepted(url: str) -> None:
    assert validate_base_url(url) == url


def test_the_url_error_does_not_echo_the_url() -> None:
    secret_url = "https://user:" + FAKE_API_KEY + "@llm.example.org/v1"
    with pytest.raises(LlmConfigError) as caught:
        validate_base_url(secret_url)
    assert FAKE_API_KEY not in str(caught.value)


def test_the_client_validates_a_hand_built_config_too() -> None:
    config = load_config(GOOD)
    bad = type(config)(
        base_url="http://llm.example.org/v1", model="m", api_key=None, timeout_s=5, max_tokens=5
    )
    client = LlmClient(mode=CassetteMode.LIVE, allow_llm=True, config=bad)
    with pytest.raises(LlmConfigError):
        client.complete(user("hello"))


def test_the_key_is_not_visible_in_any_string_form() -> None:
    config = load_config(GOOD)
    key = config.api_key
    assert isinstance(key, ApiKey)
    assert key.reveal() == FAKE_API_KEY
    for text in (repr(key), str(key), f"{key}", repr(config), str(config), f"{config!r}"):
        assert FAKE_API_KEY not in text
    with pytest.raises(TypeError):
        pickle.dumps(key)


def test_env_status_prints_set_or_not_set_only() -> None:
    status = env_status({**GOOD, "ASSAY_LLM_TIMEOUT_S": ""})
    assert set(status) == set(ENV_NAMES)
    assert status["ASSAY_LLM_API_KEY"] == "SET"
    assert status["ASSAY_LLM_TIMEOUT_S"] == "NOT SET"
    assert FAKE_API_KEY not in repr(status)


def test_the_key_reaches_only_the_authorization_header() -> None:
    endpoint = Endpoint(ok())
    client = LlmClient(
        mode=CassetteMode.LIVE,
        allow_llm=True,
        config=load_config(GOOD),
        transport=endpoint.transport,
    )
    client.complete(user("hello"))
    request = endpoint.requests[0]
    assert request.headers["authorization"] == f"Bearer {FAKE_API_KEY}"
    assert FAKE_API_KEY not in request.content.decode()
    assert FAKE_API_KEY not in str(request.url)


@pytest.mark.parametrize(
    "answer",
    [
        httpx.Response(401, text=f"bad key {FAKE_API_KEY}"),
        httpx.Response(200, text=f"not json {FAKE_API_KEY}"),
        httpx.ConnectError(f"cannot connect with {FAKE_API_KEY}"),
        httpx.ReadTimeout(f"timeout {FAKE_API_KEY}"),
        httpx.Response(503, text=f"down {FAKE_API_KEY}"),
    ],
)
def test_the_key_never_appears_in_errors_or_logs(
    answer: httpx.Response | Exception, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    client = LlmClient(
        mode=CassetteMode.LIVE,
        allow_llm=True,
        config=load_config(GOOD),
        transport=Endpoint(answer).transport,
        sleep=lambda _: None,
    )
    with pytest.raises(LlmEndpointError) as caught:
        client.complete(user("hello"))
    assert FAKE_API_KEY not in str(caught.value)
    assert FAKE_API_KEY not in repr(caught.value)
    assert FAKE_API_KEY not in caplog.text
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
