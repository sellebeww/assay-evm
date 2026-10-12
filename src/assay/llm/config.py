"""Endpoint configuration, read only from the `ASSAY_LLM_*` environment variables.

The API key lives in an `ApiKey` object whose string forms never show it. The base URL must use
`https`, or `http` for a loopback host, and must not carry credentials, a query or a fragment.
"""

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final
from urllib.parse import SplitResult, urlsplit

from assay.llm.errors import LlmConfigError

ENV_BASE_URL: Final = "ASSAY_LLM_BASE_URL"
ENV_API_KEY: Final = "ASSAY_LLM_API_KEY"
ENV_MODEL: Final = "ASSAY_LLM_MODEL"
ENV_TIMEOUT: Final = "ASSAY_LLM_TIMEOUT_S"
ENV_MAX_TOKENS: Final = "ASSAY_LLM_MAX_TOKENS"
ENV_NAMES: Final = (ENV_BASE_URL, ENV_API_KEY, ENV_MODEL, ENV_TIMEOUT, ENV_MAX_TOKENS)

DEFAULT_TIMEOUT_S: Final = 60.0
DEFAULT_MAX_TOKENS: Final = 1024
_TIMEOUT_RANGE: Final = (1.0, 600.0)
_MAX_TOKENS_RANGE: Final = (1, 32_768)
_MAX_URL_CHARS: Final = 2048
_MAX_MODEL_CHARS: Final = 200


class ApiKey:
    """A secret that cannot be printed or logged by accident."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        """Return the key. Only the client's request header uses this."""
        return self._value

    def __repr__(self) -> str:
        return "ApiKey(<redacted>)"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ApiKey) and other._value == self._value

    def __hash__(self) -> int:
        return hash(self._value)

    def __reduce__(self) -> str:
        raise TypeError("an API key cannot be pickled")


@dataclass(frozen=True)
class LlmConfig:
    """A validated endpoint configuration."""

    base_url: str
    model: str
    api_key: ApiKey | None = field(repr=False)
    timeout_s: float = DEFAULT_TIMEOUT_S
    max_tokens: int = DEFAULT_MAX_TOKENS

    @property
    def host(self) -> str:
        """The endpoint host with its port, never credentials or a path."""
        return endpoint_host(self.base_url)

    @property
    def chat_url(self) -> str:
        return self.base_url.rstrip("/") + "/chat/completions"


def _is_loopback(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _split(url: str) -> SplitResult:
    if len(url) > _MAX_URL_CHARS or not url.isascii() or not url.isprintable() or " " in url:
        raise LlmConfigError(f"{ENV_BASE_URL} is not a plain URL")
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018  # raises ValueError for an invalid port
    except ValueError as exc:
        raise LlmConfigError(f"{ENV_BASE_URL} is not a valid URL") from exc
    return parts


def validate_base_url(url: str) -> str:
    """Return `url` when it may be used as a base URL, else raise `LlmConfigError`."""
    parts = _split(url)
    host = parts.hostname
    if parts.scheme not in ("https", "http") or not host:
        raise LlmConfigError(f"{ENV_BASE_URL} must be an https URL (or http for localhost)")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise LlmConfigError(f"{ENV_BASE_URL} must not contain credentials")
    if parts.query or parts.fragment or "?" in url or "#" in url:
        raise LlmConfigError(f"{ENV_BASE_URL} must not contain a query or a fragment")
    if parts.scheme == "http" and not _is_loopback(host):
        raise LlmConfigError(f"{ENV_BASE_URL} may use http only for localhost; use https")
    return url


def endpoint_host(url: str) -> str:
    """The host (and port, when given) of a validated URL, for the ledger and cassettes."""
    parts = _split(url)
    host = parts.hostname or ""
    shown = f"[{host}]" if ":" in host else host
    return f"{shown}:{parts.port}" if parts.port is not None else shown


def _parse_number(raw: str, name: str, low: float, high: float) -> float:
    try:
        value = float(raw)
    except ValueError as exc:
        raise LlmConfigError(f"{name} must be a number") from exc
    if not low <= value <= high:
        raise LlmConfigError(f"{name} must be between {low:g} and {high:g}")
    return value


def load_config(env: Mapping[str, str]) -> LlmConfig:
    """Build the configuration from `env`. Errors name a variable, never its value."""
    missing = [name for name in (ENV_BASE_URL, ENV_MODEL) if not env.get(name, "").strip()]
    if missing:
        raise LlmConfigError(f"not set: {', '.join(missing)}")
    base_url = validate_base_url(env[ENV_BASE_URL].strip())
    model = env[ENV_MODEL].strip()
    if len(model) > _MAX_MODEL_CHARS or not model.isprintable():
        raise LlmConfigError(f"{ENV_MODEL} is not a plain model name")
    key = env.get(ENV_API_KEY, "").strip()
    host = urlsplit(base_url).hostname or ""
    if not key and not _is_loopback(host):
        raise LlmConfigError(f"not set: {ENV_API_KEY} (only a localhost endpoint may omit it)")
    timeout = DEFAULT_TIMEOUT_S
    if raw := env.get(ENV_TIMEOUT, "").strip():
        timeout = _parse_number(raw, ENV_TIMEOUT, *_TIMEOUT_RANGE)
    max_tokens = DEFAULT_MAX_TOKENS
    if raw := env.get(ENV_MAX_TOKENS, "").strip():
        low, high = _MAX_TOKENS_RANGE
        number = _parse_number(raw, ENV_MAX_TOKENS, low, high)
        if number != int(number):
            raise LlmConfigError(f"{ENV_MAX_TOKENS} must be a whole number")
        max_tokens = int(number)
    return LlmConfig(
        base_url=base_url,
        model=model,
        api_key=ApiKey(key) if key else None,
        timeout_s=timeout,
        max_tokens=max_tokens,
    )


def env_status(env: Mapping[str, str]) -> dict[str, str]:
    """`SET` or `NOT SET` for each variable; values are never returned."""
    return {name: "SET" if env.get(name, "").strip() else "NOT SET" for name in ENV_NAMES}
