"""Errors of the LLM layer. Messages never hold credentials, prompts or model output."""


class LlmError(Exception):
    """Base class of every error the LLM layer raises on purpose."""


class ConsentRequired(LlmError):
    """Sending to an endpoint was requested without the explicit `--allow-llm` flag."""


class LlmConfigError(LlmError):
    """The endpoint configuration is missing, malformed or not allowed."""


class PayloadError(LlmError):
    """The request is malformed or larger than the payload limits allow."""


class SourceNotAllowed(LlmError):
    """A file is not on the allowlist of what may be sent to an endpoint."""


class BudgetExceeded(LlmError):
    """A call or token budget is used up; the command stops instead of continuing."""


class CassetteMissing(LlmError):
    """Replay mode found no cassette for the request. It never falls back to the network."""


class CassetteError(LlmError):
    """A cassette cannot be read or written, or does not match its own key."""


class LlmEndpointError(LlmError):
    """The endpoint failed, was unreachable, or returned an unusable response."""


class StructuredOutputError(LlmError):
    """The model reply is not valid JSON for the expected model, after one repair attempt."""

    def __init__(self, code: str, detail: str, attempts: int) -> None:
        super().__init__(f"model output rejected: {code}: {detail} (after {attempts} attempt(s))")
        self.code = code
        self.detail = detail
        self.attempts = attempts
