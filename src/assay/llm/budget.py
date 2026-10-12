"""Hard per-command limits on the number of calls and tokens.

Counts come from the usage the endpoint reports (or the cassette that replays it). Reaching a
limit raises `BudgetExceeded`; nothing continues silently.
"""

from dataclasses import dataclass
from typing import Final

from assay.llm.errors import BudgetExceeded, LlmError

DEFAULT_MAX_CALLS: Final = 4
DEFAULT_MAX_TOKENS: Final = 20_000
_CALLS_CAP: Final = 1_000
_TOKENS_CAP: Final = 10_000_000


@dataclass
class Budget:
    """Limits and the use so far. One instance covers one command."""

    max_calls: int = DEFAULT_MAX_CALLS
    max_tokens: int = DEFAULT_MAX_TOKENS
    calls: int = 0
    tokens: int = 0

    def __post_init__(self) -> None:
        if not 1 <= self.max_calls <= _CALLS_CAP:
            raise LlmError(f"the call budget must be between 1 and {_CALLS_CAP}")
        if not 1 <= self.max_tokens <= _TOKENS_CAP:
            raise LlmError(f"the token budget must be between 1 and {_TOKENS_CAP}")

    def charge_call(self) -> None:
        """Count one request to the endpoint, or stop before it is sent."""
        if self.calls >= self.max_calls:
            raise BudgetExceeded(
                f"call budget exhausted: {self.calls} of {self.max_calls} calls used "
                "(raise it with --budget-calls)"
            )
        if self.tokens >= self.max_tokens:
            raise BudgetExceeded(
                f"token budget exhausted: {self.tokens} of {self.max_tokens} tokens used "
                "(raise it with --budget-tokens)"
            )
        self.calls += 1

    def add_tokens(self, tokens_in: int, tokens_out: int) -> None:
        self.tokens += tokens_in + tokens_out

    def enforce(self) -> None:
        """Raise when the tokens reported so far exceed the limit."""
        if self.tokens > self.max_tokens:
            raise BudgetExceeded(
                f"token budget exceeded: {self.tokens} tokens used, limit {self.max_tokens} "
                "(raise it with --budget-tokens)"
            )
