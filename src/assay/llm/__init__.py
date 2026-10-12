"""Optional LLM layer: one OpenAI-compatible client, redaction, cassettes, budgets, recording.

The model only proposes. Its output is untrusted data and never changes a status.
"""

from assay.llm.budget import Budget
from assay.llm.client import Completion, DryRun, LlmClient
from assay.llm.config import ApiKey, LlmConfig, load_config
from assay.llm.errors import (
    BudgetExceeded,
    CassetteError,
    CassetteMissing,
    ConsentRequired,
    LlmConfigError,
    LlmEndpointError,
    LlmError,
    PayloadError,
    SourceNotAllowed,
    StructuredOutputError,
)
from assay.llm.messages import Message
from assay.llm.output import Structured, ask_structured, parse_output
from assay.llm.redact import Redaction, redact_text, scrub_secrets

__all__ = [
    "ApiKey",
    "Budget",
    "BudgetExceeded",
    "CassetteError",
    "CassetteMissing",
    "Completion",
    "ConsentRequired",
    "DryRun",
    "LlmClient",
    "LlmConfig",
    "LlmConfigError",
    "LlmEndpointError",
    "LlmError",
    "Message",
    "PayloadError",
    "Redaction",
    "SourceNotAllowed",
    "Structured",
    "StructuredOutputError",
    "ask_structured",
    "load_config",
    "parse_output",
    "redact_text",
    "scrub_secrets",
]
