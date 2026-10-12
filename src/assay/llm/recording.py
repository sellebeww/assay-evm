"""Record each model call in the ledger as a `model_run`.

A model run is provenance only. This module never creates a claim, never calls an oracle and
never changes the status of a finding: statuses change only through oracle evidence.
"""

from assay.ledger import FindingId, Ledger
from assay.llm.client import Completion, Recorder


def ledger_recorder(ledger: Ledger, finding_id: FindingId | None = None) -> Recorder:
    """Return a recorder that stores every completion as a `model_run` row."""

    def record(completion: Completion) -> None:
        ledger.record_model_run(
            finding_id=finding_id,
            endpoint_host=completion.endpoint_host,
            model=completion.model,
            prompt_sha256=completion.prompt_sha256,
            response_sha256=completion.response_sha256,
            tokens_in=completion.prompt_tokens,
            tokens_out=completion.completion_tokens,
            latency_ms=completion.latency_ms,
            cassette_mode=completion.mode,
        )

    return record
