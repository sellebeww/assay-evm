"""Feedback for the next attempt of the fix loop: what an earlier patch did wrong, as data.

The oracle results of a failed attempt become `PatchFeedback`: which oracle failed or was
inconclusive, the reason codes and details, and the concrete evidence that helps to repair the
patch (the generated variant test with its inputs, the differences of recorded behavior). Layout
and ABI changes arrive as reasons of the RegressionOracle.

Rules, enforced here and again when the prompt is built:

- only whitelisted fields of the evidence are kept (the counterexample document is rebuilt from
  its inputs; campaign settings and seeds are never copied), and every seed spelling that still
  occurs in a text is replaced;
- every text is untrusted (it may quote revert messages and identifiers of the target), is clipped
  here and redacted and quoted as data by `assay.llm.patcher`;
- an oracle that did not run gives no feedback, and nothing from the held-out final run ever
  becomes feedback.
"""

import json
from collections.abc import Collection, Iterable
from typing import Final

from assay.ledger import RevisionKind, Verdict
from assay.llm.patcher import (
    MAX_ARTIFACT_CHARS,
    MAX_DETAIL_CHARS,
    OracleFeedback,
    PatchFeedback,
    scrub_seeds,
)
from assay.oracles.base import OracleResult
from assay.oracles.behavior import BEHAVIOR_DIFF_FILE
from assay.oracles.variant import COUNTEREXAMPLE_FILE, VARIANT_POC_FILE
from assay.orchestrator.models import OracleRow
from assay.orchestrator.verify import VerifyOutcome

COUNTEREXAMPLE_KEYS: Final = (
    "mode",
    "test",
    "invariant",
    "attacker",
    "attacker_balance_wei",
    "knobs",
    "calldata",
    "predicates",
    "calls",
)
"""The fields of a counterexample that describe the exploit input. `seed`, `base_seed`,
`seed_index`, run counts and the profile describe the campaign and are not copied."""
_WANTED: Final = (VARIANT_POC_FILE, COUNTEREXAMPLE_FILE, BEHAVIOR_DIFF_FILE)


def _counterexample(text: str) -> str:
    try:
        document = json.loads(text)
    except ValueError:
        return ""
    if not isinstance(document, dict):
        return ""
    kept = {key: document[key] for key in COUNTEREXAMPLE_KEYS if key in document}
    return json.dumps(kept, indent=2, sort_keys=True, ensure_ascii=True)


def _artifacts(result: OracleResult | None) -> Iterable[tuple[str, str]]:
    """Named evidence of the patched-revision executions that helps to repair the patch."""
    if result is None:
        return
    seen: set[str] = set()
    for execution in result.executions:
        if execution.revision is not RevisionKind.PATCHED:
            continue
        for item in execution.evidence:
            if item.name not in _WANTED or item.name in seen:
                continue
            seen.add(item.name)
            text = item.data.decode("utf-8", errors="replace")
            if item.name == COUNTEREXAMPLE_FILE:
                text = _counterexample(text)
            if text:
                yield item.name, text


def _oracle_feedback(
    row: OracleRow, results: dict[str, OracleResult], seeds: Collection[str]
) -> OracleFeedback:
    assert row.verdict is not None
    reasons = tuple(
        (item.code, scrub_seeds(item.detail, seeds)[:MAX_DETAIL_CHARS]) for item in row.reasons
    )
    artifacts = tuple(
        (name, scrub_seeds(text, seeds)[:MAX_ARTIFACT_CHARS])
        for name, text in _artifacts(results.get(row.oracle.value))
    )
    return OracleFeedback(row.oracle.value, row.verdict.value, reasons, artifacts)


def feedback_from_outcome(
    attempt: int, outcome: VerifyOutcome, diff_sha256: str, seeds: Collection[str]
) -> PatchFeedback:
    """Feedback on an attempt that did not pass: its failed and inconclusive oracles.

    `seeds` are the campaign seeds of the loop; no spelling of them survives in the result.
    """
    report = outcome.report
    results = {result.oracle.value: result for result in outcome.results}
    failed = [
        row
        for row in report.oracles
        if row.status == "ran" and row.verdict in (Verdict.FAIL, Verdict.INCONCLUSIVE)
    ]
    integrity = any(row.oracle.value == "integrity" for row in failed)
    return PatchFeedback(
        attempt=attempt,
        stage="integrity" if integrity else "verification",
        diff_sha256=diff_sha256,
        oracles=tuple(_oracle_feedback(row, results, seeds) for row in failed),
    )
