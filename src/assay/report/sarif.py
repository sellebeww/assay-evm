"""SARIF 2.1.0 export of verification results (`assay verify --sarif`, `assay ci verify`).

The scan export in `assay.analysis.sarif` reports unverified hints. This one reports what the
oracles decided about a patch, so that a rejected or inconclusive patch appears in GitHub Code
Scanning next to the diff that caused it.

One run. `tool.driver` is Assay. A result is produced for every oracle row that is not a PASS:

- an oracle that failed gives level `error`; one that was inconclusive gives `warning`;
- `ruleId` is `assay/<oracle>/<reason code>`, and the rules are exactly the ones that occur;
- the location is the path and line of the reason when it has one, else `fallback_path` (in CI,
  the first changed file of the patch), both prefixed with `path_prefix` (the project directory
  relative to the repository root, as code scanning wants). A result without a path has no
  location;
- `partialFingerprints` holds a hash of the PoC name, the rule and the location, so that the same
  problem is the same alert on the next run;
- the properties carry the oracle, the PoC name, the final verdict, the evidence level and the
  bounds statement, because a verdict is valid within recorded bounds only.

A report whose final verdict is `VERIFIED_WITHIN_BOUNDS` gives a run without results. Text that
comes from a project is passed through `neutral` like in the scan export. The document holds no
time and no host path; the same inputs give the same bytes.
"""

import hashlib
from collections.abc import Sequence
from typing import Final

from assay.analysis.sarif import SARIF_SCHEMA, SARIF_VERSION, dumps
from assay.analysis.vocabulary import neutral
from assay.ledger import Verdict
from assay.oracles.base import Reason
from assay.orchestrator.models import OracleRow, VerifyReport

__all__ = ["dumps", "verify_to_sarif"]

FINGERPRINT: Final = "assayVerifyResult/v1"
ROOT_BASE_ID: Final = "PROJECTROOT"


def _rule_id(row: OracleRow, reason: Reason | None) -> str:
    fallback = row.verdict.value.lower() if row.verdict else "unknown"
    return f"assay/{row.oracle.value}/{reason.code if reason else fallback}"


def _location(path: str | None, line: int | None) -> list[dict[str, object]]:
    if path is None:
        return []
    physical: dict[str, object] = {
        "artifactLocation": {"uri": path, "uriBaseId": ROOT_BASE_ID},
    }
    if line is not None and line >= 1:
        physical["region"] = {"startLine": line}
    return [{"physicalLocation": physical}]


def _fingerprint(poc: str, rule: str, path: str | None, line: int | None) -> str:
    text = "\0".join([poc, rule, path or "", str(line or 0)])
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def verify_to_sarif(
    entries: Sequence[tuple[str, VerifyReport]],
    *,
    assay_version: str,
    fallback_path: str | None = None,
    path_prefix: str = "",
) -> dict[str, object]:
    """The SARIF log of one or more verifications, one `(poc name, report)` pair each."""
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    for poc, report in entries:
        for row in report.oracles:
            if row.verdict is None or row.verdict is Verdict.PASS:
                continue
            level = "error" if row.verdict is Verdict.FAIL else "warning"
            reasons: Sequence[Reason | None] = row.reasons or (None,)
            for item in reasons:
                rule = _rule_id(row, item)
                rules.setdefault(
                    rule,
                    {
                        "id": rule,
                        "shortDescription": {
                            "text": f"The {row.oracle.value} oracle did not pass ({rule})"
                        },
                        "properties": {"assayOracle": row.oracle.value},
                    },
                )
                path = item.path if item and item.path else fallback_path
                line = item.line if item and item.path else None
                if path is not None:
                    path = path_prefix + path
                detail = neutral(item.detail) if item else neutral(row.summary)
                results.append(
                    {
                        "ruleId": rule,
                        "level": level,
                        "message": {
                            "text": (
                                f"Patch check for PoC {poc!a}: the {row.oracle.value} oracle "
                                f"returned {row.verdict.value}. {detail}"
                            )
                        },
                        "locations": _location(path, line),
                        "partialFingerprints": {FINGERPRINT: _fingerprint(poc, rule, path, line)},
                        "properties": {
                            "assayOracle": row.oracle.value,
                            "assayPoc": poc,
                            "assayFinalVerdict": report.final_verdict.value,
                            "assayEvidenceLevel": (report.evidence_level),
                            "assayBounds": report.bounds_statement,
                        },
                    }
                )
    names = sorted(rules)
    index = {name: number for number, name in enumerate(names)}
    for result in results:
        result["ruleIndex"] = index[str(result["ruleId"])]
    run: dict[str, object] = {
        "tool": {
            "driver": {
                "name": "assay",
                "version": assay_version,
                "rules": [rules[name] for name in names],
            }
        },
        "originalUriBaseIds": {
            ROOT_BASE_ID: {
                "description": {"text": "Root of the project; result paths are relative."}
            }
        },
        "results": results,
        "properties": {
            "assayNote": (
                "Results are decisions of deterministic oracles about a patch. A verdict is "
                "valid within the recorded bounds only; an empty run is not a proof of absence."
            ),
        },
    }
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}
