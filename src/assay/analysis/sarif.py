"""SARIF 2.1.0 export of normalized findings.

One run. `tool.driver` is Assay, and its rules are exactly the detector rules that occur among
the sources of the findings, named `<tool>/<detector>`; the analyzers themselves are listed as
extensions with their versions. Each finding is one result:

- `ruleId` is the rule of its first source; every source is listed in the result's properties;
- `level` comes from the severities the tools reported, through the table in `class_map.toml`
  (the most severe level among the sources); the severities themselves are kept as reported;
- the location is the finding's path relative to the project root (`uriBaseId` `PROJECTROOT`)
  and its line range, with the enclosing function as a logical location when there is one;
- `partialFingerprints` holds the stable finding id;
- the properties `assayEvidenceLevel` (`E0`) and `assayStatus` (`candidate`) say what the result
  is: an unverified hint, which the message states in words as well.

An analyzer that did not finish is reported as a tool execution notification, and the run's
invocation is then not successful. The document contains no time and no host path; serialized
with `dumps`, the same findings give the same bytes.
"""

import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from assay.analysis.normalize import ClassMap, Finding, SarifLevel, Source, default_class_map
from assay.analysis.vocabulary import neutral

SARIF_VERSION: Final = "2.1.0"
SARIF_SCHEMA: Final = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
ROOT_BASE_ID: Final = "PROJECTROOT"
FINGERPRINT: Final = "assayFindingId/v1"
EVIDENCE_LEVEL: Final = "E0"
STATUS: Final = "candidate"
_LEVEL_RANK: Final[dict[SarifLevel, int]] = {"none": 0, "note": 1, "warning": 2, "error": 3}


@dataclass(frozen=True, slots=True)
class ToolInfo:
    """An analyzer of the scan: its name and version, and why it did not finish, if it did not."""

    name: str
    version: str
    problem: str | None = None


def rule_id(source: Source) -> str:
    return f"{source.tool.value}/{source.rule_id}"


def _class_phrase(vuln_class: str) -> str:
    return "hint without a mapped class" if vuln_class == "other" else f"{vuln_class} hint"


def result_message(finding: Finding) -> str:
    """The text of a result: what it is, who reported it, and the tool's own words."""
    rules = ", ".join(dict.fromkeys(rule_id(source) for source in finding.sources))
    return (
        f"Candidate (unverified) {_class_phrase(finding.vuln_class)} at evidence level "
        f"{EVIDENCE_LEVEL}, reported by {rules}. This is a static-analysis hint that has not been "
        "checked: no exploit was reproduced and no oracle has run. Tool message: "
        f"{neutral(finding.message)}"
    )


def _rule(source: Source, class_map: ClassMap) -> dict[str, object]:
    vuln_class = class_map.vuln_class(source.tool, source.rule_id)
    return {
        "id": rule_id(source),
        "shortDescription": {
            "text": (
                f"{source.tool.value} detector {source.rule_id} ({_class_phrase(vuln_class)}); "
                "its results are unverified hints"
            )
        },
        "properties": {
            "assayClass": vuln_class,
            "tool": source.tool.value,
            "toolVersion": source.tool_version,
        },
    }


def _level(finding: Finding, class_map: ClassMap) -> SarifLevel:
    levels = [class_map.sarif_level(source.severity_reported) for source in finding.sources]
    return max(levels, key=lambda level: _LEVEL_RANK[level])


def _location(finding: Finding) -> dict[str, object]:
    where = finding.location
    location: dict[str, object] = {
        "physicalLocation": {
            "artifactLocation": {"uri": where.path, "uriBaseId": ROOT_BASE_ID},
            "region": {"startLine": where.start_line, "endLine": where.end_line},
        }
    }
    if where.function is not None:
        location["logicalLocations"] = [{"fullyQualifiedName": where.function, "kind": "function"}]
    return location


def _result(finding: Finding, rule_index: dict[str, int], class_map: ClassMap) -> dict[str, object]:
    first = rule_id(finding.sources[0])
    return {
        "ruleId": first,
        "ruleIndex": rule_index[first],
        "level": _level(finding, class_map),
        "message": {"text": result_message(finding)},
        "locations": [_location(finding)],
        "partialFingerprints": {FINGERPRINT: finding.id},
        "properties": {
            "assayEvidenceLevel": EVIDENCE_LEVEL,
            "assayStatus": STATUS,
            "assayClass": finding.vuln_class,
            "assaySources": [
                {
                    "tool": source.tool.value,
                    "toolVersion": source.tool_version,
                    "ruleId": source.rule_id,
                    "severityReported": source.severity_reported,
                }
                for source in finding.sources
            ],
        },
    }


def to_sarif(
    findings: Sequence[Finding],
    *,
    tools: Sequence[ToolInfo],
    assay_version: str,
    tree_sha256: str,
    class_map: ClassMap | None = None,
) -> dict[str, object]:
    """The SARIF log of one scan."""
    mapping = class_map if class_map is not None else default_class_map()
    rules: dict[str, Source] = {}
    for finding in findings:
        for source in finding.sources:
            rules.setdefault(rule_id(source), source)
    names = sorted(rules)
    rule_index = {name: index for index, name in enumerate(names)}
    notifications = [
        {"level": "error", "message": {"text": neutral(f"{tool.name}: {tool.problem}")}}
        for tool in tools
        if tool.problem is not None
    ]
    invocation: dict[str, object] = {"executionSuccessful": not notifications}
    if notifications:
        invocation["toolExecutionNotifications"] = notifications
    run: dict[str, object] = {
        "tool": {
            "driver": {
                "name": "assay",
                "version": assay_version,
                "rules": [_rule(rules[name], mapping) for name in names],
            },
            "extensions": [{"name": tool.name, "version": tool.version} for tool in tools],
        },
        "invocations": [invocation],
        "originalUriBaseIds": {
            ROOT_BASE_ID: {
                "description": {"text": "Root of the scanned project; result paths are relative."}
            }
        },
        "results": [_result(finding, rule_index, mapping) for finding in findings],
        "properties": {
            "assayInputTreeSha256": tree_sha256,
            "assayNote": (
                "Every result is a candidate (unverified) at evidence level E0: a static-analysis "
                "hint that no oracle has checked."
            ),
        },
    }
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def dumps(document: dict[str, object]) -> str:
    """Serialize a SARIF log deterministically (sorted keys, ASCII, trailing newline)."""
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
