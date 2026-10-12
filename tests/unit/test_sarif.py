"""SARIF 2.1.0 export, validated against the official OASIS schema (tests/data/sarif)."""

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from jsonschema import Draft4Validator

from assay.analysis import Aderyn, AnalyzerName, Location, Observation, Slither
from assay.analysis.normalize import Finding, ToolObservations, normalize
from assay.analysis.sarif import (
    FINGERPRINT,
    SARIF_SCHEMA,
    ToolInfo,
    dumps,
    result_message,
    to_sarif,
)
from assay.analysis.source_map import SourceReader

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIR = ROOT / "tests" / "data" / "sarif"
SCHEMA_FILE = SCHEMA_DIR / "sarif-schema-2.1.0.json"
GOLDEN = ROOT / "tests" / "data" / "analyzers"
FORBIDDEN = re.compile(
    r"\b(confirmed|vulnerable|secure|safe|proven|guaranteed|unhackable)\b", re.IGNORECASE
)
TOOLS = [ToolInfo("slither", "0.11.6"), ToolInfo("aderyn", "v0.6.8")]
TREE = "ab" * 32


@pytest.fixture(scope="module")
def validator() -> Draft4Validator:
    schema = json.loads(SCHEMA_FILE.read_text())
    Draft4Validator.check_schema(schema)
    return Draft4Validator(schema)


def errors(validator: Draft4Validator, document: object) -> list[str]:
    found = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
    return [f"{list(error.path)}: {error.message}" for error in found]


def golden_findings(fixture: str, project: Path) -> tuple[Finding, ...]:
    slither = Slither().parse((GOLDEN / "slither" / f"{fixture}.json").read_bytes())
    aderyn = Aderyn().parse((GOLDEN / "aderyn" / f"{fixture}.json").read_bytes())
    return normalize(
        [
            ToolObservations(AnalyzerName.SLITHER, "0.11.6", slither),
            ToolObservations(AnalyzerName.ADERYN, "v0.6.8", aderyn),
        ],
        SourceReader(project),
    )


@pytest.fixture(scope="module")
def findings() -> tuple[Finding, ...]:
    return golden_findings(
        "oracle_manipulation-spot_price", ROOT / "fixtures" / "oracle_manipulation" / "spot_price"
    )


def sarif(findings: tuple[Finding, ...], tools: list[ToolInfo] = TOOLS) -> dict[str, Any]:
    return to_sarif(findings, tools=tools, assay_version="0.1.0", tree_sha256=TREE)


def test_the_schema_copy_is_the_recorded_official_one() -> None:
    readme = (SCHEMA_DIR / "README.md").read_text()
    digest = hashlib.sha256(SCHEMA_FILE.read_bytes()).hexdigest()
    assert f"`{digest}`" in readme
    schema = json.loads(SCHEMA_FILE.read_text())
    assert schema["id"] == SARIF_SCHEMA
    assert schema["$schema"] == "http://json-schema.org/draft-04/schema#"


def test_the_export_of_recorded_findings_is_valid_sarif(
    validator: Draft4Validator, findings: tuple[Finding, ...]
) -> None:
    document = sarif(findings)
    assert errors(validator, document) == []
    assert document["version"] == "2.1.0"
    assert document["$schema"] == SARIF_SCHEMA
    assert len(document["runs"]) == 1


def test_an_empty_scan_and_a_failed_analyzer_are_valid_and_reported(
    validator: Draft4Validator,
) -> None:
    tools = [ToolInfo("slither", "0.11.6"), ToolInfo("aderyn", "v0.6.8", "timeout: time limit")]
    document = sarif((), tools)
    assert errors(validator, document) == []
    (run,) = document["runs"]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []
    (invocation,) = run["invocations"]
    assert invocation["executionSuccessful"] is False
    assert invocation["toolExecutionNotifications"][0]["message"]["text"].startswith("aderyn:")
    assert sarif((), TOOLS)["runs"][0]["invocations"] == [{"executionSuccessful": True}]


def test_the_driver_lists_exactly_the_rules_that_occur(findings: tuple[Finding, ...]) -> None:
    (run,) = sarif(findings)["runs"]
    rules = run["tool"]["driver"]["rules"]
    occurring = {
        f"{source.tool.value}/{source.rule_id}" for item in findings for source in item.sources
    }
    assert [rule["id"] for rule in rules] == sorted(occurring)
    assert run["tool"]["driver"]["name"] == "assay"
    assert run["tool"]["extensions"] == [
        {"name": "slither", "version": "0.11.6"},
        {"name": "aderyn", "version": "v0.6.8"},
    ]
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_each_result_is_an_unverified_candidate_with_its_stable_id(
    findings: tuple[Finding, ...],
) -> None:
    (run,) = sarif(findings)["runs"]
    assert len(run["results"]) == len(findings)
    for finding, result in zip(findings, run["results"], strict=True):
        first = finding.sources[0]
        assert result["ruleId"] == f"{first.tool.value}/{first.rule_id}"
        assert result["level"] in {"note", "warning", "error"}
        assert result["partialFingerprints"] == {FINGERPRINT: finding.id}
        properties = result["properties"]
        assert properties["assayEvidenceLevel"] == "E0"
        assert properties["assayStatus"] == "candidate"
        assert properties["assayClass"] == finding.vuln_class
        assert [item["severityReported"] for item in properties["assaySources"]] == [
            source.severity_reported for source in finding.sources
        ]
        text = result["message"]["text"]
        assert text.startswith("Candidate (unverified) ")
        assert "has not been checked" in text
        assert "no oracle has run" in text
        physical = result["locations"][0]["physicalLocation"]
        assert physical["artifactLocation"] == {
            "uri": finding.location.path,
            "uriBaseId": "PROJECTROOT",
        }
        assert physical["region"] == {
            "startLine": finding.location.start_line,
            "endLine": finding.location.end_line,
        }


def test_the_level_is_the_most_severe_reported_level(findings: tuple[Finding, ...]) -> None:
    (run,) = sarif(findings)["runs"]
    for finding, result in zip(findings, run["results"], strict=True):
        words = {source.severity_reported.split()[0] for source in finding.sources}
        expected = "error" if "High" in words else "warning" if "Medium" in words else "note"
        assert result["level"] == expected


def test_the_document_is_deterministic_and_free_of_host_paths_and_forbidden_words(
    findings: tuple[Finding, ...],
) -> None:
    first = dumps(sarif(findings))
    assert first == dumps(sarif(findings))
    assert first.endswith("\n")
    assert str(ROOT) not in first
    assert "/work/project" not in first
    assert FORBIDDEN.search(first) is None


def test_tool_text_with_forbidden_words_is_withheld(tmp_path: Path) -> None:
    project = tmp_path / "p"
    (project / "src").mkdir(parents=True)
    (project / "src" / "A.sol").write_text("contract A {\n    function f() public {}\n}\n")
    hostile = Observation(
        rule_id="reentrancy-eth",
        severity_reported="High",
        message="Confirmed: f is VULNERABLE, not safe, not secure, proven and guaranteed.",
        locations=(Location(path="src/A.sol", start_line=2, end_line=2),),
    )
    found = normalize(
        [ToolObservations(AnalyzerName.SLITHER, "0.11.6", (hostile,))], SourceReader(project)
    )
    tools = [ToolInfo("slither", "0.11.6"), ToolInfo("aderyn", "v0.6.8", "failed: unsafe? safe!")]
    text = dumps(sarif(found, tools))
    assert FORBIDDEN.search(text) is None
    assert "[term withheld]" in result_message(found[0])
    assert found[0].message.startswith("Confirmed")  # the model keeps the tool's text


_location = st.tuples(st.integers(1, 30), st.integers(0, 5))
_observation = st.builds(
    lambda rule, severity, message, place: Observation(
        rule_id=rule,
        severity_reported=severity,
        message=message,
        locations=(Location(path="src/A.sol", start_line=place[0], end_line=place[0] + place[1]),),
    ),
    st.sampled_from(["reentrancy-eth", "calls-loop", "weird.rule/x", "divide-before-multiply"]),
    st.sampled_from(["High", "Low (confidence High)", "Optimization", "Critical"]),
    st.text(min_size=1, max_size=80).filter(lambda text: text.strip()),
    _location,
)


@settings(max_examples=50, deadline=None)
@given(slither=st.lists(_observation, max_size=6), aderyn=st.lists(_observation, max_size=6))
def test_any_scan_exports_valid_sarif(
    tmp_path_factory: pytest.TempPathFactory,
    validator: Draft4Validator,
    slither: list[Observation],
    aderyn: list[Observation],
) -> None:
    project = tmp_path_factory.mktemp("sarif")
    (project / "src").mkdir()
    (project / "src" / "A.sol").write_text(
        "contract A {\n" + "".join(f"    function f{n}() public {{}}\n" for n in range(28)) + "}\n"
    )
    found = normalize(
        [
            ToolObservations(AnalyzerName.SLITHER, "0.11.6", tuple(slither)),
            ToolObservations(AnalyzerName.ADERYN, "v0.6.8", tuple(aderyn)),
        ],
        SourceReader(project),
    )
    document = json.loads(dumps(sarif(found)))
    assert errors(validator, document) == []
    assert FORBIDDEN.search(json.dumps(document)) is None
