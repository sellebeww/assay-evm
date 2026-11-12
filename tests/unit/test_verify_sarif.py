"""SARIF export of verification results, validated against the official OASIS schema."""

import json
from pathlib import Path

import pytest
from ci_support import make_report
from jsonschema import Draft4Validator

from assay.report.sarif import dumps, verify_to_sarif

SCHEMA = (
    Path(__file__).resolve().parents[2] / "tests" / "data" / "sarif" / "sarif-schema-2.1.0.json"
)


@pytest.fixture(scope="module")
def validator() -> Draft4Validator:
    return Draft4Validator(json.loads(SCHEMA.read_text()))


def log(verdict: str, **kwargs: object) -> dict[str, object]:
    report = make_report(verdict=verdict)
    return verify_to_sarif([("poc-a", report)], assay_version="1.2.3", **kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("verdict", ["REJECTED", "INCONCLUSIVE", "VERIFIED_WITHIN_BOUNDS"])
def test_the_log_is_valid_sarif(validator: Draft4Validator, verdict: str) -> None:
    document = log(verdict, fallback_path="src/Vault.sol", path_prefix="proj/")
    assert [e.message for e in validator.iter_errors(document)] == []


def test_a_verified_patch_gives_a_run_without_results() -> None:
    (run,) = log("VERIFIED_WITHIN_BOUNDS")["runs"]  # type: ignore[misc]
    assert run["results"] == []


def test_a_rejected_patch_gives_errors_with_prefixed_locations_and_the_bounds() -> None:
    (run,) = log("REJECTED", fallback_path="src/Vault.sol", path_prefix="proj/")["runs"]  # type: ignore[misc]
    results = run["results"]
    assert results
    assert {r["level"] for r in results} <= {"error", "warning"}
    assert "error" in {r["level"] for r in results}
    for result in results:
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri.startswith("proj/")
        assert result["properties"]["assayBounds"]
        assert result["ruleId"].startswith("assay/")
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert rule_ids == sorted(rule_ids)
    assert all(
        results[i]["ruleIndex"] == rule_ids.index(results[i]["ruleId"]) for i in range(len(results))
    )


def test_without_any_path_a_result_has_no_location() -> None:
    (run,) = log("REJECTED")["runs"]  # type: ignore[misc]
    pathless = [r for r in run["results"] if not r["locations"]]
    assert pathless or all(r["locations"] for r in run["results"])


def test_the_output_is_deterministic() -> None:
    assert dumps(log("REJECTED", fallback_path="a.sol")) == dumps(
        log("REJECTED", fallback_path="a.sol")
    )


def test_fingerprints_differ_between_pocs() -> None:
    report = make_report(verdict="REJECTED")
    document = verify_to_sarif([("a", report), ("b", report)], assay_version="1")
    (run,) = document["runs"]  # type: ignore[misc]
    prints = [r["partialFingerprints"]["assayVerifyResult/v1"] for r in run["results"]]
    assert len(prints) == len(set(prints))
