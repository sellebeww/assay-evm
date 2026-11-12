"""The synthetic samples of the report viewer (web/public/samples) follow the published schema."""

import json
from pathlib import Path

import pytest
from ci_support import make_report
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "web" / "public" / "samples"
VERDICTS = {
    "rejected": "REJECTED",
    "verified": "VERIFIED_WITHIN_BOUNDS",
    "inconclusive": "INCONCLUSIVE",
}


@pytest.mark.parametrize(("name", "verdict"), VERDICTS.items())
def test_a_sample_is_valid_and_equals_the_report_it_was_made_from(name: str, verdict: str) -> None:
    schema = json.loads((ROOT / "docs" / "schemas" / "verify.schema.json").read_text())
    document = json.loads((SAMPLES / f"{name}.json").read_text())
    assert list(Draft202012Validator(schema).iter_errors(document)) == []
    expected = make_report(verdict=verdict).model_dump(mode="json")
    assert document == expected, "regenerate web/public/samples (see web/README.md)"
