"""The cassettes of `make demo` are well formed, synthetic and clean."""

import json
from pathlib import Path

from assay.llm.cassette import check_clean, load_cassette

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "demo" / "cassettes"
FIXTURE = ROOT / "fixtures" / "reentrancy" / "single_function"


def cassettes() -> list[str]:
    return sorted(path.stem for path in DEMO.glob("*.json"))


def test_there_are_four_cassettes() -> None:
    assert len(cassettes()) == 4


def test_every_cassette_is_synthetic_and_matches_its_own_request_hash() -> None:
    for key in cassettes():
        cassette = load_cassette(DEMO, key)
        assert cassette.synthetic is True
        assert cassette.endpoint_host == "synthetic.invalid"
        assert cassette.note is not None
        assert cassette.note.startswith("SYNTHETIC:")
        assert "No model produced it" in cassette.note


def test_no_cassette_holds_a_secret_a_host_path_or_a_user_name() -> None:
    for key in cassettes():
        check_clean(load_cassette(DEMO, key))


def test_the_answers_are_the_fixtures_own_poc_and_patches() -> None:
    answers = [json.loads(load_cassette(DEMO, key).response.content) for key in cassettes()]
    solidity = [item["solidity"] for item in answers if "solidity" in item]
    diffs = [item["diff"] for item in answers if "diff" in item]
    assert solidity == [(FIXTURE / "poc" / "VaultReentrancy.t.sol").read_text()]
    assert sorted(diffs) == sorted(
        (FIXTURE / "patches" / f"{label}.diff").read_text() for label in ("good", "overfit")
    )
