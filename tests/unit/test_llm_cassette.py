"""Cassette keys, files and the synthetic cassette shipped with the tests."""

import hashlib
import json
from pathlib import Path

import pytest
from llm_support import FAKE_API_KEY, no_network, user

from assay.llm import CassetteError, CassetteMissing, LlmClient, Message
from assay.llm.ask import ask_messages
from assay.llm.cassette import (
    Cassette,
    CassetteRequest,
    CassetteResponse,
    cassette_key,
    cassette_path,
    check_clean,
    load_cassette,
    write_cassette,
)

__all__ = ["no_network"]
CASSETTES = Path(__file__).resolve().parents[1] / "data" / "cassettes"
QUESTION = "Name one planet of the solar system."


def make(text: str = "hello", content: str = '{"answer": "x"}', **changes: object) -> Cassette:
    messages = tuple(user(text))
    values: dict[str, object] = {
        "format": 1,
        "synthetic": True,
        "note": "SYNTHETIC: test",
        "key": cassette_key(messages, 0.0),
        "endpoint_host": "synthetic.invalid",
        "request": CassetteRequest(messages=messages, temperature=0.0),
        "response": CassetteResponse(
            content=content,
            model="m-1",
            finish_reason="stop",
            prompt_tokens=1,
            completion_tokens=1,
        ),
    }
    return Cassette(**{**values, **changes})  # type: ignore[arg-type]


# Keys


def test_the_key_hashes_messages_and_parameters() -> None:
    base = cassette_key(tuple(user("a")), 0.0)
    assert base == cassette_key(tuple(user("a")), 0.0)
    assert len(base) == 64
    assert base != cassette_key(tuple(user("b")), 0.0)
    assert base != cassette_key(tuple(user("a")), 0.5)
    assert base != cassette_key((Message(role="system", content="a"),), 0.0)
    assert base != cassette_key((*user("a"), *user("a")), 0.0)


def test_the_key_does_not_depend_on_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    messages = tuple(user("a"))
    before = cassette_key(messages, 0.0)
    for name, value in (
        ("ASSAY_LLM_BASE_URL", "https://other.example.org"),
        ("ASSAY_LLM_MODEL", "other-model"),
        ("ASSAY_LLM_MAX_TOKENS", "7"),
        ("ASSAY_LLM_API_KEY", FAKE_API_KEY),
        ("USER", "someone-else"),
    ):
        monkeypatch.setenv(name, value)
    assert cassette_key(messages, 0.0) == before


def test_the_key_is_stable_across_releases() -> None:
    """Pins the canonical form: changing it would orphan every recorded cassette."""
    canonical = '{"format":1,"messages":[{"content":"a","role":"user"}],"temperature":0.0}'
    expected = hashlib.sha256(canonical.encode()).hexdigest()
    assert cassette_key(tuple(user("a")), 0.0) == expected


@pytest.mark.parametrize("key", ["", "abc", "../x", "A" * 64, "g" * 64, "a" * 63])
def test_a_malformed_key_never_becomes_a_path(key: str, tmp_path: Path) -> None:
    with pytest.raises(CassetteError):
        cassette_path(tmp_path, key)
    with pytest.raises(CassetteError):
        load_cassette(tmp_path, key)


# Files


def test_write_then_load_round_trips(tmp_path: Path) -> None:
    cassette = make()
    path = write_cassette(tmp_path, cassette)
    assert path.name == f"{cassette.key}.json"
    assert load_cassette(tmp_path, cassette.key) == cassette
    assert path.read_text().endswith("\n")
    assert path.read_text().isascii()
    assert [p.name for p in tmp_path.iterdir()] == [path.name]


def test_missing_cassette_is_reported_as_missing(tmp_path: Path) -> None:
    with pytest.raises(CassetteMissing):
        load_cassette(tmp_path, "a" * 64)
    with pytest.raises(CassetteMissing):
        load_cassette(tmp_path / "no-such-directory", "a" * 64)


def test_a_cassette_that_does_not_match_its_key_is_refused(tmp_path: Path) -> None:
    cassette = make()
    path = write_cassette(tmp_path, cassette)
    data = json.loads(path.read_text())
    data["request"]["messages"][0]["content"] = "something else"
    path.write_text(json.dumps(data))
    with pytest.raises(CassetteError, match="does not match"):
        load_cassette(tmp_path, cassette.key)


def test_a_cassette_under_the_wrong_name_is_refused(tmp_path: Path) -> None:
    cassette = make()
    write_cassette(tmp_path, cassette).rename(cassette_path(tmp_path, "b" * 64))
    with pytest.raises(CassetteError):
        load_cassette(tmp_path, "b" * 64)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(extra=1),
        lambda d: d.update(format=2),
        lambda d: d["response"].update(prompt_tokens=-1),
        lambda d: d["response"].update(prompt_tokens="1"),
        lambda d: d.update(endpoint_host="host/with/path"),
        lambda d: d["response"].pop("model"),
    ],
)
def test_a_malformed_cassette_is_refused(tmp_path: Path, mutate: object) -> None:
    cassette = make()
    path = write_cassette(tmp_path, cassette)
    data = json.loads(path.read_text())
    mutate(data)  # type: ignore[operator]
    path.write_text(json.dumps(data))
    with pytest.raises(CassetteError, match="malformed"):
        load_cassette(tmp_path, cassette.key)


def test_oversized_and_linked_cassettes_are_refused(tmp_path: Path) -> None:
    cassette = make()
    path = write_cassette(tmp_path, cassette)
    path.write_text(path.read_text() + " " * (1024 * 1024))
    with pytest.raises(CassetteError):
        load_cassette(tmp_path, cassette.key)
    path.unlink()
    target = tmp_path / "elsewhere.json"
    target.write_text("{}")
    path.symlink_to(target)
    with pytest.raises(CassetteError):
        load_cassette(tmp_path, cassette.key)


@pytest.mark.parametrize(
    "dirty",
    [
        lambda: make(content=f"key {FAKE_API_KEY}"),
        lambda: make(content="see /Users/someone/project/src/A.sol"),
        lambda: make(text="Authorization: Bearer " + "A1b2C3d4" * 3),
        lambda: make(endpoint_host="synthetic.invalid", note="/home/someone/x/y"),
    ],
)
def test_a_cassette_with_secrets_or_paths_is_not_written(tmp_path: Path, dirty: object) -> None:
    with pytest.raises(CassetteError, match="refusing to write"):
        write_cassette(tmp_path, dirty())  # type: ignore[operator]
    assert list(tmp_path.iterdir()) == []


def test_the_configured_key_is_never_written_even_if_no_pattern_matches(tmp_path: Path) -> None:
    odd = "plainwordsecret"
    with pytest.raises(CassetteError, match="refusing to write"):
        write_cassette(tmp_path, make(content=f"the word {odd} appears"), secrets=[odd])


# The cassette shipped with the tests


def test_the_shipped_cassette_is_clearly_synthetic_and_clean() -> None:
    files = sorted(CASSETTES.glob("*.json"))
    assert files, "tests/data/cassettes must hold at least one cassette"
    for path in files:
        text = path.read_text()
        data = json.loads(text)
        assert data["synthetic"] is True
        assert data["note"].startswith("SYNTHETIC")
        assert data["endpoint_host"] == "synthetic.invalid"
        assert "authorization" not in text.lower()
        assert "/Users/" not in text
        assert "/home/" not in text
        cassette = load_cassette(CASSETTES, path.stem)
        assert cassette.key == path.stem
        check_clean(cassette)  # no secret pattern, key, or absolute path in any string


def test_the_shipped_cassette_replays_without_environment_or_network(
    no_network: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    del no_network
    for name in ("ASSAY_LLM_BASE_URL", "ASSAY_LLM_API_KEY", "ASSAY_LLM_MODEL"):
        monkeypatch.delenv(name, raising=False)
    result = LlmClient(cassette_dir=CASSETTES).complete(ask_messages(QUESTION))
    assert result.synthetic is True
    assert result.model == "synthetic-model-0"
    assert json.loads(result.content) == {"answer": "Mars"}
    assert (result.prompt_tokens, result.completion_tokens) == (40, 6)
