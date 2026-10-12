"""Content-addressed blob store and the artifact index."""

import hashlib
import json
import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from ledger_scenario import Scenario

from assay.ledger import BlobCorrupted, BlobError, BlobStore, InvalidInput, NotFound


@pytest.fixture
def store(tmp_path: Path) -> BlobStore:
    return BlobStore(tmp_path / "blobs")


@pytest.fixture
def scenario(tmp_path: Path) -> Iterator[Scenario]:
    with Scenario.create(tmp_path) as built:
        yield built


def make_writable(path: Path) -> None:
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def test_blob_is_stored_under_its_sha256(store: BlobStore) -> None:
    data = b"forge output"
    digest = store.put(data)
    assert digest == hashlib.sha256(data).hexdigest()
    path = store.root / digest[:2] / digest
    assert path.read_bytes() == data
    assert stat.S_IMODE(path.stat().st_mode) == 0o444
    assert store.get(digest) == data


def test_storing_twice_keeps_one_file(store: BlobStore) -> None:
    first = store.put(b"same")
    second = store.put(b"same")
    assert first == second
    assert [p.name for p in (store.root / first[:2]).iterdir()] == [first]


def test_a_changed_blob_is_refused_on_read(store: BlobStore) -> None:
    digest = store.put(b"original")
    path = store.path_for(digest)
    make_writable(path)
    path.write_bytes(b"replaced")
    with pytest.raises(BlobCorrupted):
        store.get(digest)
    with pytest.raises(BlobCorrupted):
        store.put(b"original")


def test_a_symlinked_blob_is_refused(store: BlobStore, tmp_path: Path) -> None:
    data = b"pointed to"
    digest = hashlib.sha256(data).hexdigest()
    (tmp_path / "elsewhere").write_bytes(data)
    store.path_for(digest).parent.mkdir(parents=True)
    store.path_for(digest).symlink_to(tmp_path / "elsewhere")
    with pytest.raises(BlobError):
        store.get(digest)
    with pytest.raises(BlobCorrupted):
        store.put(data)


@pytest.mark.parametrize("name", ["../../etc/passwd", "AB" * 32, "ab" * 31, "", "ab" * 32 + "\n"])
def test_only_sha256_names_are_accepted(store: BlobStore, name: str) -> None:
    with pytest.raises(BlobError):
        store.path_for(name)


def test_a_missing_blob_is_reported(store: BlobStore) -> None:
    with pytest.raises(NotFound):
        store.get("0" * 64)


@settings(max_examples=50, deadline=None)
@given(data=st.binary(max_size=4096))
def test_any_content_round_trips(tmp_path_factory: pytest.TempPathFactory, data: bytes) -> None:
    store = BlobStore(tmp_path_factory.mktemp("blobs"))
    assert store.get(store.put(data)) == data


def test_store_blob_indexes_the_artifact_once(scenario: Scenario) -> None:
    digest = scenario.ledger.store_blob(b"log", media_type="text/plain", label="first label")
    again = scenario.ledger.store_blob(b"log", media_type="text/plain", label="second label")
    assert again == digest
    with closing(scenario.raw()) as conn:
        rows = conn.execute(
            "SELECT sha256, size, media_type, label FROM artifact WHERE sha256 = ?", (digest,)
        ).fetchall()
        events = [
            json.loads(payload)
            for (payload,) in conn.execute(
                "SELECT payload_json FROM audit_log WHERE event = 'artifact.stored'"
            )
        ]
    assert rows == [(digest, 3, "text/plain", "first label")]
    assert [event["sha256"] for event in events].count(digest) == 1
    assert scenario.ledger.read_blob(digest) == b"log"


def test_read_blob_checks_the_content_again(scenario: Scenario) -> None:
    digest = scenario.ledger.store_blob(b"evidence", media_type="text/plain", label="e")
    path = scenario.ledger.blobs.path_for(digest)
    make_writable(path)
    path.write_bytes(b"forgery!")
    with pytest.raises(BlobCorrupted):
        scenario.ledger.read_blob(digest)


def test_read_blob_needs_an_indexed_artifact(scenario: Scenario) -> None:
    unindexed = scenario.ledger.blobs.put(b"not in the ledger")
    with pytest.raises(NotFound):
        scenario.ledger.read_blob(unindexed)
    with pytest.raises(InvalidInput):
        scenario.ledger.read_blob("../" + unindexed)


@pytest.mark.parametrize(
    ("media_type", "label"), [("plain", "x"), ("text/plain", ""), ("TEXT/x", "x")]
)
def test_store_blob_validates_its_metadata(scenario: Scenario, media_type: str, label: str) -> None:
    with pytest.raises(InvalidInput):
        scenario.ledger.store_blob(b"x", media_type=media_type, label=label)


def test_blobs_default_to_a_directory_next_to_the_database(scenario: Scenario) -> None:
    assert scenario.ledger.blobs.root == scenario.db_path.parent / "blobs"
    assert os.path.isdir(scenario.ledger.blobs.root)


def test_artifact_rows_cannot_be_rewritten(scenario: Scenario) -> None:
    with closing(scenario.raw()) as conn, pytest.raises(sqlite3.IntegrityError, match="immutable"):
        conn.execute("UPDATE artifact SET size = 0")
