"""Hash chain of the audit_log: format, verification and tamper detection."""

import hashlib
import json
import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from ledger_scenario import Scenario

from assay.ledger import FindingState, Ledger, Verdict, canonical_json
from assay.ledger.audit import GENESIS_HASH, row_hash, verify_chain


@pytest.fixture
def scenario(tmp_path: Path) -> Iterator[Scenario]:
    with Scenario.create(tmp_path) as built:
        build_history(built)
        yield built


def build_history(scenario: Scenario) -> None:
    finding = scenario.drive_to(FindingState.REPRODUCED)
    claim = scenario.claim(finding, "a second claim")
    scenario.ledger.promote_claim(claim, scenario.run(claim, Verdict.FAIL))


def tamper(db_path: Path, sql: str, *params: object) -> None:
    """Remove the append-only triggers, as an attacker with write access could, and edit."""
    with closing(sqlite3.connect(db_path, isolation_level=None)) as conn:
        conn.execute("DROP TRIGGER audit_log_no_update")
        conn.execute("DROP TRIGGER audit_log_no_delete")
        conn.execute(sql, params)


def chain_rows(db_path: Path) -> list[tuple[int, str, str, str, str]]:
    with closing(sqlite3.connect(db_path)) as conn:
        return conn.execute(
            "SELECT seq, event, payload_json, prev_hash, hash FROM audit_log ORDER BY seq"
        ).fetchall()


def test_canonical_json_is_sorted_compact_and_ascii() -> None:
    assert canonical_json({"b": [1, None, True], "a": "é"}) == '{"a":"\\u00e9","b":[1,null,true]}'


@pytest.mark.parametrize("value", [1.5, {"x": float("nan")}, {1: "x"}, {"x": b"bytes"}, {"x": {1}}])
def test_canonical_json_refuses_values_without_a_canonical_form(value: object) -> None:
    with pytest.raises(TypeError):
        canonical_json(value)


def test_row_hash_follows_the_documented_format() -> None:
    content = '[1,"schema.migrated","{\\"version\\":1}"]'
    expected = hashlib.sha256(("0" * 64 + content).encode("ascii")).hexdigest()
    assert row_hash(GENESIS_HASH, 1, "schema.migrated", '{"version":1}') == expected


def test_every_row_links_to_the_previous_one(scenario: Scenario) -> None:
    rows = chain_rows(scenario.db_path)
    assert [row[0] for row in rows] == list(range(1, len(rows) + 1))
    previous = GENESIS_HASH
    for seq, event, payload_json, prev_hash, stored in rows:
        assert prev_hash == previous
        assert stored == row_hash(prev_hash, seq, event, payload_json)
        assert canonical_json(json.loads(payload_json)) == payload_json
        previous = stored


def test_an_untouched_chain_verifies(scenario: Scenario) -> None:
    report = scenario.ledger.verify_chain()
    assert report.ok
    assert report.rows == len(chain_rows(scenario.db_path))


def test_editing_one_row_is_detected_at_that_row(scenario: Scenario) -> None:
    tamper(
        scenario.db_path,
        "UPDATE audit_log SET payload_json = replace(payload_json, 'FAIL', 'PASS') WHERE seq = ?",
        chain_rows(scenario.db_path)[-1][0],
    )
    report = scenario.ledger.verify_chain()
    last = chain_rows(scenario.db_path)[-1][0]
    assert report.violation is not None
    assert report.violation.seq == last
    assert report.violation.problem == "hash does not match the row content"
    assert report.rows == last - 1


def test_rehashing_an_edited_row_breaks_the_next_link(scenario: Scenario) -> None:
    seq, event, _, prev_hash, _ = chain_rows(scenario.db_path)[3]
    payload = '{"forged":true}'
    tamper(
        scenario.db_path,
        "UPDATE audit_log SET payload_json = ?, hash = ? WHERE seq = ?",
        payload,
        row_hash(prev_hash, seq, event, payload),
        seq,
    )
    report = scenario.ledger.verify_chain()
    assert report.violation is not None
    assert report.violation.seq == seq + 1
    assert "prev_hash" in report.violation.problem


def test_deleting_a_row_is_detected_at_the_gap(scenario: Scenario) -> None:
    tamper(scenario.db_path, "DELETE FROM audit_log WHERE seq = 5")
    report = scenario.ledger.verify_chain()
    assert report.violation is not None
    assert report.violation.seq == 6
    assert "expected seq 5" in report.violation.problem


def test_a_non_canonical_payload_is_detected(scenario: Scenario) -> None:
    seq, event, payload_json, prev_hash, _ = chain_rows(scenario.db_path)[2]
    spaced = json.dumps(json.loads(payload_json), sort_keys=True)
    assert spaced != payload_json
    tamper(
        scenario.db_path,
        "UPDATE audit_log SET payload_json = ?, hash = ? WHERE seq = ?",
        spaced,
        row_hash(prev_hash, seq, event, spaced),
        seq,
    )
    report = scenario.ledger.verify_chain()
    assert report.violation is not None
    assert report.violation.seq == seq
    assert report.violation.problem == "payload_json is not canonical JSON"


def test_removing_rows_at_the_end_is_not_detectable_by_the_chain_alone(
    scenario: Scenario,
) -> None:
    # The documented limit: the chain is tamper-evident, not a signature with an anchor.
    rows = chain_rows(scenario.db_path)
    tamper(scenario.db_path, "DELETE FROM audit_log WHERE seq = ?", rows[-1][0])
    report = scenario.ledger.verify_chain()
    assert report.ok
    assert report.rows == len(rows) - 1


FIELDS = ["event", "payload_json", "prev_hash", "hash"]


@settings(max_examples=40, deadline=None)
@given(
    index=st.integers(min_value=0, max_value=1000),
    field=st.sampled_from(FIELDS),
    text=st.text(st.characters(exclude_characters="\x00"), min_size=1, max_size=40),
    digest=st.text(alphabet="0123456789abcdef", min_size=64, max_size=64),
)
def test_any_single_field_edit_is_detected_at_its_row(
    index: int, field: str, text: str, digest: str
) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        with Scenario.create(Path(tmp)) as scenario:
            build_history(scenario)
        rows = chain_rows(scenario.db_path)
        row = rows[index % len(rows)]
        seq = row[0]
        old = row[FIELDS.index(field) + 1]
        new = digest if field in ("prev_hash", "hash") else text[:64]
        if new == old:
            return
        tamper(scenario.db_path, f"UPDATE audit_log SET {field} = ? WHERE seq = ?", new, seq)
        with Ledger.open(scenario.db_path, read_only=True) as ledger:
            report = ledger.verify_chain()
        assert report.violation is not None
        assert report.violation.seq == seq


def test_verify_chain_accepts_a_plain_connection(scenario: Scenario) -> None:
    with closing(sqlite3.connect(scenario.db_path)) as conn:
        assert verify_chain(conn).ok
