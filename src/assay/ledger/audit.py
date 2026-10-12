"""Append-only, hash-chained `audit_log`.

Every row stores `prev_hash` (the `hash` of the row before it, or 64 zeros for the first row)
and `hash = sha256(prev_hash || content)`, where `prev_hash` is the 64 hex characters and
`content` is the canonical JSON array `[seq, event, payload_json]`. `payload_json` is itself
canonical JSON: sorted keys, no spaces, ASCII only, no floating-point numbers.

The chain is tamper-evident, not a signature: it detects an edited, inserted, reordered or
removed row, but a party with write access can rebuild the whole chain, and removing rows at
the end leaves a shorter chain that is still intact. Triggers in the schema reject UPDATE and
DELETE on the table and an INSERT that does not continue the chain.
"""

import hashlib
import json
import sqlite3
from typing import Final

from pydantic import BaseModel, ConfigDict

GENESIS_HASH: Final = "0" * 64
_MAX_DEPTH: Final = 32


class ChainViolation(BaseModel):
    """The first row that breaks the chain."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    seq: int
    problem: str


class ChainReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    rows: int
    """Rows checked before the first violation, or all rows when the chain is intact."""
    violation: ChainViolation | None = None

    @property
    def ok(self) -> bool:
        return self.violation is None


def canonical_json(value: object) -> str:
    """Encode `value` as canonical JSON; refuse floats and non-string keys."""
    _check_canonical(value, 0)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _check_canonical(value: object, depth: int) -> None:
    if depth > _MAX_DEPTH:
        raise TypeError("value is nested too deeply for the audit log")
    if value is None or isinstance(value, bool | int | str):
        return
    if isinstance(value, list | tuple):
        for item in value:
            _check_canonical(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"audit payload keys must be strings, got {type(key).__name__}")
            _check_canonical(item, depth + 1)
        return
    raise TypeError(f"{type(value).__name__} is not allowed in an audit payload")


def row_hash(prev_hash: str, seq: int, event: str, payload_json: str) -> str:
    """Return the chain hash of one row."""
    content = canonical_json([seq, event, payload_json])
    return hashlib.sha256((prev_hash + content).encode("ascii")).hexdigest()


def next_seq(conn: sqlite3.Connection) -> int:
    """Return the sequence number the next appended row will get."""
    row = conn.execute("SELECT max(seq) FROM audit_log").fetchone()
    return 1 if row[0] is None else int(row[0]) + 1


def append(conn: sqlite3.Connection, event: str, payload: dict[str, object]) -> int:
    """Append one event and return its sequence number. Call inside a write transaction."""
    last = conn.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    seq, prev_hash = (1, GENESIS_HASH) if last is None else (int(last[0]) + 1, str(last[1]))
    payload_json = canonical_json(payload)
    conn.execute(
        "INSERT INTO audit_log (seq, event, payload_json, prev_hash, hash) VALUES (?, ?, ?, ?, ?)",
        (seq, event, payload_json, prev_hash, row_hash(prev_hash, seq, event, payload_json)),
    )
    return seq


def verify_chain(conn: sqlite3.Connection) -> ChainReport:
    """Walk `audit_log` in sequence order and report the first row that breaks the chain."""
    expected_prev = GENESIS_HASH
    checked = 0
    rows = conn.execute(
        "SELECT seq, event, payload_json, prev_hash, hash FROM audit_log ORDER BY seq"
    )
    for seq, event, payload_json, prev_hash, stored_hash in rows:
        problem = _row_problem(checked + 1, expected_prev, seq, event, payload_json, prev_hash)
        if problem is None and stored_hash != row_hash(prev_hash, seq, event, payload_json):
            problem = "hash does not match the row content"
        if problem is not None:
            return ChainReport(rows=checked, violation=ChainViolation(seq=seq, problem=problem))
        expected_prev = stored_hash
        checked += 1
    return ChainReport(rows=checked)


def _row_problem(
    expected_seq: int,
    expected_prev: str,
    seq: int,
    event: object,
    payload_json: object,
    prev_hash: object,
) -> str | None:
    # `seq` is the rowid alias, so SQLite always returns an integer for it. The other columns
    # are checked because a tampered database may no longer have the original column types.
    if seq != expected_seq:
        return f"expected seq {expected_seq}: a row is missing or out of order"
    if not (
        isinstance(event, str) and isinstance(payload_json, str) and isinstance(prev_hash, str)
    ):
        return "a column has an unexpected type"
    if prev_hash != expected_prev:
        return "prev_hash does not match the hash of the previous row"
    try:
        canonical = canonical_json(json.loads(payload_json))
    except (ValueError, TypeError, RecursionError):
        return "payload_json is not canonical JSON"
    if canonical != payload_json:
        return "payload_json is not canonical JSON"
    return None
