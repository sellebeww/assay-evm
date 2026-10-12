"""Schema, migrations and triggers, checked through plain sqlite3 connections.

A plain connection is what a user gets from the sqlite3 shell: no application code, and
foreign keys off. The triggers alone must keep the invariants.
"""

import sqlite3
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest
from ledger_scenario import IMAGE_DIGEST, Scenario, sha

from assay.ledger import (
    REQUIRED_ORACLES,
    SCHEMA_VERSION,
    STATE_LEVELS,
    TRANSITIONS,
    ClaimStatus,
    FindingState,
    Ledger,
    OracleName,
    ScanTool,
    SchemaVersionError,
    Verdict,
)
from assay.ledger.schema import MIGRATION_1

CORE_TABLES = {
    "project",
    "revision",
    "finding",
    "claim",
    "oracle_run",
    "patch",
    "verification",
    "artifact",
    "audit_log",
}
LLM_TABLES = {"model_run"}
STATIC_ANALYSIS_TABLES = {"scan", "observation"}


@pytest.fixture
def scenario(tmp_path: Path) -> Iterator[Scenario]:
    with Scenario.create(tmp_path) as built:
        yield built


@pytest.fixture
def raw(scenario: Scenario) -> Iterator[sqlite3.Connection]:
    with closing(scenario.raw()) as conn:
        yield conn


def rejected(conn: sqlite3.Connection, sql: str, *params: object) -> str:
    """Run `sql`, expect the database to reject it, and return the error message."""
    with pytest.raises(sqlite3.IntegrityError) as caught:
        conn.execute(sql, params)
    return str(caught.value)


# Migrations


def test_migrations_create_the_core_static_analysis_and_model_tables_only(
    raw: sqlite3.Connection,
) -> None:
    tables = {
        name for (name,) in raw.execute("SELECT name FROM sqlite_schema WHERE type = 'table'")
    }
    assert tables == CORE_TABLES | STATIC_ANALYSIS_TABLES | LLM_TABLES
    assert raw.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 3


def test_claim_status_column_is_named_exactly(raw: sqlite3.Connection) -> None:
    columns = [row[1] for row in raw.execute("PRAGMA table_info(claim)")]
    assert columns == ["id", "finding_id", "text", "status", "created_seq"]
    for status in ClaimStatus:
        assert status.value in {"asserted", "trusted", "refuted", "inconclusive"}


def test_migration_is_recorded_once(tmp_path: Path) -> None:
    db = tmp_path / "ledger.db"
    for _ in range(3):
        Ledger.open(db).close()
    with closing(sqlite3.connect(db)) as conn:
        events = conn.execute("SELECT seq, event, payload_json FROM audit_log").fetchall()
    assert events == [
        (1, "schema.migrated", '{"version":1}'),
        (2, "schema.migrated", '{"version":2}'),
        (3, "schema.migrated", '{"version":3}'),
    ]


def test_a_version_1_ledger_is_migrated_to_the_current_version(tmp_path: Path) -> None:
    db = tmp_path / "ledger.db"
    with closing(sqlite3.connect(db, isolation_level=None)) as conn:
        conn.execute("BEGIN")
        for statement in MIGRATION_1:
            conn.execute(statement)
        conn.execute("PRAGMA user_version = 1")
        conn.execute("COMMIT")
    with Ledger.open(db) as ledger:
        project = ledger.add_project("p", "tree:0")
        blob = ledger.store_blob(b"{}", media_type="application/json", label="raw")
        scan = ledger.record_scan(
            project,
            tool=ScanTool.SLITHER,
            tool_version="0.11.6",
            raw_blob_sha256=blob,
            input_tree_sha256=sha("tree"),
            observations=[],
        )
        assert ledger.get_scan(scan).result_count == 0
    with closing(sqlite3.connect(db)) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def test_a_newer_schema_is_refused(tmp_path: Path) -> None:
    db = tmp_path / "ledger.db"
    Ledger.open(db).close()
    with closing(sqlite3.connect(db)) as conn:
        conn.execute("PRAGMA user_version = 99")
    with pytest.raises(SchemaVersionError, match="newer"):
        Ledger.open(db)


def test_a_plain_database_is_not_opened_read_only_as_a_ledger(tmp_path: Path) -> None:
    db = tmp_path / "other.db"
    with closing(sqlite3.connect(db)) as conn:
        conn.execute("CREATE TABLE t (x)")
    with pytest.raises(SchemaVersionError, match="not an Assay ledger"):
        Ledger.open(db, read_only=True)


# Claims


def test_raw_update_cannot_trust_a_claim_without_an_oracle_run(
    scenario: Scenario, raw: sqlite3.Connection
) -> None:
    claim = scenario.claim(scenario.finding())
    message = rejected(raw, "UPDATE claim SET status = 'trusted' WHERE id = ?", claim)
    assert "claim status requires an oracle_run with a matching verdict" in message
    assert scenario.ledger.get_claim(claim).status is ClaimStatus.ASSERTED


def test_raw_update_cannot_trust_a_claim_on_a_failed_or_foreign_run(
    scenario: Scenario, raw: sqlite3.Connection
) -> None:
    finding = scenario.finding()
    claim, other = scenario.claim(finding), scenario.claim(finding, "other")
    scenario.run(claim, Verdict.FAIL)
    scenario.run(claim, Verdict.INCONCLUSIVE)
    scenario.run(other, Verdict.PASS)
    scenario.run(None, Verdict.PASS)
    rejected(raw, "UPDATE claim SET status = 'trusted' WHERE id = ?", claim)
    rejected(raw, "UPDATE claim SET status = 'refuted' WHERE id = ?", other)


@pytest.mark.parametrize(
    ("status", "verdict"),
    [("trusted", Verdict.PASS), ("refuted", Verdict.FAIL), ("inconclusive", Verdict.INCONCLUSIVE)],
)
def test_each_decided_status_needs_its_own_verdict(
    scenario: Scenario, raw: sqlite3.Connection, status: str, verdict: Verdict
) -> None:
    claim = scenario.claim(scenario.finding())
    for other in set(Verdict) - {verdict}:
        scenario.run(claim, other)
    rejected(raw, "UPDATE claim SET status = ? WHERE id = ?", status, claim)
    scenario.run(claim, verdict)
    raw.execute("UPDATE claim SET status = ? WHERE id = ?", (status, claim))
    assert scenario.ledger.get_claim(claim).status == status


def test_raw_insert_cannot_create_a_trusted_claim(
    scenario: Scenario, raw: sqlite3.Connection
) -> None:
    finding = scenario.finding()
    message = rejected(
        raw,
        "INSERT INTO claim (finding_id, text, status, created_seq) VALUES (?, 'x', 'trusted', 1)",
        finding,
    )
    assert "a new claim must be asserted" in message


def test_raw_update_cannot_move_a_trusted_claim_or_rewrite_it(
    scenario: Scenario, raw: sqlite3.Connection
) -> None:
    finding = scenario.finding()
    claim = scenario.claim(finding)
    scenario.ledger.promote_claim(claim, scenario.run(claim, Verdict.PASS))
    # Runs with every verdict exist, so only the status-change rule can object.
    scenario.run(claim, Verdict.FAIL)
    scenario.run(claim, Verdict.INCONCLUSIVE)
    for status in ("asserted", "refuted", "inconclusive"):
        assert "illegal claim status change" in rejected(
            raw, "UPDATE claim SET status = ? WHERE id = ?", status, claim
        )
    assert "only the status" in rejected(raw, "UPDATE claim SET text = 'other' WHERE id = ?", claim)
    # A new id has no oracle run either, so two triggers object; either message is a rejection.
    rejected(raw, "UPDATE claim SET id = 99 WHERE id = ?", claim)


def test_raw_update_cannot_repoint_a_claim_at_another_claims_run(
    scenario: Scenario, raw: sqlite3.Connection
) -> None:
    finding = scenario.finding()
    trusted = scenario.claim(finding)
    scenario.ledger.promote_claim(trusted, scenario.run(trusted, Verdict.PASS))
    unproven = scenario.claim(finding, "unproven")
    # Swapping the ids would move the trusted status onto the unproven text.
    rejected(raw, "UPDATE claim SET id = ? WHERE id = ?", unproven + 100, trusted)
    rejected(raw, "UPDATE claim SET finding_id = ? WHERE id = ?", scenario.finding(), unproven)


# Immutable tables and the audit log


@pytest.mark.parametrize("table", ["oracle_run", "artifact"])
def test_immutable_tables_reject_update_and_delete(
    scenario: Scenario, raw: sqlite3.Connection, table: str
) -> None:
    scenario.run(scenario.claim(scenario.finding()), Verdict.PASS)
    assert "immutable" in rejected(raw, f"UPDATE {table} SET created_seq = 0")
    assert "immutable" in rejected(raw, f"DELETE FROM {table}")


def test_oracle_run_verdict_cannot_be_flipped(scenario: Scenario, raw: sqlite3.Connection) -> None:
    claim = scenario.claim(scenario.finding())
    run = scenario.run(claim, Verdict.FAIL)
    rejected(raw, "UPDATE oracle_run SET verdict = 'PASS' WHERE id = ?", run)
    rejected(raw, "UPDATE claim SET status = 'trusted' WHERE id = ?", claim)


def test_audit_log_is_append_only(scenario: Scenario, raw: sqlite3.Connection) -> None:
    assert "append-only" in rejected(raw, "UPDATE audit_log SET event = 'x' WHERE seq = 2")
    assert "append-only" in rejected(raw, "DELETE FROM audit_log WHERE seq = 2")
    assert "append-only" in rejected(raw, "DELETE FROM audit_log")


def test_audit_log_insert_must_continue_the_chain(raw: sqlite3.Connection) -> None:
    last_seq, last_hash = raw.execute(
        "SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    insert = "INSERT INTO audit_log (seq, event, payload_json, prev_hash, hash) VALUES (?,?,?,?,?)"
    assert "continue the chain" in rejected(
        raw, insert, last_seq + 2, "e", "{}", last_hash, "a" * 64
    )
    assert "continue the chain" in rejected(
        raw, insert, last_seq + 1, "e", "{}", "0" * 64, "a" * 64
    )


# Findings


def test_raw_insert_cannot_create_an_advanced_finding(
    scenario: Scenario, raw: sqlite3.Connection
) -> None:
    message = rejected(
        raw,
        "INSERT INTO finding (project_id, stable_id, class, state, evidence_level, created_seq, "
        "updated_seq) VALUES (?, 'raw', 'dos', 'VERIFIED_WITHIN_BOUNDS', 'E3', 1, 1)",
        scenario.project,
    )
    assert "a new finding must be a CANDIDATE at E0" in message


@pytest.mark.parametrize("source", list(FindingState))
def test_raw_update_rejects_every_illegal_transition(
    scenario: Scenario, raw: sqlite3.Connection, source: FindingState
) -> None:
    finding = scenario.drive_to(source)
    for target in FindingState:
        if target is source:
            continue
        level = sorted(STATE_LEVELS[target])[-1]
        raw.execute("SAVEPOINT probe")
        try:
            raw.execute(
                "UPDATE finding SET state = ?, evidence_level = ?, reason = 'r' WHERE id = ?",
                (target.value, level.value, finding),
            )
            error = ""
        except sqlite3.IntegrityError as exc:
            error = str(exc)
        raw.execute("ROLLBACK TO probe")
        raw.execute("RELEASE probe")
        if (source, target) in TRANSITIONS:
            assert "illegal finding transition" not in error, (source, target)
        else:
            assert "illegal finding transition" in error, (source, target)
    assert scenario.ledger.get_finding(finding).state is source


@pytest.mark.parametrize(
    "target",
    [FindingState.REPRODUCED, FindingState.NOT_REPRODUCED, FindingState.INCONCLUSIVE],
)
def test_raw_update_cannot_decide_a_poc_without_an_exploit_run(
    scenario: Scenario, raw: sqlite3.Connection, target: FindingState
) -> None:
    finding = scenario.drive_to(FindingState.POC_DRAFTED)
    claim = scenario.claim(finding)
    # Runs that do not match: another oracle, and the exploit oracle with other verdicts.
    scenario.run(claim, Verdict.PASS, OracleName.VARIANT)
    scenario.run(claim, Verdict.FAIL if target is FindingState.REPRODUCED else Verdict.PASS)
    level = sorted(STATE_LEVELS[target])[0]
    message = rejected(
        raw,
        "UPDATE finding SET state = ?, evidence_level = ? WHERE id = ?",
        target.value,
        level.value,
        finding,
    )
    assert "lacks the required oracle evidence" in message


def test_raw_update_cannot_verify_without_every_required_oracle(
    scenario: Scenario, raw: sqlite3.Connection
) -> None:
    finding = scenario.drive_to(FindingState.PATCH_PROPOSED)
    verdicts = dict.fromkeys(REQUIRED_ORACLES - {OracleName.REGRESSION}, Verdict.PASS)
    scenario.patch_runs(finding, verdicts)
    update = (
        "UPDATE finding SET state = 'VERIFIED_WITHIN_BOUNDS', evidence_level = 'E3' WHERE id = ?"
    )
    assert "lacks the required oracle evidence" in rejected(raw, update, finding)
    scenario.patch_runs(finding, dict.fromkeys(REQUIRED_ORACLES, Verdict.PASS))
    raw.execute(update, (finding,))


def test_raw_update_cannot_propose_a_patch_that_does_not_exist(
    scenario: Scenario, raw: sqlite3.Connection
) -> None:
    finding = scenario.drive_to(FindingState.REPRODUCED)
    assert "lacks the required oracle evidence" in rejected(
        raw, "UPDATE finding SET state = 'PATCH_PROPOSED' WHERE id = ?", finding
    )


def test_evidence_level_follows_the_state(scenario: Scenario, raw: sqlite3.Connection) -> None:
    finding = scenario.drive_to(FindingState.POC_DRAFTED)
    scenario.run(scenario.claim(finding), Verdict.PASS)
    assert "CHECK constraint failed" in rejected(
        raw,
        "UPDATE finding SET state = 'REPRODUCED', evidence_level = 'E3' WHERE id = ?",
        finding,
    )
    assert "changes only through a state transition" in rejected(
        raw, "UPDATE finding SET reason = 'edited' WHERE id = ?", finding
    )


def test_rejected_needs_a_reason_in_the_database(
    scenario: Scenario, raw: sqlite3.Connection
) -> None:
    finding = scenario.drive_to(FindingState.PATCH_PROPOSED)
    scenario.patch_runs(finding, {OracleName.INTEGRITY: Verdict.FAIL})
    assert "CHECK constraint failed" in rejected(
        raw,
        "UPDATE finding SET state = 'REJECTED', evidence_level = 'E1', reason = NULL WHERE id = ?",
        finding,
    )


def test_finding_identity_is_immutable(scenario: Scenario, raw: sqlite3.Connection) -> None:
    finding = scenario.finding()
    assert "identity fields are immutable" in rejected(
        raw, "UPDATE finding SET stable_id = 'renamed' WHERE id = ?", finding
    )


# Verification


def test_a_verified_verification_needs_every_required_oracle(
    scenario: Scenario, raw: sqlite3.Connection
) -> None:
    finding = scenario.drive_to(FindingState.PATCH_PROPOSED)
    patch = raw.execute("SELECT id FROM patch WHERE finding_id = ?", (finding,)).fetchone()[0]
    insert = (
        "INSERT INTO verification (patch_id, final_verdict, reason, bounds_json, created_seq) "
        "VALUES (?, ?, 'r', '{}', 1)"
    )
    assert "every required oracle" in rejected(raw, insert, patch, "VERIFIED_WITHIN_BOUNDS")
    raw.execute(insert, (patch, "INCONCLUSIVE"))
    assert "immutable" in rejected(raw, "UPDATE verification SET final_verdict = 'REJECTED'")
    assert "immutable" in rejected(raw, "DELETE FROM verification")


def test_a_verification_with_all_required_passes_is_accepted(
    scenario: Scenario, raw: sqlite3.Connection
) -> None:
    finding = scenario.drive_to(FindingState.VERIFIED_WITHIN_BOUNDS)
    patch = raw.execute(
        "SELECT v.patch_id FROM oracle_run AS r JOIN revision AS v ON v.id = r.revision_id "
        "JOIN patch AS p ON p.id = v.patch_id WHERE p.finding_id = ? LIMIT 1",
        (finding,),
    ).fetchone()[0]
    raw.execute(
        "INSERT INTO verification (patch_id, final_verdict, reason, bounds_json, created_seq) "
        "VALUES (?, 'VERIFIED_WITHIN_BOUNDS', 'all required oracles passed', ?, 1)",
        (patch, '{"fuzz_runs":256,"seed":"1"}'),
    )


def test_column_checks_reject_malformed_values(scenario: Scenario, raw: sqlite3.Connection) -> None:
    claim = scenario.claim(scenario.finding())
    insert = (
        "INSERT INTO oracle_run (claim_id, revision_id, oracle, argv_json, image_digest, seed, "
        "verdict, reason, trace_blob_sha256, created_seq) VALUES (?, ?, ?, ?, ?, ?, ?, 'r', ?, 1)"
    )
    good = [claim, scenario.vulnerable, "exploit", "[]", IMAGE_DIGEST, "7", "PASS", scenario.trace]
    raw.execute(insert, good)
    for index, bad in [
        (2, "fuzzer"),
        (3, "{}"),
        (4, "sha256:latest"),
        (5, "007"),
        (5, "-1"),
        (6, "MAYBE"),
    ]:
        values = list(good)
        values[index] = bad
        rejected(raw, insert, *values)
    rejected(raw, "INSERT INTO artifact VALUES (?, 1, 'text/plain', 'x', 1)", sha("x").upper())
