"""`assay dev ledger-audit` and the global invariants of the ledger."""

import sqlite3
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest
from ledger_scenario import Scenario, sha
from typer.testing import CliRunner

from assay.cli.main import app
from assay.ledger import (
    REQUIRED_ORACLES,
    CassetteMode,
    FindingState,
    Ledger,
    Verdict,
    audit,
)

runner = CliRunner()


@pytest.fixture
def scenario(tmp_path: Path) -> Iterator[Scenario]:
    with Scenario.create(tmp_path) as built:
        yield built


def audit_cli(db: Path) -> tuple[int, str]:
    result = runner.invoke(app, ["dev", "ledger-audit", str(db)])
    return result.exit_code, result.stdout


def kinds(scenario: Scenario) -> list[str]:
    return [item.invariant for item in scenario.ledger.check_invariants()]


def drop_triggers(conn: sqlite3.Connection, *names: str) -> None:
    for name in names:
        conn.execute(f"DROP TRIGGER {name}")


def test_a_ledger_through_every_state_holds_all_invariants(scenario: Scenario) -> None:
    for state in FindingState:
        scenario.drive_to(state)
    scenario.ledger.record_model_run(
        finding_id=None,
        endpoint_host="llm.example.org",
        model="m",
        prompt_sha256=sha("a"),
        response_sha256=sha("b"),
        tokens_in=1,
        tokens_out=1,
        latency_ms=1,
        cassette_mode=CassetteMode.LIVE,
    )
    assert kinds(scenario) == []
    assert audit_cli(scenario.db_path) == (0, "OK: all ledger invariants hold\n")


def test_the_demo_ledger_is_clean(tmp_path: Path) -> None:
    db = tmp_path / "demo.db"
    assert runner.invoke(app, ["dev", "ledger-demo", str(db)]).exit_code == 0
    assert audit_cli(db)[0] == 0


def test_a_trusted_claim_without_an_oracle_run_is_a_violation(scenario: Scenario) -> None:
    claim = scenario.claim(scenario.finding())
    with closing(scenario.raw()) as conn:
        drop_triggers(conn, "claim_status_requires_oracle_run")
        conn.execute("UPDATE claim SET status = 'trusted' WHERE id = ?", (claim,))
    assert kinds(scenario) == ["claim_without_oracle_run"]
    code, text = audit_cli(scenario.db_path)
    assert code == 5
    assert "VIOLATION claim_without_oracle_run" in text


def test_a_trusted_claim_whose_only_run_failed_is_a_violation(scenario: Scenario) -> None:
    finding = scenario.finding()
    claim = scenario.claim(finding)
    scenario.run(claim, Verdict.FAIL)
    with closing(scenario.raw()) as conn:
        drop_triggers(conn, "claim_status_requires_oracle_run")
        conn.execute("UPDATE claim SET status = 'trusted' WHERE id = ?", (claim,))
    assert "claim_without_oracle_run" in kinds(scenario)


def test_a_reproduced_finding_without_an_oracle_run_is_a_violation(scenario: Scenario) -> None:
    finding = scenario.drive_to(FindingState.POC_DRAFTED)
    with closing(scenario.raw()) as conn:
        drop_triggers(conn, "finding_transition_evidence")
        conn.execute(
            "UPDATE finding SET state = 'REPRODUCED', evidence_level = 'E1' WHERE id = ?",
            (finding,),
        )
    assert "finding_without_oracle_run" in kinds(scenario)
    assert audit_cli(scenario.db_path)[0] == 5


def test_a_verified_finding_without_every_required_pass_is_a_violation(
    scenario: Scenario,
) -> None:
    finding = scenario.drive_to(FindingState.PATCH_PROPOSED)
    scenario.patch_runs(finding, dict.fromkeys(list(REQUIRED_ORACLES)[:2], Verdict.PASS))
    with closing(scenario.raw()) as conn:
        drop_triggers(conn, "finding_transition_evidence")
        conn.execute(
            "UPDATE finding SET state = 'VERIFIED_WITHIN_BOUNDS', evidence_level = 'E3' "
            "WHERE id = ?",
            (finding,),
        )
    assert "finding_without_oracle_run" in kinds(scenario)


def test_a_status_event_that_names_no_oracle_run_is_a_violation(scenario: Scenario) -> None:
    scenario.drive_to(FindingState.CANDIDATE)
    with closing(scenario.raw()) as conn:
        conn.execute("BEGIN")
        audit.append(
            conn,
            "finding.transitioned",
            {
                "finding_id": 1,
                "from": "POC_DRAFTED",
                "to": "REPRODUCED",
                "evidence_level": "E1",
                "oracle_run_ids": [],
                "reason": None,
            },
        )
        conn.execute("COMMIT")
    assert "status_without_oracle" in kinds(scenario)


def test_a_recorded_step_that_claims_evidence_is_a_violation(scenario: Scenario) -> None:
    with closing(scenario.raw()) as conn:
        conn.execute("BEGIN")
        audit.append(
            conn,
            "finding.transitioned",
            {
                "finding_id": 1,
                "from": "CANDIDATE",
                "to": "HYPOTHESIZED",
                "evidence_level": "E1",
                "oracle_run_ids": [],
                "reason": None,
            },
        )
        conn.execute("COMMIT")
    assert "status_without_oracle" in kinds(scenario)


def test_a_status_that_rests_on_a_model_run_is_a_violation(scenario: Scenario) -> None:
    finding = scenario.drive_to(FindingState.REPRODUCED)
    del finding
    with closing(scenario.raw()) as conn:
        conn.execute("BEGIN")
        audit.append(
            conn,
            "claim.promoted",
            {
                "claim_id": 1,
                "oracle_run_id": 1,
                "model_run_id": 1,
                "from": "asserted",
                "to": "trusted",
                "verdict": "PASS",
            },
        )
        conn.execute("COMMIT")
    assert "status_from_model_run" in kinds(scenario)


def test_a_broken_audit_chain_is_a_violation(scenario: Scenario) -> None:
    scenario.drive_to(FindingState.REPRODUCED)
    with closing(scenario.raw()) as conn:
        drop_triggers(conn, "audit_log_no_update")
        conn.execute("UPDATE audit_log SET payload_json = '{}' WHERE seq = 3")
    assert "audit_chain" in kinds(scenario)
    code, text = audit_cli(scenario.db_path)
    assert code == 5
    assert "audit_chain" in text


def test_the_audit_never_changes_the_file(scenario: Scenario) -> None:
    scenario.drive_to(FindingState.REPRODUCED)
    before = scenario.db_path.read_bytes()
    audit_cli(scenario.db_path)
    assert scenario.db_path.read_bytes() == before


def test_a_file_that_is_not_a_ledger_is_refused(tmp_path: Path) -> None:
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"not a database" * 100)
    assert audit_cli(junk)[0] == 5
    empty = tmp_path / "empty.db"
    with closing(sqlite3.connect(empty)) as conn:
        conn.execute("CREATE TABLE t (x)")
    assert audit_cli(empty)[0] == 5
    assert runner.invoke(app, ["dev", "ledger-audit", str(tmp_path / "missing.db")]).exit_code == 2


def test_check_invariants_is_read_only_on_a_read_only_ledger(scenario: Scenario) -> None:
    scenario.drive_to(FindingState.REPRODUCED)
    with Ledger.open(scenario.db_path, read_only=True) as ledger:
        assert ledger.check_invariants() == []
