"""Hidden ledger commands: `assay dev ledger-demo` and `assay dev ledger-verify`."""

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.cli.main import app
from assay.ledger import ClaimId, ClaimStatus, FindingId, FindingState, Ledger, OracleRunId

runner = CliRunner()


@pytest.fixture
def demo_db(tmp_path: Path) -> Path:
    db = tmp_path / "demo.db"
    result = runner.invoke(app, ["dev", "ledger-demo", str(db)])
    assert result.exit_code == 0, result.output
    return db


def test_ledger_commands_are_listed_under_dev() -> None:
    result = runner.invoke(app, ["dev", "--help"])
    assert "ledger-demo" in result.stdout
    assert "ledger-verify" in result.stdout


def test_demo_prints_what_it_created(tmp_path: Path) -> None:
    db = tmp_path / "demo.db"
    result = runner.invoke(app, ["dev", "ledger-demo", str(db)])
    assert result.exit_code == 0
    lines = result.stdout.splitlines()
    assert lines[1] == "synthetic demo record: no project was built and no oracle was executed"
    assert lines[2:] == [
        "finding 1 demo-reentrancy-1: REPRODUCED (E1)",
        "claim 1: asserted (left unpromoted on purpose)",
        "claim 2: trusted (oracle_run 1, exploit PASS)",
        "audit_log: 14 rows, chain OK",
    ]


def test_demo_content_matches_its_description(demo_db: Path) -> None:
    with Ledger.open(demo_db, read_only=True) as ledger:
        assert ledger.get_claim(ClaimId(1)).status is ClaimStatus.ASSERTED
        assert ledger.get_claim(ClaimId(2)).status is ClaimStatus.TRUSTED
        run = ledger.get_oracle_run(OracleRunId(1))
        assert run.claim_id == 2
        assert "no oracle was executed" in run.reason
        assert ledger.get_finding(FindingId(1)).state is FindingState.REPRODUCED
        assert ledger.read_blob(run.trace_blob_sha256).startswith(b"{")
    assert (demo_db.parent / "blobs").is_dir()


def test_demo_claim_1_cannot_be_trusted_with_a_raw_update(demo_db: Path) -> None:
    with (
        closing(sqlite3.connect(demo_db)) as conn,
        pytest.raises(sqlite3.IntegrityError, match="matching verdict"),
    ):
        conn.execute("UPDATE claim SET status = 'trusted' WHERE id = 1")


def test_demo_is_byte_identical_across_runs(tmp_path: Path) -> None:
    first, second = tmp_path / "a" / "demo.db", tmp_path / "b" / "demo.db"
    for db in (first, second):
        db.parent.mkdir()
        assert runner.invoke(app, ["dev", "ledger-demo", str(db)]).exit_code == 0
    assert first.read_bytes() == second.read_bytes()


def test_demo_refuses_to_overwrite(demo_db: Path) -> None:
    before = demo_db.read_bytes()
    result = runner.invoke(app, ["dev", "ledger-demo", str(demo_db)])
    assert result.exit_code == 2
    assert "refusing to overwrite" in result.stderr
    assert demo_db.read_bytes() == before


def test_demo_needs_an_existing_directory(tmp_path: Path) -> None:
    result = runner.invoke(app, ["dev", "ledger-demo", str(tmp_path / "missing" / "demo.db")])
    assert result.exit_code == 2
    assert "directory does not exist" in result.stderr


def test_verify_reports_an_intact_chain(demo_db: Path) -> None:
    before = demo_db.read_bytes()
    result = runner.invoke(app, ["dev", "ledger-verify", str(demo_db)])
    assert result.exit_code == 0
    assert result.stdout == "OK: audit_log chain intact (14 rows)\n"
    assert demo_db.read_bytes() == before


def test_verify_reports_where_the_chain_breaks(demo_db: Path) -> None:
    with closing(sqlite3.connect(demo_db, isolation_level=None)) as conn:
        conn.execute("DROP TRIGGER audit_log_no_update")
        conn.execute("UPDATE audit_log SET payload_json = '{\"forged\":true}' WHERE seq = 7")
    result = runner.invoke(app, ["dev", "ledger-verify", str(demo_db)])
    assert result.exit_code == 5
    assert result.stdout == ("VIOLATION at audit_log seq 7: hash does not match the row content\n")


@pytest.mark.parametrize("content", [b"", b"not a database at all, just text\n" * 10])
def test_verify_refuses_a_file_that_is_not_a_ledger(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "other.db"
    path.write_bytes(content)
    result = runner.invoke(app, ["dev", "ledger-verify", str(path)])
    assert result.exit_code == 5
    assert "not a readable ledger" in result.stderr


def test_verify_needs_an_existing_file(tmp_path: Path) -> None:
    result = runner.invoke(app, ["dev", "ledger-verify", str(tmp_path / "missing.db")])
    assert result.exit_code == 2
