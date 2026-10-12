"""`assay scan` with the real analyzers in the runner image, on the reentrancy fixture.

Checks idempotence (no duplicate findings, nothing new in the ledger on a repeat), determinism
(byte-identical JSON across runs and ledgers), the SARIF schema, the wording rules, and that no
claim exists after a scan.
"""

import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from jsonschema import Draft4Validator
from typer.testing import CliRunner

from assay.cli.main import app

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("runner")]

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures" / "reentrancy" / "single_function"
SCHEMA = json.loads((ROOT / "tests" / "data" / "sarif" / "sarif-schema-2.1.0.json").read_text())
FORBIDDEN = re.compile(
    r"\b(confirmed|vulnerable|secure|safe|proven|guaranteed|unhackable)\b", re.IGNORECASE
)


def scan(*args: str) -> tuple[int, str, str]:
    result = CliRunner().invoke(app, ["scan", str(FIXTURE), *args])
    return result.exit_code, result.stdout, result.stderr


def rows(database: Path) -> dict[str, int]:
    with closing(sqlite3.connect(database)) as conn:
        return {
            table: conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in ("finding", "claim", "scan", "observation", "audit_log")
        }


def test_a_repeated_scan_is_idempotent_and_byte_identical(tmp_path: Path) -> None:
    database = tmp_path / "ledger.db"
    code, first, errors = scan("--format", "json", "--ledger", str(database))
    assert code == 0, errors
    before = rows(database)
    code, second, errors = scan("--format", "json", "--ledger", str(database))
    assert code == 0, errors
    assert second == first
    assert rows(database) == before
    assert "0 new findings" in errors
    code, fresh, _ = scan("--format", "json", "--ledger", str(tmp_path / "fresh.db"))
    assert fresh == first

    document = json.loads(first)
    assert document["complete"] is True
    assert {tool["tool"]: tool["status"] for tool in document["tools"]} == {
        "slither": "ok",
        "aderyn": "ok",
    }
    reentrancy = [item for item in document["findings"] if item["class"] == "reentrancy"]
    assert reentrancy, [item["class"] for item in document["findings"]]
    assert {source["tool"] for item in reentrancy for source in item["sources"]} == {
        "slither",
        "aderyn",
    }
    assert reentrancy[0]["location"]["function"] == "Vault.withdraw"
    assert before["finding"] == len(document["findings"])
    assert str(tmp_path) not in first
    assert str(ROOT) not in first


def test_no_claim_exists_after_a_scan(tmp_path: Path) -> None:
    database = tmp_path / "ledger.db"
    code, _, errors = scan("--ledger", str(database))
    assert code == 0, errors
    with closing(sqlite3.connect(database)) as conn:
        assert conn.execute("SELECT count(*) FROM claim").fetchone() == (0,)
        assert conn.execute("SELECT count(*) FROM oracle_run").fetchone() == (0,)
        states = conn.execute("SELECT DISTINCT state, evidence_level FROM finding").fetchall()
    assert states == [("CANDIDATE", "E0")]


def test_the_sarif_output_validates_and_no_output_uses_forbidden_words(tmp_path: Path) -> None:
    database = str(tmp_path / "ledger.db")
    out = tmp_path / "scan.sarif"
    code, stdout, errors = scan("--format", "sarif", "--out", str(out), "--ledger", database)
    assert code == 0, errors
    assert stdout == ""
    document = json.loads(out.read_text())
    assert list(Draft4Validator(SCHEMA).iter_errors(document)) == []
    texts = [out.read_text(), errors]
    for output_format in ("table", "json"):
        code, stdout, errors = scan("--format", output_format, "--ledger", database)
        assert code == 0, errors
        texts += [stdout, errors]
    for text in texts:
        assert FORBIDDEN.search(text) is None, text
    assert "candidate (unverified)" in texts[2]
