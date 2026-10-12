"""scan -> prove -> REPRODUCED against the real runner image, with synthetic cassettes.

The cassettes play the model: the fixture's own PoC is its answer. Everything else is real:
the analyzers of `assay scan`, the static PoC checker, forge in the sandbox, the ExploitOracle
(three replays), the ledger.
"""

import json
import re
from pathlib import Path

import pytest
from prove_support import (
    ACCESS_CONTROL,
    CASSETTES,
    POC_FILE,
    REENTRANCY,
    Fixture,
)
from typer.testing import CliRunner

from assay.cli.main import app
from assay.ledger import FindingState, Ledger

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("runner")]
runner = CliRunner()
FORBIDDEN = re.compile(r"\b(secure|safe|proven|guaranteed|unhackable|confirmed|vulnerable)\b", re.I)


def scan(tmp_path: Path, fixture: Fixture) -> Path:
    ledger = tmp_path / "ledger.db"
    result = runner.invoke(app, ["scan", str(fixture.project), "--ledger", str(ledger)])
    assert result.exit_code == 0, result.output
    return ledger


def prove(tmp_path: Path, fixture: Fixture, ledger: Path, *selector: str):  # type: ignore[no-untyped-def]
    return runner.invoke(
        app,
        [
            "prove",
            str(fixture.project),
            *selector,
            "--ledger",
            str(ledger),
            "--poc-dir",
            str(tmp_path / "poc"),
            "--cassette-dir",
            str(CASSETTES),
        ],
    )


def test_the_captured_scan_is_what_the_analyzers_report_today(tmp_path: Path) -> None:
    """Guards the cassettes: they were recorded from this exact analyzer output."""
    for fixture in (REENTRANCY, ACCESS_CONTROL):
        base = tmp_path / fixture.project.name
        base.mkdir()
        ledger = scan(base, fixture)
        captured = json.loads(fixture.scan.read_text())["findings"]
        with Ledger.open(ledger, read_only=True) as opened:
            found = opened.findings()
            assert [f.vuln_class for f in found] == [c["vuln_class"] for c in captured]
            for finding, entry in zip(found, captured, strict=True):
                messages = [o.message for o in opened.finding_observations(finding.id)]
                assert messages == [o["message"] for o in entry["observations"]]


@pytest.mark.parametrize(
    ("fixture", "vuln_class"), [(REENTRANCY, "reentrancy"), (ACCESS_CONTROL, "access_control")]
)
def test_scan_then_prove_reaches_reproduced(
    tmp_path: Path, fixture: Fixture, vuln_class: str
) -> None:
    ledger = scan(tmp_path, fixture)
    result = prove(tmp_path, fixture, ledger, "--class", vuln_class)
    assert result.exit_code == 0, result.output
    assert "final state: REPRODUCED (evidence level E1)" in result.stdout
    assert FORBIDDEN.search(result.stdout) is None
    assert (tmp_path / "poc" / POC_FILE).read_text().strip() == fixture.poc.read_text().strip()
    with Ledger.open(ledger, read_only=True) as opened:
        conn = opened._conn
        runs = conn.execute("SELECT oracle, verdict, exit_code FROM oracle_run").fetchall()
        assert runs == [("exploit", "PASS", 0)]
        assert opened.check_invariants() == []


def test_a_poc_that_runs_but_does_not_reproduce_is_repaired_with_feedback(tmp_path: Path) -> None:
    ledger = scan(tmp_path, REENTRANCY)
    with Ledger.open(ledger, read_only=True) as opened:
        target = opened.findings()[1]
    result = prove(tmp_path, REENTRANCY, ledger, "--finding", str(int(target.id)))
    assert result.exit_code == 0, result.output
    assert "attempt 1: exploit run INCONCLUSIVE (vacuous_poc)" in result.stdout
    assert "attempt 2: exploit run PASS" in result.stdout
    with Ledger.open(ledger, read_only=True) as opened:
        rows = opened._conn.execute("SELECT verdict FROM oracle_run ORDER BY id").fetchall()
        assert rows == [("INCONCLUSIVE",), ("PASS",)]
        assert opened.get_finding(target.id).state is FindingState.REPRODUCED


def test_a_poc_the_checker_refuses_is_repaired_without_running_it(tmp_path: Path) -> None:
    ledger = scan(tmp_path, REENTRANCY)
    with Ledger.open(ledger, read_only=True) as opened:
        target = opened.findings()[0]
    result = prove(tmp_path, REENTRANCY, ledger, "--finding", str(int(target.id)))
    assert result.exit_code == 0, result.output
    assert "attempt 1: rejected by the static checker, not run" in result.stdout
    assert "attempt 2: exploit run PASS" in result.stdout
    with Ledger.open(ledger, read_only=True) as opened:
        rows = opened._conn.execute("SELECT verdict FROM oracle_run").fetchall()
        assert rows == [("PASS",)]
