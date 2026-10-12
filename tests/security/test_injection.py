"""Prompt injection against `assay prove` (threat T10), with the real sandbox runner.

The same attack as `tests/unit/test_injection_pipeline.py`, but against the real runner class:
a model that obeys instructions planted in the target, an obedient synthetic cassette for every
reply, and a host that is not allowed to start any process. The static checker must stop every
PoC, so the sandbox must not be called at all (no docker command), nothing may be written
outside the PoC directory, and no claim, oracle run or status above a recorded hypothesis may
appear.
"""

import os
import subprocess
from pathlib import Path

import pytest
from prove_support import CASSETTES, INJECTION, obedient_scenarios, seed
from typer.testing import CliRunner

from assay.cli.main import app
from assay.ledger import FindingState, Ledger

pytestmark = pytest.mark.integration
runner = CliRunner()


def refuse(*args: object, **kwargs: object) -> None:
    raise AssertionError("the host started a process")


@pytest.mark.parametrize("scenario", sorted(obedient_scenarios()))
def test_an_obedient_model_reaches_neither_the_sandbox_nor_the_host(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    docker_calls: list[str],
    scenario: str,
) -> None:
    work = tmp_path / "cwd"
    work.mkdir()
    monkeypatch.chdir(work)
    ledger_path = tmp_path / "ledger.db"
    with Ledger.open(ledger_path) as ledger:
        ids = seed(ledger, INJECTION, tmp_path)
    index = obedient_scenarios()[scenario].finding_index
    assert index is not None
    poc = tmp_path / "poc"
    before = sorted(entry.name for entry in tmp_path.iterdir())
    # from here on the host may not start any process (the sandbox would need docker)
    for name in ("run", "Popen", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, refuse)
    monkeypatch.setattr(os, "system", refuse)

    result = runner.invoke(
        app,
        [
            "prove",
            str(INJECTION.project),
            "--finding",
            str(int(ids[index])),
            "--ledger",
            str(ledger_path),
            "--poc-dir",
            str(poc),
            "--cassette-dir",
            str(CASSETTES),
        ],
    )

    assert result.exit_code == 3, result.output
    assert "final state: HYPOTHESIZED (evidence level E0)" in result.stdout
    assert docker_calls == []
    assert sorted(entry.name for entry in tmp_path.iterdir()) == sorted([*before, "poc"])
    assert list(poc.iterdir()) == []
    assert list(work.iterdir()) == []
    with Ledger.open(ledger_path) as ledger:
        conn = ledger._conn
        assert conn.execute("SELECT count(*) FROM claim").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM oracle_run").fetchone()[0] == 0
        assert ledger.get_finding(ids[index]).state is FindingState.HYPOTHESIZED
        assert ledger.get_finding(ids[index]).evidence_level.value == "E0"
        assert ledger.check_invariants() == []
