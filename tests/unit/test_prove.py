"""`assay prove` end to end with synthetic cassettes and a stand-in forge (no Docker, no model)."""

import json
import re
import shutil
from pathlib import Path

import pytest
from llm_support import no_network
from prove_support import (
    ACCESS_CONTROL,
    CASSETTES,
    POC_FILE,
    REENTRANCY,
    Fixture,
    scenarios,
    seed,
    stand_in_forge,
)
from schema_support import assert_valid
from typer.testing import CliRunner, Result

from assay.cli.main import app
from assay.ledger import CassetteMode, ClaimStatus, FindingState, Ledger

__all__ = ["no_network"]
runner = CliRunner()
FORBIDDEN = re.compile(r"\b(secure|safe|proven|guaranteed|unhackable|confirmed|vulnerable)\b", re.I)


class Env:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fixture: Fixture) -> None:
        self.tmp = tmp_path
        self.fixture = fixture
        self.ledger_path = tmp_path / "ledger.db"
        self.poc_dir = tmp_path / "poc"
        with Ledger.open(self.ledger_path) as ledger:
            self.ids = seed(ledger, fixture, tmp_path)
        self.forge = stand_in_forge(next(iter(scenarios().values())))
        monkeypatch.setattr("assay.cli.prove.SandboxRunner", lambda: self.forge)

    def prove(self, *args: str, cassettes: Path = CASSETTES) -> Result:
        return runner.invoke(
            app,
            [
                "prove",
                str(self.fixture.project),
                "--ledger",
                str(self.ledger_path),
                "--poc-dir",
                str(self.poc_dir),
                "--cassette-dir",
                str(cassettes),
                *args,
            ],
        )

    def ledger(self) -> Ledger:
        return Ledger.open(self.ledger_path)

    def finding_state(self, index: int) -> FindingState:
        with self.ledger() as ledger:
            return ledger.get_finding(self.ids[index]).state


@pytest.fixture
def reentrancy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Env:
    return Env(tmp_path, monkeypatch, REENTRANCY)


def test_prove_prints_json_that_matches_the_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_network: None
) -> None:
    del no_network
    env = Env(tmp_path, monkeypatch, REENTRANCY)
    result = env.prove("--class", "reentrancy", "--json")
    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert document["format"] == "assay-prove/1"
    assert document["final_state"] == "REPRODUCED"
    assert document["evidence_level"] == "E1"
    assert document["poc_dir"] == str(env.poc_dir)
    assert [item["number"] for item in document["attempts"]] == [1]
    assert_valid("prove", document)
    assert FORBIDDEN.search(result.stdout) is None


def test_prove_json_cannot_be_combined_with_a_dry_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = Env(tmp_path, monkeypatch, REENTRANCY)
    result = env.prove("--class", "reentrancy", "--json", "--llm-dry-run")
    assert result.exit_code == 2


def audit_clean(env: Env) -> None:
    with env.ledger() as ledger:
        assert ledger.check_invariants() == []
    result = runner.invoke(app, ["dev", "ledger-audit", str(env.ledger_path)])
    assert result.exit_code == 0, result.output


@pytest.mark.parametrize(
    ("fixture", "vuln_class", "scenario"),
    [
        (REENTRANCY, "reentrancy", "reentrancy_good"),
        (ACCESS_CONTROL, "access_control", "access_control_good"),
    ],
)
def test_scan_to_reproduced_from_a_synthetic_cassette(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    no_network: None,
    fixture: Fixture,
    vuln_class: str,
    scenario: str,
) -> None:
    del no_network, scenario
    env = Env(tmp_path, monkeypatch, fixture)
    result = env.prove("--class", vuln_class)
    assert result.exit_code == 0, result.output
    assert "final state: REPRODUCED (evidence level E1)" in result.stdout
    assert "attempts: 1 of 3" in result.stdout
    assert FORBIDDEN.search(result.stdout) is None
    # the PoC the "model" wrote is the fixture's own, saved only in the PoC directory
    assert (env.poc_dir / POC_FILE).read_text().strip() == fixture.poc.read_text().strip()
    assert [p.name for p in env.poc_dir.iterdir()] == [POC_FILE]
    with env.ledger() as ledger:
        finding = next(f for f in ledger.findings(vuln_class=vuln_class))
        assert finding.state is FindingState.REPRODUCED
        assert finding.evidence_level.value == "E1"
        conn = ledger._conn
        runs = conn.execute("SELECT oracle, verdict FROM oracle_run").fetchall()
        assert runs == [("exploit", "PASS")]
        assert conn.execute("SELECT status FROM claim").fetchall() == [("trusted",)]
        models = conn.execute("SELECT cassette_mode, endpoint_host FROM model_run").fetchall()
        assert models == [("replay", "synthetic.invalid")] * 2
        # every other candidate stays a candidate
        others = [f for f in ledger.findings() if f.id != finding.id]
        assert {f.state for f in others} == {FindingState.CANDIDATE}
    with env.ledger() as ledger:
        assert ledger.check_invariants() == []


def test_the_run_never_touches_the_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_network: None
) -> None:
    del no_network
    env = Env(tmp_path, monkeypatch, REENTRANCY)
    assert env.prove("--class", "reentrancy").exit_code == 0


def test_a_poc_the_checker_rejects_never_runs_and_the_next_attempt_repairs_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = Env(tmp_path, monkeypatch, REENTRANCY)
    result = env.prove("--finding", str(env.ids[0]))
    assert result.exit_code == 0, result.output
    assert (
        "attempt 1: rejected by the static checker, not run (cheatcode_not_allowed)"
        in result.stdout
    )
    assert "attempt 2: exploit run PASS" in result.stdout
    assert "attempts: 2 of 3" in result.stdout
    with env.ledger() as ledger:
        conn = ledger._conn
        assert conn.execute("SELECT verdict FROM oracle_run").fetchall() == [("PASS",)]
        assert conn.execute("SELECT count(*) FROM model_run").fetchone()[0] == 3
    # the stand-in forge ran the second PoC only: one build, one inspect, three replays
    assert sum(1 for call in env.forge.calls if "test" in call) == 3
    audit_clean(env)


def test_a_poc_that_runs_without_reproducing_gets_feedback_and_a_second_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = Env(tmp_path, monkeypatch, REENTRANCY)
    result = env.prove("--finding", str(env.ids[1]))
    assert result.exit_code == 0, result.output
    assert "attempt 1: exploit run INCONCLUSIVE (vacuous_poc)" in result.stdout
    assert "attempt 2: exploit run PASS" in result.stdout
    with env.ledger() as ledger:
        conn = ledger._conn
        rows = conn.execute("SELECT verdict FROM oracle_run ORDER BY id").fetchall()
        assert rows == [("INCONCLUSIVE",), ("PASS",)]
        statuses = conn.execute("SELECT status FROM claim ORDER BY id").fetchall()
        assert statuses == [("inconclusive",), ("trusted",)]
    assert env.finding_state(1) is FindingState.REPRODUCED
    audit_clean(env)


def test_attempts_that_run_out_end_inconclusive_by_the_last_oracle_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = Env(tmp_path, monkeypatch, REENTRANCY)
    result = env.prove("--finding", str(env.ids[1]), "--max-attempts", "1")
    assert result.exit_code == 3, result.output
    assert "final state: INCONCLUSIVE (evidence level E0)" in result.stdout
    assert "attempts: 1 of 1" in result.stdout
    audit_clean(env)


def test_attempts_that_run_out_without_a_checked_poc_leave_the_finding_hypothesized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = Env(tmp_path, monkeypatch, REENTRANCY)
    result = env.prove("--finding", str(env.ids[0]), "--max-attempts", "1")
    assert result.exit_code == 3, result.output
    assert "final state: HYPOTHESIZED (evidence level E0)" in result.stdout
    assert env.forge.calls == []
    assert list(env.poc_dir.iterdir()) == []
    audit_clean(env)


def test_a_poc_that_does_not_reproduce_ends_not_reproduced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = Env(tmp_path, monkeypatch, REENTRANCY)
    env.forge.decide = lambda tree, number: "reverted"
    result = env.prove("--class", "reentrancy", "--max-attempts", "1")
    assert result.exit_code == 1, result.output
    assert "final state: NOT_REPRODUCED (evidence level E0)" in result.stdout
    with env.ledger() as ledger:
        conn = ledger._conn
        assert conn.execute("SELECT verdict FROM oracle_run").fetchall() == [("FAIL",)]
        assert conn.execute("SELECT status FROM claim").fetchall() == [("refuted",)]
    audit_clean(env)


def test_the_hypothesis_is_recorded_as_data_at_level_e0(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = Env(tmp_path, monkeypatch, REENTRANCY)
    assert env.prove("--class", "reentrancy").exit_code == 0
    with env.ledger() as ledger:
        conn = ledger._conn
        event = conn.execute(
            "SELECT payload_json FROM audit_log WHERE event = 'finding.transitioned' ORDER BY seq"
        ).fetchall()
    steps = [row[0] for row in event]
    assert '"to":"HYPOTHESIZED"' in steps[0]
    assert '"evidence_level":"E0"' in steps[0]
    assert '"to":"POC_DRAFTED"' in steps[1]
    assert '"evidence_level":"E0"' in steps[1]
    assert '"to":"REPRODUCED"' in steps[2]
    assert '"oracle_run_ids":[1]' in steps[2]


# Usage errors and refusals


def test_exactly_one_selector_is_required(reentrancy: Env) -> None:
    assert reentrancy.prove().exit_code == 2
    assert reentrancy.prove("--class", "reentrancy", "--finding", "1").exit_code == 2


@pytest.mark.parametrize("attempts", ["0", "6", "-1"])
def test_max_attempts_is_bounded(reentrancy: Env, attempts: str) -> None:
    result = reentrancy.prove("--class", "reentrancy", "--max-attempts", attempts)
    assert result.exit_code == 2
    assert reentrancy.forge.calls == []


def test_an_unknown_finding_or_class_is_a_usage_error(reentrancy: Env) -> None:
    assert reentrancy.prove("--finding", "999").exit_code == 2
    assert reentrancy.prove("--class", "dos").exit_code == 2


def test_a_finding_of_another_project_version_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = Env(tmp_path, monkeypatch, REENTRANCY)
    other = tmp_path / "other"
    shutil.copytree(REENTRANCY.project, other)
    (other / "src" / "Extra.sol").write_text(
        "// INTENTIONALLY VULNERABLE: test fixture, do not deploy\ncontract Extra {}\n"
    )
    result = runner.invoke(
        app,
        ["prove", str(other), "--finding", str(env.ids[2]), "--ledger", str(env.ledger_path)],
    )
    assert result.exit_code == 2
    assert "another version" in result.output


def test_only_a_candidate_can_be_proved(reentrancy: Env) -> None:
    assert reentrancy.prove("--class", "reentrancy").exit_code == 0
    again = reentrancy.prove("--finding", str(reentrancy.ids[2]))
    assert again.exit_code == 2
    assert "already REPRODUCED" in again.output


def test_the_poc_directory_must_be_outside_the_project_and_clean(reentrancy: Env) -> None:
    inside = runner.invoke(
        app,
        [
            "prove",
            str(REENTRANCY.project),
            "--class",
            "reentrancy",
            "--ledger",
            str(reentrancy.ledger_path),
            "--poc-dir",
            str(REENTRANCY.project / "poc"),
        ],
    )
    assert inside.exit_code == 2
    reentrancy.poc_dir.mkdir()
    (reentrancy.poc_dir / "Other.t.sol").write_text("contract Other {}")
    dirty = reentrancy.prove("--class", "reentrancy")
    assert dirty.exit_code == 2
    assert "empty or hold only" in dirty.output
    assert reentrancy.finding_state(2) is FindingState.CANDIDATE


@pytest.mark.parametrize("mode", ["record", "live"])
def test_sending_modes_need_the_consent_flag(reentrancy: Env, mode: str) -> None:
    result = reentrancy.prove("--class", "reentrancy", "--mode", mode)
    assert result.exit_code == 2
    assert "--allow-llm" in result.output
    assert reentrancy.finding_state(2) is FindingState.CANDIDATE


def test_a_missing_cassette_stops_the_run_without_a_status_change(
    reentrancy: Env, tmp_path: Path, no_network: None
) -> None:
    del no_network
    empty = tmp_path / "empty"
    empty.mkdir()
    result = reentrancy.prove("--class", "reentrancy", cassettes=empty)
    assert result.exit_code == 4
    assert "no cassette" in result.output
    assert reentrancy.finding_state(2) is FindingState.CANDIDATE


def test_the_budget_stops_the_loop_and_says_so(reentrancy: Env) -> None:
    result = reentrancy.prove("--class", "reentrancy", "--budget-calls", "1")
    assert result.exit_code == 3, result.output
    assert "stopped early: the model budget is used up" in result.stdout
    assert "final state: HYPOTHESIZED (evidence level E0)" in result.stdout
    assert reentrancy.forge.calls == []


def test_a_dry_run_prints_size_and_hash_and_changes_nothing(
    reentrancy: Env, no_network: None
) -> None:
    del no_network
    result = reentrancy.prove("--class", "reentrancy", "--llm-dry-run", "--mode", "live")
    assert result.exit_code == 0, result.output
    assert "dry run: nothing was sent" in result.stdout
    assert re.search(r"payload sha256: [0-9a-f]{64}", result.stdout)
    assert reentrancy.finding_state(2) is FindingState.CANDIDATE
    with reentrancy.ledger() as ledger:
        assert ledger._conn.execute("SELECT count(*) FROM model_run").fetchone()[0] == 0


def test_a_target_that_reads_the_test_environment_is_refused_before_anything_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    shutil.copytree(REENTRANCY.project, project)
    source = project / "src" / "Vault.sol"
    source.write_text(
        source.read_text().replace(
            "contract Vault {", 'import {Test} from "forge-std/Test.sol";\n\ncontract Vault {', 1
        )
    )
    (tmp_path / "env").mkdir()
    env = Env(tmp_path / "env", monkeypatch, Fixture(project, REENTRANCY.scan, REENTRANCY.poc))
    result = env.prove("--class", "reentrancy")
    assert result.exit_code == 5
    assert "reads the test environment" in result.output
    assert env.forge.calls == []
    with env.ledger() as ledger:
        assert ledger._conn.execute("SELECT count(*) FROM model_run").fetchone()[0] == 0
    assert env.finding_state(2) is FindingState.CANDIDATE


def test_replay_records_each_call_with_the_replay_mode(reentrancy: Env) -> None:
    assert reentrancy.prove("--class", "reentrancy").exit_code == 0
    with reentrancy.ledger() as ledger:
        modes = {row[0] for row in ledger._conn.execute("SELECT cassette_mode FROM model_run")}
    assert modes == {CassetteMode.REPLAY.value}


def test_verdicts_of_failed_runs_never_become_trusted_claims(reentrancy: Env) -> None:
    reentrancy.forge.decide = lambda tree, number: "reverted"
    reentrancy.prove("--class", "reentrancy", "--max-attempts", "1")
    with reentrancy.ledger() as ledger:
        rows = ledger._conn.execute("SELECT status FROM claim").fetchall()
    assert ClaimStatus.TRUSTED.value not in {row[0] for row in rows}


def test_the_shipped_synthetic_cassettes_are_up_to_date(tmp_path: Path) -> None:
    """Regenerating them from the current prompts gives the same files: no stale cassette."""
    from prove_support import generate

    fresh = {path.name: path.read_bytes() for path in generate(tmp_path)}
    shipped = {
        path.name: path.read_bytes() for path in CASSETTES.glob("*.json") if path.name in fresh
    }
    assert fresh == shipped
