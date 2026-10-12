"""`assay fix` and `assay run` end to end with cassettes and a stand-in forge (no Docker)."""

import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest
from fake_forge import FakeForge
from fix_support import (
    FixRun,
    Reproduced,
    diff_of,
    diff_reply,
    patch_text,
    reproduce,
)
from llm_support import no_network
from prove_support import REENTRANCY, seed
from schema_support import assert_valid
from typer.testing import CliRunner, Result
from vault_scenario import vault_forge

from assay.cli.main import app
from assay.ledger import FindingState, Ledger

__all__ = ["no_network"]
cli = CliRunner()
FORBIDDEN = re.compile(r"\b(secure|safe|proven|guaranteed|unhackable)\b", re.IGNORECASE)
OVERFIT = patch_text(REENTRANCY, "overfit")
GOOD = patch_text(REENTRANCY, "good")
DESTRUCTIVE = patch_text(REENTRANCY, "destructive")


@dataclass
class Env:
    """A recorded scenario (cassettes) and a fresh ledger with a REPRODUCED finding."""

    root: Path
    cassettes: Path
    reproduced: Reproduced
    forge: FakeForge

    def fix(self, *extra: str, finding: int | None = None) -> Result:
        return cli.invoke(
            app,
            [
                "fix",
                str(REENTRANCY.project),
                "--finding",
                str(self.reproduced.finding_id if finding is None else finding),
                "--ledger",
                str(self.reproduced.ledger_path),
                "--poc-dir",
                str(self.reproduced.poc_dir),
                "--cassette-dir",
                str(self.cassettes),
                "--profile",
                "quick",
                *extra,
            ],
        )

    def state(self) -> FindingState:
        with Ledger.open(self.reproduced.ledger_path, read_only=True) as ledger:
            return ledger.get_finding(self.reproduced.finding_id).state  # type: ignore[arg-type]


def make_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replies: list[str],
    max_attempts: int = 3,
) -> Env:
    recorded = tmp_path / "recorded"
    recorded.mkdir()
    FixRun(reproduce(recorded), recorded, replies, max_attempts=max_attempts).run()
    cassettes = tmp_path / "cassettes"
    cassettes.mkdir()
    for source in ("fix-cassettes", "prove-cassettes"):
        for item in (recorded / source).glob("*.json"):
            shutil.copy(item, cassettes / item.name)
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    reproduced = reproduce(fresh)
    forge = vault_forge()
    monkeypatch.setattr("assay.cli.fix.SandboxRunner", lambda: forge)
    return Env(tmp_path, cassettes, reproduced, forge)


def clean(text: str) -> None:
    assert FORBIDDEN.search(text) is None, text


@pytest.mark.usefixtures("no_network")
def test_fix_reaches_verified_within_bounds_with_two_attempts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = make_env(tmp_path, monkeypatch, [diff_reply(OVERFIT), diff_reply(GOOD)])
    bundle = tmp_path / "out" / "bundle"
    result = env.fix("--bundle-out", str(bundle))
    assert result.exit_code == 0, result.output
    out = result.output
    assert "attempt 1: patch " in out
    assert "REJECTED in the loop: variant FAIL (variant_found)" in out
    assert "attempt 2: patch " in out
    assert "VERIFIED_WITHIN_BOUNDS in the loop" in out
    assert "final verdict: VERIFIED_WITHIN_BOUNDS" in out
    assert "held-out seed" in out
    assert "finding state: VERIFIED_WITHIN_BOUNDS (evidence level E3)" in out
    assert "not a proof of absence" in out
    assert "bounds:" in out
    assert (bundle / "fix" / "history.json").is_file()
    assert "bundle: written, manifest sha256" in out
    clean(out)
    assert env.state() is FindingState.VERIFIED_WITHIN_BOUNDS
    audit = cli.invoke(app, ["dev", "ledger-audit", str(env.reproduced.ledger_path)])
    assert audit.exit_code == 0, audit.output


@pytest.mark.usefixtures("no_network")
def test_fix_prints_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = make_env(tmp_path, monkeypatch, [diff_reply(OVERFIT), diff_reply(GOOD)])
    result = env.fix("--json")
    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert document["final_verdict"] == "VERIFIED_WITHIN_BOUNDS"
    assert document["finding_state"] == "VERIFIED_WITHIN_BOUNDS"
    assert [a["number"] for a in document["history"]["attempts"]] == [1, 2]
    assert document["report"]["final_verdict"] == "VERIFIED_WITHIN_BOUNDS"
    assert document["format"] == "assay-fix/1"
    assert_valid("fix", document)
    clean(result.stdout)


@pytest.mark.usefixtures("no_network")
def test_fix_exits_one_when_the_attempts_run_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = make_env(tmp_path, monkeypatch, [diff_reply(DESTRUCTIVE)] * 3)
    result = env.fix()
    assert result.exit_code == 1, result.output
    assert "final verdict: REJECTED" in result.output
    assert "attempts exhausted (3 of 3)" in result.output
    assert "final verdict: VERIFIED_WITHIN_BOUNDS" not in result.output
    assert "VERIFIED_WITHIN_BOUNDS in the loop" not in result.output
    assert env.state() is FindingState.REJECTED
    assert env.forge.commands("test") == []


@pytest.mark.usefixtures("no_network")
def test_fix_exits_five_for_a_patch_that_touches_a_protected_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protected = diff_of(
        REENTRANCY, "test/Vault.t.sol", lambda t: t.replace("function", "function ", 1)
    )
    env = make_env(tmp_path, monkeypatch, [diff_reply(protected)], max_attempts=1)
    result = env.fix("--max-attempts", "1")
    assert result.exit_code == 5, result.output
    assert "protected_path_modified" in result.output
    assert env.forge.calls == []


@pytest.mark.usefixtures("no_network")
def test_fix_exits_four_when_no_cassette_answers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = make_env(tmp_path, monkeypatch, [diff_reply(GOOD)], max_attempts=1)
    empty = tmp_path / "empty"
    empty.mkdir()
    env.cassettes = empty
    result = env.fix()
    assert result.exit_code == 4, result.output
    assert env.state() is FindingState.REPRODUCED
    assert env.forge.calls == []


def test_fix_dry_run_sends_nothing_and_prints_the_payload_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_network: None
) -> None:
    env = make_env(tmp_path, monkeypatch, [diff_reply(GOOD)], max_attempts=1)
    result = env.fix("--llm-dry-run")
    assert result.exit_code == 0, result.output
    assert "dry run: nothing was sent" in result.output
    match = re.search(r"payload sha256: ([0-9a-f]{64})", result.output)
    assert match is not None
    assert (env.cassettes / f"{match.group(1)}.json").is_file()
    assert env.forge.calls == []
    assert env.state() is FindingState.REPRODUCED


def test_fix_usage_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = make_env(tmp_path, monkeypatch, [diff_reply(GOOD)], max_attempts=1)
    record = env.fix("--mode", "record")
    assert record.exit_code == 2
    assert "--allow-llm" in record.output
    assert env.fix(finding=999).exit_code == 2
    assert env.fix("--max-attempts", "6").exit_code == 2
    assert env.fix("--seed", "feed").exit_code == 2
    assert env.fix("--max-files", "0").exit_code == 2
    assert env.fix("--budget-calls", "0").exit_code == 2
    full = tmp_path / "full"
    full.mkdir()
    (full / "x").write_text("x")
    assert env.fix("--bundle-out", str(full)).exit_code == 2
    missing = cli.invoke(
        app,
        [
            "fix",
            str(REENTRANCY.project),
            "--finding",
            "1",
            "--ledger",
            str(env.reproduced.ledger_path),
            "--poc-dir",
            str(tmp_path / "nope"),
        ],
    )
    assert missing.exit_code == 2
    assert env.forge.calls == []
    assert env.state() is FindingState.REPRODUCED


def test_only_a_reproduced_finding_is_accepted_by_the_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = tmp_path / "ledger.db"
    with Ledger.open(ledger) as opened:
        ids = seed(opened, REENTRANCY, tmp_path)
    forge = vault_forge()
    monkeypatch.setattr("assay.cli.fix.SandboxRunner", lambda: forge)
    poc = tmp_path / "poc"
    poc.mkdir()
    result = cli.invoke(
        app,
        [
            "fix",
            str(REENTRANCY.project),
            "--finding",
            str(int(ids[0])),
            "--ledger",
            str(ledger),
            "--poc-dir",
            str(poc),
        ],
    )
    assert result.exit_code == 2
    assert "only a REPRODUCED finding is fixed" in result.output


def test_the_help_lists_the_new_commands_and_the_limits() -> None:
    top = cli.invoke(app, ["--help"])
    assert "fix" in top.output
    assert "run" in top.output
    fix = cli.invoke(app, ["fix", "--help"])
    for option in (
        "--finding",
        "--mode",
        "--allow-llm",
        "--max-attempts",
        "--profile",
        "--symbolic",
        "--bundle-out",
        "--max-changed-lines",
        "--max-files",
    ):
        assert option in fix.output
    run = cli.invoke(app, ["run", "--help"])
    assert "--class" in run.output
    assert "scan, prove, fix and bundle" in " ".join(run.output.split())


# -- assay run ------------------------------------------------------------------------------------


def stub_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    """`assay scan` needs the analyzers; the ledger gets the captured result instead."""

    def run_scan(project: Path, *, runner: object, ledger: Ledger, work_dir: Path) -> object:
        seed(ledger, REENTRANCY, work_dir)
        found = [SimpleNamespace(vuln_class=c) for c in ("access_control", "other", "reentrancy")]
        return SimpleNamespace(report=SimpleNamespace(findings=found, complete=True))

    monkeypatch.setattr("assay.cli.run.run_scan", run_scan)


@pytest.mark.usefixtures("no_network")
def test_run_goes_from_scan_to_a_bundle_that_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorded = tmp_path / "recorded"
    recorded.mkdir()
    FixRun(reproduce(recorded), recorded, [diff_reply(OVERFIT), diff_reply(GOOD)]).run()
    cassettes = tmp_path / "cassettes"
    cassettes.mkdir()
    for source in ("fix-cassettes", "prove-cassettes"):
        for item in (recorded / source).glob("*.json"):
            shutil.copy(item, cassettes / item.name)
    forge = vault_forge()
    monkeypatch.setattr("assay.cli.run.SandboxRunner", lambda: forge)
    monkeypatch.setattr("assay.cli.replay._runner", lambda image: forge)
    stub_scan(monkeypatch)
    bundle = tmp_path / "bundle"
    result = cli.invoke(
        app,
        [
            "run",
            str(REENTRANCY.project),
            "--class",
            "reentrancy",
            "--ledger",
            str(tmp_path / "run" / "ledger.db"),
            "--poc-dir",
            str(tmp_path / "poc"),
            "--cassette-dir",
            str(cassettes),
            "--profile",
            "quick",
            "--bundle-out",
            str(bundle),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "scan: 3 candidate findings (unverified), 1 of class reentrancy" in result.output
    assert "prove: finding" in result.output
    assert "REPRODUCED (evidence level E1)" in result.output
    assert "final verdict: VERIFIED_WITHIN_BOUNDS" in result.output
    clean(result.output)
    replayed = cli.invoke(app, ["replay", str(bundle)])
    assert replayed.exit_code == 0, replayed.output
    assert "REPLAY MATCH" in replayed.output


@pytest.mark.usefixtures("no_network")
def test_run_prints_json_that_matches_the_run_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorded = tmp_path / "recorded"
    recorded.mkdir()
    FixRun(reproduce(recorded), recorded, [diff_reply(OVERFIT), diff_reply(GOOD)]).run()
    cassettes = tmp_path / "cassettes"
    cassettes.mkdir()
    for source in ("fix-cassettes", "prove-cassettes"):
        for item in (recorded / source).glob("*.json"):
            shutil.copy(item, cassettes / item.name)
    forge = vault_forge()
    monkeypatch.setattr("assay.cli.run.SandboxRunner", lambda: forge)
    stub_scan(monkeypatch)
    result = cli.invoke(
        app,
        [
            "run",
            str(REENTRANCY.project),
            "--class",
            "reentrancy",
            "--ledger",
            str(tmp_path / "run" / "ledger.db"),
            "--poc-dir",
            str(tmp_path / "poc"),
            "--cassette-dir",
            str(cassettes),
            "--profile",
            "quick",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert document["format"] == "assay-run/1"
    assert document["final_verdict"] == "VERIFIED_WITHIN_BOUNDS"
    assert_valid("run", document)


@pytest.mark.usefixtures("no_network")
def test_run_stops_when_the_class_has_no_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    forge = vault_forge()
    monkeypatch.setattr("assay.cli.run.SandboxRunner", lambda: forge)
    stub_scan(monkeypatch)
    result = cli.invoke(
        app,
        [
            "run",
            str(REENTRANCY.project),
            "--class",
            "rounding",
            "--ledger",
            str(tmp_path / "ledger.db"),
            "--poc-dir",
            str(tmp_path / "poc"),
            "--cassette-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 2
    assert "no candidate finding of class rounding" in result.output
    assert forge.calls == []
