"""The bundle of a fix loop: attempt history, determinism, and a replay that needs no model."""

import getpass
import hashlib
import json
import re
from collections.abc import Callable
from pathlib import Path

import pytest
from fix_support import FixRun, diff_reply, patch_text, reproduce
from llm_support import no_network
from prove_support import REENTRANCY
from typer.testing import CliRunner
from vault_scenario import vault_forge

from assay.cli.main import app
from assay.ledger import FinalVerdict
from assay.report.bundle import HISTORY_FILE, without_timing
from assay.report.replay import ReplayError, load_bundle, replay_bundle

__all__ = ["no_network"]
cli = CliRunner()
OVERFIT = patch_text(REENTRANCY, "overfit")
GOOD = patch_text(REENTRANCY, "good")
DESTRUCTIVE = patch_text(REENTRANCY, "destructive")
FORBIDDEN = re.compile(r"\b(secure|safe|proven|guaranteed|unhackable)\b", re.IGNORECASE)


def files_of(bundle: Path) -> dict[str, bytes]:
    return {
        path.relative_to(bundle).as_posix(): path.read_bytes()
        for path in sorted(bundle.rglob("*"))
        if path.is_file()
    }


def fixed(tmp_path: Path, replies: list[str], name: str = "run") -> tuple[FixRun, Path]:
    root = tmp_path / name
    root.mkdir()
    bundle = root / "bundle"
    run = FixRun(reproduce(root), root, replies, bundle_dir=bundle)
    run.run()
    return run, bundle


@pytest.fixture
def no_model(monkeypatch: pytest.MonkeyPatch) -> Callable[[], None]:
    """Returns a function that arms the check: after it, no model client can be created."""

    def arm() -> None:
        def forbidden(*args: object, **kwargs: object) -> None:
            raise AssertionError("a model client was created during a replay")

        monkeypatch.setattr("assay.llm.client.LlmClient.__init__", forbidden)
        monkeypatch.setattr("assay.llm.client.LlmClient.complete", forbidden)

    return arm


def test_the_bundle_holds_the_final_patch_the_poc_the_history_and_the_bounds(
    tmp_path: Path,
) -> None:
    run, bundle = fixed(tmp_path, [diff_reply(OVERFIT), diff_reply(GOOD)])
    files = files_of(bundle)
    manifest = json.loads(files["manifest.json"])
    listed = {item["path"]: item["sha256"] for item in manifest["files"]}
    assert HISTORY_FILE in listed
    assert listed[HISTORY_FILE] == hashlib.sha256(files[HISTORY_FILE]).hexdigest()
    assert files["patch.diff"].decode() == GOOD
    assert any(path.startswith("poc/") for path in files)
    assert manifest["final_verdict"] == "VERIFIED_WITHIN_BOUNDS"
    assert manifest["bounds_statement"]

    history = json.loads(files[HISTORY_FILE])
    assert history["format"] == "assay-fix-history"
    attempts = history["attempts"]
    assert [a["number"] for a in attempts] == [1, 2]
    assert attempts[0]["diff_sha256"] == hashlib.sha256(OVERFIT.encode()).hexdigest()
    assert attempts[1]["diff_sha256"] == hashlib.sha256(GOOD.encode()).hexdigest()
    assert history["final"]["diff_sha256"] == attempts[1]["diff_sha256"]
    assert history["final"]["decision"] == "held_out_run"
    verdicts = {row["oracle"]: row["verdict"] for row in attempts[0]["oracles"]}
    assert verdicts["variant"] == "FAIL"
    assert history["limits"]["max_changed_lines"] == 200
    assert history["limits"]["max_files"] == 5
    # The final run used the held-out seed, and the manifest says which.
    assert manifest["settings"]["fuzz_seed"] == history["held_out_bounds"]["fuzz_seed"]
    assert history["loop_bounds"]["fuzz_seed"] != history["held_out_bounds"]["fuzz_seed"]
    assert run.outcome is not None


def test_the_bundle_holds_no_prompt_no_key_no_path_and_no_forbidden_word(tmp_path: Path) -> None:
    run, bundle = fixed(tmp_path, [diff_reply(OVERFIT), diff_reply(GOOD)])
    prompt_text = run.prompt_text()
    system = json.loads(run.endpoint.requests[0].content)["messages"][0]["content"]
    for path, data in files_of(bundle).items():
        text = data.decode("utf-8", errors="replace")
        assert str(tmp_path) not in text, path
        assert getpass.getuser() not in text or len(getpass.getuser()) < 4, path
        assert system not in text, path
        assert "untrusted_data" not in text, path
        assert "synthetic-not-a-key" not in text, path
        assert "feedback_on_earlier_attempts" not in text, path
        if path.startswith(("fix/", "evidence/")) or path == "manifest.json":
            assert FORBIDDEN.search(text) is None, path
    assert "untrusted_data" in prompt_text


def test_two_runs_of_the_same_inputs_give_the_same_history_and_manifest(tmp_path: Path) -> None:
    _, first = fixed(tmp_path, [diff_reply(OVERFIT), diff_reply(GOOD)], "one")
    _, second = fixed(tmp_path, [diff_reply(OVERFIT), diff_reply(GOOD)], "two")
    one, two = files_of(first), files_of(second)
    assert one[HISTORY_FILE] == two[HISTORY_FILE]
    assert without_timing(one["manifest.json"]) == without_timing(two["manifest.json"])
    assert one.keys() == two.keys()


@pytest.mark.usefixtures("no_network")
def test_replay_runs_the_oracles_only_and_matches(
    tmp_path: Path, no_model: Callable[[], None]
) -> None:
    _, bundle = fixed(tmp_path, [diff_reply(OVERFIT), diff_reply(GOOD)])
    no_model()
    manifest = load_bundle(bundle)
    work = tmp_path / "replay"
    work.mkdir()
    forge = vault_forge()
    outcome = replay_bundle(bundle, manifest, runner=forge, work_dir=work)
    assert outcome.matches, outcome.differences
    assert outcome.report.final_verdict is FinalVerdict.VERIFIED_WITHIN_BOUNDS
    assert forge.commands("test")


@pytest.mark.usefixtures("no_network")
def test_the_replay_command_prints_a_match_for_a_fix_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_model: Callable[[], None]
) -> None:
    _, bundle = fixed(tmp_path, [diff_reply(OVERFIT), diff_reply(GOOD)])
    no_model()
    monkeypatch.setattr("assay.cli.replay._runner", lambda image: vault_forge())
    result = cli.invoke(app, ["replay", str(bundle)])
    assert result.exit_code == 0, result.output
    assert "REPLAY MATCH" in result.output
    assert "VERIFIED_WITHIN_BOUNDS" in result.output
    assert FORBIDDEN.search(result.output) is None


@pytest.mark.usefixtures("no_network")
def test_a_rejected_fix_has_a_bundle_that_replays_as_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_model: Callable[[], None]
) -> None:
    run, bundle = fixed(tmp_path, [diff_reply(OVERFIT)] * 3)
    no_model()
    assert run.outcome is not None
    assert run.outcome.verdict is FinalVerdict.REJECTED
    history = json.loads((bundle / HISTORY_FILE).read_text())
    assert history["final"]["decision"] == "last_attempt"
    assert history["final"]["verdict"] == "REJECTED"
    assert len(history["attempts"]) == 3
    monkeypatch.setattr("assay.cli.replay._runner", lambda image: vault_forge())
    result = cli.invoke(app, ["replay", str(bundle)])
    assert result.exit_code == 0, result.output
    assert "final verdict: REJECTED (recorded and replayed)" in result.output


def test_a_changed_history_is_a_tampered_bundle_and_nothing_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_model: Callable[[], None]
) -> None:
    _, bundle = fixed(tmp_path, [diff_reply(OVERFIT), diff_reply(GOOD)])
    no_model()
    history = bundle / HISTORY_FILE
    history.write_text(history.read_text().replace("REJECTED", "VERIFIED_WITHIN_BOUNDS", 1))
    with pytest.raises(ReplayError) as caught:
        load_bundle(bundle)
    assert caught.value.kind == "tampered"
    assert any("changed: fix/history.json" in item for item in caught.value.details)
    forge = vault_forge()
    monkeypatch.setattr("assay.cli.replay._runner", lambda image: forge)
    result = cli.invoke(app, ["replay", str(bundle)])
    assert result.exit_code == 5
    assert forge.calls == []


def test_extra_bundle_files_must_lie_under_fix(tmp_path: Path) -> None:
    from dataclasses import replace

    from fix_support import bundle_request
    from vault_scenario import FIXTURE

    from assay.ledger import Ledger
    from assay.orchestrator.verify import VerifyRequest, run_verification
    from assay.report.bundle import BundleError, bundle_files

    work = tmp_path / "w"
    work.mkdir()
    with Ledger.open(tmp_path / "l.db") as ledger:
        outcome = run_verification(
            VerifyRequest(FIXTURE, FIXTURE / "patches" / "good.diff", FIXTURE / "poc"),
            runner=vault_forge(),
            ledger=ledger,
            work_dir=work,
            bundle=replace(bundle_request(tmp_path / "out", work), write=False),
        )
    assert outcome.contents is not None
    assert outcome.manifest_sha256 is None
    assert not (tmp_path / "out").exists()
    contents = outcome.contents
    ok = replace(contents, extra=((HISTORY_FILE, b"{}"),))
    assert HISTORY_FILE in [
        path for path, _ in bundle_files(ok, bundle_request(tmp_path / "o", work).sanitizer)
    ]
    for bad in ("evil.txt", "patch.diff", "base/src/Vault.sol", "fix/../patch.diff"):
        with pytest.raises(BundleError if not bad.startswith("fix/..") else Exception):
            bundle_files(
                replace(contents, extra=((bad, b"x"),)),
                bundle_request(tmp_path / "o", work).sanitizer,
            )
