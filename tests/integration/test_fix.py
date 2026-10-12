"""`assay fix` and `assay run` against the real runner image, with synthetic cassettes.

The scripted answers of the "model" are the fixture's own patches. They are recorded into
cassettes by the first phase of each test (the requests of the second attempt hold feedback from
the real oracles, so the cassettes follow the oracle output instead of going stale), and the
second phase replays them through the command line. Everything else is real: the analyzers of
`assay scan`, the static PoC checker, forge in the sandbox, the five oracles, the held-out run,
the ledger, the bundle and `assay replay`.
"""

import json
import re
import shutil
from collections.abc import Sequence
from pathlib import Path

import pytest
from fix_support import CONFIG, QUICK, Reproduced, diff_of, diff_reply, patch_text
from llm_support import Endpoint, ok
from prove_support import ACCESS_CONTROL, CASSETTES, REENTRANCY, Fixture
from typer.testing import CliRunner

from assay.cli.main import app
from assay.ledger import CassetteMode, FindingState, Ledger
from assay.llm import Budget, LlmClient
from assay.llm.client import Recorder
from assay.orchestrator.fix import FixOutcome, FixRequest, run_fix
from assay.sandbox import SandboxResult, SandboxRunner

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("runner")]
cli = CliRunner()
FORBIDDEN = re.compile(r"\b(secure|safe|proven|guaranteed|unhackable)\b", re.IGNORECASE)


def reproduce_with_cli(root: Path, fixture: Fixture, vuln_class: str) -> Reproduced:
    """`assay scan`, then `assay prove --class`, both real, answering from the shipped cassettes."""
    root.mkdir(parents=True)
    ledger = root / "ledger.db"
    poc = root / "poc"
    scanned = cli.invoke(app, ["scan", str(fixture.project), "--ledger", str(ledger)])
    assert scanned.exit_code == 0, scanned.output
    proved = cli.invoke(
        app,
        [
            "prove",
            str(fixture.project),
            "--class",
            vuln_class,
            "--ledger",
            str(ledger),
            "--poc-dir",
            str(poc),
            "--cassette-dir",
            str(CASSETTES),
        ],
    )
    assert proved.exit_code == 0, proved.output
    with Ledger.open(ledger, read_only=True) as opened:
        (found,) = opened.findings(vuln_class=vuln_class, state=FindingState.REPRODUCED)
    return Reproduced(ledger, int(found.id), poc, None, fixture)  # type: ignore[arg-type]


def record(
    reproduced: Reproduced, root: Path, replies: Sequence[str], runner: SandboxRunner, attempts: int
) -> tuple[Path, FixOutcome]:
    """Phase one: run the fix loop on a copy of the ledger and record the cassettes."""
    copy = root / "record"
    shutil.copytree(reproduced.ledger_path.parent, copy)
    cassettes = root / "cassettes"
    endpoint = Endpoint(*(ok(reply, model="synthetic-model-0") for reply in replies))

    def make_client(recorder: Recorder) -> LlmClient:
        return LlmClient(
            mode=CassetteMode.RECORD,
            allow_llm=True,
            config=CONFIG,
            budget=Budget(max_calls=30, max_tokens=5_000_000),
            cassette_dir=cassettes,
            recorder=recorder,
            transport=endpoint.transport,
        )

    work = root / "record-work"
    work.mkdir()
    with Ledger.open(copy / "ledger.db") as ledger:
        outcome = run_fix(
            FixRequest(
                reproduced.fixture.project,
                reproduced.poc_dir,
                reproduced.finding_id,
                attempts,
                settings=QUICK,
            ),
            ledger=ledger,
            make_client=make_client,
            runner=runner,
            work_dir=work,
        )
    assert isinstance(outcome, FixOutcome)
    return cassettes, outcome


def fix_command(reproduced: Reproduced, cassettes: Path, *extra: str):  # type: ignore[no-untyped-def]
    return cli.invoke(
        app,
        [
            "fix",
            str(reproduced.fixture.project),
            "--finding",
            str(reproduced.finding_id),
            "--ledger",
            str(reproduced.ledger_path),
            "--poc-dir",
            str(reproduced.poc_dir),
            "--cassette-dir",
            str(cassettes),
            "--profile",
            "quick",
            *extra,
        ],
    )


def test_overfit_then_good_from_cassettes(tmp_path: Path, runner: SandboxRunner) -> None:
    reproduced = reproduce_with_cli(tmp_path / "base", REENTRANCY, "reentrancy")
    replies = [
        diff_reply(patch_text(REENTRANCY, "overfit")),
        diff_reply(patch_text(REENTRANCY, "good")),
    ]
    cassettes, recorded = record(reproduced, tmp_path, replies, runner, 3)
    assert [a.in_loop_verdict.value for a in recorded.history.attempts if a.in_loop_verdict] == [
        "REJECTED",
        "VERIFIED_WITHIN_BOUNDS",
    ]
    bundle = tmp_path / "bundle"
    result = fix_command(reproduced, cassettes, "--bundle-out", str(bundle))
    assert result.exit_code == 0, result.output
    assert "REJECTED in the loop: variant FAIL (variant_found)" in result.output
    assert "VERIFIED_WITHIN_BOUNDS in the loop" in result.output
    assert "final verdict: VERIFIED_WITHIN_BOUNDS" in result.output
    assert FORBIDDEN.search(result.output) is None
    with Ledger.open(reproduced.ledger_path, read_only=True) as opened:
        assert (
            opened.get_finding(reproduced.finding_id).state is FindingState.VERIFIED_WITHIN_BOUNDS
        )  # type: ignore[arg-type]
        assert opened.check_invariants() == []
    replayed = cli.invoke(app, ["replay", str(bundle)])
    assert replayed.exit_code == 0, replayed.output
    assert "REPLAY MATCH" in replayed.output


def test_a_good_patch_for_a_missing_modifier_passes_at_once(
    tmp_path: Path, runner: SandboxRunner
) -> None:
    reproduced = reproduce_with_cli(tmp_path / "base", ACCESS_CONTROL, "access_control")
    replies = [diff_reply(patch_text(ACCESS_CONTROL, "good"))]
    cassettes, recorded = record(reproduced, tmp_path, replies, runner, 3)
    assert len(recorded.history.attempts) == 1
    result = fix_command(reproduced, cassettes)
    assert result.exit_code == 0, result.output
    assert "final verdict: VERIFIED_WITHIN_BOUNDS" in result.output
    assert "attempt 2" not in result.output


def test_destructive_patches_end_rejected_when_the_attempts_run_out(
    tmp_path: Path, runner: SandboxRunner
) -> None:
    reproduced = reproduce_with_cli(tmp_path / "base", REENTRANCY, "reentrancy")
    replies = [diff_reply(patch_text(REENTRANCY, "destructive"))]
    cassettes, recorded = record(reproduced, tmp_path, replies * 3, runner, 3)
    assert recorded.verdict.value == "REJECTED"
    result = fix_command(reproduced, cassettes)
    assert result.exit_code == 1, result.output
    assert "final verdict: REJECTED" in result.output
    assert "attempts exhausted (3 of 3)" in result.output


class NeverRuns(SandboxRunner):
    """The real image id, and a failure for anything that would run in a container."""

    def __init__(self, real: SandboxRunner) -> None:
        super().__init__(docker=real._docker, image=real.image)
        self.calls = 0

    def run(self, *args: object, **kwargs: object) -> SandboxResult:
        self.calls += 1
        raise AssertionError("a rejected diff must not run anything in the sandbox")


@pytest.mark.parametrize(
    ("kind", "code"),
    [
        ("protected", "protected_path_modified"),
        ("traversal", "path_traversal"),
        ("large", "patch_too_large"),
    ],
)
def test_dangerous_diffs_are_rejected_before_anything_runs(
    tmp_path: Path, runner: SandboxRunner, kind: str, code: str
) -> None:
    reproduced = reproduce_with_cli(tmp_path / "base", REENTRANCY, "reentrancy")
    diffs = {
        "protected": diff_of(REENTRANCY, "test/Vault.t.sol", lambda t: t + "// edit\n"),
        "traversal": "--- a/../../outside.sol\n+++ b/../../outside.sol\n@@ -0,0 +1 @@\n+x\n",
        "large": diff_of(
            REENTRANCY,
            "src/Vault.sol",
            lambda t: t.replace(
                "    error ZeroAmount();",
                "".join(f"    // filler {i}\n" for i in range(250)) + "    error ZeroAmount();",
            ),
        ),
    }
    spy = NeverRuns(runner)
    endpoint = Endpoint(ok(diff_reply(diffs[kind]), model="synthetic-model-0"))
    work = tmp_path / "work"
    work.mkdir()
    with Ledger.open(reproduced.ledger_path) as ledger:
        outcome = run_fix(
            FixRequest(
                REENTRANCY.project, reproduced.poc_dir, reproduced.finding_id, 1, settings=QUICK
            ),
            ledger=ledger,
            make_client=lambda recorder: LlmClient(
                mode=CassetteMode.RECORD,
                allow_llm=True,
                config=CONFIG,
                budget=Budget(max_calls=5, max_tokens=1_000_000),
                cassette_dir=tmp_path / "cassettes",
                recorder=recorder,
                transport=endpoint.transport,
            ),
            runner=spy,
            work_dir=work,
        )
    assert isinstance(outcome, FixOutcome)
    assert spy.calls == 0
    assert outcome.verdict.value == "REJECTED"
    integrity = outcome.history.attempts[0].oracles[0]
    assert code in [reason.code for reason in integrity.reasons]


def test_run_goes_from_scan_to_a_bundle_that_replays_without_network(
    tmp_path: Path, runner: SandboxRunner
) -> None:
    reproduced = reproduce_with_cli(tmp_path / "base", REENTRANCY, "reentrancy")
    replies = [
        diff_reply(patch_text(REENTRANCY, "overfit")),
        diff_reply(patch_text(REENTRANCY, "good")),
    ]
    recorded, _ = record(reproduced, tmp_path, replies, runner, 3)
    cassettes = tmp_path / "all-cassettes"
    shutil.copytree(CASSETTES, cassettes)
    for item in recorded.glob("*.json"):
        shutil.copy(item, cassettes / item.name)
    bundle = tmp_path / "run-bundle"
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
            str(tmp_path / "run-poc"),
            "--cassette-dir",
            str(cassettes),
            "--profile",
            "quick",
            "--bundle-out",
            str(bundle),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "final verdict: VERIFIED_WITHIN_BOUNDS" in result.output
    assert json.loads((bundle / "fix" / "history.json").read_text())["final"]["decision"] == (
        "held_out_run"
    )
    replayed = cli.invoke(app, ["replay", str(bundle)])
    assert replayed.exit_code == 0, replayed.output
    assert "REPLAY MATCH" in replayed.output
