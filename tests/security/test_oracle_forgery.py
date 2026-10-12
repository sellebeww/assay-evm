"""Evidence forgery against the ExploitOracle (threat T7), with the real runner image.

The target prints console lines in the exact format of the harness, and emits an event with the
exact signature of `AssayPredicate` from its own address; a helper contract that the PoC deploys
does the same. None of it may count: the oracle accepts a predicate only from an event emitted
by the test contract itself, and only for a predicate kind of the harness. A control PoC against
a real hole in the same project shows that the setup reproduces when it should.

A PoC that the test contract itself lets emit the event is not stopped by the oracle; that is
the job of the static PoC checker (see `tests/unit/test_poc_checker.py`), which refuses any PoC
that names the event or the predicate counter.
"""

import shutil
from pathlib import Path

import pytest

from assay.ingest import create_snapshot
from assay.ledger import Verdict
from assay.oracles.exploit import ExploitOracle
from assay.oracles.runtree import load_harness
from assay.sandbox import SandboxRunner

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("runner")]

DATA = Path(__file__).resolve().parents[1] / "data" / "forgery"
FORGERIES = ["ConsoleForgery", "TargetEventForgery", "HelperEventForgery"]


def reproduce(runner: SandboxRunner, tmp_path: Path, poc: str):  # type: ignore[no-untyped-def]
    target = create_snapshot(DATA / "project", tmp_path / "target")
    poc_dir = tmp_path / "poc-source"
    poc_dir.mkdir()
    shutil.copyfile(DATA / "pocs" / f"{poc}.t.sol", poc_dir / f"{poc}.t.sol")
    work = tmp_path / "work"
    work.mkdir()
    return ExploitOracle().reproduce(
        runner, target, create_snapshot(poc_dir, tmp_path / "poc"), load_harness(), work
    )


def test_a_real_hole_reproduces_in_the_same_project(runner: SandboxRunner, tmp_path: Path) -> None:
    result = reproduce(runner, tmp_path, "Control")
    assert result.verdict is Verdict.PASS, result.summary
    replays = result.executions[0].trace["replays"]
    assert isinstance(replays, list)
    assert len(replays) == 3
    assert all(item["outcome"] == "exploited" for item in replays)  # type: ignore[index,call-overload]


@pytest.mark.parametrize("poc", FORGERIES)
def test_forged_evidence_never_counts_as_a_predicate(
    runner: SandboxRunner, tmp_path: Path, poc: str
) -> None:
    result = reproduce(runner, tmp_path, poc)
    assert result.verdict is Verdict.INCONCLUSIVE, result.summary
    assert result.codes() == ["vacuous_poc"]
    replays = result.executions[0].trace["replays"]
    assert isinstance(replays, list)
    assert replays
    for item in replays:
        assert item["predicates"] == []  # type: ignore[index,call-overload]
        assert item["outcome"] == "no_predicate"  # type: ignore[index,call-overload]


def test_the_forged_console_lines_were_really_printed_and_still_ignored(
    runner: SandboxRunner, tmp_path: Path
) -> None:
    result = reproduce(runner, tmp_path, "ConsoleForgery")
    replays = result.executions[0].trace["replays"]
    assert isinstance(replays, list)
    markers = [m for item in replays for m in item["markers"]]  # type: ignore[index,call-overload]
    assert markers == ["ASSAY_PREDICATE|attacker_profit|eth:1->2"] * 3
    assert result.verdict is Verdict.INCONCLUSIVE
