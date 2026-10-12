"""Foundry adapter against the real runner image."""

from collections.abc import Callable
from pathlib import Path

import pytest

from assay.analyzers import foundry
from assay.ingest import Snapshot
from assay.sandbox import SandboxRunner

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("runner")]

SnapshotOf = Callable[[Path], Snapshot]


def test_smoke_project_passes(
    runner: SandboxRunner, snapshot_of: SnapshotOf, data_dir: Path
) -> None:
    run = foundry.test(runner, snapshot_of(data_dir / "smoke").tree_dir)

    assert run.exit_code == 0
    assert run.image_id == runner.image_id()
    assert (run.summary.passed, run.summary.failed, run.summary.skipped) == (1, 0, 0)
    (suite,) = run.suites
    assert suite.name == "test/Counter.t.sol:CounterTest"
    (case,) = suite.tests
    assert (case.name, case.kind, case.status) == ("test_IncrementFromZero()", "unit", "success")
    assert case.gas is not None
    assert case.gas > 0


def test_smoke_project_builds(
    runner: SandboxRunner, snapshot_of: SnapshotOf, data_dir: Path
) -> None:
    run = foundry.build(runner, snapshot_of(data_dir / "smoke").tree_dir)
    assert run.succeeded
    assert run.exit_code == 0
    assert run.errors == ()


def test_probe_results_match_the_captured_output(
    runner: SandboxRunner, snapshot_of: SnapshotOf, data_dir: Path
) -> None:
    run = foundry.test(runner, snapshot_of(data_dir / "forge" / "probe").tree_dir)
    captured = (data_dir / "forge" / "probe-test.json").read_text(encoding="utf-8")

    assert run.exit_code == 1
    assert run.suites == foundry.parse_test_output(captured)


def test_compile_errors_match_the_captured_output(
    runner: SandboxRunner, snapshot_of: SnapshotOf, data_dir: Path
) -> None:
    tree = snapshot_of(data_dir / "forge" / "broken").tree_dir
    captured = (data_dir / "forge" / "broken-build.json").read_text(encoding="utf-8")

    build = foundry.build(runner, tree)
    assert not build.succeeded
    assert build.errors == foundry.parse_build_errors(captured)

    with pytest.raises(foundry.ForgeOutputError) as info:
        foundry.test(runner, tree)
    assert info.value.problem == "failed"
    assert "Undeclared identifier" in info.value.result.stderr
