"""S1 for Halmos (ADR 0018): a project cannot widen what Halmos does.

Halmos reads options from `halmos.toml` at the project root and from NatSpec annotations
(`@custom:halmos ...`), and with `--ffi` it would run commands. Ingest leaves a project's
`halmos.toml` out, the symbolic oracle refuses sources with option annotations before Halmos
runs, the allowlist has no `--ffi`, and a property that calls `vm.ffi` gets no result from it.
"""

import shutil
from pathlib import Path

import pytest

from assay.ingest import create_snapshot
from assay.ingest.patch import prepare_patched_revision
from assay.ledger import Verdict
from assay.oracles.runtree import build_symbolic_tree, load_harness
from assay.oracles.symbolic import HalmosSettings, SymbolicContext, SymbolicOracle
from assay.oracles.symbolic.halmos import run_halmos
from assay.sandbox import SandboxRunner

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("runner", "symbolic_runner")]

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures" / "access_control" / "missing_modifier"
HOSTILE_HALMOS_TOML = """\
[global]
ffi = true
loop = 1
solver-command = "/bin/sh -c id"
"""
FFI_PROPERTY = """\
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayCheck} from "assay/AssayCheck.sol";

contract FfiCheck is AssayCheck {
    function check_variant_ffi(uint256 value) public {
        string[] memory command = new string[](1);
        command[0] = "id";
        bytes memory output = vm.ffi(command);
        assertInvariantHolds("no_ffi", output.length == 0 && value == value);
    }
}
"""


def _copy(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    shutil.copytree(FIXTURE, project)
    return project


def _context(
    runner: SandboxRunner, halmos: SandboxRunner, project: Path, work: Path
) -> SymbolicContext:
    base = create_snapshot(project, work / "base")
    poc = create_snapshot(project / "poc", work / "poc")
    prepared = prepare_patched_revision(
        base, (project / "patches" / "good.diff").read_bytes(), work / "patched"
    )
    assert prepared.snapshot is not None
    (work / "symbolic").mkdir()
    return SymbolicContext(
        runner=runner,
        symbolic_runner=halmos,
        vulnerable=base,
        patched=prepared.snapshot,
        poc=poc,
        harness=load_harness(),
        work_dir=work / "symbolic",
    )


def test_a_hostile_halmos_toml_changes_no_result(
    runner: SandboxRunner, symbolic_runner: SandboxRunner, tmp_path: Path
) -> None:
    project = _copy(tmp_path)
    (project / "halmos.toml").write_text(HOSTILE_HALMOS_TOML)
    (project / "poc" / "halmos.toml").write_text(HOSTILE_HALMOS_TOML)
    work = tmp_path / "work"
    work.mkdir()
    context = _context(runner, symbolic_runner, project, work)
    assert not (context.vulnerable.tree_dir / "halmos.toml").exists()
    assert not (context.poc.tree_dir / "halmos.toml").exists()
    outcome = SymbolicOracle().search(context)
    assert outcome.result.verdict is Verdict.PASS
    assert outcome.bounds.loop_bound == 3
    for execution in outcome.result.executions:
        argv = execution.argv
        assert argv[argv.index("--loop") + 1] == "3"
        assert argv[argv.index("--solver") + 1] == "z3"
        assert "--ffi" not in argv


def test_an_option_annotation_is_refused_before_halmos_runs(
    runner: SandboxRunner,
    symbolic_runner: SandboxRunner,
    tmp_path: Path,
    docker_calls: list[str],
) -> None:
    project = _copy(tmp_path)
    check = project / "poc" / "symbolic" / "FeeCollectorCheck.t.sol"
    check.write_text(
        check.read_text().replace(
            "contract FeeCollectorCheck is",
            "/// @custom:halmos --ffi --loop 1\ncontract FeeCollectorCheck is",
        )
    )
    work = tmp_path / "work"
    work.mkdir()
    context = _context(runner, symbolic_runner, project, work)
    docker_calls.clear()
    result = SymbolicOracle().run(context)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.codes() == ["inline_halmos_config"]
    assert "run" not in docker_calls


def test_a_property_gets_nothing_from_ffi(
    runner: SandboxRunner, symbolic_runner: SandboxRunner, tmp_path: Path
) -> None:
    project = _copy(tmp_path)
    (project / "poc" / "symbolic" / "FfiCheck.t.sol").write_text(FFI_PROPERTY)
    snapshot = create_snapshot(project, tmp_path / "base")
    poc = create_snapshot(project / "poc", tmp_path / "poc")
    tree = build_symbolic_tree(snapshot, snapshot, poc, load_harness(), tmp_path / "tree")
    run = run_halmos(symbolic_runner, tree.tree, tree.scratch, "check_variant_", HalmosSettings())
    assert run.problem is None
    (check,) = [item for item in run.checks if item.name == "check_variant_ffi"]
    assert check.outcome != "no_counterexample"
    assert check.witnesses == ()
