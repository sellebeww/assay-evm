"""S1 for the static analyzers: a project cannot configure or extend Slither and Aderyn.

Slither reads `slither.config.json` and Aderyn reads `aderyn.toml` from the project root. With
them a project could switch detectors off, filter its own files out of the results, force
another compilation framework or set environment variables for the analyzer. Ingest leaves
both files out of the snapshot and keeps them only as evidence (ADR 0015). Slither is a Python
program, so a project could also try to have its own Python files imported (a module named like
one of Slither's, `sitecustomize`, `usercustomize`); the image runs Python with neither the
working directory nor the script directory on the module path.
"""

import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from assay.analysis import Aderyn, Analysis, AnalyzerFailed, Slither
from assay.ingest import Snapshot
from assay.sandbox import SandboxRunner, make_scratch_dir

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("runner")]

SnapshotOf = Callable[[Path], Snapshot]
FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "reentrancy" / "single_function"

HOSTILE_SLITHER_CONFIG = """{
  "detectors_to_exclude": "reentrancy-eth,reentrancy-benign,reentrancy-events,low-level-calls",
  "filter_paths": "src",
  "exclude_high": true,
  "compile_force_framework": "solc",
  "solc": "./evil-solc"
}
"""
HOSTILE_ADERYN_CONFIG = """version = 1
exclude = ["src/"]

[env]
XDG_DATA_HOME = "/work/project/fake"
"""
# Each module writes a marker into the scratch directory when it is imported.
MARKER = """import pathlib
pathlib.Path("/work/scratch/imported-{name}").write_text("{name}")
"""
SHADOWING_MODULES = (
    "slither.py",
    "sitecustomize.py",
    "usercustomize.py",
    "crytic_compile/__init__.py",
    "web3/__init__.py",
)


def hostile_copy(tmp_path: Path) -> Path:
    project = tmp_path / "hostile"
    shutil.copytree(FIXTURE, project)
    (project / "slither.config.json").write_text(HOSTILE_SLITHER_CONFIG)
    (project / "aderyn.toml").write_text(HOSTILE_ADERYN_CONFIG)
    for module in SHADOWING_MODULES:
        path = project / module
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(MARKER.format(name=module.replace("/", "-")))
    return project


def analyze(
    analyzer: Slither | Aderyn, runner: SandboxRunner, snapshot: Snapshot, parent: Path
) -> tuple[Analysis, Path]:
    parent.mkdir()
    scratch = make_scratch_dir(parent)
    return analyzer.analyze(runner, snapshot.tree_dir, scratch), scratch


def test_ingest_keeps_the_analyzer_config_out_of_the_snapshot(
    snapshot_of: SnapshotOf, tmp_path: Path
) -> None:
    snapshot = snapshot_of(hostile_copy(tmp_path))
    assert not (snapshot.tree_dir / "slither.config.json").exists()
    assert not (snapshot.tree_dir / "aderyn.toml").exists()
    assert (snapshot.evidence_dir / "slither.config.json").read_text() == HOSTILE_SLITHER_CONFIG
    assert (snapshot.evidence_dir / "aderyn.toml").read_text() == HOSTILE_ADERYN_CONFIG


def test_a_hostile_slither_config_and_shadowing_modules_have_no_effect(
    runner: SandboxRunner, snapshot_of: SnapshotOf, tmp_path: Path
) -> None:
    hostile, scratch = analyze(
        Slither(), runner, snapshot_of(hostile_copy(tmp_path)), tmp_path / "hostile-run"
    )
    clean, _ = analyze(Slither(), runner, snapshot_of(FIXTURE), tmp_path / "clean-run")

    assert "reentrancy-eth" in [item.rule_id for item in hostile.observations]
    assert hostile.observations == clean.observations
    assert sorted(path.name for path in scratch.glob("imported-*")) == []


def test_a_hostile_aderyn_config_has_no_effect(
    runner: SandboxRunner, snapshot_of: SnapshotOf, tmp_path: Path
) -> None:
    hostile, _ = analyze(
        Aderyn(), runner, snapshot_of(hostile_copy(tmp_path)), tmp_path / "hostile-run"
    )
    clean, _ = analyze(Aderyn(), runner, snapshot_of(FIXTURE), tmp_path / "clean-run")

    assert "reentrancy-state-change" in [item.rule_id for item in hostile.observations]
    assert hostile.observations == clean.observations


def test_control_the_same_config_inside_the_snapshot_would_change_the_results(
    runner: SandboxRunner, snapshot_of: SnapshotOf, tmp_path: Path
) -> None:
    """Without ingest's rule the files do take effect, so the tests above test that rule."""
    snapshot = snapshot_of(FIXTURE)
    (snapshot.tree_dir / "slither.config.json").write_text(
        '{"detectors_to_exclude": "reentrancy-eth,reentrancy-benign,reentrancy-events"}\n'
    )
    (snapshot.tree_dir / "aderyn.toml").write_text('version = 1\nexclude = ["src/"]\n')
    slither, _ = analyze(Slither(), runner, snapshot, tmp_path / "slither-run")
    assert "reentrancy-eth" not in [item.rule_id for item in slither.observations]
    # With every source excluded, Aderyn scans nothing and writes no report at all.
    with pytest.raises(AnalyzerFailed, match="no report"):
        analyze(Aderyn(), runner, snapshot, tmp_path / "aderyn-run")
