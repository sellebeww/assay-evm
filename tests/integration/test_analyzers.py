"""Slither and Aderyn in the runner image, on the reentrancy fixture.

Both tools run through `SandboxRunner` on an ingested snapshot (no network, read-only project,
one writable scratch directory). Their output goes through the same bounded parsing as any
untrusted input.
"""

import hashlib
import sqlite3
from collections.abc import Callable
from contextlib import closing
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.analysis import Aderyn, Analysis, AnalyzerName, Slither
from assay.cli.main import app
from assay.ingest import Snapshot
from assay.ledger import Ledger, ScanTool
from assay.report.bundle import read_versions_lock
from assay.sandbox import SandboxRunner, make_scratch_dir

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("runner")]

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures" / "reentrancy" / "single_function"
SnapshotOf = Callable[[Path], Snapshot]


def pinned(key: str) -> str:
    for line in read_versions_lock().splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1]
    raise AssertionError(f"{key} missing from versions.lock")


def analyze(
    analyzer: Slither | Aderyn, runner: SandboxRunner, snapshot: Snapshot, tmp_path: Path
) -> Analysis:
    scratch_parent = tmp_path / f"run-{analyzer.name.value}-{len(list(tmp_path.iterdir()))}"
    scratch_parent.mkdir()
    return analyzer.analyze(runner, snapshot.tree_dir, make_scratch_dir(scratch_parent))


def test_the_image_declares_the_pinned_analyzer_versions(runner: SandboxRunner) -> None:
    labels = runner.image_labels()
    assert labels["assay.slither.version"] == pinned("SLITHER_VERSION")
    assert labels["assay.aderyn.version"] == pinned("ADERYN_VERSION")
    assert labels["assay.python.version"] == pinned("PYTHON_VERSION")


def test_slither_reports_the_reentrancy_of_the_fixture(
    runner: SandboxRunner, snapshot_of: SnapshotOf, tmp_path: Path
) -> None:
    analysis = analyze(Slither(), runner, snapshot_of(FIXTURE), tmp_path)

    assert analysis.raw.exit_code == 0
    assert analysis.raw.tool_version == pinned("SLITHER_VERSION")
    reentrancy = [item for item in analysis.observations if "reentrancy" in item.rule_id]
    assert reentrancy, [item.rule_id for item in analysis.observations]
    locations = [loc for item in reentrancy for loc in item.locations]
    assert any(loc.path == "src/Vault.sol" for loc in locations)
    for item in analysis.observations:
        for loc in item.locations:
            assert not loc.path.startswith(("/", "..")), loc.path


def test_aderyn_runs_offline_and_reports_project_paths(
    runner: SandboxRunner, snapshot_of: SnapshotOf, tmp_path: Path
) -> None:
    analysis = analyze(Aderyn(), runner, snapshot_of(FIXTURE), tmp_path)

    assert analysis.raw.exit_code == 0
    assert analysis.raw.tool_version == pinned("ADERYN_VERSION")
    assert analysis.raw.output
    for item in analysis.observations:
        for loc in item.locations:
            assert loc.path.startswith("src/"), loc.path


@pytest.mark.parametrize("analyzer", [Slither(), Aderyn()], ids=["slither", "aderyn"])
def test_the_raw_output_repeats(
    analyzer: Slither | Aderyn, runner: SandboxRunner, snapshot_of: SnapshotOf, tmp_path: Path
) -> None:
    outputs = [
        hashlib.sha256(
            analyze(analyzer, runner, snapshot_of(FIXTURE), tmp_path).raw.output
        ).hexdigest()
        for _ in range(2)
    ]
    assert outputs[0] == outputs[1]


@pytest.mark.parametrize("tool", list(AnalyzerName))
def test_dev_analyze_records_the_scan_without_raising_any_status(
    tool: AnalyzerName, tmp_path: Path
) -> None:
    database = tmp_path / "ledger.db"
    result = CliRunner().invoke(
        app, ["dev", "analyze", tool.value, str(FIXTURE), "--ledger", str(database)]
    )
    assert result.exit_code == 0, result.output
    lines = dict(line.split(": ", 1) for line in result.stdout.splitlines())
    assert lines["tool"].startswith(f"{tool.value} ")
    count = int(lines["results"].split()[0])
    assert lines["results"].endswith("candidate (unverified)")
    blob = lines["raw output"].split()[1]
    with Ledger.open(database, read_only=True) as ledger:
        scan = ledger.get_scan(1)  # type: ignore[arg-type]
        assert scan.tool is ScanTool(tool.value)
        assert scan.raw_blob_sha256 == blob
        assert scan.result_count == count == len(ledger.scan_observations(scan.id))
        assert ledger.read_blob(blob)
        assert ledger.verify_chain().ok
    with closing(sqlite3.connect(database)) as conn:
        claims = conn.execute("SELECT count(*) FROM claim").fetchone()
        findings = conn.execute("SELECT count(*) FROM finding").fetchone()
    assert (claims, findings) == ((0,), (0,))
    assert str(tmp_path) not in result.stdout
