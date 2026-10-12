"""Slither and Aderyn adapters on recorded output (tests/data/analyzers/), and the analyzer run
logic and `assay dev analyze` with a fake runner. No Docker.
"""

import json
import re
import sqlite3
from collections.abc import Sequence
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import assay.cli.dev
from assay.analysis import (
    Aderyn,
    AnalyzerFailed,
    AnalyzerOutOfMemory,
    AnalyzerOutputError,
    AnalyzerTimeout,
    RawAnalysis,
    Slither,
)
from assay.analysis.base import AnalyzerName
from assay.cli.main import app
from assay.ledger import Ledger
from assay.sandbox import SandboxResult

DATA = Path(__file__).resolve().parents[1] / "data" / "analyzers"
ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures" / "reentrancy" / "single_function"
IMAGE_ID = "sha256:" + "ab" * 32
LABELS = {"assay.slither.version": "0.11.6", "assay.aderyn.version": "v0.6.8"}
FORBIDDEN = re.compile(
    r"\b(secure|safe|proven|guaranteed|unhackable|confirmed|vulnerable)\b", re.IGNORECASE
)


def golden(tool: str, name: str) -> bytes:
    return (DATA / tool / f"{name}.json").read_bytes()


# -- recorded output ------------------------------------------------------------------------------


def test_slither_reports_the_reentrancy_of_the_vault() -> None:
    observations = Slither().parse(golden("slither", "reentrancy-single_function"))

    rules = [item.rule_id for item in observations]
    assert rules == ["reentrancy-eth", "reentrancy-benign", "reentrancy-events", "low-level-calls"]
    first = observations[0]
    assert first.severity_reported == "High (confidence Medium)"
    assert first.message.startswith("Reentrancy in Vault.withdraw(uint256)")
    assert first.locations[0].path == "src/Vault.sol"
    assert (first.locations[0].start_line, first.locations[0].end_line) == (29, 40)


def test_slither_on_the_oracle_fixture_reports_only_project_paths() -> None:
    observations = Slither().parse(golden("slither", "oracle_manipulation-spot_price"))

    assert len(observations) == 18
    paths = {loc.path for item in observations for loc in item.locations}
    assert paths == {"src/Lender.sol", "src/MiniPool.sol"}
    assert all(len(item.locations) <= 64 for item in observations)


def test_aderyn_reports_one_observation_per_instance() -> None:
    observations = Aderyn().parse(golden("aderyn", "reentrancy-single_function"))

    assert [(item.rule_id, item.severity_reported) for item in observations] == [
        ("eth-send-unchecked-address", "High"),
        ("reentrancy-state-change", "High"),
    ]
    assert [item.locations[0].start_line for item in observations] == [29, 34]
    assert all(len(item.locations) == 1 for item in observations)
    assert "Hint: State is changed at" in observations[1].message


def test_aderyn_on_the_oracle_fixture() -> None:
    observations = Aderyn().parse(golden("aderyn", "oracle_manipulation-spot_price"))

    assert len(observations) == 20
    assert {loc.path for item in observations for loc in item.locations} == {
        "src/Lender.sol",
        "src/MiniPool.sol",
    }


@pytest.mark.parametrize(
    ("analyzer", "tool"), [(Slither(), "slither"), (Aderyn(), "aderyn")], ids=["slither", "aderyn"]
)
@pytest.mark.parametrize("name", ["reentrancy-single_function", "oracle_manipulation-spot_price"])
def test_parsing_is_deterministic(analyzer: Slither | Aderyn, tool: str, name: str) -> None:
    data = golden(tool, name)
    assert analyzer.parse(data) == analyzer.parse(data)


def test_a_long_description_is_cut_not_refused() -> None:
    report = json.loads(golden("slither", "reentrancy-single_function"))
    report["results"]["detectors"][0]["description"] = "x" * 50_000
    (first, *_) = Slither().parse(json.dumps(report).encode())
    assert len(first.message) == 4000
    assert first.message.endswith(" [cut]")


def test_a_slither_report_that_did_not_succeed_is_not_parsed() -> None:
    data = json.dumps({"success": False, "error": "Compilation failed", "results": {}}).encode()
    with pytest.raises(AnalyzerOutputError) as caught:
        Slither().parse(data)
    assert caught.value.code == "schema_mismatch"


def test_slither_dependency_elements_are_left_out_of_the_locations() -> None:
    report = json.loads(golden("slither", "reentrancy-single_function"))
    element = report["results"]["detectors"][0]["elements"][0]
    element["source_mapping"]["is_dependency"] = True
    element["source_mapping"]["filename_absolute"] = "/opt/assay/lib/forge-std/src/Test.sol"
    (first, *_) = Slither().parse(json.dumps(report).encode())
    assert all(loc.path == "src/Vault.sol" for loc in first.locations)
    assert (29, 40) not in [(loc.start_line, loc.end_line) for loc in first.locations]


# -- the run logic, with a fake runner -------------------------------------------------------------


class FakeRunner:
    """Stands in for SandboxRunner: returns a prepared result, optionally writes a report."""

    def __init__(
        self,
        *,
        stdout: str = "",
        exit_code: int = 0,
        timed_out: bool = False,
        oom_killed: bool = False,
        truncated: bool = False,
        report: bytes | None = None,
        labels: dict[str, str] | None = None,
    ) -> None:
        self.result: dict[str, Any] = {
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": "error: something went wrong\n",
            "truncated": truncated,
            "timed_out": timed_out,
            "oom_killed": oom_killed,
            "duration_s": 1.25,
            "image_id": IMAGE_ID,
        }
        self.report = report
        self.labels = LABELS if labels is None else labels
        self.calls: list[tuple[str, ...]] = []

    def image_labels(self) -> dict[str, str]:
        return self.labels

    def image_id(self) -> str:
        return IMAGE_ID

    def run(self, argv: Sequence[str], *, project_dir: Path, scratch_dir: Path) -> SandboxResult:
        self.calls.append(tuple(argv))
        if self.report is not None:
            (scratch_dir / "aderyn.json").write_bytes(self.report)
        return SandboxResult(argv=tuple(argv), **self.result)


def run(analyzer: Slither | Aderyn, runner: FakeRunner, tmp_path: Path) -> RawAnalysis:
    scratch = tmp_path / "scratch"
    scratch.mkdir(exist_ok=True)
    return analyzer.run(runner, tmp_path, scratch)  # type: ignore[arg-type]


def test_a_successful_run_keeps_the_raw_output_and_the_command(tmp_path: Path) -> None:
    output = golden("slither", "reentrancy-single_function")
    runner = FakeRunner(stdout=output.decode())
    raw = run(Slither(), runner, tmp_path)

    assert raw.output == output
    assert raw.argv == ("slither", ".", "--json", "-", "--fail-none", "--disable-color")
    assert (raw.tool, raw.tool_version, raw.duration_s) == (AnalyzerName.SLITHER, "0.11.6", 1.25)
    assert runner.calls == [raw.argv]


def test_aderyn_output_is_read_from_the_report_file(tmp_path: Path) -> None:
    report = golden("aderyn", "reentrancy-single_function")
    raw = run(Aderyn(), FakeRunner(stdout="progress text", report=report), tmp_path)
    assert raw.output == report
    assert raw.argv == ("aderyn", ".", "--output", "/work/scratch/aderyn.json")


@pytest.mark.parametrize(
    ("runner", "error"),
    [
        (FakeRunner(timed_out=True, exit_code=-9), AnalyzerTimeout),
        (FakeRunner(oom_killed=True, exit_code=137), AnalyzerOutOfMemory),
        (FakeRunner(exit_code=1), AnalyzerFailed),
        (FakeRunner(truncated=True, stdout="{"), AnalyzerFailed),
    ],
    ids=["timeout", "oom", "tool-error", "truncated"],
)
def test_runs_without_a_usable_result_raise_with_the_raw_result(
    runner: FakeRunner, error: type[Exception], tmp_path: Path
) -> None:
    with pytest.raises(error) as caught:
        run(Slither(), runner, tmp_path)
    assert caught.value.raw is not None  # type: ignore[attr-defined]


def test_a_failed_slither_run_names_the_reported_error(tmp_path: Path) -> None:
    stdout = json.dumps({"success": False, "error": "Invalid compilation\nmore", "results": {}})
    with pytest.raises(AnalyzerFailed, match="exit code 255: Invalid compilation"):
        run(Slither(), FakeRunner(stdout=stdout, exit_code=255), tmp_path)


def test_aderyn_without_a_report_fails(tmp_path: Path) -> None:
    with pytest.raises(AnalyzerFailed, match="no report"):
        run(Aderyn(), FakeRunner(), tmp_path)


def test_an_image_without_the_tool_label_is_refused(tmp_path: Path) -> None:
    runner = FakeRunner(labels={"assay.foundry.version": "v1.8.4"})
    with pytest.raises(AnalyzerFailed, match="make image"):
        run(Slither(), runner, tmp_path)
    assert runner.calls == []


def test_a_target_outside_the_project_never_reaches_the_runner(tmp_path: Path) -> None:
    runner = FakeRunner()
    with pytest.raises(ValueError, match="outside the project"):
        Slither().run(runner, tmp_path, tmp_path, target="../elsewhere")  # type: ignore[arg-type]
    assert runner.calls == []


# -- assay dev analyze ----------------------------------------------------------------------------


def invoke(
    monkeypatch: pytest.MonkeyPatch, runner: FakeRunner, tool: str, ledger: Path, project: Path
) -> Any:
    monkeypatch.setattr(assay.cli.dev, "SandboxRunner", lambda: runner)
    return CliRunner().invoke(app, ["dev", "analyze", tool, str(project), "--ledger", str(ledger)])


@pytest.mark.parametrize(("tool", "count"), [("slither", 4), ("aderyn", 2)])
def test_dev_analyze_prints_a_summary_and_records_the_scan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, tool: str, count: int
) -> None:
    output = golden(tool, "reentrancy-single_function")
    runner = FakeRunner(stdout=output.decode()) if tool == "slither" else FakeRunner(report=output)
    database = tmp_path / "ledger.db"
    result = invoke(monkeypatch, runner, tool, database, FIXTURE)

    assert result.exit_code == 0, result.output
    lines = dict(line.split(": ", 1) for line in result.stdout.splitlines())
    assert lines["tool"] == f"{tool} {LABELS[f'assay.{tool}.version']}"
    assert lines["results"] == f"{count} candidate (unverified)"
    assert lines["duration"] == "1.2 s"
    assert re.fullmatch(r"sha256 [0-9a-f]{64} \(\d+ bytes\)", lines["raw output"])
    assert FORBIDDEN.search(result.stdout) is None
    with Ledger.open(database, read_only=True) as ledger:
        scan = ledger.get_scan(1)  # type: ignore[arg-type]
        assert ledger.read_blob(scan.raw_blob_sha256) == output
        assert scan.result_count == count
    with closing(sqlite3.connect(database)) as conn:
        assert conn.execute("SELECT count(*) FROM claim").fetchone() == (0,)


def test_dev_analyze_keeps_unusable_output_as_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    database = tmp_path / "ledger.db"
    result = invoke(monkeypatch, FakeRunner(stdout="[" * 1000), "slither", database, FIXTURE)

    assert result.exit_code == 3, result.output
    assert "unusable output: too_deep" in result.stderr
    with closing(sqlite3.connect(database)) as conn:
        assert conn.execute("SELECT count(*) FROM scan").fetchone() == (0,)
        assert conn.execute("SELECT count(*) FROM artifact").fetchone() == (1,)


@pytest.mark.parametrize(
    ("runner", "code"),
    [
        (FakeRunner(exit_code=1), 1),
        (FakeRunner(timed_out=True, exit_code=-9), 3),
        (FakeRunner(oom_killed=True, exit_code=137), 4),
    ],
    ids=["tool-error", "timeout", "oom"],
)
def test_dev_analyze_exit_codes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, runner: FakeRunner, code: int
) -> None:
    result = invoke(monkeypatch, runner, "slither", tmp_path / "ledger.db", FIXTURE)
    assert result.exit_code == code, result.output


def test_dev_analyze_rejects_a_project_with_a_symlink_out_of_the_tree(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / "src" / "leak.sol").symlink_to("/etc/passwd")
    runner = FakeRunner()
    result = invoke(monkeypatch, runner, "aderyn", tmp_path / "ledger.db", project)

    assert result.exit_code == 5, result.output
    assert runner.calls == []
