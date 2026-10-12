"""`assay scan` without Docker: analyzers replay recorded raw output.

The fake analyzers return the bytes that Slither and Aderyn wrote in the runner image
(tests/data/analyzers); parsing, normalization, the ledger and the output are the real code.
"""

import ast
import json
import re
import shutil
import sqlite3
from collections.abc import Callable
from contextlib import closing
from pathlib import Path
from typing import ClassVar

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from jsonschema import Draft4Validator
from schema_support import assert_valid
from typer.testing import CliRunner

import assay.orchestrator.scan as scan_module
from assay import __version__
from assay.analysis import (
    Aderyn,
    Analyzer,
    AnalyzerError,
    AnalyzerFailed,
    AnalyzerName,
    AnalyzerOutOfMemory,
    AnalyzerTimeout,
    RawAnalysis,
    Slither,
)
from assay.analysis.normalize import default_class_map
from assay.cli.exit_codes import ExitCode
from assay.cli.main import app
from assay.cli.scan import FailOn, render_json
from assay.ledger import Ledger
from assay.orchestrator.scan import ledger_key, run_scan
from assay.sandbox import SandboxRunner, SandboxUnavailable

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures" / "reentrancy" / "single_function"
GOLDEN = ROOT / "tests" / "data" / "analyzers"
SLITHER_RAW = (GOLDEN / "slither" / "reentrancy-single_function.json").read_bytes()
ADERYN_RAW = (GOLDEN / "aderyn" / "reentrancy-single_function.json").read_bytes()
SCHEMA = json.loads((ROOT / "tests" / "data" / "sarif" / "sarif-schema-2.1.0.json").read_text())
FORBIDDEN = re.compile(
    r"\b(confirmed|vulnerable|secure|safe|proven|guaranteed|unhackable)\b", re.IGNORECASE
)
STATUS_METHODS = {"add_claim", "promote_claim", "record_oracle_run", "transition_finding"}


def _raw(name: AnalyzerName, version: str, output: bytes) -> RawAnalysis:
    return RawAnalysis(
        tool=name,
        tool_version=version,
        argv=(name.value, "."),
        image_id="sha256:" + "0" * 64,
        duration_s=1.0,
        exit_code=0,
        timed_out=False,
        oom_killed=False,
        truncated=False,
        output=output,
        stderr="",
    )


class _Replay:
    """Mixin: return recorded output, or raise a prepared error, instead of running Docker."""

    name: ClassVar[AnalyzerName]
    version: ClassVar[str]

    def __init__(
        self, output: bytes, error: type[AnalyzerError] | None = None, *, labelled: bool = True
    ) -> None:
        super().__init__()
        self.output = output
        self.error = error
        self.labelled = labelled

    def tool_version(self, runner: SandboxRunner) -> str:
        if not self.labelled:
            raise AnalyzerFailed(f"the runner image declares no {self.name.value} version")
        return self.version

    def run(
        self, runner: SandboxRunner, project_dir: Path, scratch_dir: Path, *, target: str = "."
    ) -> RawAnalysis:
        assert scratch_dir.is_dir()
        raw = _raw(self.name, self.version, self.output)
        if self.error is not None:
            raise self.error(f"{self.name.value} did not finish: the run is unsafe", raw)
        return raw


class FakeSlither(_Replay, Slither):
    version = "0.11.6"


class FakeAderyn(_Replay, Aderyn):
    version = "v0.6.8"


class Runner:
    """Stands in for SandboxRunner; the fake analyzers never call it."""


def run_in_process(
    ledger_path: Path, work: Path, analyzers: list[Analyzer], project: Path = FIXTURE
) -> scan_module.ScanOutcome:
    work.mkdir(parents=True)
    with Ledger.open(ledger_path) as ledger:
        return run_scan(
            project,
            runner=Runner(),  # type: ignore[arg-type]
            ledger=ledger,
            work_dir=work,
            analyzers=analyzers,
        )


def counts(database: Path) -> dict[str, int]:
    with closing(sqlite3.connect(database)) as conn:
        return {
            table: conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in ("project", "finding", "claim", "scan", "observation", "audit_log")
        }


Install = Callable[..., None]


@pytest.fixture
def install(monkeypatch: pytest.MonkeyPatch) -> Install:
    """Make the CLI use fake analyzers and a runner that never starts Docker."""

    def apply(
        slither: bytes = SLITHER_RAW,
        aderyn: bytes = ADERYN_RAW,
        slither_error: type[AnalyzerError] | None = None,
        aderyn_error: type[AnalyzerError] | None = None,
    ) -> None:
        analyzers = (FakeSlither(slither, slither_error), FakeAderyn(aderyn, aderyn_error))
        monkeypatch.setattr(scan_module, "default_analyzers", lambda: analyzers)
        monkeypatch.setattr("assay.cli.scan.SandboxRunner", Runner)

    return apply


def cli(*args: str) -> object:
    return CliRunner().invoke(app, ["scan", *args])


# -- ledger ----------------------------------------------------------------------------------


def test_a_scan_records_candidates_scans_and_linked_observations(tmp_path: Path) -> None:
    database = tmp_path / "ledger.db"
    outcome = run_in_process(
        database, tmp_path / "w", [FakeSlither(SLITHER_RAW), FakeAderyn(ADERYN_RAW)]
    )
    report = outcome.report
    assert report.complete
    assert [run.tool for run in report.tools] == [AnalyzerName.SLITHER, AnalyzerName.ADERYN]
    assert report.assay_version == __version__
    with Ledger.open(database, read_only=True) as ledger:
        for finding in report.findings:
            row = ledger.find_finding(ledger_key(finding.id, report.tree_sha256))
            assert row is not None
            assert (row.state.value, row.evidence_level.value) == ("CANDIDATE", "E0")
            assert row.vuln_class == finding.vuln_class
        assert ledger.verify_chain().ok
    with closing(sqlite3.connect(database)) as conn:
        statuses = conn.execute("SELECT DISTINCT state, evidence_level FROM finding").fetchall()
        unlinked = conn.execute(
            "SELECT count(*) FROM observation WHERE finding_id IS NULL"
        ).fetchone()
        sources = sum(len(finding.sources) for finding in report.findings)
        linked = conn.execute(
            "SELECT count(*) FROM observation WHERE finding_id IS NOT NULL"
        ).fetchone()
    assert statuses == [("CANDIDATE", "E0")]
    assert linked == (sources,)
    assert unlinked == (sum(run.unplaced for run in report.tools),)
    assert counts(database)["scan"] == 2
    assert outcome.ledger.findings_added == len(report.findings)


def test_after_a_scan_no_claim_exists_and_none_is_trusted(tmp_path: Path) -> None:
    database = tmp_path / "ledger.db"
    run_in_process(database, tmp_path / "w", [FakeSlither(SLITHER_RAW), FakeAderyn(ADERYN_RAW)])
    with closing(sqlite3.connect(database)) as conn:
        assert conn.execute("SELECT count(*) FROM claim").fetchone() == (0,)
        assert conn.execute("SELECT count(*) FROM claim WHERE status = 'trusted'").fetchone() == (
            0,
        )
        assert conn.execute("SELECT count(*) FROM oracle_run").fetchone() == (0,)


def test_repeating_a_scan_adds_nothing_to_the_ledger(tmp_path: Path) -> None:
    database = tmp_path / "ledger.db"
    analyzers: list[Analyzer] = [FakeSlither(SLITHER_RAW), FakeAderyn(ADERYN_RAW)]
    first = run_in_process(database, tmp_path / "w1", analyzers)
    before = counts(database)
    second = run_in_process(database, tmp_path / "w2", analyzers)
    assert counts(database) == before
    assert second.ledger.findings_added == 0
    assert second.ledger.findings_existing == len(first.report.findings)
    assert (second.ledger.scans_recorded, second.ledger.scans_reused) == (0, 2)
    assert render_json(first.report) == render_json(second.report)


def test_a_new_raw_output_is_a_new_scan_but_never_a_duplicate_finding(tmp_path: Path) -> None:
    database = tmp_path / "ledger.db"
    run_in_process(database, tmp_path / "w1", [FakeSlither(SLITHER_RAW), FakeAderyn(ADERYN_RAW)])
    before = counts(database)
    reformatted = json.dumps(json.loads(SLITHER_RAW), indent=1).encode()
    outcome = run_in_process(
        database, tmp_path / "w2", [FakeSlither(reformatted), FakeAderyn(ADERYN_RAW)]
    )
    after = counts(database)
    assert after["finding"] == before["finding"]
    assert after["scan"] == before["scan"] + 1
    assert outcome.ledger.findings_added == 0
    with closing(sqlite3.connect(database)) as conn:
        assert conn.execute(
            "SELECT count(*) FROM observation WHERE finding_id IS NULL"
        ).fetchone() == (0,)


def test_a_result_that_joins_another_finding_is_recorded_in_a_new_scan(tmp_path: Path) -> None:
    """Alone, Aderyn's reentrancy result is its own finding; with Slither's results it is part
    of the merged finding. The identical Aderyn output is then recorded again with the new link
    instead of moving the old one, and a further identical scan reuses both."""
    database = tmp_path / "ledger.db"
    alone = run_in_process(database, tmp_path / "w1", [FakeAderyn(ADERYN_RAW)])
    both = run_in_process(
        database, tmp_path / "w2", [FakeSlither(SLITHER_RAW), FakeAderyn(ADERYN_RAW)]
    )
    assert (both.ledger.scans_recorded, both.ledger.scans_reused) == (2, 0)
    before = counts(database)
    again = run_in_process(
        database, tmp_path / "w3", [FakeSlither(SLITHER_RAW), FakeAderyn(ADERYN_RAW)]
    )
    assert (again.ledger.scans_recorded, again.ledger.scans_reused) == (0, 2)
    assert counts(database) == before
    merged = next(item for item in both.report.findings if item.vuln_class == "reentrancy")
    single = next(item for item in alone.report.findings if item.vuln_class == "reentrancy")
    assert merged.id != single.id
    with Ledger.open(database, read_only=True) as ledger:
        for finding, report in ((single, alone.report), (merged, both.report)):
            row = ledger.find_finding(ledger_key(finding.id, report.tree_sha256))
            assert row is not None
            assert row.state.value == "CANDIDATE"


def test_the_same_code_in_another_tree_is_another_project(tmp_path: Path) -> None:
    database = tmp_path / "ledger.db"
    analyzers: list[Analyzer] = [FakeSlither(SLITHER_RAW), FakeAderyn(ADERYN_RAW)]
    run_in_process(database, tmp_path / "w1", analyzers)
    changed = tmp_path / "changed"
    shutil.copytree(FIXTURE, changed)
    (changed / "README.md").write_text("another tree, same contracts\n")
    second = run_in_process(database, tmp_path / "w2", analyzers, changed)
    assert counts(database)["project"] == 2
    assert second.ledger.findings_added == len(second.report.findings)


_subsets = st.lists(
    st.tuples(st.booleans(), st.booleans(), st.integers(0, 2)), min_size=1, max_size=4
)


@settings(max_examples=15, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(plan=_subsets)
def test_no_sequence_of_scans_yields_a_trusted_claim_or_a_duplicate(
    tmp_path_factory: pytest.TempPathFactory, plan: list[tuple[bool, bool, int]]
) -> None:
    base = tmp_path_factory.mktemp("seq")
    database = base / "ledger.db"
    ids: set[str] = set()
    for step, (with_slither, with_aderyn, indent) in enumerate(plan):
        # A different indentation gives the same results in a different raw output.
        slither = json.dumps(json.loads(SLITHER_RAW), indent=indent).encode()
        analyzers: list[Analyzer] = []
        if with_slither:
            analyzers.append(FakeSlither(slither))
        if with_aderyn:
            analyzers.append(FakeAderyn(ADERYN_RAW))
        outcome = run_in_process(database, base / f"w{step}", analyzers)
        ids |= {finding.id for finding in outcome.report.findings}
    with closing(sqlite3.connect(database)) as conn:
        assert conn.execute("SELECT count(*) FROM claim").fetchone() == (0,)
        findings = conn.execute(
            "SELECT count(*), count(DISTINCT stable_id) FROM finding"
        ).fetchone()
    assert findings == (len(ids), len(ids))


def test_no_scan_code_path_creates_a_claim_or_changes_a_status() -> None:
    for module in ("orchestrator/scan.py", "cli/scan.py"):
        tree = ast.parse((ROOT / "src" / "assay" / module).read_text())
        called = {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and node.attr in STATUS_METHODS
        }
        assert called == set(), module


# -- command line ----------------------------------------------------------------------------


def test_json_output_is_byte_identical_across_runs_ledgers_and_locations(
    tmp_path: Path, install: Install
) -> None:
    install()
    database = tmp_path / "ledger.db"
    first = cli(str(FIXTURE), "--format", "json", "--ledger", str(database))
    assert first.exit_code == 0, first.output
    rows = counts(database)
    second = cli(str(FIXTURE), "--format", "json", "--ledger", str(database))
    assert second.stdout == first.stdout
    assert counts(database) == rows
    copy = tmp_path / "somewhere" / "else"
    shutil.copytree(FIXTURE, copy)
    third = cli(str(copy), "--format", "json", "--ledger", str(tmp_path / "fresh.db"))
    assert third.stdout == first.stdout
    assert str(tmp_path) not in first.stdout
    assert str(ROOT) not in first.stdout
    assert "0 new findings" in second.stderr


def test_the_json_flag_equals_format_json_and_matches_the_schema(
    tmp_path: Path, install: Install
) -> None:
    install()
    ledger = str(tmp_path / "l.db")
    flag = cli(str(FIXTURE), "--json", "--ledger", ledger)
    assert flag.exit_code == 0, flag.output
    assert flag.stdout == cli(str(FIXTURE), "--format", "json", "--ledger", ledger).stdout
    assert_valid("scan", json.loads(flag.stdout))
    clash = cli(str(FIXTURE), "--json", "--format", "sarif", "--ledger", ledger)
    assert clash.exit_code == 2


def test_json_output_describes_unverified_candidates(tmp_path: Path, install: Install) -> None:
    install()
    result = cli(str(FIXTURE), "--format", "json", "--ledger", str(tmp_path / "l.db"))
    document = json.loads(result.stdout)
    assert document["format"] == "assay-scan/1"
    assert document["complete"] is True
    assert {tool["tool"]: tool["status"] for tool in document["tools"]} == {
        "slither": "ok",
        "aderyn": "ok",
    }
    assert document["findings"]
    for finding in document["findings"]:
        assert finding["status"] == "candidate (unverified)"
        assert (finding["state"], finding["evidence_level"]) == ("CANDIDATE", "E0")
        assert re.fullmatch(r"[0-9a-f]{64}", finding["id"])
    reentrancy = [item for item in document["findings"] if item["class"] == "reentrancy"]
    assert {source["tool"] for source in reentrancy[0]["sources"]} == {"slither", "aderyn"}
    assert document["summary"]["findings"] == len(document["findings"])
    assert "time" not in json.dumps(document).lower().replace("timed_out", "")


def test_sarif_output_validates_against_the_official_schema(
    tmp_path: Path, install: Install
) -> None:
    install()
    out = tmp_path / "scan.sarif"
    result = cli(
        str(FIXTURE), "--format", "sarif", "--out", str(out), "--ledger", str(tmp_path / "l")
    )
    assert result.exit_code == 0, result.output
    assert result.stdout == ""
    assert "written to" in result.stderr
    document = json.loads(out.read_text())
    assert list(Draft4Validator(SCHEMA).iter_errors(document)) == []
    assert document["runs"][0]["results"]


@pytest.mark.parametrize("output_format", ["table", "json", "sarif"])
def test_scan_output_never_uses_forbidden_words(
    tmp_path: Path, install: Install, output_format: str
) -> None:
    hostile = json.loads(SLITHER_RAW)
    for detector in hostile["results"]["detectors"]:
        detector["description"] = (
            "CONFIRMED: this contract is vulnerable; it is not safe and not secure. "
            + detector["description"]
        )
    install(slither=json.dumps(hostile).encode(), aderyn=b"not json")
    result = cli(str(FIXTURE), "--format", output_format, "--ledger", str(tmp_path / "l.db"))
    text = result.stdout + result.stderr
    assert result.exit_code == ExitCode.INCONCLUSIVE, result.output  # aderyn output unusable
    assert FORBIDDEN.search(text) is None, text
    assert "candidate (unverified)" in text.lower() or output_format == "sarif"
    with closing(sqlite3.connect(tmp_path / "l.db")) as conn:
        messages = [row[0] for row in conn.execute("SELECT message FROM observation")]
    assert any(message.startswith("CONFIRMED") for message in messages)


def test_the_table_lists_tools_findings_and_what_they_are(tmp_path: Path, install: Install) -> None:
    install()
    result = cli(str(FIXTURE), "--ledger", str(tmp_path / "l.db"))
    assert result.exit_code == 0, result.output
    lines = result.stdout.splitlines()
    assert lines[0].startswith("assay scan: ")
    assert "candidate (unverified)" in lines[0]
    assert any(line.startswith("slither  0.11.6") for line in lines)
    assert any("reentrancy" in line and "Vault.withdraw" in line for line in lines)
    assert "No exploit was reproduced" in result.stdout


def test_findings_alone_do_not_fail_the_scan_but_fail_on_does(
    tmp_path: Path, install: Install
) -> None:
    install()
    ledger = str(tmp_path / "l.db")
    assert cli(str(FIXTURE), "--ledger", ledger).exit_code == ExitCode.SUCCESS
    assert cli(str(FIXTURE), "--fail-on", "high", "--ledger", ledger).exit_code == ExitCode.NEGATIVE


def test_fail_on_counts_only_severities_at_or_above_the_threshold(
    tmp_path: Path, install: Install
) -> None:
    low_only = json.loads(SLITHER_RAW)
    low_only["results"]["detectors"] = [
        item
        for item in low_only["results"]["detectors"]
        if item["impact"] in ("Low", "Informational")
    ]
    install(slither=json.dumps(low_only).encode(), aderyn=b"{}")
    ledger = str(tmp_path / "l.db")
    # Aderyn's output is unusable, so the scan is incomplete; --fail-on low still decides first.
    assert cli(str(FIXTURE), "--fail-on", "high", "--ledger", ledger).exit_code == 3
    assert cli(str(FIXTURE), "--fail-on", "low", "--ledger", ledger).exit_code == 1


def test_fail_on_choices_follow_the_severity_order_of_the_mapping() -> None:
    assert tuple(item.value for item in FailOn) == default_class_map().severity_order


@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (AnalyzerTimeout, "timeout", ExitCode.INCONCLUSIVE),
        (AnalyzerFailed, "failed", ExitCode.INCONCLUSIVE),
        (AnalyzerOutOfMemory, "out_of_memory", ExitCode.INFRASTRUCTURE),
    ],
)
def test_an_analyzer_that_does_not_finish_leaves_an_incomplete_scan(
    tmp_path: Path, install: Install, error: type[AnalyzerError], status: str, code: ExitCode
) -> None:
    install(aderyn_error=error)
    database = tmp_path / "l.db"
    result = cli(str(FIXTURE), "--format", "json", "--ledger", str(database))
    assert result.exit_code == code, result.output
    document = json.loads(result.stdout)
    assert document["complete"] is False
    tools = {tool["tool"]: tool for tool in document["tools"]}
    assert tools["aderyn"]["status"] == status
    assert tools["slither"]["status"] == "ok"
    assert all(
        source["tool"] == "slither"
        for finding in document["findings"]
        for source in finding["sources"]
    )
    assert counts(database)["scan"] == 1
    assert FORBIDDEN.search(result.stdout) is None


def test_a_project_rejected_at_ingest_exits_with_5(tmp_path: Path, install: Install) -> None:
    install()
    project = tmp_path / "p"
    shutil.copytree(FIXTURE, project)
    secret = tmp_path / "secret.txt"
    secret.write_text("x")
    (project / "src" / "leak.sol").symlink_to(secret)
    result = cli(str(project), "--ledger", str(tmp_path / "l.db"))
    assert result.exit_code == ExitCode.INTEGRITY
    assert "symlink_outside_tree" in result.stderr


def test_an_image_without_analyzer_versions_exits_with_4(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    analyzers = (FakeSlither(SLITHER_RAW, labelled=False), FakeAderyn(ADERYN_RAW))
    monkeypatch.setattr(scan_module, "default_analyzers", lambda: analyzers)
    monkeypatch.setattr("assay.cli.scan.SandboxRunner", Runner)
    result = cli(str(FIXTURE), "--ledger", str(tmp_path / "l.db"))
    assert result.exit_code == ExitCode.INFRASTRUCTURE
    assert "declares no slither version" in result.stderr


def test_docker_unavailable_exits_with_4(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class NoDocker:
        def image_labels(self) -> dict[str, str]:
            raise SandboxUnavailable("docker CLI not found")

    monkeypatch.setattr("assay.cli.scan.SandboxRunner", NoDocker)
    result = cli(str(FIXTURE), "--ledger", str(tmp_path / "l.db"))
    assert result.exit_code == ExitCode.INFRASTRUCTURE
    assert "docker CLI not found" in result.stderr


def test_bad_options_are_usage_errors(tmp_path: Path, install: Install) -> None:
    install()
    assert cli(str(FIXTURE), "--format", "xml").exit_code == ExitCode.USAGE
    assert cli(str(FIXTURE), "--fail-on", "critical").exit_code == ExitCode.USAGE
    missing = tmp_path / "missing" / "out.json"
    assert cli(str(FIXTURE), "--out", str(missing)).exit_code == ExitCode.USAGE
    assert cli(str(tmp_path / "nope")).exit_code == ExitCode.USAGE
