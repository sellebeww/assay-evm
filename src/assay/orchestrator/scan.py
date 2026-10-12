"""`assay scan`: static analysis of a project, normalized into candidate findings in the ledger.

Order: snapshot the project under the ingest rules; run every analyzer on the snapshot through
the sandbox runner; store each raw output as a blob; parse it; normalize and deduplicate the
results (`assay.analysis.normalize`); record them. The ledger receives one project per input
tree, one finding per normalized finding (`CANDIDATE` at E0), one scan per analyzer run with
one observation per result, and a link from each observation to its finding.

An analyzer that times out, fails or writes unusable output does not stop the scan: the other
analyzer's results are still normalized and recorded, and the report marks the scan incomplete.
A missing runner image, an unavailable Docker daemon or a ledger error stops it.

Idempotence. A finding's ledger key is its stable id together with the input tree, so the same
input never creates a second finding, and a scan whose raw output is byte-identical to one
already recorded, with its results belonging to the same findings, is not recorded again.
Repeating a scan on the same input leaves the ledger unchanged and produces the same report.

Nothing here creates a claim or changes a status. Analyzer output is an unverified hint; only
oracle runs change a status.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from assay import __version__
from assay.analysis import (
    ANALYZERS,
    Analyzer,
    AnalyzerFailed,
    AnalyzerName,
    AnalyzerOutOfMemory,
    AnalyzerOutputError,
    AnalyzerTimeout,
    Observation,
    RawAnalysis,
)
from assay.analysis.normalize import (
    TOOL_ORDER,
    ClassMap,
    Finding,
    ToolObservations,
    default_class_map,
    normalize,
)
from assay.analysis.source_map import SourceReader
from assay.ingest import create_snapshot
from assay.ledger import (
    FindingId,
    Ledger,
    LedgerError,
    ObservationInput,
    ProjectId,
    ScanId,
    ScanLocation,
    ScanTool,
)
from assay.sandbox import SandboxRunner, make_scratch_dir

PROJECT_NAME: Final = "scan"
STATUS_LABEL: Final = "candidate (unverified)"
ToolStatus = Literal["ok", "failed", "timeout", "out_of_memory", "unusable_output"]


class ScanInfrastructureError(Exception):
    """The scan cannot run: the runner image or the environment is not usable."""


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ToolRun(_Model):
    """What one analyzer run gave: its status, its result count and its raw output hash."""

    tool: AnalyzerName
    version: str
    status: ToolStatus
    detail: str | None = None
    """Why the run gave no usable result (tool text, unverified); `None` when it did."""
    results: int = 0
    unplaced: int = 0
    """Results without a location in the project, which give no finding."""
    raw_output_sha256: str | None = None


class ScanReport(_Model):
    """The outcome of one scan. It holds no time and no host path."""

    assay_version: str
    tree_sha256: str
    tools: tuple[ToolRun, ...]
    findings: tuple[Finding, ...]

    @property
    def complete(self) -> bool:
        """True when every analyzer produced a usable result."""
        return all(run.status == "ok" for run in self.tools)


@dataclass(frozen=True, slots=True)
class LedgerSummary:
    project_id: ProjectId
    findings_added: int
    findings_existing: int
    scans_recorded: int
    scans_reused: int
    observations_linked: int


@dataclass(frozen=True, slots=True)
class ScanOutcome:
    report: ScanReport
    ledger: LedgerSummary


@dataclass(frozen=True, slots=True)
class _Parsed:
    run: ToolRun
    observations: tuple[Observation, ...]
    inputs: tuple[ObservationInput, ...]


def default_analyzers() -> tuple[Analyzer, ...]:
    return tuple(ANALYZERS[name]() for name in TOOL_ORDER)


def project_label(tree_sha256: str) -> str:
    return f"tree:{tree_sha256[:16]}"


def ledger_key(finding_id: str, tree_sha256: str) -> str:
    """The ledger's `stable_id` of a scan finding: its stable id within one input tree."""
    return f"scan:{finding_id}:{tree_sha256[:16]}"


def _store_raw(ledger: Ledger, raw: RawAnalysis | None) -> str | None:
    if raw is None or not raw.output:
        return None
    return ledger.store_blob(
        raw.output, media_type="application/json", label=f"{raw.tool.value} raw output"
    )


def _ledger_inputs(observations: Sequence[Observation]) -> tuple[ObservationInput, ...]:
    return tuple(
        ObservationInput(
            rule_id=item.rule_id,
            severity_reported=item.severity_reported,
            message=item.message,
            locations=tuple(
                ScanLocation(path=loc.path, start_line=loc.start_line, end_line=loc.end_line)
                for loc in item.locations
            ),
        )
        for item in observations
    )


def _run_tool(
    analyzer: Analyzer, runner: SandboxRunner, ledger: Ledger, tree_dir: Path, work_dir: Path
) -> _Parsed:
    try:
        version = analyzer.tool_version(runner)
    except AnalyzerFailed as exc:
        raise ScanInfrastructureError(str(exc)) from exc
    parent = work_dir / f"run-{analyzer.name.value}"
    parent.mkdir()

    def failed(status: ToolStatus, detail: str, raw: RawAnalysis | None) -> _Parsed:
        return _Parsed(
            ToolRun(
                tool=analyzer.name,
                version=version,
                status=status,
                detail=detail,
                raw_output_sha256=_store_raw(ledger, raw),
            ),
            (),
            (),
        )

    try:
        raw = analyzer.run(runner, tree_dir, make_scratch_dir(parent))
    except AnalyzerTimeout as exc:
        return failed("timeout", str(exc), exc.raw)
    except AnalyzerOutOfMemory as exc:
        return failed("out_of_memory", str(exc), exc.raw)
    except AnalyzerFailed as exc:
        return failed("failed", str(exc), exc.raw)
    try:
        observations = analyzer.parse(raw.output)
        inputs = _ledger_inputs(observations)
    except AnalyzerOutputError as exc:
        return failed("unusable_output", f"{exc.code}: {exc.detail}", raw)
    except ValidationError as exc:
        problem = exc.errors(include_url=False, include_input=False)[0]["msg"]
        return failed("unusable_output", f"a result the ledger cannot store: {problem}", raw)
    run = ToolRun(
        tool=analyzer.name,
        version=raw.tool_version,
        status="ok",
        results=len(observations),
        unplaced=sum(1 for item in observations if not item.locations),
        raw_output_sha256=_store_raw(ledger, raw),
    )
    return _Parsed(run, observations, inputs)


def _consistent_scan(
    ledger: Ledger,
    project: ProjectId,
    tree: str,
    run: ToolRun,
    targets: Sequence[FindingId | None],
) -> ScanId | None:
    """A recorded scan of the same output whose observations can carry this scan's links.

    The finding an observation belongs to can depend on what the other analyzer reported (a
    result merged with another tool's is part of a different finding than when it stands
    alone). A recorded scan is reused only when each of its observations is unlinked or
    already linked to the finding it belongs to now; otherwise the run is recorded as a new
    scan.
    """
    assert run.raw_output_sha256 is not None
    for scan in ledger.find_scans(
        project,
        tool=ScanTool(run.tool.value),
        tool_version=run.version,
        raw_blob_sha256=run.raw_output_sha256,
        input_tree_sha256=tree,
    ):
        stored = ledger.scan_observations(scan.id)
        if len(stored) == len(targets) and all(
            observation.finding_id is None or observation.finding_id == target
            for observation, target in zip(stored, targets, strict=True)
        ):
            return scan.id
    return None


def _record(ledger: Ledger, report: ScanReport, parsed: Sequence[_Parsed]) -> LedgerSummary:
    tree = report.tree_sha256
    label = project_label(tree)
    found = ledger.find_project(PROJECT_NAME, label)
    project = found if found is not None else ledger.add_project(PROJECT_NAME, label)

    ids: dict[str, FindingId] = {}
    added = existing = 0
    for finding in report.findings:
        key = ledger_key(finding.id, tree)
        row = ledger.find_finding(key)
        if row is None:
            ids[finding.id] = ledger.add_finding(project, key, finding.vuln_class)
            added += 1
            continue
        if row.project_id != project or row.vuln_class != finding.vuln_class:
            raise LedgerError(f"finding {key} is recorded with another project or class")
        ids[finding.id] = row.id
        existing += 1
    links = {
        (source.tool, source.observation_index): ids[finding.id]
        for finding in report.findings
        for source in finding.sources
    }

    recorded = reused = linked = 0
    for item in parsed:
        run = item.run
        if run.status != "ok" or run.raw_output_sha256 is None:
            continue
        targets = [links.get((run.tool, index)) for index in range(len(item.observations))]
        scan_id = _consistent_scan(ledger, project, tree, run, targets)
        if scan_id is None:
            scan_id = ledger.record_scan(
                project,
                tool=ScanTool(run.tool.value),
                tool_version=run.version,
                raw_blob_sha256=run.raw_output_sha256,
                input_tree_sha256=tree,
                observations=item.inputs,
            )
            recorded += 1
        else:
            reused += 1
        for observation, target in zip(ledger.scan_observations(scan_id), targets, strict=True):
            if target is not None and ledger.link_observation(observation.id, target):
                linked += 1
    return LedgerSummary(project, added, existing, recorded, reused, linked)


def run_scan(
    project: Path,
    *,
    runner: SandboxRunner,
    ledger: Ledger,
    work_dir: Path,
    analyzers: Sequence[Analyzer] | None = None,
    class_map: ClassMap | None = None,
) -> ScanOutcome:
    """Scan `project` and record the results; see the module docstring.

    `work_dir` must be an empty private directory. Raises `IngestError` when the project is
    rejected at ingest, `ScanInfrastructureError` or `SandboxError` when the analyzers cannot
    run, and `LedgerError` when the ledger refuses a change.
    """
    snapshot = create_snapshot(project, work_dir / "snapshot")
    tools = analyzers if analyzers is not None else default_analyzers()
    parsed = [_run_tool(tool, runner, ledger, snapshot.tree_dir, work_dir) for tool in tools]
    parsed.sort(key=lambda item: TOOL_ORDER.index(item.run.tool))
    findings = normalize(
        [
            ToolObservations(item.run.tool, item.run.version, item.observations)
            for item in parsed
            if item.run.status == "ok"
        ],
        SourceReader(snapshot.tree_dir),
        class_map if class_map is not None else default_class_map(),
    )
    if len({finding.id for finding in findings}) != len(findings):
        raise LedgerError("two normalized findings share a stable id")
    report = ScanReport(
        assay_version=__version__,
        tree_sha256=snapshot.tree_sha256,
        tools=tuple(item.run for item in parsed),
        findings=findings,
    )
    return ScanOutcome(report=report, ledger=_record(ledger, report, parsed))
