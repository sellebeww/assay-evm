"""`assay scan`: run the static analyzers and record their results as candidate findings."""

import json
import os
import tempfile
from collections import Counter
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Final, NoReturn

import typer

from assay.analysis.normalize import ClassMap, Finding, FindingLocation, default_class_map
from assay.analysis.sarif import ToolInfo, dumps, rule_id, to_sarif
from assay.analysis.vocabulary import neutral
from assay.cli.documents import SCAN_FORMAT, ScanDocument
from assay.cli.exit_codes import ExitCode
from assay.cli.text import printable
from assay.ingest import IngestError
from assay.ledger import Ledger, LedgerError
from assay.orchestrator.scan import (
    STATUS_LABEL,
    ScanInfrastructureError,
    ScanOutcome,
    ScanReport,
    run_scan,
)
from assay.sandbox import SandboxError, SandboxRunner, SandboxUnavailable

DEFAULT_LEDGER: Final = Path(".assay") / "ledger.db"
JSON_FORMAT: Final = SCAN_FORMAT
NOTE: Final = (
    "Every finding is a candidate (unverified): a static-analysis hint at evidence level E0. "
    "No exploit was reproduced and no oracle has run; only an oracle run changes a status."
)


class OutputFormat(StrEnum):
    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


class FailOn(StrEnum):
    """Reported severities, lowest first, as the analyzers name them."""

    OPTIMIZATION = "optimization"
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


def _location(location: FindingLocation) -> dict[str, object]:
    return {
        "path": location.path,
        "start_line": location.start_line,
        "end_line": location.end_line,
        "function": location.function,
    }


def _finding(finding: Finding) -> dict[str, object]:
    return {
        "id": finding.id,
        "class": finding.vuln_class,
        "state": finding.state,
        "status": STATUS_LABEL,
        "evidence_level": finding.evidence_level,
        "location": _location(finding.location),
        "snippet_sha256": finding.snippet_sha256,
        "message": neutral(finding.message),
        "sources": [
            {
                "tool": source.tool.value,
                "tool_version": source.tool_version,
                "rule_id": source.rule_id,
                "severity_reported": source.severity_reported,
                "message": neutral(source.message),
                "locations": [_location(location) for location in source.locations],
            }
            for source in finding.sources
        ],
    }


def render_json(report: ScanReport) -> str:
    """Stable machine output: sorted keys, no time, no host path, tool text neutralized."""
    by_class = Counter(finding.vuln_class for finding in report.findings)
    document = {
        "format": JSON_FORMAT,
        "assay_version": report.assay_version,
        "input_tree_sha256": report.tree_sha256,
        "complete": report.complete,
        "note": NOTE,
        "tools": [
            {
                "tool": run.tool.value,
                "version": run.version,
                "status": run.status,
                "detail": None if run.detail is None else neutral(run.detail),
                "results": run.results,
                "unplaced_results": run.unplaced,
                "raw_output_sha256": run.raw_output_sha256,
            }
            for run in report.tools
        ],
        "summary": {"findings": len(report.findings), "by_class": dict(sorted(by_class.items()))},
        "findings": [_finding(finding) for finding in report.findings],
    }
    checked = ScanDocument.model_validate(document).model_dump(mode="json", by_alias=True)
    return json.dumps(checked, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def render_sarif(report: ScanReport) -> str:
    tools = [
        ToolInfo(
            name=run.tool.value,
            version=run.version,
            problem=None if run.status == "ok" else f"{run.status}: {run.detail}",
        )
        for run in report.tools
    ]
    return dumps(
        to_sarif(
            report.findings,
            tools=tools,
            assay_version=report.assay_version,
            tree_sha256=report.tree_sha256,
        )
    )


def _columns(rows: list[tuple[str, ...]]) -> list[str]:
    widths = [max(len(row[index]) for row in rows) for index in range(len(rows[0]))]
    return [
        "  ".join(cell.ljust(width) for cell, width in zip(row, widths, strict=True)).rstrip()
        for row in rows
    ]


def render_table(report: ScanReport) -> str:
    """Plain text: tools first, then one line per finding, then what the findings are."""
    count = len(report.findings)
    lines = [
        f"assay scan: {count} finding{'' if count == 1 else 's'}, each {STATUS_LABEL} "
        "at evidence level E0",
        f"input tree sha256 {report.tree_sha256}",
        "",
    ]
    tool_rows: list[tuple[str, ...]] = [("tool", "version", "status", "results")]
    tool_rows += [
        (run.tool.value, run.version, run.status, str(run.results)) for run in report.tools
    ]
    lines += _columns(tool_rows)
    problems = [run for run in report.tools if run.status != "ok"]
    if problems:
        lines += ["", "incomplete scan; these analyzers gave no usable result:"]
        lines += [f"  {run.tool.value}: {neutral(run.detail or run.status)}" for run in problems]
    if report.findings:
        rows: list[tuple[str, ...]] = [("id", "class", "location", "function", "reported by")]
        for finding in report.findings:
            where = finding.location
            reported = ", ".join(
                f"{rule_id(source)} [{source.severity_reported}]" for source in finding.sources
            )
            rows.append(
                (
                    finding.id[:12],
                    finding.vuln_class,
                    f"{where.path}:{where.start_line}-{where.end_line}",
                    where.function or "-",
                    reported,
                )
            )
        lines += ["", *_columns(rows)]
    lines += ["", NOTE, "Tool messages: --format json or --format sarif."]
    return printable("\n".join(lines)) + "\n"


RENDERERS: Final = {
    OutputFormat.TABLE: render_table,
    OutputFormat.JSON: render_json,
    OutputFormat.SARIF: render_sarif,
}


def exit_code(report: ScanReport, fail_on: FailOn | None, class_map: ClassMap) -> ExitCode:
    """4 if an analyzer ran out of memory; 1 if --fail-on is met; 3 if incomplete; else 0."""
    if any(run.status == "out_of_memory" for run in report.tools):
        return ExitCode.INFRASTRUCTURE
    if fail_on is not None and any(
        class_map.meets(source.severity_reported, fail_on.value)
        for finding in report.findings
        for source in finding.sources
    ):
        return ExitCode.NEGATIVE
    if not report.complete:
        return ExitCode.INCONCLUSIVE
    return ExitCode.SUCCESS


def _fail(code: ExitCode, message: str) -> NoReturn:
    typer.echo(printable(message), err=True)
    raise typer.Exit(int(code))


def _write(path: Path, text: str) -> None:
    """Write `text` to `path` through a temporary file in the same directory."""
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _scan(project: Path, ledger_path: Path) -> ScanOutcome:
    runner = SandboxRunner()
    try:
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with (
            tempfile.TemporaryDirectory(prefix="assay-scan-", ignore_cleanup_errors=True) as tmp,
            Ledger.open(ledger_path) as ledger,
        ):
            return run_scan(project, runner=runner, ledger=ledger, work_dir=Path(tmp))
    except IngestError as exc:
        _fail(ExitCode.INTEGRITY, f"project rejected: {exc}")
    except (ScanInfrastructureError, SandboxUnavailable, SandboxError, LedgerError, OSError) as exc:
        _fail(ExitCode.INFRASTRUCTURE, f"error: {exc}")


def scan_command(
    project: Annotated[
        Path,
        typer.Argument(help="Foundry project directory to scan.", exists=True, file_okay=False),
    ],
    output_format: Annotated[
        OutputFormat, typer.Option("--format", help="Output format.")
    ] = OutputFormat.TABLE,
    json_output: Annotated[
        bool, typer.Option("--json", help="Same as --format json (stable machine output).")
    ] = False,
    out: Annotated[
        Path | None,
        typer.Option("--out", help="Write the output to this file instead of standard output."),
    ] = None,
    fail_on: Annotated[
        FailOn | None,
        typer.Option(
            "--fail-on",
            help="Exit with 1 when a finding has a reported severity at or above this one.",
        ),
    ] = None,
    ledger_path: Annotated[
        Path,
        typer.Option("--ledger", help="Ledger database; created if missing.", dir_okay=False),
    ] = DEFAULT_LEDGER,
) -> None:
    """Run Slither and Aderyn on PROJECT and record their results as candidate findings.

    The project is snapshotted under the ingest rules, both analyzers run in the sandbox (no
    network, read-only project), and their results are normalized: each gets a class (one of
    the eight vulnerability classes or `other`), a stable id, the severity exactly as the tool
    reported it, and the state CANDIDATE at evidence level E0. Results of both tools at the same
    place are merged. Findings, scans and raw outputs go to the ledger; repeating a scan of the
    same input adds nothing and prints the same JSON. Every finding is a candidate
    (unverified): a hint, not a reproduced exploit.

    \b
    Examples:
      assay scan fixtures/reentrancy/single_function
      assay scan . --format sarif --out assay.sarif
      assay scan . --json --fail-on high

    Exit codes: 0 scan finished (findings or not); 1 --fail-on met; 2 usage error;
    3 incomplete scan (an analyzer failed, timed out or wrote unusable output);
    4 infrastructure problem (Docker, runner image, ledger, out of memory);
    5 the project was rejected at ingest.
    """
    if json_output:
        if output_format not in (OutputFormat.TABLE, OutputFormat.JSON):
            _fail(ExitCode.USAGE, f"error: --json conflicts with --format {output_format.value}")
        output_format = OutputFormat.JSON
    if out is not None and not out.parent.is_dir():
        _fail(ExitCode.USAGE, f"error: directory does not exist: {out.parent}")
    if out is not None and out.is_dir():
        _fail(ExitCode.USAGE, f"error: --out names a directory: {out}")
    outcome = _scan(project, ledger_path)
    report = outcome.report
    text = RENDERERS[output_format](report)
    if out is None:
        typer.echo(text, nl=False)
    else:
        try:
            _write(out, text)
        except OSError as exc:
            _fail(ExitCode.INFRASTRUCTURE, f"error: cannot write {out}: {exc}")
        typer.echo(
            printable(
                f"scan output ({output_format.value}) written to {out}: "
                f"{len(report.findings)} findings, {STATUS_LABEL}"
            ),
            err=True,
        )
    summary = outcome.ledger
    typer.echo(
        f"ledger: {summary.findings_added} new findings, {summary.findings_existing} already "
        f"recorded; {summary.scans_recorded} scans recorded, {summary.scans_reused} unchanged",
        err=True,
    )
    raise typer.Exit(int(exit_code(report, fail_on, default_class_map())))
