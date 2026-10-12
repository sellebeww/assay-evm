"""Static analysis coverage of the development fixtures (`make static-coverage`).

Runs `assay scan` (its orchestrator, in this process) on the vulnerable revision of every
fixture under `fixtures/<class>/<name>/`, with a temporary ledger, and renders
`docs/static-coverage.md` from the results, so that the page is never written by hand. For each
fixture and each analyzer the page shows how many normalized findings the analyzer contributed
and whether at least one of them maps to the fixture's class; it lists the classes that no
analyzer detected.

Neither the fixtures nor the detector mapping (`src/assay/analysis/class_map.toml`) are adjusted
to change these numbers. The page holds no timestamps, host paths or user names.

Exit status: 0 when every scan completed (whatever it detected), 1 when a scan was incomplete
(the page is still written and says so), 2 when the fixtures, the runner image or the
arguments cannot be used.
"""

import argparse
import hashlib
import sys
import tempfile
import textwrap
from collections.abc import Sequence
from pathlib import Path
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, ValidationError

import fixture_check
from assay import __version__
from assay.analysis.sarif import rule_id
from assay.ingest import IngestError
from assay.ledger import Ledger, LedgerError
from assay.orchestrator.scan import ScanInfrastructureError, ScanReport, run_scan
from assay.report.bundle import EnvironmentUnavailable, read_versions_lock
from assay.sandbox import DEFAULT_IMAGE, SandboxError, SandboxRunner

REPO_ROOT: Final = fixture_check.REPO_ROOT
FIXTURES_DIR: Final = fixture_check.FIXTURES_DIR
CLASS_IDS: Final = fixture_check.CLASS_IDS
DEFAULT_OUT: Final = REPO_ROOT / "docs" / "static-coverage.md"
TOOLS: Final = ("slither", "aderyn")
TOOL_TITLES: Final = {"slither": "Slither", "aderyn": "Aderyn"}
RESULT_PREFIX: Final = "STATIC COVERAGE:"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class FindingSummary(_Strict):
    """One normalized finding of a fixture: class, rules, place."""

    vuln_class: str
    rules: tuple[str, ...]
    path: str
    start_line: int
    end_line: int
    function: str | None


class ToolCoverage(_Strict):
    tool: str
    version: str
    status: str
    results: int
    findings: int
    class_findings: int


class FixtureCoverage(_Strict):
    fixture: str
    class_id: str
    tree_sha256: str
    tools: tuple[ToolCoverage, ...]
    findings: tuple[FindingSummary, ...]

    @property
    def class_findings(self) -> tuple[FindingSummary, ...]:
        return tuple(item for item in self.findings if item.vuln_class == self.class_id)

    def tool(self, name: str) -> ToolCoverage | None:
        return next((item for item in self.tools if item.tool == name), None)


class CoverageResults(_Strict):
    schema_version: Literal[1] = 1
    assay_version: str
    tool_versions: dict[str, str]
    versions_lock_sha256: str
    fixtures: tuple[FixtureCoverage, ...]

    @property
    def complete(self) -> bool:
        return all(tool.status == "ok" for item in self.fixtures for tool in item.tools)


def coverage_of(fixture: str, report: ScanReport) -> FixtureCoverage:
    """Summarize the scan of one fixture: per tool, findings and findings of the class."""
    class_id = fixture.split("/", 1)[0]
    tools = []
    for run in report.tools:
        mine = [
            finding
            for finding in report.findings
            if any(source.tool is run.tool for source in finding.sources)
        ]
        tools.append(
            ToolCoverage(
                tool=run.tool.value,
                version=run.version,
                status=run.status,
                results=run.results,
                findings=len(mine),
                class_findings=sum(1 for finding in mine if finding.vuln_class == class_id),
            )
        )
    return FixtureCoverage(
        fixture=fixture,
        class_id=class_id,
        tree_sha256=report.tree_sha256,
        tools=tuple(tools),
        findings=tuple(
            FindingSummary(
                vuln_class=finding.vuln_class,
                rules=tuple(dict.fromkeys(rule_id(source) for source in finding.sources)),
                path=finding.location.path,
                start_line=finding.location.start_line,
                end_line=finding.location.end_line,
                function=finding.location.function,
            )
            for finding in report.findings
        ),
    )


def _class_order(fixture: str) -> tuple[int, str]:
    class_id = fixture.split("/", 1)[0]
    index = CLASS_IDS.index(class_id) if class_id in CLASS_IDS else len(CLASS_IDS)
    return index, fixture


def collect(fixtures_dir: Path, runner: SandboxRunner) -> CoverageResults:
    """Scan every fixture with one temporary ledger and summarize the results."""
    fixtures = sorted(fixture_check.discover_fixtures(fixtures_dir), key=_class_order)
    found: list[FixtureCoverage] = []
    versions: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="assay-coverage-", ignore_cleanup_errors=True) as tmp:
        work = Path(tmp)
        with Ledger.open(work / "ledger.db") as ledger:
            for index, fixture in enumerate(fixtures):
                print(f"scanning {fixture}", file=sys.stderr, flush=True)
                run_dir = work / f"scan-{index}"
                run_dir.mkdir()
                outcome = run_scan(
                    fixtures_dir / fixture, runner=runner, ledger=ledger, work_dir=run_dir
                )
                found.append(coverage_of(fixture, outcome.report))
                versions.update({run.tool.value: run.version for run in outcome.report.tools})
    lock = read_versions_lock().encode("utf-8")
    return CoverageResults(
        assay_version=__version__,
        tool_versions=dict(sorted(versions.items())),
        versions_lock_sha256=hashlib.sha256(lock).hexdigest(),
        fixtures=tuple(found),
    )


def detected(item: FixtureCoverage) -> bool:
    return bool(item.class_findings)


def result_line(results: CoverageResults) -> str:
    hits = sum(1 for item in results.fixtures if detected(item))
    return (
        f"{RESULT_PREFIX} {hits}/{len(results.fixtures)} fixture classes with at least one "
        "finding mapped to the class"
    )


def _paragraph(text: str) -> str:
    return textwrap.fill(text, width=100, break_long_words=False, break_on_hyphens=False)


def _cell(text: str) -> str:
    return text.replace("\\", "\\\\").replace("|", "\\|")


def _tool_cell(tool: ToolCoverage | None) -> tuple[str, str]:
    if tool is None:
        return "-", "-"
    if tool.status != "ok":
        return f"no result ({tool.status})", "-"
    return str(tool.findings), "yes" if tool.class_findings else "no"


def _place(item: FindingSummary) -> str:
    where = f"`{_cell(item.path)}:{item.start_line}-{item.end_line}`"
    return where + (f" (`{_cell(item.function)}`)" if item.function else "")


INTRODUCTION: Final = (
    "The development split has one fixture per vulnerability class. This page shows what the "
    "two static analyzers report on the unpatched code of each fixture, after Assay "
    "normalized and deduplicated their results. A finding counts for an analyzer when one of "
    "its sources comes from that analyzer; a finding of both analyzers counts for both and "
    "once in the column after deduplication."
)
LIMITS: Final = (
    "A class hit means only that at least one finding in the fixture maps to the fixture's "
    "class through `src/assay/analysis/class_map.toml`. It does not mean that the finding points "
    "at the defect the fixture contains, and it is not a reproduction: every finding is a "
    "candidate (unverified) at evidence level E0. A class without a hit says nothing about the "
    "code either; the analyzers simply reported nothing of that class."
)
GAP_NOTE: Final = (
    "These gaps are expected and are the reason Assay does not stop at static analysis. A "
    "hypothesis can be turned into a PoC and checked by the oracles whether or not an analyzer "
    "flagged it, and a patch is judged by the oracles, never by analyzer output."
)
HONESTY_NOTE: Final = (
    "The detector mapping was written from the detector documentation of the pinned tool "
    "versions before any coverage run. Neither the mapping nor the fixtures are changed to "
    "improve these numbers."
)


def render_markdown(results: CoverageResults) -> str:
    """The page `docs/static-coverage.md`, from the results of one run."""
    tools = ", ".join(f"{name} {version}" for name, version in results.tool_versions.items())
    lines = [
        "# Static analysis coverage",
        "",
        _paragraph(
            "`make static-coverage` writes this page from one run of `assay scan` over the "
            "development fixtures, with `tools/static_coverage.py`. It is not edited by hand."
        ),
        "",
        _paragraph(INTRODUCTION),
        "",
        "## What this result means",
        "",
        _paragraph(LIMITS),
        "",
        _paragraph(HONESTY_NOTE),
        "",
        "## Result",
        "",
        f"`{result_line(results)}`",
        "",
    ]
    if not results.complete:
        lines += [
            _paragraph(
                "Incomplete run: at least one analyzer gave no usable result on a fixture; "
                "those cells say `no result`."
            ),
            "",
        ]
    header = ["Class", "Fixture"]
    for name in TOOLS:
        header += [f"{TOOL_TITLES[name]} findings", f"{TOOL_TITLES[name]} class hit"]
    header += ["Findings after deduplication", "Class hit by any analyzer"]
    lines += ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    for item in results.fixtures:
        cells = [f"`{item.class_id}`", f"`{item.fixture.split('/', 1)[1]}`"]
        for name in TOOLS:
            cells += _tool_cell(item.tool(name))
        cells += [str(len(item.findings)), "yes" if detected(item) else "no"]
        lines.append("| " + " | ".join(cells) + " |")

    missed = [item for item in results.fixtures if not detected(item)]
    lines += ["", "## Classes the analyzers did not detect", ""]
    if missed:
        lines.append(
            _paragraph(
                f"No finding of either analyzer maps to the class of {len(missed)} of the "
                f"{len(results.fixtures)} fixtures:"
            )
        )
        lines.append("")
        for item in missed:
            other = sorted({rule for finding in item.findings for rule in finding.rules})
            reported = ", ".join(f"`{_cell(rule)}`" for rule in other) or "nothing"
            lines.append(
                f"- `{item.class_id}` (`{item.fixture}`): the analyzers reported {reported}."
            )
    else:
        lines.append("Every fixture has at least one finding mapped to its class.")
    single = [
        (item, name)
        for item in results.fixtures
        if detected(item)
        for name in TOOLS
        if (tool := item.tool(name)) is not None and tool.status == "ok" and not tool.class_findings
    ]
    if single:
        lines += [
            "",
            "Detected by one analyzer only (the other reported nothing of the class):",
            "",
        ]
        lines += [
            f"- `{item.class_id}` (`{item.fixture}`): nothing from {TOOL_TITLES[name]}."
            for item, name in single
        ]
    lines += ["", _paragraph(GAP_NOTE), "", "## Findings mapped to the fixture's class", ""]
    for item in results.fixtures:
        hits = item.class_findings
        if not hits:
            continue
        lines.append(f"- `{item.fixture}`:")
        lines += [
            f"  - {', '.join(f'`{_cell(rule)}`' for rule in hit.rules)} at {_place(hit)}"
            for hit in hits
        ]
    lines += ["", "## All findings per fixture", ""]
    for item in results.fixtures:
        lines += [
            f"### `{item.fixture}`",
            "",
            f"Input tree sha256 `{item.tree_sha256}`.",
            "",
        ]
        if not item.findings:
            lines += ["No findings.", ""]
            continue
        lines += ["| Class | Reported by | Location |", "|---|---|---|"]
        lines += [
            f"| `{finding.vuln_class}` | {', '.join(f'`{_cell(rule)}`' for rule in finding.rules)} "
            f"| {_place(finding)} |"
            for finding in item.findings
        ]
        lines.append("")
    lines += [
        "## Run",
        "",
        "| Item | Value |",
        "|---|---|",
        f"| Assay version | `{_cell(results.assay_version)}` |",
        f"| Analyzers in the image | {_cell(tools) or '-'} |",
        f"| `versions.lock` sha256 | `{results.versions_lock_sha256}` |",
        "",
        "## Reproduce",
        "",
        "```",
        "make image",
        "make static-coverage",
        "```",
        "",
    ]
    return "\n".join(lines)


def table_lines(results: CoverageResults) -> list[str]:
    """A plain-text summary for the terminal."""
    lines = []
    for item in results.fixtures:
        cells = []
        for name in TOOLS:
            findings, hit = _tool_cell(item.tool(name))
            cells.append(f"{name} {findings} findings, class hit {hit}")
        status = "detected" if detected(item) else "NOT DETECTED"
        lines.append(f"{item.fixture:40} {'; '.join(cells)}; {status}")
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="static_coverage.py",
        description="Scan every development fixture and render the static coverage page.",
    )
    parser.add_argument("--image", default=DEFAULT_IMAGE, help="runner image")
    parser.add_argument("--fixtures", type=Path, default=FIXTURES_DIR, help="fixtures root")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Markdown page to write")
    parser.add_argument("--results", type=Path, default=None, help="also write results JSON")
    parser.add_argument(
        "--from-results", type=Path, default=None, help="render from results JSON, no scans"
    )
    args = parser.parse_args(argv)

    if args.from_results is not None:
        try:
            results = CoverageResults.model_validate_json(args.from_results.read_bytes())
        except (OSError, ValidationError) as exc:
            print(f"error: the coverage results cannot be read: {exc}", file=sys.stderr)
            return 2
    else:
        try:
            results = collect(args.fixtures, SandboxRunner(image=args.image))
        except IngestError as exc:
            print(f"error: a fixture was rejected at ingest: {exc}", file=sys.stderr)
            return 2
        except (
            ScanInfrastructureError,
            SandboxError,
            LedgerError,
            EnvironmentUnavailable,
            OSError,
        ) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.results is not None and args.from_results is None:
        args.results.parent.mkdir(parents=True, exist_ok=True)
        args.results.write_text(results.model_dump_json(indent=2) + "\n", encoding="utf-8")
    print("\n".join(table_lines(results)))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render_markdown(results), encoding="utf-8")
    print(f"wrote {args.out}")
    print(result_line(results))
    return 0 if results.complete else 1


if __name__ == "__main__":
    sys.exit(main())
