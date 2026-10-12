"""The Markdown summary of `assay ci verify` for a GitHub job summary and a pull request comment.

Everything that can come from the pull request (PoC and file names, contract names, reasons,
bounds, revision ids) is data. It appears only inside code spans or fenced code blocks, which
GitHub renders literally: no HTML, no mention, no link, no image, no emoji code. The fixed text
of this module holds none of the characters `< > @ [ ] &`, and the unit tests check that for
hostile input. Table cells escape the pipe character.
"""

import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from assay.ci.gitdiff import ScopedChange
from assay.cli.exit_codes import ExitCode
from assay.ledger import FinalVerdict, OracleName
from assay.orchestrator.models import REPORT_ORDER, VerifyReport

__all__ = [
    "MAX_SUMMARY_CHARS",
    "NO_CHANGES",
    "CiRun",
    "PocResult",
    "block",
    "inline",
    "overall_verdict",
    "render_summary",
    "slug",
]

MAX_SUMMARY_CHARS: Final = 60_000
"""A comment holds at most 65 536 characters; the job summary at most 1 MiB."""
NO_CHANGES: Final = "NO_CHANGES_IN_SCOPE"
ERROR: Final = "ERROR"
LIMITS: Final = (
    "A verdict covers only the checks and bounds listed here. VERIFIED_WITHIN_BOUNDS means that "
    "nothing was found within them. It is not a proof of absence."
)
_INLINE_LIMIT: Final = 300
_BLOCK_LIMIT: Final = 4000
_MAX_FILES: Final = 50
_MAX_REASONS: Final = 20
_SLUG: Final = re.compile(r"[^A-Za-z0-9._-]+")
_LINE_BREAKS: Final = "\r\n\v\f\x85\N{LINE SEPARATOR}\N{PARAGRAPH SEPARATOR}"
_NEWLINES: Final = re.compile(f"[{_LINE_BREAKS}\\t]+")
_NEWLINES_KEEP: Final = re.compile(f"\r\n|[{_LINE_BREAKS}]")


def _escape(text: str) -> str:
    """Control, invisible formatting and unassigned characters as \\uXXXX escapes."""
    return "".join(
        f"\\u{ord(ch):04x}" if unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn") else ch
        for ch in text
    )


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _longest_run(text: str, char: str = "`") -> int:
    return max((len(item) for item in re.findall(f"{re.escape(char)}+", text)), default=0)


def inline(text: str, *, limit: int = _INLINE_LIMIT) -> str:
    """`text` as one code span: single line, escaped, clipped, with a delimiter that is longer
    than any backtick run inside."""
    flat = _escape(_NEWLINES.sub(" ", text)).strip()
    flat = _clip(flat, limit)
    if not flat:
        return "(empty)"
    fence = "`" * (_longest_run(flat) + 1)
    pad = " " if flat.startswith("`") or flat.endswith("`") else ""
    return f"{fence}{pad}{flat}{pad}{fence}"


def cell(text: str) -> str:
    """A code span for a table cell: a pipe would end the cell, so it is escaped."""
    return inline(text).replace("|", "\\|")


def block(text: str, *, limit: int = _BLOCK_LIMIT) -> str:
    """`text` as a fenced code block whose fence is longer than any backtick run inside."""
    lines = [_escape(line) for line in _NEWLINES_KEEP.split(text)]
    body = "\n".join(lines).strip("\n")
    if len(body) > limit:
        body = body[: limit - 1] + "…"
    fence = "`" * max(3, _longest_run(body) + 1)
    return f"{fence}text\n{body}\n{fence}"


def slug(name: str, taken: Sequence[str] = ()) -> str:
    """A directory name made of `A-Za-z0-9._-` from a PoC name; unique among `taken`."""
    base = _SLUG.sub("_", name).strip("._") or "poc"
    base = base[:64]
    candidate, number = base, 1
    while candidate in taken:
        number += 1
        candidate = f"{base}-{number}"
    return candidate


@dataclass(frozen=True, slots=True)
class PocResult:
    name: str
    """The name of the PoC directory, untrusted."""
    slug: str
    """The directory under `bundles/` that holds its evidence bundle."""
    code: ExitCode
    """The exit code `assay verify` would have given."""
    report: VerifyReport | None
    detail: str | None = None
    """Why there is no report (an input rejected, an infrastructure problem); untrusted text."""


@dataclass(frozen=True, slots=True)
class CiRun:
    scope: str
    base_sha: str
    head_sha: str
    profile: str
    symbolic: bool
    fail_on: str
    changes: tuple[ScopedChange, ...]
    results: tuple[PocResult, ...]
    poc_changed: bool = False
    """The pull request changed files under the PoC directory."""


def result_verdict(result: PocResult) -> str:
    if result.report is None:
        return "REJECTED" if result.code is ExitCode.INTEGRITY else ERROR
    return result.report.final_verdict.value


def overall_verdict(results: Sequence[PocResult]) -> str:
    """REJECTED if any PoC was rejected, else ERROR if any could not run, else INCONCLUSIVE if
    any was inconclusive, else VERIFIED_WITHIN_BOUNDS."""
    verdicts = {result_verdict(item) for item in results}
    for verdict in ("REJECTED", ERROR, FinalVerdict.INCONCLUSIVE.value):
        if verdict in verdicts:
            return verdict
    return FinalVerdict.VERIFIED_WITHIN_BOUNDS.value


def _oracle_columns(results: Sequence[PocResult]) -> list[OracleName]:
    ran = {
        row.oracle
        for item in results
        if item.report is not None
        for row in item.report.oracles
        if row.status == "ran"
    }
    return [oracle for oracle in REPORT_ORDER if oracle is not OracleName.SYMBOLIC or oracle in ran]


def _row_text(report: VerifyReport | None, oracle: OracleName) -> str:
    if report is None:
        return "-"
    for row in report.oracles:
        if row.oracle is oracle:
            return row.verdict.value if row.status == "ran" and row.verdict else row.status
    return "missing"


def _verdict_text(result: PocResult) -> str:
    verdict = result_verdict(result)
    if result.code is ExitCode.INTEGRITY:
        return f"{verdict} (integrity violation)"
    return verdict


def no_changes_summary(run: CiRun) -> str:
    return "\n".join(
        [
            "## Assay patch verification",
            "",
            "**no changes in scope**",
            "",
            f"No file under {inline(run.scope)} changed between {inline(run.base_sha[:12])} "
            f"and {inline(run.head_sha[:12])}, so no patch was verified.",
            "",
        ]
    )


def _details(result: PocResult) -> list[str]:
    lines = [f"### PoC {inline(result.name)}", ""]
    lines.append(f"Verdict: **{_verdict_text(result)}**")
    lines.append("")
    report = result.report
    if report is None:
        if result.detail:
            lines += [block(result.detail), ""]
        return lines
    if report.reasons:
        lines.append("Reasons: " + ", ".join(inline(item) for item in report.reasons))
        lines.append("")
    entries: list[str] = []
    for row in report.oracles:
        for item in row.reasons:
            where = ""
            if item.path is not None:
                where = f" at {inline(item.path + (f':{item.line}' if item.line else ''))}"
            entries.append(
                f"- {inline(row.oracle.value)} {inline(item.code)}: {inline(item.detail)}{where}"
            )
        for item in row.warnings:
            entries.append(
                f"- {inline(row.oracle.value)} warning {inline(item.code)}: {inline(item.detail)}"
            )
    lines += entries[:_MAX_REASONS]
    if len(entries) > _MAX_REASONS:
        lines.append(f"- and {len(entries) - _MAX_REASONS} more in the bundle")
    if entries:
        lines.append("")
    lines += [
        "Bounds that ran:",
        "",
        block(report.bounds_statement),
        "",
        f"Evidence level: {inline(report.evidence_level or 'none')}",
        "",
    ]
    return lines


def render_summary(run: CiRun, *, detail: bool = True) -> str:
    """The Markdown summary of `run`; at most `MAX_SUMMARY_CHARS` characters."""
    if not run.changes and not run.results:
        return no_changes_summary(run)
    text = _render(run, detail=detail)
    if len(text) > MAX_SUMMARY_CHARS and detail:
        text = _render(run, detail=False)
    if len(text) > MAX_SUMMARY_CHARS:
        text = text[: text.rfind("\n", 0, MAX_SUMMARY_CHARS - 200)] + "\n\n(summary cut)\n"
    return text


def _render(run: CiRun, *, detail: bool) -> str:
    columns = _oracle_columns(run.results)
    lines = [
        "## Assay patch verification",
        "",
        f"**{overall_verdict(run.results)}**",
        "",
        f"Scope {inline(run.scope)}, base {inline(run.base_sha[:12])}, head "
        f"{inline(run.head_sha[:12])}, profile {inline(run.profile)}, symbolic oracle "
        f"{inline('yes' if run.symbolic else 'no')}, fail on {inline(run.fail_on)}.",
        "",
        LIMITS,
        "",
        "### Verdict per PoC",
        "",
        "| PoC | Verdict | " + " | ".join(oracle.value for oracle in columns) + " |",
        "|---|---|" + "---|" * len(columns),
    ]
    for item in run.results:
        cells = [_row_text(item.report, oracle) for oracle in columns]
        lines.append(f"| {cell(item.name)} | {_verdict_text(item)} | " + " | ".join(cells) + " |")
    lines.append("")
    if run.poc_changed:
        lines += [
            "This pull request also changes files of the PoC directory. The PoC was read from "
            "the checked-out head, so a changed PoC can change the result. Review those "
            "changes first.",
            "",
        ]
    shown = run.changes[:_MAX_FILES]
    if shown:
        lines += ["### Changed files in scope", ""]
        lines += [f"- {inline(item.status)} {inline(item.path)}" for item in shown]
        if len(run.changes) > len(shown):
            lines.append(f"- and {len(run.changes) - len(shown)} more")
        lines.append("")
    if detail:
        for item in run.results:
            lines += _details(item)
    lines += [
        "### Reproduce",
        "",
        "Download the evidence artifact of this job and re-check a bundle offline (replay needs "
        "Docker and the runner image, and no network):",
        "",
        block("\n".join(f"assay replay bundles/{item.slug}" for item in run.results)),
        "",
    ]
    return "\n".join(lines)
