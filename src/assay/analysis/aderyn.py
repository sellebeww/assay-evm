"""Aderyn through the sandbox runner.

Aderyn writes its report to a file whose extension selects the format; the adapter asks for
`/work/scratch/aderyn.json` inside the container and reads it from the host side of the scratch
directory with `read_report` (no symlink followed, regular file only, size-capped).

Aderyn groups its results by detector; each instance of an issue becomes one observation with
one location, so that every observation names a single place in the code.

The report is untrusted input. Only the fields below are read; everything else is ignored and
never interpreted.
"""

from pathlib import Path
from typing import Annotated, ClassVar, Final

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from assay.analysis.base import (
    Analyzer,
    AnalyzerName,
    Location,
    Observation,
    RawAnalysis,
    project_relative,
    read_report,
    validate,
)
from assay.analysis.limits import load_json
from assay.sandbox import SandboxResult
from assay.sandbox.layout import SCRATCH_MOUNT

REPORT_NAME: Final = "aderyn.json"
REPORT_PATH: Final = f"{SCRATCH_MOUNT}/{REPORT_NAME}"
ARGV: Final = ("aderyn", "{target}", "--output", REPORT_PATH)
MAX_MESSAGE_CHARS: Final = 4000
_CUT: Final = " [cut]"

_Text = Annotated[str, StringConstraints(max_length=100_000)]


class _Report(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="ignore")


class _Instance(_Report):
    contract_path: _Text
    line_no: Annotated[int, Field(ge=0, le=10_000_000)]
    hint: _Text | None = None


class _Issue(_Report):
    title: _Text
    description: _Text
    detector_name: _Text
    instances: list[_Instance] = Field(default_factory=list, max_length=100_000)


class _Issues(_Report):
    issues: list[_Issue] = Field(default_factory=list, max_length=10_000)


class AderynReport(_Report):
    high_issues: _Issues
    low_issues: _Issues


def _message(issue: _Issue, instance: _Instance) -> str:
    parts = [issue.title.strip(), issue.description.strip()]
    if instance.hint and instance.hint.strip():
        parts.append(f"Hint: {instance.hint.strip()}")
    text = "\n\n".join(part for part in parts if part) or "(no description)"
    if len(text) > MAX_MESSAGE_CHARS:
        return text[: MAX_MESSAGE_CHARS - len(_CUT)] + _CUT
    return text


def _location(instance: _Instance) -> tuple[Location, ...]:
    path = project_relative(instance.contract_path)
    if instance.line_no < 1:
        return ()
    location = {"path": path, "start_line": instance.line_no, "end_line": instance.line_no}
    return (validate(Location, location),)


class Aderyn(Analyzer):
    name: ClassVar[AnalyzerName] = AnalyzerName.ADERYN

    def argv(self, target: str) -> tuple[str, ...]:
        return tuple(target if item == "{target}" else item for item in ARGV)

    def collect_output(self, result: SandboxResult, scratch_dir: Path) -> bytes:
        return read_report(scratch_dir / REPORT_NAME, self.limits.max_bytes)

    def failure(self, raw: RawAnalysis) -> str | None:
        if raw.exit_code == 0:
            return None
        last = raw.stderr.strip().splitlines()[-1:] or [""]
        return f"exit code {raw.exit_code}" + (f": {last[0][:500]}" if last[0] else "")

    def parse(self, output: bytes) -> tuple[Observation, ...]:
        """One observation per instance: each instance is a separate place in the code."""
        report = validate(AderynReport, load_json(output, self.limits))
        groups = (("High", report.high_issues.issues), ("Low", report.low_issues.issues))
        self.check_count(sum(len(issue.instances) for _, issues in groups for issue in issues))
        return tuple(
            validate(
                Observation,
                {
                    "rule_id": issue.detector_name,
                    "severity_reported": severity,
                    "message": _message(issue, instance),
                    "locations": _location(instance),
                },
            )
            for severity, issues in groups
            for issue in issues
            for instance in issue.instances
        )
