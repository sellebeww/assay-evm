"""Slither through the sandbox runner.

Slither compiles a Foundry project with crytic-compile, which runs `forge build --build-info`
inside the same container (offline, with the pinned solc), and prints its JSON report to
standard output (`--json -`). With `--fail-none` the exit code is 0 whether or not detectors
report anything; any other exit code means that Slither failed, and its report then carries
`success: false` and an error message.

The report is untrusted input. Only the fields below are read; everything else is ignored and
never interpreted. Elements in dependencies (for example forge-std inside the image) are left
out of the locations; any other path outside the project is an error.
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
    validate,
)
from assay.analysis.limits import AnalyzerOutputError, load_json
from assay.sandbox import SandboxResult

ARGV: Final = ("slither", "{target}", "--json", "-", "--fail-none", "--disable-color")
MAX_MESSAGE_CHARS: Final = 4000
_CUT: Final = " [cut]"

_Text = Annotated[str, StringConstraints(max_length=100_000)]


class _Report(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="ignore")


class _SourceMapping(_Report):
    filename_absolute: _Text | None = None
    filename_relative: _Text | None = None
    is_dependency: bool = False
    lines: list[Annotated[int, Field(ge=0, le=10_000_000)]] = Field(
        default_factory=list, max_length=100_000
    )


class _Element(_Report):
    type: _Text
    name: _Text
    source_mapping: _SourceMapping | None = None


class _Detector(_Report):
    check: _Text
    impact: _Text
    confidence: _Text
    description: _Text
    elements: list[_Element] = Field(default_factory=list, max_length=1000)


class _Results(_Report):
    detectors: list[_Detector] = Field(default_factory=list, max_length=100_000)


class SlitherReport(_Report):
    success: bool
    error: _Text | None = None
    results: _Results | None = None


def _message(text: str) -> str:
    text = text.strip() or "(no description)"
    if len(text) > MAX_MESSAGE_CHARS:
        return text[: MAX_MESSAGE_CHARS - len(_CUT)] + _CUT
    return text


def _location(mapping: _SourceMapping) -> Location | None:
    if mapping.is_dependency:
        return None
    path = mapping.filename_absolute or mapping.filename_relative
    if not path or not mapping.lines:
        return None
    lines = [line for line in mapping.lines if line >= 1]
    if not lines:
        return None
    return validate(
        Location,
        {"path": project_relative(path), "start_line": min(lines), "end_line": max(lines)},
    )


def _locations(detector: _Detector) -> tuple[Location, ...]:
    found: dict[tuple[str, int, int], Location] = {}
    for element in detector.elements:
        if element.source_mapping is None:
            continue
        location = _location(element.source_mapping)
        if location is not None:
            found.setdefault((location.path, location.start_line, location.end_line), location)
    return tuple(found.values())[:64]


class Slither(Analyzer):
    name: ClassVar[AnalyzerName] = AnalyzerName.SLITHER

    def argv(self, target: str) -> tuple[str, ...]:
        return tuple(target if item == "{target}" else item for item in ARGV)

    def collect_output(self, result: SandboxResult, scratch_dir: Path) -> bytes:
        if result.truncated:
            raise AnalyzerOutputError("output_too_large", "the output exceeded the run's limit")
        return result.stdout.encode("utf-8")

    def failure(self, raw: RawAnalysis) -> str | None:
        if raw.exit_code == 0:
            return None
        # A failed run still prints a report; its error message explains the failure.
        try:
            report = self._report(raw.output)
        except AnalyzerOutputError:
            return f"exit code {raw.exit_code}"
        detail = (report.error or "").strip().splitlines()[:1]
        return f"exit code {raw.exit_code}" + (f": {detail[0][:500]}" if detail else "")

    def _report(self, output: bytes) -> SlitherReport:
        return validate(SlitherReport, load_json(output, self.limits))

    def parse(self, output: bytes) -> tuple[Observation, ...]:
        report = self._report(output)
        if not report.success:
            raise AnalyzerOutputError(
                "schema_mismatch", "the report says that the analysis did not succeed"
            )
        detectors = report.results.detectors if report.results is not None else []
        self.check_count(len(detectors))
        return tuple(
            validate(
                Observation,
                {
                    "rule_id": detector.check,
                    "severity_reported": f"{detector.impact} (confidence {detector.confidence})",
                    "message": _message(detector.description),
                    "locations": _locations(detector),
                },
            )
            for detector in detectors
        )
