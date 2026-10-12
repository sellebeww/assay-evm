"""Normalized findings: analyzer observations with a class, a stable id, and one entry per place.

Each observation that has a location in the project becomes a candidate finding:

- its vulnerability class comes from the detector id through the mapping in `class_map.toml`
  (one of the eight classes of docs/fixture-spec.md, or `other`);
- its location is the first location the tool reported, with the line range ordered and the
  enclosing function found in the snapshot (`source_map`);
- its severity, rule and message stay exactly as the tool reported them; Assay adds no severity;
- it is a `CANDIDATE` at evidence level E0, an unverified hint.

Deduplication merges candidates of the same class in the same file when they lie in the same
function, or, for locations outside any function, when their line ranges overlap. A location
that spans several functions (a whole contract, for example) is outside any function, so it is
never merged with a location inside one. A merged finding keeps every source and covers the
union of their line ranges.

The stable id is the sha256 of the class, the relative path, the line range and the sha256 of
the code in that range (each line stripped of surrounding whitespace). It contains no time and
no host path, so the same code gives the same id on every machine and in every run.

Observations without a location in the project (for example results that lie only in a
dependency) cannot be placed and give no finding; the scan report counts them.
"""

import hashlib
import tomllib
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import cache
from importlib import resources
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from assay.analysis.base import AnalyzerName, Location, Observation
from assay.analysis.source_map import SourceReader, Span, snippet_sha256

OTHER: Final = "other"
ID_SCHEME: Final = "assay-finding-v1"
CLASS_MAP_RESOURCE: Final = "class_map.toml"
TOOL_ORDER: Final = tuple(AnalyzerName)

SarifLevel = Literal["none", "note", "warning", "error"]
UNKNOWN_SEVERITY_LEVEL: Final[SarifLevel] = "warning"
_ClassId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
_Word = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,31}$")]
_DetectorId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,199}$")]


class ClassMapError(ValueError):
    """The mapping file is malformed."""


# The mapping file is trusted package data, but it is still checked: TOML gives lists and
# strings, which these models turn into tuples and tool names.
class _SeverityTable(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    order: tuple[_Word, ...] = Field(min_length=1)
    sarif_level: dict[_Word, SarifLevel]


class _ClassMapFile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1]
    classes: tuple[_ClassId, ...] = Field(min_length=1)
    severity: _SeverityTable
    detectors: dict[AnalyzerName, dict[_DetectorId, _ClassId]]


@dataclass(frozen=True, slots=True)
class ClassMap:
    """Detector to class, and reported severity to SARIF level and `--fail-on` rank."""

    classes: tuple[str, ...]
    severity_order: tuple[str, ...]
    sarif_levels: Mapping[str, SarifLevel]
    detectors: Mapping[AnalyzerName, Mapping[str, str]]

    def vuln_class(self, tool: AnalyzerName, rule_id: str) -> str:
        """The class of a detector, or `other` for a detector that is not listed."""
        return self.detectors.get(tool, {}).get(rule_id, OTHER)

    def sarif_level(self, severity_reported: str) -> SarifLevel:
        return self.sarif_levels.get(severity_word(severity_reported), UNKNOWN_SEVERITY_LEVEL)

    def meets(self, severity_reported: str, threshold: str) -> bool:
        """True when a reported severity is at or above `threshold` (a word of the order).

        A severity whose first word is not in the order meets every threshold.
        """
        word = severity_word(severity_reported)
        if word not in self.severity_order:
            return True
        return self.severity_order.index(word) >= self.severity_order.index(threshold)


def severity_word(severity_reported: str) -> str:
    """The first word of a reported severity, in lower case (`High (confidence Low)` -> high)."""
    words = severity_reported.split()
    return words[0].lower() if words else ""


def parse_class_map(text: str) -> ClassMap:
    """Parse and check the mapping file, or raise `ClassMapError`."""
    try:
        data = _ClassMapFile.model_validate(tomllib.loads(text))
    except (tomllib.TOMLDecodeError, ValidationError) as exc:
        raise ClassMapError(f"malformed class map: {exc}") from exc
    if len(set(data.classes)) != len(data.classes) or OTHER in data.classes:
        raise ClassMapError("classes must be unique and must not include 'other'")
    allowed = {*data.classes, OTHER}
    for tool, table in data.detectors.items():
        unknown = sorted({value for value in table.values() if value not in allowed})
        if unknown:
            raise ClassMapError(f"{tool.value}: unknown classes {', '.join(unknown)}")
    order = data.severity.order
    if len(set(order)) != len(order) or set(data.severity.sarif_level) != set(order):
        raise ClassMapError("severity.order and severity.sarif_level must list the same words")
    return ClassMap(
        classes=data.classes,
        severity_order=order,
        sarif_levels=dict(data.severity.sarif_level),
        detectors={tool: dict(table) for tool, table in data.detectors.items()},
    )


@cache
def default_class_map() -> ClassMap:
    """The mapping shipped with Assay (`assay/analysis/class_map.toml`)."""
    text = resources.files("assay.analysis").joinpath(CLASS_MAP_RESOURCE).read_text("utf-8")
    return parse_class_map(text)


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class FindingLocation(_Model):
    """A project-relative path, an ordered line range and the enclosing function, if any."""

    path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    function: str | None


class Source(_Model):
    """One analyzer result behind a finding, as the tool reported it (unverified, E0)."""

    tool: AnalyzerName
    tool_version: str
    rule_id: str
    severity_reported: str
    message: str
    locations: tuple[FindingLocation, ...] = Field(min_length=1)
    """Every location the tool reported; the first is where the result was placed."""
    observation_index: int = Field(ge=0, exclude=True)
    """Position of the result in the tool's report (links it to its ledger observation)."""


class Finding(_Model):
    """A normalized candidate finding. Never more than a hint: `CANDIDATE` at E0."""

    id: str = Field(pattern=r"^[0-9a-f]{64}$")
    vuln_class: str
    location: FindingLocation
    snippet_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    message: str
    """The message of the first source, as the tool wrote it."""
    evidence_level: Literal["E0"] = "E0"
    state: Literal["CANDIDATE"] = "CANDIDATE"
    sources: tuple[Source, ...] = Field(min_length=1)


@dataclass(frozen=True, slots=True)
class ToolObservations:
    """The parsed results of one analyzer run."""

    tool: AnalyzerName
    tool_version: str
    observations: tuple[Observation, ...]


@dataclass(frozen=True, slots=True)
class _Candidate:
    vuln_class: str
    path: str
    start_line: int
    end_line: int
    function: Span | None
    source: Source


def stable_id(vuln_class: str, path: str, start_line: int, end_line: int, snippet: str) -> str:
    """sha256 over the class, the relative path, the line range and the snippet hash."""
    material = "\n".join([ID_SCHEME, vuln_class, path, f"{start_line}:{end_line}", snippet])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _place(location: Location, sources: SourceReader) -> tuple[FindingLocation, Span | None]:
    start, end = sorted((location.start_line, location.end_line))
    source = sources.get(location.path)
    span = source.function_at(start, end) if source is not None else None
    placed = FindingLocation(
        path=location.path,
        start_line=start,
        end_line=end,
        function=span.name if span is not None else None,
    )
    return placed, span


def _candidates(
    results: Iterable[ToolObservations], sources: SourceReader, class_map: ClassMap
) -> list[_Candidate]:
    found: list[_Candidate] = []
    for result in results:
        for index, item in enumerate(result.observations):
            if not item.locations:
                continue
            placed = [_place(location, sources) for location in item.locations]
            first, span = placed[0]
            source = Source(
                tool=result.tool,
                tool_version=result.tool_version,
                rule_id=item.rule_id,
                severity_reported=item.severity_reported,
                message=item.message,
                locations=tuple(location for location, _ in placed),
                observation_index=index,
            )
            found.append(
                _Candidate(
                    vuln_class=class_map.vuln_class(result.tool, item.rule_id),
                    path=first.path,
                    start_line=first.start_line,
                    end_line=first.end_line,
                    function=span,
                    source=source,
                )
            )
    return found


def _groups(candidates: Sequence[_Candidate]) -> list[list[_Candidate]]:
    """Partition candidates: same class and file, and same function or overlapping lines."""
    in_function: dict[tuple[str, str, Span], list[_Candidate]] = defaultdict(list)
    outside: dict[tuple[str, str], list[_Candidate]] = defaultdict(list)
    for item in candidates:
        if item.function is not None:
            in_function[(item.vuln_class, item.path, item.function)].append(item)
        else:
            outside[(item.vuln_class, item.path)].append(item)
    groups = list(in_function.values())
    for members in outside.values():
        members = sorted(members, key=lambda item: (item.start_line, item.end_line))
        current = [members[0]]
        reach = members[0].end_line
        for item in members[1:]:
            if item.start_line <= reach:
                current.append(item)
                reach = max(reach, item.end_line)
            else:
                groups.append(current)
                current, reach = [item], item.end_line
        groups.append(current)
    return groups


def _source_key(source: Source) -> tuple[object, ...]:
    # Every reported field comes before the report position, so that the order of the sources
    # depends on the report order only between sources that are identical.
    return (
        TOOL_ORDER.index(source.tool),
        source.rule_id,
        tuple((item.path, item.start_line, item.end_line) for item in source.locations),
        source.severity_reported,
        source.message,
        source.observation_index,
    )


def _merge(group: Sequence[_Candidate], sources: SourceReader) -> Finding:
    head = group[0]
    start = min(item.start_line for item in group)
    end = max(item.end_line for item in group)
    file = sources.get(head.path)
    snippet = file.snippet(start, end) if file is not None else ""
    ordered = tuple(sorted((item.source for item in group), key=_source_key))
    return Finding(
        id=stable_id(head.vuln_class, head.path, start, end, snippet_sha256(snippet)),
        vuln_class=head.vuln_class,
        location=FindingLocation(
            path=head.path,
            start_line=start,
            end_line=end,
            function=head.function.name if head.function is not None else None,
        ),
        snippet_sha256=snippet_sha256(snippet),
        message=ordered[0].message,
        sources=ordered,
    )


def finding_sort_key(finding: Finding) -> tuple[str, int, int, str, str]:
    location = finding.location
    return (location.path, location.start_line, location.end_line, finding.vuln_class, finding.id)


def normalize(
    results: Iterable[ToolObservations],
    sources: SourceReader,
    class_map: ClassMap | None = None,
) -> tuple[Finding, ...]:
    """Map, place, deduplicate and order the observations of one scan.

    `sources` reads the scanned snapshot. The result is ordered by path, line range, class and
    id, and does not depend on the order of `results` or of the observations in them.
    """
    mapping = class_map if class_map is not None else default_class_map()
    candidates = _candidates(results, sources, mapping)
    findings = [_merge(group, sources) for group in _groups(candidates)]
    return tuple(sorted(findings, key=finding_sort_key))
