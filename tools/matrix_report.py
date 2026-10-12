"""Classification matrix of the development fixtures (`make matrix`).

`tests/integration/test_matrix.py` runs `assay verify` on every patch of every fixture under
`fixtures/<class>/<name>/` and writes the results as JSON. This tool compares each result with
the fixture's `expected.json`, prints the matrix and the closing line
`MATRIX RESULT: <matching>/<total> match`, and renders `docs/classification-matrix.md` from the
same results, so that the page is never written by hand.

A patch matches when its final verdict equals the expected verdict and the expected reason, if
there is one, is among the reported reasons (docs/fixture-spec.md, section 4). An expected patch
without a result, and a result without an expected patch, count as mismatches.

The rendered page holds no timestamps, host paths or user names; it states the running time of
the run it was rendered from.

Exit status: 0 when every patch matches, 1 when one does not, 2 when the results or the fixtures
cannot be read or the arguments are invalid.
"""

import argparse
import sys
import textwrap
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

import fixture_check

REPO_ROOT: Final = Path(__file__).resolve().parent.parent
FIXTURES_DIR: Final = REPO_ROOT / "fixtures"
PATCH_LABELS: Final = fixture_check.PATCH_LABELS
CLASS_IDS: Final = fixture_check.CLASS_IDS
NOT_RUN: Final = "-"
RESULT_PREFIX: Final = "MATRIX RESULT:"

Label = Literal["good", "overfit", "destructive", "regressing"]
_Code = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]*$")]
_FixtureId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]*/[a-z0-9][a-z0-9_]*$")]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class CaseResult(_Strict):
    """The outcome of `assay verify` for one patch of one fixture."""

    fixture: _FixtureId
    label: Label
    exit_code: int
    final_verdict: Literal["VERIFIED_WITHIN_BOUNDS", "REJECTED", "INCONCLUSIVE"] | None
    reasons: tuple[_Code, ...]
    seconds: float = Field(ge=0)
    error: str | None = None


class MatrixResults(_Strict):
    """One run of the matrix: the environment, the bounds and every case."""

    schema_version: Literal[2] = 2
    assay_version: str
    image_digest: Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
    tool_versions: dict[str, str]
    versions_lock_sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    profile: Literal["quick", "standard", "thorough"]
    fuzz_seed: str
    fuzz_runs: int = Field(ge=1)
    variant_seeds: int = Field(ge=1)
    invariant_runs: int = Field(ge=1)
    invariant_depth: int = Field(ge=1)
    exploit_replays: int = Field(ge=1)
    total_seconds: float = Field(ge=0)
    cases: tuple[CaseResult, ...]


@dataclass(frozen=True)
class Expectation:
    fixture: str
    label: str
    verdict: str
    reason: str | None


@dataclass(frozen=True)
class Row:
    fixture: str
    label: str
    expected: str
    actual: str
    seconds: float | None
    matches: bool

    @property
    def class_id(self) -> str:
        return self.fixture.split("/", 1)[0]

    @property
    def name(self) -> str:
        return self.fixture.split("/", 1)[1]


def matches(
    verdict: str | None, reasons: Sequence[str], expected_verdict: str, expected_reason: str | None
) -> bool:
    """The matching rule of the classification matrix (docs/fixture-spec.md, section 4)."""
    if verdict != expected_verdict:
        return False
    return expected_reason is None or expected_reason in reasons


def _class_order(fixture: str) -> tuple[int, str]:
    class_id = fixture.split("/", 1)[0]
    index = CLASS_IDS.index(class_id) if class_id in CLASS_IDS else len(CLASS_IDS)
    return index, fixture


def load_expectations(root: Path = FIXTURES_DIR) -> list[Expectation]:
    """The expected verdict and reason of every patch, in class order (raises CheckError)."""
    found: list[Expectation] = []
    for fixture in sorted(fixture_check.discover_fixtures(root), key=_class_order):
        expected = fixture_check.load_expected(root / fixture / "expected.json")
        for label in PATCH_LABELS:
            spec = expected.variants.get(label)
            assert isinstance(spec, fixture_check.PatchSpec)
            found.append(Expectation(fixture, label, spec.verdict, spec.reason))
    return found


def _verdict_text(verdict: str | None, reasons: Sequence[str]) -> str:
    if verdict is None:
        return NOT_RUN
    return f"{verdict} ({', '.join(reasons)})" if reasons else verdict


def compare(expectations: Sequence[Expectation], results: MatrixResults) -> list[Row]:
    """One row per expected patch, then one per result that no expectation asked for."""
    by_case: dict[tuple[str, str], CaseResult] = {
        (case.fixture, case.label): case for case in results.cases
    }
    rows: list[Row] = []
    for item in expectations:
        expected = _verdict_text(item.verdict, [item.reason] if item.reason else [])
        case = by_case.pop((item.fixture, item.label), None)
        if case is None:
            rows.append(Row(item.fixture, item.label, expected, NOT_RUN, None, False))
            continue
        ok = matches(case.final_verdict, case.reasons, item.verdict, item.reason)
        actual = _verdict_text(case.final_verdict, case.reasons)
        rows.append(Row(item.fixture, item.label, expected, actual, case.seconds, ok))
    for case in by_case.values():
        actual = _verdict_text(case.final_verdict, case.reasons)
        rows.append(Row(case.fixture, case.label, NOT_RUN, actual, case.seconds, False))
    return rows


def result_line(rows: Sequence[Row]) -> str:
    return f"{RESULT_PREFIX} {sum(row.matches for row in rows)}/{len(rows)} match"


def label_counts(rows: Sequence[Row]) -> dict[str, tuple[int, int]]:
    """Matching and total rows per patch label, in label order."""
    counts: dict[str, tuple[int, int]] = {}
    for label in PATCH_LABELS:
        selected = [row for row in rows if row.label == label]
        counts[label] = (sum(row.matches for row in selected), len(selected))
    return counts


TABLE_COLUMNS: Final = ("class", "fixture", "patch", "expected", "actual", "result")


def table_lines(rows: Sequence[Row]) -> list[str]:
    """The matrix as a plain-text table."""
    table = [list(TABLE_COLUMNS)] + [
        [
            row.class_id,
            row.name,
            row.label,
            row.expected,
            row.actual,
            "match" if row.matches else "MISMATCH",
        ]
        for row in rows
    ]
    widths = [max(len(line[index]) for line in table) for index in range(len(TABLE_COLUMNS))]
    return [
        "  ".join(cell.ljust(width) for cell, width in zip(line, widths, strict=True)).rstrip()
        for line in table
    ]


def summary_lines(rows: Sequence[Row]) -> list[str]:
    return [
        f"  {label.ljust(11)}  {matched}/{total} match"
        for label, (matched, total) in label_counts(rows).items()
    ]


def duration(seconds: float) -> str:
    total = round(seconds)
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours} h {minutes:02d} min"
    return f"{minutes} min {secs:02d} s"


def _paragraph(text: str) -> str:
    return textwrap.fill(text, width=100, break_long_words=False, break_on_hyphens=False)


def _cell(text: str) -> str:
    return text.replace("\\", "\\\\").replace("|", "\\|")


def _code(text: str) -> str:
    return f"`{text}`" if text != NOT_RUN else NOT_RUN


EXPECTED_BY_LABEL: Final = {
    "good": ("VERIFIED_WITHIN_BOUNDS", "none"),
    "overfit": ("REJECTED", "`variant_found`"),
    "destructive": ("REJECTED", "`benign_test_failed` or an integrity reason"),
    "regressing": ("REJECTED", "`layout_changed`, `abi_changed` or `event_changed`"),
}
INTRODUCTION: Final = (
    "The matrix runs `assay verify` on each of the four labelled patches of the {fixtures} "
    "development fixtures under `fixtures/`, and compares the final verdict and its reasons with "
    "the verdict and reason that the fixture's `expected.json` gives for the patch label. A patch "
    "matches when the final verdict is the expected one and the expected reason, if there is "
    "one, is among the reported reasons. The labels themselves are established with plain "
    "Foundry by `make fixtures-check`, which uses no oracle code "
    "([fixture specification](fixture-spec.md), section 8)."
)
LIMITS: Final = (
    "This is a self-validation on synthetic fixtures, not an independent benchmark. The "
    "fixtures, their patches and their labels were written by the same author as the oracles, "
    "and they were designed so that the overfit and regressing patches pass the existing tests "
    "while the oracles have something to find. A full match shows that the oracles reproduce "
    "these labels within the bounds below. The numbers must not be read as a detection rate on "
    "real code, or as a statement about patches, contracts or vulnerability shapes outside these "
    "fixtures. Each verdict covers only the checks and bounds that ran; "
    "`VERIFIED_WITHIN_BOUNDS` means that nothing was found within them and is not a proof of "
    "absence ([Oracles and `assay verify`](oracles.md))."
)
IMAGE_NOTE: Final = (
    "The image id identifies a local build of the runner image; images built on another machine "
    "or platform have other ids ([ADR 0008](adr/0008-runner-platform.md)). Times depend on the "
    "machine and are given for orientation only."
)
REPRODUCE_NOTE: Final = (
    "`make matrix` needs Docker and runs the verifications one after the other, which takes from "
    "about half an hour to two hours depending on the machine. It can also be started by hand in "
    "the GitHub workflow `matrix.yml`, which uploads this page as a workflow artifact."
)


def render_markdown(results: MatrixResults, rows: Sequence[Row]) -> str:
    """The page `docs/classification-matrix.md`, from the results of one run."""
    fixtures = len({row.fixture for row in rows})
    versions = sorted(results.tool_versions.items())
    tools = ", ".join(f"{name} {version}" for name, version in versions)
    lines = [
        "# Classification matrix",
        "",
        _paragraph(
            "`make matrix` writes this page from the results of one run, with "
            "`tools/matrix_report.py`. It is not edited by hand."
        ),
        "",
        _paragraph(INTRODUCTION.format(fixtures=fixtures)),
        "",
        "## What this result means",
        "",
        _paragraph(LIMITS),
        "",
        "## Result",
        "",
        f"`{result_line(rows)}`",
        "",
        f"Campaign profile of the variant search: `{results.profile}`.",
        "",
        "| Patch label | Expected verdict | Expected reason | Matching |",
        "|---|---|---|---|",
    ]
    for label, (matched, total) in label_counts(rows).items():
        verdict, reason = EXPECTED_BY_LABEL[label]
        lines.append(f"| `{label}` | `{verdict}` | {reason} | {matched}/{total} |")
    lines += [
        "",
        "## Patches",
        "",
        "| Class | Fixture | Patch | Expected | Actual | Time | Result |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        time = NOT_RUN if row.seconds is None else f"{round(row.seconds)} s"
        lines.append(
            f"| `{row.class_id}` | `{row.name}` | `{row.label}` | {_code(_cell(row.expected))} "
            f"| {_code(_cell(row.actual))} | {time} | {'match' if row.matches else 'MISMATCH'} |"
        )
    lines += [
        "",
        "## Run",
        "",
        "| Item | Value |",
        "|---|---|",
        f"| Assay version | `{_cell(results.assay_version)}` |",
        f"| Runner image (local image id) | `{results.image_digest}` |",
        f"| Tools in the image | {_cell(tools) or NOT_RUN} |",
        f"| `versions.lock` sha256 | `{results.versions_lock_sha256}` |",
        f"| Campaign profile of the variant search | `{results.profile}` |",
        f"| Base seed | `{_cell(results.fuzz_seed)}` |",
        f"| Seeds per search mode | {results.variant_seeds} |",
        f"| Fuzz runs per campaign | {results.fuzz_runs} |",
        f"| Invariant runs and depth per campaign | {results.invariant_runs} sequences of up to "
        f"{results.invariant_depth} calls |",
        f"| Replays of the PoC per revision | {results.exploit_replays} |",
        f"| Total time | {duration(results.total_seconds)} for {len(results.cases)} "
        "verifications, one after the other |",
        "",
        _paragraph(IMAGE_NOTE),
        "",
        "## Reproduce",
        "",
        "```sh",
        "make image",
        f"make matrix PROFILE={results.profile}",
        "```",
        "",
        _paragraph(REPRODUCE_NOTE),
        "",
    ]
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="matrix_report.py",
        description="Compare matrix results with expected.json and render the matrix page.",
    )
    parser.add_argument("--results", type=Path, required=True, help="results JSON of a run")
    parser.add_argument("--out", type=Path, default=None, help="write the Markdown page here")
    parser.add_argument("--fixtures", type=Path, default=FIXTURES_DIR, help="fixtures root")
    args = parser.parse_args(argv)

    try:
        results = MatrixResults.model_validate_json(args.results.read_bytes())
    except (OSError, ValueError, ValidationError) as exc:
        print(f"error: the matrix results cannot be read: {exc}", file=sys.stderr)
        return 2
    try:
        expectations = load_expectations(args.fixtures)
    except (OSError, fixture_check.CheckError) as exc:
        print(f"error: the fixtures cannot be read: {exc}", file=sys.stderr)
        return 2

    rows = compare(expectations, results)
    print("\n".join(table_lines(rows)))
    print()
    print("per patch label")
    print("\n".join(summary_lines(rows)))
    print(f"total time: {duration(results.total_seconds)}")
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(render_markdown(results, rows), encoding="utf-8")
        print(f"wrote {args.out}")
    print(result_line(rows))
    return 0 if rows and all(row.matches for row in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
