"""The static coverage page (`tools/static_coverage.py`), rendered from results without Docker."""

import re
from pathlib import Path

import pytest

import fixture_check
import static_coverage
from assay.analysis import Aderyn, AnalyzerName, Slither
from assay.analysis.normalize import Finding, ToolObservations, normalize
from assay.analysis.source_map import SourceReader
from assay.orchestrator.scan import ScanReport, ToolRun
from static_coverage import CoverageResults, coverage_of, render_markdown, result_line

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "tests" / "data" / "analyzers"
FORBIDDEN = re.compile(r"\b(confirmed|vulnerable|secure|safe|proven|guaranteed|unhackable)\b", re.I)
FIXTURES = sorted(
    fixture_check.discover_fixtures(fixture_check.FIXTURES_DIR),
    key=lambda item: fixture_check.CLASS_IDS.index(item.split("/")[0]),
)
GOLDEN_FIXTURES = {
    "reentrancy/single_function": "reentrancy-single_function",
    "oracle_manipulation/spot_price": "oracle_manipulation-spot_price",
}


def tools(aderyn_status: str = "ok") -> tuple[ToolRun, ...]:
    return (
        ToolRun(tool=AnalyzerName.SLITHER, version="0.11.6", status="ok", results=1),
        ToolRun(tool=AnalyzerName.ADERYN, version="v0.6.8", status=aderyn_status),  # type: ignore[arg-type]
    )


def findings_of(fixture: str) -> tuple[Finding, ...]:
    name = GOLDEN_FIXTURES.get(fixture)
    if name is None:
        return ()
    return normalize(
        [
            ToolObservations(
                AnalyzerName.SLITHER,
                "0.11.6",
                Slither().parse((GOLDEN / "slither" / f"{name}.json").read_bytes()),
            ),
            ToolObservations(
                AnalyzerName.ADERYN,
                "v0.6.8",
                Aderyn().parse((GOLDEN / "aderyn" / f"{name}.json").read_bytes()),
            ),
        ],
        SourceReader(fixture_check.FIXTURES_DIR / fixture),
    )


def results(aderyn_status: str = "ok") -> CoverageResults:
    covered = tuple(
        coverage_of(
            fixture,
            ScanReport(
                assay_version="0.1.0",
                tree_sha256=f"{index:064x}",
                tools=tools(aderyn_status),
                findings=findings_of(fixture),
            ),
        )
        for index, fixture in enumerate(FIXTURES)
    )
    return CoverageResults(
        assay_version="0.1.0",
        tool_versions={"aderyn": "v0.6.8", "slither": "0.11.6"},
        versions_lock_sha256="c" * 64,
        fixtures=covered,
    )


def table_rows(page: str) -> list[list[str]]:
    """The cells of the result table (between `## Result` and the next section)."""
    section = page.split("## Result\n", 1)[1].split("\n## ", 1)[0]
    return [
        [cell.strip() for cell in line.strip("|").split("|")]
        for line in section.splitlines()
        if line.startswith("| `")
    ]


def test_the_development_split_has_one_fixture_per_class() -> None:
    assert [item.split("/")[0] for item in FIXTURES] == list(fixture_check.CLASS_IDS)


def test_the_page_has_one_row_per_fixture_with_findings_per_analyzer() -> None:
    page = render_markdown(results())
    rows = table_rows(page)
    assert len(rows) == 8
    by_class = {row[0].strip("`"): row for row in rows}
    assert set(by_class) == set(fixture_check.CLASS_IDS)
    reentrancy = by_class["reentrancy"]
    assert reentrancy[2:6] == ["2", "yes", "2", "yes"]  # Slither, Aderyn: findings, class hit
    assert reentrancy[7] == "yes"
    oracle = by_class["oracle_manipulation"]
    assert oracle[3] == oracle[5] == oracle[7] == "no"
    assert int(oracle[6]) == len(findings_of("oracle_manipulation/spot_price"))


def test_the_page_names_every_class_that_no_analyzer_detected() -> None:
    page = render_markdown(results())
    section = page.split("## Classes the analyzers did not detect", 1)[1].split("##", 1)[0]
    missed = [item for item in FIXTURES if not item.startswith("reentrancy/")]
    for fixture in missed:
        assert f"`{fixture.split('/')[0]}` (`{fixture}`)" in section
    assert "`reentrancy`" not in section
    assert "7 of the 8 fixtures" in section
    assert "`slither/unchecked-transfer`" in section  # what was reported instead
    assert result_line(results()) in page
    assert "STATIC COVERAGE: 1/8" in result_line(results())


def test_the_page_is_deterministic_and_states_its_limits() -> None:
    page = render_markdown(results())
    assert page == render_markdown(results())
    assert "It is not edited by hand." in page
    assert "candidate (unverified)" in page
    assert "Neither the mapping nor the fixtures are changed" in page
    assert FORBIDDEN.search(page) is None
    assert str(ROOT) not in page
    assert re.search(r"\b20\d\d-\d\d-\d\d\b", page) is None


def test_an_incomplete_run_is_marked_and_fails(tmp_path: Path) -> None:
    incomplete = results(aderyn_status="timeout")
    assert not incomplete.complete
    page = render_markdown(incomplete)
    assert "Incomplete run" in page
    assert "no result (timeout)" in page
    saved = tmp_path / "results.json"
    saved.write_text(incomplete.model_dump_json())
    out = tmp_path / "page.md"
    assert static_coverage.main(["--from-results", str(saved), "--out", str(out)]) == 1
    assert out.read_text() == page


def test_rendering_from_saved_results_reproduces_the_page(tmp_path: Path) -> None:
    complete = results()
    saved = tmp_path / "results.json"
    saved.write_text(complete.model_dump_json())
    out = tmp_path / "docs" / "page.md"
    assert static_coverage.main(["--from-results", str(saved), "--out", str(out)]) == 0
    assert out.read_text() == render_markdown(complete)


def test_unreadable_results_exit_with_2(tmp_path: Path) -> None:
    bad = tmp_path / "results.json"
    bad.write_text('{"schema_version": 2}')
    assert static_coverage.main(["--from-results", str(bad), "--out", str(tmp_path / "x")]) == 2


@pytest.mark.parametrize("name", ["slither", "aderyn"])
def test_the_page_uses_the_analyzer_names(name: str) -> None:
    assert static_coverage.TOOL_TITLES[name] in render_markdown(results())
