"""Ledger lookups and links used by `assay scan`: find_project, find_scan, link_observation."""

import sqlite3
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest
from ledger_scenario import Scenario, sha

from assay.ledger import (
    ClaimStatus,
    FindingState,
    InvalidInput,
    NotFound,
    ObservationId,
    ObservationInput,
    ScanLocation,
    ScanTool,
)


@pytest.fixture
def scenario(tmp_path: Path) -> Iterator[Scenario]:
    with Scenario.create(tmp_path) as built:
        yield built


def record(scenario: Scenario, count: int = 2, *, raw: bytes = b"{}", project: int = 0) -> int:
    blob = scenario.ledger.store_blob(raw, media_type="application/json", label="raw")
    return scenario.ledger.record_scan(
        project or scenario.project,  # type: ignore[arg-type]
        tool=ScanTool.ADERYN,
        tool_version="v0.6.8",
        raw_blob_sha256=blob,
        input_tree_sha256=sha("tree"),
        observations=[
            ObservationInput(
                rule_id="reentrancy-state-change",
                severity_reported="High",
                message=f"result {index}",
                locations=(
                    ScanLocation(path="src/A.sol", start_line=index + 1, end_line=index + 1),
                ),
            )
            for index in range(count)
        ],
    )


def observation_ids(scenario: Scenario, scan_id: int) -> list[ObservationId]:
    return [item.id for item in scenario.ledger.scan_observations(scan_id)]  # type: ignore[arg-type]


def test_find_project_returns_the_first_match_or_none(scenario: Scenario) -> None:
    ledger = scenario.ledger
    assert ledger.find_project("project", "project") == scenario.project
    assert ledger.find_project("scan", "tree:0123") is None
    added = ledger.add_project("scan", "tree:0123")
    ledger.add_project("scan", "tree:0123")
    assert ledger.find_project("scan", "tree:0123") == added
    with pytest.raises(InvalidInput):
        ledger.find_project("", "tree:0123")


def test_find_scans_matches_tool_version_input_and_raw_output(scenario: Scenario) -> None:
    ledger = scenario.ledger
    first = record(scenario, raw=b'{"a": 1}')
    second = record(scenario, raw=b'{"a": 1}')
    record(scenario, raw=b'{"a": 2}')
    blob = ledger.get_scan(first).raw_blob_sha256  # type: ignore[arg-type]
    key = {
        "tool": ScanTool.ADERYN,
        "tool_version": "v0.6.8",
        "raw_blob_sha256": blob,
        "input_tree_sha256": sha("tree"),
    }
    found = ledger.find_scans(scenario.project, **key)  # type: ignore[arg-type]
    assert [scan.id for scan in found] == [first, second]
    for changed in (
        {"tool": ScanTool.SLITHER},
        {"tool_version": "v0.6.9"},
        {"raw_blob_sha256": sha("other output")},
        {"input_tree_sha256": sha("other tree")},
    ):
        assert ledger.find_scans(scenario.project, **{**key, **changed}) == ()  # type: ignore[arg-type]
    elsewhere = ledger.add_project("other", "other")
    assert ledger.find_scans(elsewhere, **key) == ()  # type: ignore[arg-type]


def test_an_observation_is_linked_once_and_relinking_is_a_no_op(scenario: Scenario) -> None:
    ledger = scenario.ledger
    first, second = observation_ids(scenario, record(scenario))
    finding, other = scenario.finding(), scenario.finding()
    with closing(scenario.raw()) as conn:
        rows_before = conn.execute("SELECT count(*) FROM audit_log").fetchone()[0]

    assert ledger.link_observation(first, finding) is True
    assert ledger.link_observation(first, finding) is False
    with pytest.raises(InvalidInput, match="already linked"):
        ledger.link_observation(first, other)
    assert ledger.link_observation(second, other) is True

    stored = ledger.scan_observations(ledger.get_scan(1).id)  # type: ignore[arg-type]
    assert [item.finding_id for item in stored] == [finding, other]
    with closing(scenario.raw()) as conn:
        events = [
            row[0]
            for row in conn.execute("SELECT event FROM audit_log WHERE seq > ?", (rows_before,))
        ]
    assert events == ["observation.linked", "observation.linked"]
    assert ledger.verify_chain().ok


def test_links_stay_within_one_project_and_refer_to_existing_rows(scenario: Scenario) -> None:
    ledger = scenario.ledger
    (obs,) = observation_ids(scenario, record(scenario, 1))
    elsewhere = ledger.add_project("other", "other")
    foreign = ledger.add_finding(elsewhere, "foreign-finding", "dos")
    with pytest.raises(InvalidInput, match="different projects"):
        ledger.link_observation(obs, foreign)
    with pytest.raises(NotFound, match="observation"):
        ledger.link_observation(ObservationId(obs + 100), scenario.finding())
    with pytest.raises(NotFound, match="finding"):
        ledger.link_observation(obs, 999)  # type: ignore[arg-type]
    with pytest.raises(InvalidInput):
        ledger.link_observation(0, scenario.finding())  # type: ignore[arg-type]


def test_a_link_changes_no_status_and_creates_no_claim(scenario: Scenario) -> None:
    ledger = scenario.ledger
    finding = scenario.finding()
    claim = scenario.claim(finding)
    for obs in observation_ids(scenario, record(scenario, 3)):
        ledger.link_observation(obs, finding)
    assert ledger.get_finding(finding).state is FindingState.CANDIDATE
    assert ledger.get_claim(claim).status is ClaimStatus.ASSERTED
    with closing(scenario.raw()) as conn:
        assert conn.execute("SELECT count(*) FROM claim").fetchone() == (1,)
        with pytest.raises(sqlite3.IntegrityError, match="oracle_run"):
            conn.execute("UPDATE claim SET status = 'trusted' WHERE id = ?", (claim,))


def test_the_database_still_refuses_a_second_link_written_directly(scenario: Scenario) -> None:
    ledger = scenario.ledger
    (obs,) = observation_ids(scenario, record(scenario, 1))
    first, second = scenario.finding(), scenario.finding()
    ledger.link_observation(obs, first)
    with closing(scenario.raw()) as conn, pytest.raises(sqlite3.IntegrityError, match="linked"):
        conn.execute("UPDATE observation SET finding_id = ? WHERE id = ?", (second, obs))
