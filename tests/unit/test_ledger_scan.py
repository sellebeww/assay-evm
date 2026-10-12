"""Scans and observations (ledger migration 2), and the rule that analyzer output never raises a
status: no code path turns it into a `trusted` claim.
"""

import ast
import inspect
import sqlite3
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from ledger_scenario import Scenario, sha

import assay.analysis
import assay.cli.dev
from assay.ledger import (
    ClaimStatus,
    FindingState,
    InvalidInput,
    Ledger,
    NotFound,
    ObservationInput,
    ScanLocation,
    ScanTool,
)

ROOT = Path(__file__).resolve().parents[2]
ANALYSIS_DIR = ROOT / "src" / "assay" / "analysis"
# Ledger methods that create claims or change a status.
STATUS_METHODS = {"add_claim", "promote_claim", "record_oracle_run", "transition_finding"}


def observation(rule: str = "reentrancy-eth", line: int = 30) -> ObservationInput:
    return ObservationInput(
        rule_id=rule,
        severity_reported="High (confidence Medium)",
        message="Reentrancy in Vault.withdraw(uint256)",
        locations=(ScanLocation(path="src/Vault.sol", start_line=line, end_line=line + 8),),
    )


@pytest.fixture
def scenario(tmp_path: Path) -> Iterator[Scenario]:
    with Scenario.create(tmp_path) as built:
        yield built


def record(scenario: Scenario, observations: list[ObservationInput]) -> int:
    blob = scenario.ledger.store_blob(
        b'{"success": true}', media_type="application/json", label="slither raw output"
    )
    return scenario.ledger.record_scan(
        scenario.project,
        tool=ScanTool.SLITHER,
        tool_version="0.11.6",
        raw_blob_sha256=blob,
        input_tree_sha256=sha("tree"),
        observations=observations,
    )


# -- recording -------------------------------------------------------------------------------


def test_a_scan_and_its_observations_round_trip(scenario: Scenario) -> None:
    scan_id = record(scenario, [observation(), observation("low-level-calls", 12)])
    ledger = scenario.ledger

    scan = ledger.get_scan(scan_id)
    assert (scan.tool, scan.tool_version, scan.result_count) == (ScanTool.SLITHER, "0.11.6", 2)
    assert ledger.read_blob(scan.raw_blob_sha256) == b'{"success": true}'
    stored = ledger.scan_observations(scan_id)
    assert [item.rule_id for item in stored] == ["reentrancy-eth", "low-level-calls"]
    assert stored[0].locations == (ScanLocation(path="src/Vault.sol", start_line=30, end_line=38),)
    assert all(item.finding_id is None for item in stored)
    assert ledger.verify_chain().ok
    with closing(scenario.raw()) as conn:
        events = [row[0] for row in conn.execute("SELECT event FROM audit_log ORDER BY seq")]
    assert events[-1] == "scan.recorded"


def test_a_scan_needs_its_raw_output_and_its_project(scenario: Scenario) -> None:
    with pytest.raises(NotFound, match="artifact"):
        scenario.ledger.record_scan(
            scenario.project,
            tool=ScanTool.ADERYN,
            tool_version="v0.6.8",
            raw_blob_sha256=sha("never stored"),
            input_tree_sha256=sha("tree"),
            observations=[],
        )
    blob = scenario.ledger.store_blob(b"{}", media_type="application/json", label="raw")
    with pytest.raises(NotFound, match="project"):
        scenario.ledger.record_scan(
            999,  # type: ignore[arg-type]
            tool=ScanTool.ADERYN,
            tool_version="v0.6.8",
            raw_blob_sha256=blob,
            input_tree_sha256=sha("tree"),
            observations=[],
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("rule_id", ""),
        ("rule_id", "../etc/passwd"),
        ("rule_id", "x" * 201),
        ("severity_reported", "High; DROP TABLE claim"),
        ("message", "   "),
        ("message", "nul\x00byte"),
        ("message", "m" * 4001),
    ],
)
def test_malformed_observations_are_refused(field: str, value: str) -> None:
    fields = observation().model_dump()
    fields[field] = value
    with pytest.raises(ValueError, match="validation error"):
        ObservationInput.model_validate(fields)


def test_a_scan_with_a_bad_version_or_too_many_locations_is_refused(scenario: Scenario) -> None:
    blob = scenario.ledger.store_blob(b"{}", media_type="application/json", label="raw")
    with pytest.raises(InvalidInput, match="tool_version"):
        scenario.ledger.record_scan(
            scenario.project,
            tool=ScanTool.SLITHER,
            tool_version="0.11.6 --latest",
            raw_blob_sha256=blob,
            input_tree_sha256=sha("tree"),
            observations=[],
        )
    location = ScanLocation(path="src/A.sol", start_line=1, end_line=1)
    with pytest.raises(ValueError, match="validation error"):
        ObservationInput(
            rule_id="r", severity_reported="Low", message="m", locations=(location,) * 65
        )


# -- triggers, with a plain sqlite3 connection ---------------------------------------------------


def rejected(conn: sqlite3.Connection, sql: str, *params: object) -> str:
    with pytest.raises(sqlite3.IntegrityError) as caught:
        conn.execute(sql, params)
    return str(caught.value)


def test_scans_are_immutable(scenario: Scenario) -> None:
    scan_id = record(scenario, [observation()])
    with closing(scenario.raw()) as conn:
        assert "immutable" in rejected(
            conn, "UPDATE scan SET result_count = 9 WHERE id = ?", scan_id
        )
        assert "immutable" in rejected(conn, "DELETE FROM scan WHERE id = ?", scan_id)


def test_observations_can_only_be_linked_to_a_finding_once(scenario: Scenario) -> None:
    scan_id = record(scenario, [observation()])
    first, second = scenario.finding(), scenario.finding()
    with closing(scenario.raw()) as conn:
        (obs_id,) = conn.execute(
            "SELECT id FROM observation WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        assert "linked" in rejected(
            conn, "UPDATE observation SET message = 'edited' WHERE id = ?", obs_id
        )
        assert "deleted" in rejected(conn, "DELETE FROM observation WHERE id = ?", obs_id)
        conn.execute("UPDATE observation SET finding_id = ? WHERE id = ?", (first, obs_id))
        assert "linked" in rejected(
            conn, "UPDATE observation SET finding_id = ? WHERE id = ?", second, obs_id
        )
        assert "linked" in rejected(
            conn, "UPDATE observation SET finding_id = NULL WHERE id = ?", obs_id
        )


def test_a_scan_holds_no_more_observations_than_it_reported(scenario: Scenario) -> None:
    scan_id = record(scenario, [observation()])
    with closing(scenario.raw()) as conn:
        message = rejected(
            conn,
            "INSERT INTO observation (scan_id, rule_id, severity_reported, location_json, "
            "message, created_seq) VALUES (?, 'extra', 'High', '[]', 'injected', 1)",
            scan_id,
        )
    assert "more observations than the scan reported" in message


# -- analyzer output never raises a status -------------------------------------------------------


def test_recording_a_scan_creates_no_finding_and_no_claim_and_changes_no_status(
    scenario: Scenario,
) -> None:
    finding = scenario.finding()
    claim = scenario.claim(finding, "the reentrancy reproduces")
    with closing(scenario.raw()) as conn:
        before = (
            conn.execute("SELECT count(*) FROM finding").fetchone(),
            conn.execute("SELECT count(*) FROM claim").fetchone(),
        )
    record(scenario, [observation() for _ in range(5)])

    with closing(scenario.raw()) as conn:
        after = (
            conn.execute("SELECT count(*) FROM finding").fetchone(),
            conn.execute("SELECT count(*) FROM claim").fetchone(),
        )
        (obs_id,) = conn.execute("SELECT min(id) FROM observation").fetchone()
        conn.execute("UPDATE observation SET finding_id = ? WHERE id = ?", (finding, obs_id))
        # Even with observations linked to its finding, a claim stays asserted, and the database
        # refuses to trust it without an oracle run.
        assert "oracle_run" in rejected(
            conn, "UPDATE claim SET status = 'trusted' WHERE id = ?", claim
        )
    assert before == after
    assert scenario.ledger.get_claim(claim).status is ClaimStatus.ASSERTED
    assert scenario.ledger.get_finding(finding).state is FindingState.CANDIDATE


def _calls(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    return {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr in STATUS_METHODS
    }


def test_no_analysis_code_path_creates_a_claim_or_changes_a_status() -> None:
    """The analyzer adapters, the scan recording and the `dev analyze` command never call a
    ledger method that creates a claim or changes a status."""
    for path in sorted(ANALYSIS_DIR.glob("*.py")):
        assert _calls(path) == set(), path.name
    record_scan = inspect.getsource(Ledger.record_scan)
    assert "claim" not in record_scan.replace("no claim", "")
    assert "finding" not in record_scan.replace("no finding", "")
    for name in ("analyze", "_analyze", "_store_raw"):
        source = inspect.getsource(getattr(assay.cli.dev, name))
        assert not {method for method in STATUS_METHODS if f".{method}(" in source}, name
    assert assay.analysis.__all__  # the package imports cleanly


_rule = st.from_regex(r"[a-z][a-z0-9-]{0,30}", fullmatch=True)
_text = st.text(min_size=1, max_size=200).filter(lambda text: "\x00" not in text and text.strip())
_observation = st.builds(
    ObservationInput,
    rule_id=_rule,
    severity_reported=st.sampled_from(["High", "Medium", "Low", "Informational"]),
    message=_text,
    locations=st.lists(
        st.builds(
            ScanLocation,
            path=st.sampled_from(["src/A.sol", "src/lib/B.sol"]),
            start_line=st.integers(1, 1000),
            end_line=st.integers(1, 1000),
        ),
        max_size=3,
    ).map(tuple),
)


@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(scans=st.lists(st.lists(_observation, max_size=8), min_size=1, max_size=4))
def test_no_sequence_of_scans_yields_a_trusted_claim(
    tmp_path_factory: pytest.TempPathFactory, scans: list[list[ObservationInput]]
) -> None:
    with Scenario.create(tmp_path_factory.mktemp("scans")) as scenario:
        claim = scenario.claim(scenario.finding())
        for observations in scans:
            scan_id = record(scenario, observations)
            assert scenario.ledger.get_scan(scan_id).result_count == len(observations)
        with closing(scenario.raw()) as conn:
            trusted = conn.execute("SELECT count(*) FROM claim WHERE status = 'trusted'").fetchone()
            linked = conn.execute(
                "SELECT count(*) FROM observation WHERE finding_id IS NOT NULL"
            ).fetchone()
        assert trusted == (0,)
        assert linked == (0,)
        assert scenario.ledger.get_claim(claim).status is ClaimStatus.ASSERTED
        assert scenario.ledger.verify_chain().ok


def test_an_unknown_scan_is_not_found(scenario: Scenario) -> None:
    scan_id = record(scenario, [])
    with pytest.raises(NotFound, match="scan"):
        scenario.ledger.scan_observations(scan_id + 100)  # type: ignore[arg-type]
    with pytest.raises(NotFound, match="scan"):
        scenario.ledger.get_scan(scan_id + 100)  # type: ignore[arg-type]
