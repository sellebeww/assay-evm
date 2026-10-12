"""Ledger migration 3 (`model_run`) and the rule that a model call never raises a status."""

import ast
import inspect
import sqlite3
import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from ledger_scenario import Scenario, sha

import assay.cli.dev
import assay.llm
from assay.ledger import (
    CassetteMode,
    ClaimStatus,
    FindingState,
    IllegalTransition,
    InvalidInput,
    Ledger,
    LedgerIntegrityError,
    NotFound,
)

ROOT = Path(__file__).resolve().parents[2]
LLM_DIR = ROOT / "src" / "assay" / "llm"
# Ledger methods that create claims or change a status.
STATUS_METHODS = {"add_claim", "promote_claim", "record_oracle_run", "transition_finding"}
FORBIDDEN_IMPORTS = ("assay.oracles", "assay.orchestrator", "assay.sandbox", "assay.analyzers")
# Pure readers of Solidity source text and constants: they run nothing and decide nothing.
SOURCE_READERS = {
    "assay.oracles.integrity.solidity",
    "assay.oracles.integrity.checks",
}


def record(ledger: Ledger, **changes: object) -> int:
    values: dict[str, object] = {
        "finding_id": None,
        "endpoint_host": "llm.example.org",
        "model": "model-as-returned",
        "prompt_sha256": sha("prompt"),
        "response_sha256": sha("response"),
        "tokens_in": 12,
        "tokens_out": 7,
        "latency_ms": 250,
        "cassette_mode": CassetteMode.LIVE,
    }
    return int(ledger.record_model_run(**{**values, **changes}))  # type: ignore[arg-type]


@pytest.fixture
def scenario(tmp_path: Path) -> Iterator[Scenario]:
    with Scenario.create(tmp_path) as built:
        yield built


def test_a_model_run_is_stored_with_its_provenance(tmp_path: Path) -> None:
    with Scenario.create(tmp_path) as scenario:
        finding = scenario.finding()
        run_id = record(scenario.ledger, finding_id=finding)
        run = scenario.ledger.get_model_run(run_id)  # type: ignore[arg-type]
        assert run.finding_id == finding
        assert run.endpoint_host == "llm.example.org"
        assert run.model == "model-as-returned"
        assert (run.tokens_in, run.tokens_out, run.latency_ms) == (12, 7, 250)
        assert run.cassette_mode is CassetteMode.LIVE
        assert run.prompt_sha256 == sha("prompt")
        assert run.response_sha256 == sha("response")
        assert scenario.ledger.verify_chain().ok


def test_a_model_run_is_an_audit_event_without_prompt_text(tmp_path: Path) -> None:
    with Scenario.create(tmp_path) as scenario:
        record(scenario.ledger)
        with scenario.raw() as raw:
            event, payload = raw.execute(
                "SELECT event, payload_json FROM audit_log ORDER BY seq DESC LIMIT 1"
            ).fetchone()
    assert event == "model_run.recorded"
    assert '"cassette_mode":"live"' in payload
    assert '"endpoint_host":"llm.example.org"' in payload


@pytest.mark.parametrize(
    "changes",
    [
        {"endpoint_host": "user:pass@llm.example.org"},
        {"endpoint_host": "llm.example.org/v1"},
        {"endpoint_host": "llm.example.org?key=1"},
        {"endpoint_host": ""},
        {"model": " "},
        {"prompt_sha256": "abc"},
        {"response_sha256": "G" * 64},
        {"tokens_in": -1},
        {"tokens_out": -1},
        {"latency_ms": -1},
        {"cassette_mode": "offline"},
    ],
)
def test_invalid_model_runs_are_rejected(scenario: Scenario, changes: dict[str, object]) -> None:
    with pytest.raises(InvalidInput):
        record(scenario.ledger, **changes)


def test_an_unknown_finding_is_rejected(scenario: Scenario) -> None:
    with pytest.raises(NotFound):
        record(scenario.ledger, finding_id=999)


def test_the_database_itself_rejects_a_host_with_credentials(scenario: Scenario) -> None:
    record(scenario.ledger)
    with scenario.raw() as raw, pytest.raises(sqlite3.IntegrityError):
        raw.execute(
            "INSERT INTO model_run (endpoint_host, model, prompt_sha256, response_sha256, "
            "tokens_in, tokens_out, latency_ms, cassette_mode, created_seq) "
            "VALUES ('u:p@h', 'm', ?, ?, 0, 0, 0, 'live', 1)",
            (sha("a"), sha("b")),
        )


def test_model_runs_are_immutable(scenario: Scenario) -> None:
    run_id = record(scenario.ledger)
    with scenario.raw() as raw:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            raw.execute("UPDATE model_run SET model = 'x' WHERE id = ?", (run_id,))
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            raw.execute("DELETE FROM model_run WHERE id = ?", (run_id,))


# A model call never raises a status


def test_recording_model_runs_changes_no_claim_and_no_finding(scenario: Scenario) -> None:
    finding = scenario.finding()
    claim = scenario.claim(finding)
    for mode in CassetteMode:
        record(scenario.ledger, finding_id=finding, cassette_mode=mode)
    assert scenario.ledger.get_claim(claim).status is ClaimStatus.ASSERTED
    assert scenario.ledger.get_finding(finding).state is FindingState.CANDIDATE


def test_a_model_run_is_no_evidence_for_a_claim_or_a_transition(scenario: Scenario) -> None:
    finding = scenario.drive_to(FindingState.POC_DRAFTED)
    claim = scenario.claim(finding)
    record(scenario.ledger, finding_id=finding)
    with scenario.raw() as raw:
        with pytest.raises(sqlite3.IntegrityError, match="oracle_run"):
            raw.execute("UPDATE claim SET status = 'trusted' WHERE id = ?", (claim,))
        with pytest.raises(sqlite3.IntegrityError, match="oracle evidence"):
            raw.execute(
                "UPDATE finding SET state = 'REPRODUCED', evidence_level = 'E1' WHERE id = ?",
                (finding,),
            )
    with pytest.raises((IllegalTransition, LedgerIntegrityError)):
        scenario.ledger.transition_finding(finding, FindingState.REPRODUCED)
    assert scenario.ledger.get_finding(finding).state is FindingState.POC_DRAFTED


def _status_calls(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    return {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr in STATUS_METHODS
    }


def _imports(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
        elif isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
    return found


def test_no_llm_code_path_creates_a_claim_or_changes_a_status() -> None:
    """The LLM package and the `llm-ask` command call no ledger method that creates a claim or
    changes a status, and import nothing that runs an oracle."""
    paths = sorted(LLM_DIR.glob("*.py"))
    assert {p.name for p in paths} >= {"client.py", "recording.py", "output.py", "redact.py"}
    for path in paths:
        assert _status_calls(path) == set(), path.name
        for module in _imports(path):
            if module in SOURCE_READERS:
                assert path.name in {"context.py", "poc_checker.py"}, (path.name, module)
                continue
            assert not module.startswith(FORBIDDEN_IMPORTS), (path.name, module)
    for name in ("llm_ask", "_consent_message"):
        source = inspect.getsource(getattr(assay.cli.dev, name))
        assert not {m for m in STATUS_METHODS if f".{m}(" in source}, name
    function = ast.parse(textwrap.dedent(inspect.getsource(Ledger.record_model_run))).body[0]
    assert isinstance(function, ast.FunctionDef)
    sql = [
        node.value.lower()
        for statement in function.body[1:]  # the first statement is the docstring
        for node in ast.walk(statement)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]
    for text in sql:
        assert not any(word in text for word in ("update ", "claim", "oracle_run", "delete "))
    assert assay.llm.__all__


def test_the_schema_has_nothing_that_reads_model_run_to_decide_a_status(scenario: Scenario) -> None:
    with scenario.raw() as raw:
        sql = [
            text
            for (text,) in raw.execute(
                "SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT LIKE 'model_run%'"
            )
        ]
    assert not [text for text in sql if "model_run" in text]


_runs = st.lists(
    st.tuples(
        st.sampled_from(list(CassetteMode)),
        st.integers(0, 10_000),
        st.integers(0, 10_000),
        st.booleans(),
    ),
    min_size=1,
    max_size=10,
)


@settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(runs=_runs)
def test_no_sequence_of_model_runs_yields_a_trusted_claim(
    tmp_path_factory: pytest.TempPathFactory, runs: list[tuple[CassetteMode, int, int, bool]]
) -> None:
    with Scenario.create(tmp_path_factory.mktemp("runs")) as scenario:
        finding = scenario.finding()
        claim = scenario.claim(finding)
        for mode, tokens_in, tokens_out, linked in runs:
            record(
                scenario.ledger,
                finding_id=finding if linked else None,
                cassette_mode=mode,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
            )
        assert scenario.ledger.get_claim(claim).status is ClaimStatus.ASSERTED
        assert scenario.ledger.get_finding(finding).state is FindingState.CANDIDATE
        assert scenario.ledger.verify_chain().ok


def test_the_prove_orchestrator_changes_a_status_only_through_recorded_oracle_runs() -> None:
    """`prove.py` creates no claim and promotes none itself (`record_result` does, from an
    oracle verdict); its only transitions are the recorded steps, and the one that ends the loop,
    which names the oracle run that backs it."""
    path = ROOT / "src" / "assay" / "orchestrator" / "prove.py"
    tree = ast.parse(path.read_text())
    called = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    } & STATUS_METHODS
    assert called == {"transition_finding"}
    for function in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
        for node in ast.walk(function):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "transition_finding"
            ):
                names = {keyword.arg for keyword in node.keywords}
                if function.name == "_finish":
                    assert "oracle_run_ids" in names
                else:
                    assert function.name == "run_prove" or "oracle_run_ids" not in names
                    assert "oracle_run_ids" not in names
