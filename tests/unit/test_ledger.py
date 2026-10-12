"""Ledger API: records, claim promotion, finding transitions and their audit events."""

import ast
import json
import re
import sqlite3
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

import pytest
from ledger_scenario import IMAGE_DIGEST, Scenario, sha

from assay.ledger import (
    REQUIRED_ORACLES,
    ClaimId,
    ClaimPromotionError,
    ClaimStatus,
    EvidenceLevel,
    FinalVerdict,
    FindingId,
    FindingState,
    IllegalTransition,
    InvalidInput,
    Ledger,
    LedgerError,
    NotFound,
    OracleName,
    OracleRunId,
    OracleRunInput,
    PatchId,
    PatchSource,
    ProjectId,
    RevisionId,
    RevisionKind,
    Verdict,
)

SRC = Path(__file__).resolve().parents[2] / "src" / "assay"


@pytest.fixture
def scenario(tmp_path: Path) -> Iterator[Scenario]:
    with Scenario.create(tmp_path) as built:
        yield built


def audit_rows(scenario: Scenario) -> list[tuple[int, str, dict[str, object]]]:
    with closing(scenario.raw()) as conn:
        rows = conn.execute("SELECT seq, event, payload_json FROM audit_log ORDER BY seq")
        return [(seq, event, json.loads(payload)) for seq, event, payload in rows]


def test_records_round_trip(scenario: Scenario) -> None:
    finding = scenario.finding()
    claim = scenario.claim(finding, "text with ünïcode")
    run = scenario.run(claim, Verdict.PASS)

    loaded = scenario.ledger.get_finding(finding)
    assert loaded.state is FindingState.CANDIDATE
    assert loaded.evidence_level is EvidenceLevel.E0
    assert loaded.reason is None
    assert loaded.vuln_class == "reentrancy"
    assert scenario.ledger.get_claim(claim).text == "text with ünïcode"
    assert scenario.ledger.get_claim(claim).status is ClaimStatus.ASSERTED
    stored = scenario.ledger.get_oracle_run(run)
    assert stored.argv == ("forge", "test")
    assert stored.image_digest == IMAGE_DIGEST
    assert stored.claim_id == claim


def test_every_row_points_at_the_audit_event_that_created_it(scenario: Scenario) -> None:
    finding = scenario.finding()
    claim = scenario.claim(finding)
    events = {event: seq for seq, event, _ in audit_rows(scenario)}
    with closing(scenario.raw()) as conn:
        finding_seq = conn.execute(
            "SELECT created_seq FROM finding WHERE id = ?", (finding,)
        ).fetchone()[0]
        claim_seq = conn.execute("SELECT created_seq FROM claim WHERE id = ?", (claim,)).fetchone()[
            0
        ]
    assert finding_seq == events["finding.added"]
    assert claim_seq == events["claim.added"]


def test_a_huge_seed_is_kept_exactly(scenario: Scenario) -> None:
    seed = 2**256 - 1
    run = scenario.ledger.record_oracle_run(
        OracleRunInput(
            claim_id=None,
            revision_id=scenario.vulnerable,
            oracle=OracleName.VARIANT,
            argv=(),
            image_digest=IMAGE_DIGEST,
            seed=seed,
            exit_code=None,
            verdict=Verdict.INCONCLUSIVE,
            reason="timeout",
            trace_blob_sha256=scenario.trace,
        )
    )
    assert scenario.ledger.get_oracle_run(run).seed == seed


# Claims


@pytest.mark.parametrize(
    ("verdict", "status"),
    [
        (Verdict.PASS, ClaimStatus.TRUSTED),
        (Verdict.FAIL, ClaimStatus.REFUTED),
        (Verdict.INCONCLUSIVE, ClaimStatus.INCONCLUSIVE),
    ],
)
def test_promote_claim_takes_the_status_of_the_run(
    scenario: Scenario, verdict: Verdict, status: ClaimStatus
) -> None:
    claim = scenario.claim(scenario.finding())
    run = scenario.run(claim, verdict)
    assert scenario.ledger.promote_claim(claim, run) is status
    assert scenario.ledger.get_claim(claim).status is status
    seq, event, payload = audit_rows(scenario)[-1]
    assert event == "claim.promoted"
    assert payload == {
        "claim_id": claim,
        "oracle_run_id": run,
        "verdict": verdict.value,
        "from": "asserted",
        "to": status.value,
    }
    assert scenario.ledger.verify_chain().rows == seq


def test_promote_claim_refuses_a_run_for_another_claim(scenario: Scenario) -> None:
    finding = scenario.finding()
    claim, other = scenario.claim(finding), scenario.claim(finding, "another claim")
    run = scenario.run(other, Verdict.PASS)
    with pytest.raises(ClaimPromotionError, match="not a run for claim"):
        scenario.ledger.promote_claim(claim, run)
    assert scenario.ledger.get_claim(claim).status is ClaimStatus.ASSERTED


def test_promote_claim_refuses_a_run_without_a_claim(scenario: Scenario) -> None:
    claim = scenario.claim(scenario.finding())
    run = scenario.run(None, Verdict.PASS)
    with pytest.raises(ClaimPromotionError):
        scenario.ledger.promote_claim(claim, run)


def test_promote_claim_refuses_unknown_ids(scenario: Scenario) -> None:
    claim = scenario.claim(scenario.finding())
    run = scenario.run(claim, Verdict.PASS)
    with pytest.raises(NotFound):
        scenario.ledger.promote_claim(ClaimId(999), run)
    with pytest.raises(NotFound):
        scenario.ledger.promote_claim(claim, OracleRunId(999))
    with pytest.raises(InvalidInput):
        scenario.ledger.promote_claim(claim, True)  # type: ignore[arg-type]


def test_trusted_claims_are_final(scenario: Scenario) -> None:
    claim = scenario.claim(scenario.finding())
    scenario.ledger.promote_claim(claim, scenario.run(claim, Verdict.PASS))
    rows_before = len(audit_rows(scenario))
    with pytest.raises(ClaimPromotionError, match="trusted claim cannot become refuted"):
        scenario.ledger.promote_claim(claim, scenario.run(claim, Verdict.FAIL))
    assert scenario.ledger.get_claim(claim).status is ClaimStatus.TRUSTED
    assert len(audit_rows(scenario)) == rows_before + 1  # only the oracle run was recorded


def test_an_inconclusive_claim_can_be_decided_by_a_later_run(scenario: Scenario) -> None:
    claim = scenario.claim(scenario.finding())
    scenario.ledger.promote_claim(claim, scenario.run(claim, Verdict.INCONCLUSIVE))
    assert (
        scenario.ledger.promote_claim(claim, scenario.run(claim, Verdict.FAIL))
        is ClaimStatus.REFUTED
    )


class _SqlStrings(ast.NodeVisitor):
    """Collect string literals, except docstrings, with the function that contains them."""

    def __init__(self) -> None:
        self.found: list[tuple[str, str]] = []
        self._functions: list[str] = []
        self._docstrings: set[int] = set()

    def visit(self, node: ast.AST) -> None:
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                self._docstrings.add(id(body[0].value))
        super().visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._functions.append(node.name)
        self.generic_visit(node)
        self._functions.pop()

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and id(node) not in self._docstrings:
            self.found.append((node.value, self._functions[-1] if self._functions else ""))


def test_only_promote_claim_writes_claim_status() -> None:
    writers = []
    for path in sorted(SRC.rglob("*.py")):
        visitor = _SqlStrings()
        visitor.visit(ast.parse(path.read_text()))
        for text, function in visitor.found:
            if re.search(r"UPDATE\s+claim\b", text, re.IGNORECASE):
                writers.append((path.relative_to(SRC).as_posix(), function))
    assert writers == [("ledger/ledger.py", "promote_claim")]


def test_the_trigger_backs_up_promote_claim(
    scenario: Scenario, monkeypatch: pytest.MonkeyPatch
) -> None:
    claim = scenario.claim(scenario.finding())
    run = scenario.run(claim, Verdict.INCONCLUSIVE)
    rows_before = audit_rows(scenario)
    monkeypatch.setattr(
        "assay.ledger.ledger.claim_status_after", lambda current, verdict: ClaimStatus.TRUSTED
    )
    with pytest.raises(LedgerError, match="matching verdict"):
        scenario.ledger.promote_claim(claim, run)
    assert scenario.ledger.get_claim(claim).status is ClaimStatus.ASSERTED
    assert audit_rows(scenario) == rows_before


# Findings


@pytest.mark.parametrize("state", list(FindingState))
def test_every_state_is_reachable_with_evidence(scenario: Scenario, state: FindingState) -> None:
    finding = scenario.ledger.get_finding(scenario.drive_to(state))
    assert finding.state is state
    assert scenario.ledger.verify_chain().ok


def test_transitions_set_the_evidence_level(scenario: Scenario) -> None:
    expected = {
        FindingState.REPRODUCED: EvidenceLevel.E1,
        FindingState.PATCH_PROPOSED: EvidenceLevel.E1,
        FindingState.VERIFIED_WITHIN_BOUNDS: EvidenceLevel.E3,
        FindingState.REJECTED: EvidenceLevel.E1,
        FindingState.NOT_REPRODUCED: EvidenceLevel.E0,
    }
    for state, level in expected.items():
        assert scenario.ledger.get_finding(scenario.drive_to(state)).evidence_level is level


def test_inconclusive_after_a_patch_records_e2(scenario: Scenario) -> None:
    finding = scenario.drive_to(FindingState.PATCH_PROPOSED)
    verdicts = dict.fromkeys(REQUIRED_ORACLES, Verdict.PASS)
    verdicts[OracleName.VARIANT] = Verdict.INCONCLUSIVE
    runs = scenario.patch_runs(finding, verdicts)
    moved = scenario.ledger.transition_finding(
        finding, FindingState.INCONCLUSIVE, oracle_run_ids=runs, reason="variant_search_ineffective"
    )
    assert moved.evidence_level is EvidenceLevel.E2
    assert moved.reason == "variant_search_ineffective"


def test_a_transition_is_audited_with_its_runs(scenario: Scenario) -> None:
    finding = scenario.drive_to(FindingState.POC_DRAFTED)
    run = scenario.run(scenario.claim(finding), Verdict.PASS)
    scenario.ledger.transition_finding(finding, FindingState.REPRODUCED, oracle_run_ids=[run])
    seq, event, payload = audit_rows(scenario)[-1]
    assert event == "finding.transitioned"
    assert payload == {
        "finding_id": finding,
        "from": "POC_DRAFTED",
        "to": "REPRODUCED",
        "evidence_level": "E1",
        "oracle_run_ids": [run],
        "reason": None,
    }
    with closing(scenario.raw()) as conn:
        updated = conn.execute("SELECT updated_seq FROM finding WHERE id = ?", (finding,))
        assert updated.fetchone()[0] == seq


def test_illegal_transitions_change_nothing(scenario: Scenario) -> None:
    finding = scenario.finding()
    rows_before = audit_rows(scenario)
    with pytest.raises(IllegalTransition, match="not in the transition table"):
        scenario.ledger.transition_finding(finding, FindingState.VERIFIED_WITHIN_BOUNDS)
    assert scenario.ledger.get_finding(finding).state is FindingState.CANDIDATE
    assert audit_rows(scenario) == rows_before


def test_reproduction_needs_a_run_for_a_claim_of_the_same_finding(scenario: Scenario) -> None:
    finding, other = (scenario.drive_to(FindingState.POC_DRAFTED) for _ in range(2))
    foreign = scenario.run(scenario.claim(other), Verdict.PASS)
    unclaimed = scenario.run(None, Verdict.PASS)
    for run in (foreign, unclaimed):
        with pytest.raises(IllegalTransition, match="not a run for a claim of finding"):
            scenario.ledger.transition_finding(
                finding, FindingState.REPRODUCED, oracle_run_ids=[run]
            )
    with pytest.raises(NotFound):
        scenario.ledger.transition_finding(
            finding, FindingState.REPRODUCED, oracle_run_ids=[OracleRunId(999)]
        )


def test_a_run_cannot_be_counted_twice(scenario: Scenario) -> None:
    finding = scenario.drive_to(FindingState.POC_DRAFTED)
    run = scenario.run(scenario.claim(finding), Verdict.PASS)
    with pytest.raises(IllegalTransition, match="more than once"):
        scenario.ledger.transition_finding(
            finding, FindingState.REPRODUCED, oracle_run_ids=[run, run]
        )


def test_verification_needs_runs_on_a_patch_of_the_same_finding(scenario: Scenario) -> None:
    finding = scenario.drive_to(FindingState.PATCH_PROPOSED)
    other = scenario.drive_to(FindingState.PATCH_PROPOSED)
    revision = scenario.patched_revision(other, attempt_no=2)
    claim = scenario.claim(finding)
    runs = [scenario.run(claim, Verdict.PASS, oracle, revision) for oracle in REQUIRED_ORACLES]
    with pytest.raises(IllegalTransition, match="patch of another finding"):
        scenario.ledger.transition_finding(
            finding, FindingState.VERIFIED_WITHIN_BOUNDS, oracle_run_ids=runs
        )


def test_rejection_needs_a_reason(scenario: Scenario) -> None:
    finding = scenario.drive_to(FindingState.PATCH_PROPOSED)
    runs = scenario.patch_runs(finding, {OracleName.BEHAVIOR: Verdict.FAIL})
    with pytest.raises(IllegalTransition, match="needs a reason"):
        scenario.ledger.transition_finding(finding, FindingState.REJECTED, oracle_run_ids=runs)
    with pytest.raises(InvalidInput):
        scenario.ledger.transition_finding(
            finding, FindingState.REJECTED, oracle_run_ids=runs, reason="  "
        )


def test_the_trigger_backs_up_transition_finding(
    scenario: Scenario, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding = scenario.drive_to(FindingState.POC_DRAFTED)
    monkeypatch.setattr(
        "assay.ledger.ledger.check_transition", lambda *args, **kwargs: EvidenceLevel.E1
    )
    with pytest.raises(LedgerError, match="lacks the required oracle evidence"):
        scenario.ledger.transition_finding(finding, FindingState.REPRODUCED)
    with pytest.raises(LedgerError, match="illegal finding transition"):
        scenario.ledger.transition_finding(finding, FindingState.PATCH_PROPOSED)
    assert scenario.ledger.get_finding(finding).state is FindingState.POC_DRAFTED
    assert scenario.ledger.verify_chain().ok


# Projects, revisions, patches, oracle runs


def test_duplicate_stable_ids_are_refused(scenario: Scenario) -> None:
    scenario.ledger.add_finding(scenario.project, "same", "dos")
    with pytest.raises(InvalidInput, match="already exists"):
        scenario.ledger.add_finding(scenario.project, "same", "dos")


@pytest.mark.parametrize(
    ("stable_id", "vuln_class"),
    [("", "dos"), ("../x", "dos"), ("ok", "Dos"), ("ok", "dos class"), ("ok", "")],
)
def test_finding_identifiers_are_validated(
    scenario: Scenario, stable_id: str, vuln_class: str
) -> None:
    with pytest.raises(InvalidInput):
        scenario.ledger.add_finding(scenario.project, stable_id, vuln_class)


@pytest.mark.parametrize("text", ["", "   ", "nul\x00inside", "x" * 2001])
def test_claim_text_is_validated(scenario: Scenario, text: str) -> None:
    with pytest.raises(InvalidInput):
        scenario.claim(scenario.finding(), text)


def test_unknown_parents_are_refused(scenario: Scenario) -> None:
    with pytest.raises(NotFound):
        scenario.claim(FindingId(scenario.finding() + 100))
    with pytest.raises(NotFound):
        scenario.ledger.add_finding(ProjectId(scenario.project + 100), "x", "dos")


def test_revision_kind_and_patch_must_agree(scenario: Scenario) -> None:
    finding = scenario.finding()
    patch = scenario.ledger.add_patch(finding, PatchSource.MODEL, b"diff", 1)
    with pytest.raises(InvalidInput, match="patched revision needs a patch_id"):
        scenario.ledger.add_revision(scenario.project, RevisionKind.PATCHED, sha("x"))
    with pytest.raises(InvalidInput):
        scenario.ledger.add_revision(scenario.project, RevisionKind.VULNERABLE, sha("x"), patch)
    other_project = scenario.ledger.add_project("other", "other")
    with pytest.raises(InvalidInput, match="another project"):
        scenario.ledger.add_revision(other_project, RevisionKind.PATCHED, sha("x"), patch)


def test_patches_are_stored_as_blobs_once_per_attempt(scenario: Scenario) -> None:
    finding = scenario.finding()
    scenario.ledger.add_patch(finding, PatchSource.FIXTURE, b"--- a\n+++ b\n", 1)
    with pytest.raises(InvalidInput, match="already has a patch for attempt 1"):
        scenario.ledger.add_patch(finding, PatchSource.FIXTURE, b"other", 1)
    with closing(scenario.raw()) as conn:
        digest = conn.execute("SELECT diff_blob_sha256 FROM patch").fetchone()[0]
    assert scenario.ledger.read_blob(digest) == b"--- a\n+++ b\n"


def test_oracle_runs_check_their_references(scenario: Scenario) -> None:
    finding = scenario.finding()
    claim = scenario.claim(finding)
    other_project = scenario.ledger.add_project("other", "other")
    foreign_revision = scenario.ledger.add_revision(
        other_project, RevisionKind.VULNERABLE, sha("o")
    )
    with pytest.raises(InvalidInput, match="different projects"):
        scenario.run(claim, Verdict.PASS, revision=foreign_revision)
    with pytest.raises(NotFound):
        scenario.run(ClaimId(999), Verdict.PASS)
    base = scenario.ledger.get_oracle_run(scenario.run(claim, Verdict.PASS))
    missing_trace = OracleRunInput(
        claim_id=claim,
        revision_id=scenario.vulnerable,
        oracle=OracleName.EXPLOIT,
        argv=base.argv,
        image_digest=IMAGE_DIGEST,
        seed=None,
        exit_code=0,
        verdict=Verdict.PASS,
        reason="r",
        trace_blob_sha256=sha("not stored"),
    )
    with pytest.raises(NotFound, match="trace blob"):
        scenario.ledger.record_oracle_run(missing_trace)


def test_oracle_run_input_is_strict() -> None:
    with pytest.raises(ValueError, match="image_digest"):
        OracleRunInput(
            claim_id=None,
            revision_id=RevisionId(1),
            oracle=OracleName.EXPLOIT,
            argv=(),
            image_digest="latest",
            seed=None,
            exit_code=None,
            verdict=Verdict.PASS,
            reason="r",
            trace_blob_sha256=sha("t"),
        )
    with pytest.raises(ValueError, match="verdict"):
        OracleRunInput(
            claim_id=None,
            revision_id=RevisionId(1),
            oracle=OracleName.EXPLOIT,
            argv=(),
            image_digest=IMAGE_DIGEST,
            seed=None,
            exit_code=None,
            verdict="PASS",  # type: ignore[arg-type]
            reason="r",
            trace_blob_sha256=sha("t"),
        )


def test_a_read_only_ledger_cannot_be_changed(tmp_path: Path) -> None:
    with Scenario.create(tmp_path) as scenario:
        scenario.finding()
    with Ledger.open(tmp_path / "ledger.db", read_only=True) as ledger:
        assert ledger.verify_chain().ok
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            ledger.add_project("x", "x")


def test_an_empty_diff_is_a_patch(scenario: Scenario) -> None:
    patch = scenario.ledger.add_patch(scenario.finding(), PatchSource.HUMAN, b"", 1)
    with closing(scenario.raw()) as conn:
        digest = conn.execute("SELECT diff_sha256 FROM patch WHERE id = ?", (patch,)).fetchone()
    assert digest[0] == sha("")


def test_verifications_record_the_final_verdict_and_the_bounds(scenario: Scenario) -> None:
    finding = scenario.drive_to(FindingState.PATCH_PROPOSED)
    runs = scenario.patch_runs(finding, {OracleName.INTEGRITY: Verdict.PASS})
    with closing(scenario.raw()) as conn:
        patch = conn.execute(
            "SELECT v.patch_id FROM oracle_run AS r JOIN revision AS v ON v.id = r.revision_id "
            "WHERE r.id = ?",
            (runs[0],),
        ).fetchone()[0]
    bounds = {"fuzz_seed": "0x1", "oracles_run": ["integrity"], "replays": 3}
    verification = scenario.ledger.add_verification(
        patch, FinalVerdict.INCONCLUSIVE, "missing_oracles: exploit", bounds
    )
    with closing(scenario.raw()) as conn:
        row = conn.execute(
            "SELECT patch_id, final_verdict, reason, bounds_json, bundle_manifest_sha256 "
            "FROM verification WHERE id = ?",
            (verification,),
        ).fetchone()
        event = conn.execute(
            "SELECT event, payload_json FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
    assert row == (
        patch,
        "INCONCLUSIVE",
        "missing_oracles: exploit",
        '{"fuzz_seed":"0x1","oracles_run":["integrity"],"replays":3}',
        None,
    )
    assert event[0] == "verification.recorded"
    assert json.loads(event[1])["verification_id"] == verification
    assert scenario.ledger.verify_chain().ok


def test_verified_within_bounds_needs_every_required_oracle(scenario: Scenario) -> None:
    finding = scenario.drive_to(FindingState.PATCH_PROPOSED)
    partial = dict.fromkeys(REQUIRED_ORACLES - {OracleName.VARIANT}, Verdict.PASS)
    scenario.patch_runs(finding, partial)
    with pytest.raises(IllegalTransition, match="missing: variant"):
        scenario.ledger.add_verification(
            _patch_of_last_revision(scenario), FinalVerdict.VERIFIED_WITHIN_BOUNDS, "ok", {}
        )
    failed = {**dict.fromkeys(REQUIRED_ORACLES, Verdict.PASS), OracleName.SYMBOLIC: Verdict.FAIL}
    scenario.patch_runs(finding, failed)
    with pytest.raises(IllegalTransition, match="no FAIL"):
        scenario.ledger.add_verification(
            _patch_of_last_revision(scenario), FinalVerdict.VERIFIED_WITHIN_BOUNDS, "ok", {}
        )
    scenario.patch_runs(finding, dict.fromkeys(REQUIRED_ORACLES, Verdict.PASS))
    scenario.ledger.add_verification(
        _patch_of_last_revision(scenario), FinalVerdict.VERIFIED_WITHIN_BOUNDS, "ok", {}
    )


def _patch_of_last_revision(scenario: Scenario) -> PatchId:
    with closing(scenario.raw()) as conn:
        return PatchId(
            conn.execute("SELECT patch_id FROM revision ORDER BY id DESC LIMIT 1").fetchone()[0]
        )


def test_verification_input_is_checked(scenario: Scenario) -> None:
    with pytest.raises(NotFound):
        scenario.ledger.add_verification(PatchId(99), FinalVerdict.REJECTED, "r", {})
    finding = scenario.finding()
    patch = scenario.ledger.add_patch(finding, PatchSource.HUMAN, b"d", 1)
    with pytest.raises(InvalidInput, match="bounds"):
        scenario.ledger.add_verification(patch, FinalVerdict.REJECTED, "r", {"seconds": 1.5})
    with pytest.raises(InvalidInput):
        scenario.ledger.add_verification(patch, FinalVerdict.REJECTED, "  ", {})
    with pytest.raises(InvalidInput):
        scenario.ledger.add_verification(patch, "PASSED", "r", {})  # type: ignore[arg-type]


def test_findings_are_found_by_stable_id(scenario: Scenario) -> None:
    finding = scenario.finding()
    found = scenario.ledger.find_finding("finding-1")
    assert found is not None
    assert found.id == finding
    assert scenario.ledger.find_finding("missing") is None
