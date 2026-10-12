"""The claims checker (tools/claims_check.py): evidence must exist, README areas must be covered."""

import pytest

import claims_check as cc

TABLE = """\
# Claims

| Area | Claim | Evidence | Status |
|---|---|---|---|
| a | first claim | `README.md` | met |
| b | second claim | `docs/claims.md`, `tools/claims_check.py::parse_claims` | bounded |
"""


def test_the_repository_claims_table_parses_and_every_path_exists() -> None:
    text = cc.CLAIMS_PAGE.read_text(encoding="utf-8")
    claims = cc.parse_claims(text)
    assert len(claims) >= 20
    assert {c.status for c in claims} <= cc.ALLOWED_STATUS
    for claim in claims:
        assert claim.evidence, claim.area
        for reference in claim.evidence:
            assert cc.evidence_problem(reference) is None, (claim.area, reference)


def test_the_repository_passes_its_own_check() -> None:
    claims_text = cc.CLAIMS_PAGE.read_text(encoding="utf-8")
    readme_text = cc.README.read_text(encoding="utf-8")
    assert cc.check(claims_text, readme_text) == []


def test_a_missing_evidence_path_is_a_problem() -> None:
    assert cc.evidence_problem("does/not/exist.py") is not None
    assert cc.evidence_problem("README.md") is None


def test_a_named_test_must_appear_in_its_file() -> None:
    assert cc.evidence_problem("tools/claims_check.py::parse_claims") is None
    problem = cc.evidence_problem("tools/claims_check.py::no_such_symbol")
    assert problem is not None
    assert "does not contain" in problem


def test_a_readme_area_without_a_row_is_reported() -> None:
    readme = "<!-- claim: a -->\n<!-- claim: missing -->\nsee docs/claims.md\n"
    problems = cc.check(TABLE, readme)
    assert any("missing" in p for p in problems)
    assert not any("area 'a'" in p for p in problems)


def test_an_unknown_status_is_reported() -> None:
    table = TABLE.replace("| met |", "| perfect |")
    problems = cc.check(table, "see docs/claims.md")
    assert any("perfect" in p for p in problems)


def test_a_missing_link_to_the_table_is_reported() -> None:
    problems = cc.check(TABLE, "<!-- claim: a -->\n<!-- claim: b -->\n")
    assert any("does not link" in p for p in problems)


def test_a_table_without_the_expected_columns_is_an_error() -> None:
    with pytest.raises(cc.ClaimsError):
        cc.parse_claims("# No table here\n\njust text\n")
