"""Ablation configurations V0 to V4, computed from the stored per-oracle results of a case.

A configuration accepts a case (True), rejects it (False) or cannot say (None) because an oracle
it needs did not run. Nothing here runs an oracle (bench/PROTOCOL.md, section 6).
"""

from collections.abc import Iterable

from assay.bench.models import CaseResult, OracleOutcome

TESTS_FAILED = "benign_test_failed"
SUITE_FAILED = "test_suite_failed"


def _and(values: Iterable[bool | None]) -> bool | None:
    """Three-valued conjunction: any False is False, otherwise any None is None."""
    result: bool | None = True
    for value in values:
        if value is False:
            return False
        if value is None:
            result = None
    return result


def _by_oracle(case: CaseResult) -> dict[str, OracleOutcome]:
    return {item.oracle: item for item in case.oracles}


def _passes(row: OracleOutcome | None) -> bool | None:
    if row is None or row.status != "ran":
        return None
    return row.verdict == "PASS"


def tests_pass(case: CaseResult) -> bool | None:
    """V0: the benign tests, and the project's test suite, pass on the patched revision."""
    rows = _by_oracle(case)
    behavior, regression = rows.get("behavior"), rows.get("regression")
    if behavior is None or behavior.status != "ran" or behavior.verdict == "INCONCLUSIVE":
        return None
    if regression is None or regression.status != "ran":
        return None
    return TESTS_FAILED not in behavior.codes and SUITE_FAILED not in regression.codes


def accepts(case: CaseResult, config: str) -> bool | None:
    """Whether configuration `config` accepts the case."""
    rows = _by_oracle(case)
    v0 = tests_pass(case)
    v1 = _and([v0, _passes(rows.get("exploit"))])
    v2 = _and([v1, _passes(rows.get("variant"))])
    v3 = _and(
        _passes(rows.get(name))
        for name in ("integrity", "exploit", "variant", "behavior", "regression")
    )
    if config == "V0":
        return v0
    if config == "V1":
        return v1
    if config == "V2":
        return v2
    if config == "V3":
        return v3
    if config == "V4":
        if "symbolic" not in rows or rows["symbolic"].status != "ran":
            return None
        return _and([v3, _passes(rows["symbolic"])])
    raise ValueError(f"unknown configuration {config!r}")
