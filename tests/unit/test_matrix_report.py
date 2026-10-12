"""The classification matrix report (tools/matrix_report.py), without Docker.

The verifications themselves run in `tests/integration/test_matrix.py` (`make matrix`).
"""

import json
import re
from pathlib import Path
from typing import Any

import pytest

import matrix_report as mr

FORBIDDEN = re.compile(r"\b(secure|safe|proven|guaranteed|unhackable)\b", re.IGNORECASE)
EXPECTATIONS = mr.load_expectations()


def _case(item: mr.Expectation, **changes: Any) -> dict[str, Any]:
    case: dict[str, Any] = {
        "fixture": item.fixture,
        "label": item.label,
        "exit_code": 0 if item.verdict == "VERIFIED_WITHIN_BOUNDS" else 1,
        "final_verdict": item.verdict,
        "reasons": [item.reason] if item.reason else [],
        "seconds": 41.5,
        "error": None,
    }
    case.update(changes)
    return case


def _results(cases: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": 2,
        "assay_version": "0.1.0.dev0",
        "image_digest": "sha256:" + "ab" * 32,
        "tool_versions": {"foundry": "v1.8.4", "solc": "0.8.36"},
        "versions_lock_sha256": "cd" * 32,
        "profile": "standard",
        "fuzz_seed": "0x1",
        "fuzz_runs": 256,
        "variant_seeds": 3,
        "invariant_runs": 64,
        "invariant_depth": 25,
        "exploit_replays": 3,
        "total_seconds": 1534.2,
        "cases": cases,
    }


def _all_matching() -> dict[str, Any]:
    return _results([_case(item) for item in EXPECTATIONS])


def _model(data: dict[str, Any]) -> mr.MatrixResults:
    return mr.MatrixResults.model_validate_json(json.dumps(data))


# -- expectations ------------------------------------------------------------------------------


def test_expectations_cover_four_patches_of_every_fixture_in_class_order() -> None:
    assert len(EXPECTATIONS) == len(mr.CLASS_IDS) * len(mr.PATCH_LABELS)
    classes = list(dict.fromkeys(item.fixture.split("/")[0] for item in EXPECTATIONS))
    assert classes == list(mr.CLASS_IDS)
    assert [item.label for item in EXPECTATIONS[:4]] == list(mr.PATCH_LABELS)
    good = [item for item in EXPECTATIONS if item.label == "good"]
    assert {(item.verdict, item.reason) for item in good} == {("VERIFIED_WITHIN_BOUNDS", None)}
    overfit = [item for item in EXPECTATIONS if item.label == "overfit"]
    assert {(item.verdict, item.reason) for item in overfit} == {("REJECTED", "variant_found")}


# -- the matching rule -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("verdict", "reasons", "expected_verdict", "expected_reason", "result"),
    [
        ("VERIFIED_WITHIN_BOUNDS", [], "VERIFIED_WITHIN_BOUNDS", None, True),
        ("REJECTED", ["variant_found"], "REJECTED", "variant_found", True),
        (
            "REJECTED",
            ["benign_test_failed", "test_suite_failed"],
            "REJECTED",
            "benign_test_failed",
            True,
        ),
        ("REJECTED", ["variant_found"], "REJECTED", "layout_changed", False),
        ("REJECTED", ["abi_changed"], "VERIFIED_WITHIN_BOUNDS", None, False),
        ("INCONCLUSIVE", ["timeout"], "REJECTED", "variant_found", False),
        (None, [], "REJECTED", "variant_found", False),
    ],
)
def test_matching_rule(
    verdict: str | None,
    reasons: list[str],
    expected_verdict: str,
    expected_reason: str | None,
    result: bool,
) -> None:
    assert mr.matches(verdict, reasons, expected_verdict, expected_reason) is result


def test_every_result_matching_gives_a_full_match() -> None:
    rows = mr.compare(EXPECTATIONS, _model(_all_matching()))
    assert all(row.matches for row in rows)
    assert mr.result_line(rows) == "MATRIX RESULT: 32/32 match"
    assert mr.label_counts(rows) == dict.fromkeys(mr.PATCH_LABELS, (8, 8))


def test_a_wrong_reason_is_a_mismatch() -> None:
    data = _all_matching()
    data["cases"][1] = _case(EXPECTATIONS[1], reasons=["behavior_changed"])
    rows = mr.compare(EXPECTATIONS, _model(data))
    assert [row.matches for row in rows].count(False) == 1
    assert not rows[1].matches
    assert rows[1].actual == "REJECTED (behavior_changed)"
    assert mr.result_line(rows) == "MATRIX RESULT: 31/32 match"


def test_missing_and_unexpected_results_are_mismatches() -> None:
    data = _all_matching()
    missing = data["cases"].pop(0)
    data["cases"].append({**missing, "fixture": "reentrancy/other_shape"})
    rows = mr.compare(EXPECTATIONS, _model(data))
    assert len(rows) == 33
    assert rows[0].actual == mr.NOT_RUN
    assert not rows[0].matches
    assert rows[-1].fixture == "reentrancy/other_shape"
    assert rows[-1].expected == mr.NOT_RUN
    assert not rows[-1].matches
    assert mr.result_line(rows) == "MATRIX RESULT: 31/33 match"


def test_a_verification_without_a_report_is_a_mismatch() -> None:
    data = _all_matching()
    data["cases"][0] = _case(
        EXPECTATIONS[0], exit_code=5, final_verdict=None, reasons=[], error="error: rejected"
    )
    rows = mr.compare(EXPECTATIONS, _model(data))
    assert not rows[0].matches
    assert rows[0].actual == mr.NOT_RUN


@pytest.mark.parametrize(
    ("path", "value"),
    [
        pytest.param(("extra",), 1, id="unknown-field"),
        pytest.param(("cases", 0, "label"), "vulnerable", id="unknown-label"),
        pytest.param(("cases", 0, "final_verdict"), "PASS", id="unknown-verdict"),
        pytest.param(("cases", 0, "reasons"), ["Not A Code"], id="malformed-reason"),
        pytest.param(("cases", 0, "fixture"), "../outside", id="malformed-fixture"),
        pytest.param(("image_digest",), "assay-runner:dev", id="image-name-instead-of-id"),
        pytest.param(("fuzz_runs",), "256", id="string-number"),
    ],
)
def test_malformed_results_are_rejected(path: tuple[Any, ...], value: Any) -> None:
    data = _all_matching()
    target: Any = data
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValueError, match="validation error"):
        _model(data)


# -- output ------------------------------------------------------------------------------------


def test_the_table_has_one_row_per_patch_and_the_requested_columns() -> None:
    data = _all_matching()
    data["cases"][2] = _case(EXPECTATIONS[2], reasons=["vacuous_patch"])
    lines = mr.table_lines(mr.compare(EXPECTATIONS, _model(data)))
    assert lines[0].split() == ["class", "fixture", "patch", "expected", "actual", "result"]
    assert len(lines) == 33
    assert lines[1].split()[:3] == ["reentrancy", "single_function", "good"]
    assert lines[3].endswith("MISMATCH")
    assert sum(line.endswith("match") and not line.endswith("MISMATCH") for line in lines) == 31


@pytest.mark.parametrize(
    ("seconds", "text"),
    [(0, "0 min 00 s"), (59.6, "1 min 00 s"), (754, "12 min 34 s"), (5025, "1 h 23 min")],
)
def test_duration(seconds: float, text: str) -> None:
    assert mr.duration(seconds) == text


def test_the_page_states_the_result_the_limits_and_the_run() -> None:
    results = _model(_all_matching())
    page = mr.render_markdown(results, mr.compare(EXPECTATIONS, results))

    assert page.startswith("# Classification matrix\n")
    assert "`MATRIX RESULT: 32/32 match`" in page
    assert "self-validation on synthetic fixtures, not an independent benchmark" in " ".join(
        page.split()
    )
    assert "must not be read as a detection rate on real code" in " ".join(page.split())
    assert max(len(line) for line in page.splitlines() if not line.startswith("|")) <= 100
    assert "| `overfit` | `REJECTED` | `variant_found` | 8/8 |" in page
    patch_rows = [line for line in page.splitlines() if line.startswith("| `") and "` | `" in line]
    assert len([line for line in patch_rows if line.count("|") == 8]) == 32
    assert "`sha256:" + "ab" * 32 + "`" in page
    assert "foundry v1.8.4, solc 0.8.36" in page
    assert "25 min 34 s for 32 verifications" in page
    assert FORBIDDEN.search(page.replace("not a proof of absence", "")) is None
    # The page is public: no attribution line of the kind that a footer would carry.
    assert re.search(r"generated (by|with)", page, re.IGNORECASE) is None


def test_the_page_is_deterministic_and_free_of_host_details(tmp_path: Path) -> None:
    results = _model(_all_matching())
    rows = mr.compare(EXPECTATIONS, results)
    page = mr.render_markdown(results, rows)
    assert page == mr.render_markdown(_model(_all_matching()), rows)
    for detail in (str(Path.home()), str(tmp_path), str(mr.REPO_ROOT)):
        assert detail not in page
    assert re.search(r"\b20[0-9]{2}-[0-9]{2}-[0-9]{2}\b", page) is None


def test_the_page_escapes_table_separators() -> None:
    data = _all_matching()
    data["assay_version"] = "1.0|x"
    page = mr.render_markdown(_model(data), mr.compare(EXPECTATIONS, _model(data)))
    assert "`1.0\\|x`" in page


# -- command line ------------------------------------------------------------------------------


def _write(tmp_path: Path, data: dict[str, Any]) -> Path:
    path = tmp_path / "results.json"
    path.write_text(json.dumps(data))
    return path


def test_main_writes_the_page_and_ends_with_the_result_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "docs" / "classification-matrix.md"
    code = mr.main(["--results", str(_write(tmp_path, _all_matching())), "--out", str(out)])

    lines = capsys.readouterr().out.splitlines()
    assert code == 0
    assert lines[-1] == "MATRIX RESULT: 32/32 match"
    assert "total time: 25 min 34 s" in lines
    assert out.read_text().startswith("# Classification matrix\n")


def test_main_fails_on_a_mismatch(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data = _all_matching()
    data["cases"][0] = _case(EXPECTATIONS[0], final_verdict="REJECTED", reasons=["variant_found"])
    code = mr.main(["--results", str(_write(tmp_path, data))])

    lines = capsys.readouterr().out.splitlines()
    assert code == 1
    assert lines[-1] == "MATRIX RESULT: 31/32 match"


def test_main_rejects_unreadable_results(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    broken = tmp_path / "results.json"
    broken.write_text("{")
    assert mr.main(["--results", str(broken)]) == 2
    assert mr.main(["--results", str(tmp_path / "missing.json")]) == 2
    assert "cannot be read" in capsys.readouterr().err


def test_main_rejects_an_unreadable_fixtures_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fixtures = tmp_path / "fixtures"
    (fixtures / "reentrancy" / "broken").mkdir(parents=True)
    (fixtures / "reentrancy" / "broken" / "expected.json").write_text("{}")
    code = mr.main(
        ["--results", str(_write(tmp_path, _all_matching())), "--fixtures", str(fixtures)]
    )
    assert code == 2
    assert "fixtures cannot be read" in capsys.readouterr().err
