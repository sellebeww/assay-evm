"""The benchmark: statistics, the freeze, ablations, splits, the report and the CLI wiring."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.bench import freeze
from assay.bench.ablation import accepts
from assay.bench.models import CLASS_IDS, CaseResult, OracleOutcome, RunInfo
from assay.bench.report import ReportError, build_report
from assay.bench.run import case_file_name, run_id
from assay.bench.splits import SplitError, load_expectations, load_split
from assay.bench.stats import rate_text, wilson
from assay.cli.main import app

REPO = Path(__file__).resolve().parents[2]
ORACLES = ("integrity", "exploit", "variant", "behavior", "regression")

# -- statistics --------------------------------------------------------------------------------


def test_wilson_reference_values() -> None:
    assert wilson(0, 8)[1] == pytest.approx(0.324, abs=0.001)
    low, high = wilson(4, 8)
    assert (low, high) == (pytest.approx(0.215, abs=0.001), pytest.approx(0.785, abs=0.001))
    assert wilson(0, 24)[1] == pytest.approx(0.14, abs=0.005)


def test_wilson_bounds_stay_in_the_unit_interval() -> None:
    assert wilson(0, 1)[0] == 0.0
    assert wilson(8, 8)[1] == 1.0


@pytest.mark.parametrize(("k", "n"), [(-1, 8), (9, 8), (0, 0)])
def test_wilson_rejects_impossible_samples(k: int, n: int) -> None:
    with pytest.raises(ValueError, match="wilson"):
        wilson(k, n)


def test_rates_round_away_from_the_favorable_direction() -> None:
    # 1/3 = 33.33 %: a rate where lower is better rounds up, where higher is better rounds down.
    assert rate_text(1, 3, lower_is_better=True).startswith("1/3 (33.4 %")
    assert rate_text(1, 3, lower_is_better=False).startswith("1/3 (33.3 %")
    # 0 of 8: the upper bound 32.44 % rounds up, the lower bound stays 0.
    assert rate_text(0, 8, lower_is_better=True) == "0/8 (0.0 %, 95 % CI 0.0 to 32.5 %)"
    assert rate_text(8, 8, lower_is_better=False).endswith("to 100.0 %)")
    assert rate_text(0, 0, lower_is_better=True) == "n/a"


# -- the freeze --------------------------------------------------------------------------------


def _tree(root: Path) -> None:
    (root / "src/assay/oracles").mkdir(parents=True)
    (root / "src/assay/oracles/a.py").write_text("a = 1\n")
    (root / "solidity").mkdir()
    (root / "solidity/H.sol").write_text("contract H {}\n")
    (root / "docker/runner").mkdir(parents=True)
    (root / "docker/runner/versions.lock").write_text("A=1\n")


def test_tree_hash_ignores_caches_and_detects_changes(tmp_path: Path) -> None:
    _tree(tmp_path)
    first = freeze.tree_hash(tmp_path)
    cache = tmp_path / "src/assay/oracles/__pycache__"
    cache.mkdir()
    (cache / "a.cpython-312.pyc").write_bytes(b"\x00")
    (tmp_path / "solidity/.DS_Store").write_bytes(b"x")
    assert freeze.tree_hash(tmp_path) == first
    (tmp_path / "src/assay/oracles/a.py").write_text("a = 2\n")
    assert freeze.tree_hash(tmp_path) != first


def test_tree_hash_sees_a_new_and_a_renamed_file(tmp_path: Path) -> None:
    _tree(tmp_path)
    first = freeze.tree_hash(tmp_path)
    (tmp_path / "src/assay/oracles/a.py").rename(tmp_path / "src/assay/oracles/b.py")
    assert freeze.tree_hash(tmp_path) != first
    (tmp_path / "src/assay/oracles/b.py").rename(tmp_path / "src/assay/oracles/a.py")
    (tmp_path / "solidity/New.sol").write_text("contract N {}\n")
    assert freeze.tree_hash(tmp_path) != first


def test_tree_hash_rejects_a_symbolic_link(tmp_path: Path) -> None:
    _tree(tmp_path)
    (tmp_path / "solidity/link.sol").symlink_to(tmp_path / "solidity/H.sol")
    with pytest.raises(freeze.FreezeError, match="symbolic link"):
        freeze.tree_hash(tmp_path)


def test_frozen_file_round_trip(tmp_path: Path) -> None:
    _tree(tmp_path)
    assert freeze.read_frozen(tmp_path) is None
    value = freeze.write_frozen(tmp_path)
    assert freeze.read_frozen(tmp_path) == value == freeze.tree_hash(tmp_path)
    (tmp_path / freeze.FROZEN_FILE).write_text("not a hash\n")
    with pytest.raises(freeze.FreezeError, match="sha256"):
        freeze.read_frozen(tmp_path)


def test_the_repository_hash_is_stable_between_two_calls() -> None:
    assert freeze.tree_hash(REPO) == freeze.tree_hash(REPO)


# -- ablations ---------------------------------------------------------------------------------


def _outcomes(**verdicts: tuple[str, tuple[str, ...]]) -> tuple[OracleOutcome, ...]:
    rows = []
    for name in ORACLES:
        verdict, codes = verdicts.get(name, ("PASS", ()))
        rows.append(
            OracleOutcome(
                oracle=name,  # type: ignore[arg-type]
                status="ran",
                verdict=verdict,  # type: ignore[arg-type]
                codes=codes,
            )
        )
    return tuple(rows)


def _case(
    label: str = "good",
    fixture: str = "reentrancy/single_function",
    final: str = "VERIFIED_WITHIN_BOUNDS",
    reasons: tuple[str, ...] = (),
    oracles: tuple[OracleOutcome, ...] | None = None,
    expected: tuple[str, str | None] | None = None,
) -> CaseResult:
    default = {
        "good": ("VERIFIED_WITHIN_BOUNDS", None),
        "overfit": ("REJECTED", "variant_found"),
        "destructive": ("REJECTED", "benign_test_failed"),
        "regressing": ("REJECTED", "layout_changed"),
    }[label]
    verdict, reason = expected or default
    return CaseResult(
        fixture=fixture,
        label=label,  # type: ignore[arg-type]
        expected_verdict=verdict,  # type: ignore[arg-type]
        expected_reason=reason,
        exit_code=0,
        final_verdict=final,  # type: ignore[arg-type]
        reasons=reasons,
        evidence_level=None,
        oracles=_outcomes() if oracles is None else oracles,
        base_tree_sha256="a" * 64,
        poc_tree_sha256="b" * 64,
        patch_sha256="c" * 64,
        seconds=1.5,
    )


def test_a_good_patch_is_accepted_by_every_configuration() -> None:
    case = _case()
    assert [accepts(case, config) for config in ("V0", "V1", "V2", "V3")] == [True] * 4


def test_an_overfit_patch_passes_the_tests_and_the_poc_but_not_the_variant_search() -> None:
    case = _case("overfit", oracles=_outcomes(variant=("FAIL", ("variant_found",))))
    assert [accepts(case, config) for config in ("V0", "V1", "V2", "V3")] == [
        True,
        True,
        False,
        False,
    ]


def test_a_destructive_patch_fails_the_tests_in_every_configuration() -> None:
    case = _case(
        "destructive",
        oracles=_outcomes(
            behavior=("FAIL", ("benign_test_failed",)),
            regression=("FAIL", ("test_suite_failed",)),
        ),
    )
    assert [accepts(case, config) for config in ("V0", "V1", "V2", "V3")] == [False] * 4


def test_a_regressing_patch_passes_until_the_regression_oracle() -> None:
    case = _case("regressing", oracles=_outcomes(regression=("FAIL", ("layout_changed",))))
    assert [accepts(case, config) for config in ("V0", "V1", "V2", "V3")] == [
        True,
        True,
        True,
        False,
    ]


def test_an_exploit_that_still_works_is_not_accepted_by_v1() -> None:
    case = _case("overfit", oracles=_outcomes(exploit=("FAIL", ("exploit_still_reproducible",))))
    assert accepts(case, "V0") is True
    assert accepts(case, "V1") is False


def test_a_skipped_oracle_leaves_the_configuration_undecided_unless_another_one_failed() -> None:
    rows = tuple(
        OracleOutcome(oracle=name, status="skipped", verdict=None, codes=())  # type: ignore[arg-type]
        for name in ORACLES[1:]
    )
    integrity = OracleOutcome(oracle="integrity", status="ran", verdict="FAIL", codes=("x",))
    case = _case("destructive", oracles=(integrity, *rows))
    assert accepts(case, "V0") is None
    assert accepts(case, "V3") is False


def test_an_inconclusive_oracle_is_never_an_acceptance() -> None:
    case = _case("overfit", oracles=_outcomes(variant=("INCONCLUSIVE", ("timeout",))))
    assert accepts(case, "V2") is False
    assert accepts(case, "V3") is False


def test_v4_needs_the_symbolic_oracle() -> None:
    assert accepts(_case(), "V4") is None
    symbolic = OracleOutcome(oracle="symbolic", status="ran", verdict="PASS", codes=())
    case = _case(oracles=(*_outcomes(), symbolic))
    assert accepts(case, "V4") is True


def test_an_unknown_configuration_is_an_error() -> None:
    with pytest.raises(ValueError, match="unknown configuration"):
        accepts(_case(), "V9")


# -- splits ------------------------------------------------------------------------------------


def test_the_dev_split_lists_the_development_fixtures() -> None:
    split = load_split(REPO, "dev")
    assert split.root == "fixtures"
    assert sorted(item.split("/", 1)[0] for item in split.fixtures) == sorted(CLASS_IDS)
    expectations = load_expectations(REPO, split)
    assert len(expectations) == 4 * len(split.fixtures)
    assert {item.verdict for item in expectations if item.label == "good"} == {
        "VERIFIED_WITHIN_BOUNDS"
    }


def test_a_split_with_a_missing_fixture_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "bench/splits").mkdir(parents=True)
    (tmp_path / "bench/splits/dev.json").write_text(
        json.dumps({"schema_version": 1, "name": "dev", "root": "fx", "fixtures": ["dos/x"]})
    )
    with pytest.raises(SplitError, match=r"expected\.json"):
        load_split(tmp_path, "dev")


def test_run_ids_and_case_files_are_plain_names() -> None:
    name = run_id(
        "dev",
        __import__("assay.bench.run", fromlist=["RunSettings"]).RunSettings(),
        "a" * 64,
        "b" * 64,
    )
    assert name == "dev-standard-aaaaaaaaaa-bbbbbbbbbb"
    assert case_file_name("dos/payout_loop", "good") == "dos__payout_loop__good.json"


# -- the report --------------------------------------------------------------------------------


def _run_info(split: str, oracle_hash: str) -> RunInfo:
    return RunInfo(
        run_id=f"{split}-run",
        split=split,  # type: ignore[arg-type]
        split_file_sha256="1" * 64,
        fixtures_tree_sha256="2" * 64,
        cases=0,
        assay_version="0.0.0",
        git_commit=None,
        oracle_tree_sha256=oracle_hash,
        image_digest="sha256:" + "3" * 64,
        tool_versions={"forge": "1.0.0"},
        versions_lock_sha256="4" * 64,
        machine="arm64",
        profile="standard",
        fuzz_seed="0x1",
        fuzz_runs=256,
        variant_seeds=3,
        invariant_runs=64,
        invariant_depth=25,
        exploit_replays=3,
        symbolic=False,
        total_seconds=12.0,
    )


def _write_run(root: Path, split: str, oracle_hash: str, cases: list[CaseResult]) -> Path:
    folder = root / "bench/results" / f"{split}-run"
    (folder / "cases").mkdir(parents=True)
    info = _run_info(split, oracle_hash).model_copy(update={"cases": len(cases)})
    (folder / "run.json").write_text(info.model_dump_json(indent=2))
    for case in cases:
        name = case_file_name(case.fixture, case.label)
        (folder / "cases" / name).write_text(case.model_dump_json(indent=2))
    return folder


def _all_labels(fixture: str = "dos/payout_loop") -> list[CaseResult]:
    return [
        _case("good", fixture),
        _case(
            "overfit",
            fixture,
            "REJECTED",
            ("variant_found",),
            oracles=_outcomes(variant=("FAIL", ("variant_found",))),
        ),
        _case(
            "destructive",
            fixture,
            "REJECTED",
            ("benign_test_failed",),
            oracles=_outcomes(behavior=("FAIL", ("benign_test_failed",))),
        ),
        _case(
            "regressing",
            fixture,
            "REJECTED",
            ("layout_changed",),
            oracles=_outcomes(regression=("FAIL", ("layout_changed",))),
        ),
    ]


def _repo(tmp_path: Path) -> Path:
    _tree(tmp_path)
    (tmp_path / "bench").mkdir(exist_ok=True)
    (tmp_path / "bench/PROTOCOL.md").write_text(
        "# P\n\n## 9. Threats to validity\n\n1. Same author.\n2. Small n.\n\n## 10. Next\n\nx\n"
    )
    (tmp_path / "docs").mkdir()
    return tmp_path


def test_held_out_results_are_marked_only_when_the_hash_equals_the_frozen_hash(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path)
    current = freeze.write_frozen(root)
    folder = _write_run(root, "heldout", current, _all_labels())
    page, data, warnings = build_report(root, [folder])
    assert "Status: **HELD-OUT: the oracle hash of the run equals bench/FROZEN_HASH**" in page
    assert json.loads(data)["splits"]["heldout"]["held_out"] is True
    assert warnings == []


def test_held_out_results_with_another_hash_are_not_held_out(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    freeze.write_frozen(root)
    folder = _write_run(root, "heldout", "f" * 64, _all_labels())
    page, data, warnings = build_report(root, [folder])
    assert "NOT HELD-OUT: the oracle hash of the run differs" in page
    assert json.loads(data)["splits"]["heldout"]["held_out"] is False
    assert warnings


def test_held_out_results_without_a_freeze_are_not_held_out(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    folder = _write_run(root, "heldout", freeze.tree_hash(root), _all_labels())
    page, _, _ = build_report(root, [folder])
    assert "NOT HELD-OUT: the oracles were never frozen" in page


def test_the_report_lists_a_mismatch_as_unexplained_until_a_finding_names_it(
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path)
    cases = _all_labels()
    cases[1] = _case("overfit", "dos/payout_loop", "VERIFIED_WITHIN_BOUNDS")
    folder = _write_run(root, "dev", freeze.tree_hash(root), cases)
    page, _, _ = build_report(root, [folder])
    assert "| unexplained |" in page
    assert "Mismatches between a verdict and a label: none." not in page
    (root / "bench/findings.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "result_version": "v1",
                "findings": [
                    {
                        "id": "F1",
                        "kind": "oracle",
                        "split": "dev",
                        "case": "dos/payout_loop/overfit",
                        "summary": "s",
                        "cause": "the variant search missed the variant",
                        "status": "deferred-to-v2",
                    }
                ],
                "corrections": [],
            }
        )
    )
    page, _, _ = build_report(root, [folder])
    assert "the variant search missed the variant" in page
    assert "| unexplained |" not in page


def test_the_report_says_none_when_every_verdict_equals_its_label(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    folder = _write_run(root, "dev", freeze.tree_hash(root), _all_labels())
    page, data, _ = build_report(root, [folder])
    assert "Mismatches between a verdict and a label: none." in page
    assert "4/4 (100.0 %" in page
    assert "1. Same author." in page
    assert "## 10." not in page
    assert json.loads(data)["splits"]["dev"]["match"]["count"] == 4


def test_the_report_is_deterministic_and_holds_no_host_path(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    folder = _write_run(root, "dev", freeze.tree_hash(root), _all_labels())
    first = build_report(root, [folder])
    second = build_report(root, [folder])
    assert first == second
    assert str(tmp_path) not in first[0] + first[1]
    assert "/Users/" not in first[0] + first[1]


def test_the_report_rejects_two_runs_of_one_split_and_a_miscounted_run(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    folder = _write_run(root, "dev", freeze.tree_hash(root), _all_labels())
    with pytest.raises(ReportError, match="two result folders"):
        build_report(root, [folder, folder])
    (folder / "cases" / case_file_name("dos/payout_loop", "good")).unlink()
    with pytest.raises(ReportError, match="found 3"):
        build_report(root, [folder])


def test_bench_commands_are_registered() -> None:
    result = CliRunner().invoke(app, ["bench", "--help"])
    assert result.exit_code == 0
    for command in ("run", "freeze", "report"):
        assert command in result.stdout


def test_the_heldout_split_lists_the_heldout_fixtures() -> None:
    split = load_split(REPO, "heldout")
    assert split.root == "bench/heldout"
    assert sorted(item.split("/", 1)[0] for item in split.fixtures) == sorted(CLASS_IDS)
    assert len(load_expectations(REPO, split)) == 4 * len(split.fixtures)


def test_no_fixture_belongs_to_both_splits() -> None:
    assert not set(load_split(REPO, "dev").fixtures) & set(load_split(REPO, "heldout").fixtures)


def test_the_oracles_still_match_the_frozen_hash() -> None:
    """Freeze rule of bench/PROTOCOL.md: the frozen paths do not change after the freeze."""
    frozen = freeze.read_frozen(REPO)
    assert frozen is not None
    assert freeze.tree_hash(REPO) == frozen
