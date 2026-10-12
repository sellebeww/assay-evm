"""Logic of the fixture checker (tools/fixture_check.py) and static checks of every fixture.

The sandboxed runs themselves are exercised by `make fixtures-check`.
"""

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

import fixture_check as fc

FIXTURES = fc.discover_fixtures(fc.FIXTURES_DIR)
EXAMPLE = fc.FIXTURES_DIR / "reentrancy" / "single_function"
PREDICATE = "0x" + "aa" * 32
RECORD = "0x" + "bb" * 32
OTHER = "0x" + "cc" * 32
TEST_CONTRACT = fc.TEST_CONTRACT
TARGET = "0x" + "11" * 20


# -- the fixtures in the repository ------------------------------------------------------------


DEVELOPMENT_FIXTURES = (
    "reentrancy/single_function",
    "access_control/missing_modifier",
    "unchecked_call/ignored_return",
    "signature_replay/missing_nonce",
    "delegatecall/user_controlled_target",
    "oracle_manipulation/spot_price",
    "dos/payout_loop",
    "rounding/share_inflation",
)


def test_fixtures_exist() -> None:
    assert set(DEVELOPMENT_FIXTURES) == set(FIXTURES)


def test_each_class_has_one_development_fixture() -> None:
    classes = [fixture_id.split("/", 1)[0] for fixture_id in FIXTURES]
    assert len(set(classes)) == len(classes)
    assert set(classes) == set(fc.CLASS_IDS)


def test_the_repository_fixtures_root_holds_only_fixtures() -> None:
    assert fc.layout_errors(fc.FIXTURES_DIR) == []


@pytest.mark.parametrize("fixture_id", FIXTURES)
def test_fixture_passes_the_static_checks(fixture_id: str) -> None:
    assert fc.static_errors(fc.FIXTURES_DIR / fixture_id, fixture_id, fc.pinned_solc()) == []


@pytest.mark.parametrize("fixture_id", FIXTURES)
def test_expected_json_of_every_fixture_matches_the_schema(fixture_id: str) -> None:
    """Strict schema (unknown fields and duplicate keys are rejected) and consistency rules."""
    fixture_dir = fc.FIXTURES_DIR / fixture_id
    expected = fc.load_expected(fixture_dir / "expected.json")
    assert fc.expected_errors(expected, fixture_id, fc.pinned_solc()) == []
    assert expected.fixture == fixture_id
    assert expected.class_id == fixture_id.split("/", 1)[0]
    path, name = expected.contract.split(":")
    assert f"contract {name} " in (fixture_dir / "src" / path).read_text()
    for label in fc.PATCH_LABELS:
        spec = expected.variants.get(label)
        assert isinstance(spec, fc.PatchSpec), label
        assert (fixture_dir / "patches" / f"{label}.diff").read_bytes().strip(), label


@pytest.mark.parametrize("fixture_id", FIXTURES)
def test_fixture_solc_matches_versions_lock(fixture_id: str) -> None:
    fixture_dir = fc.FIXTURES_DIR / fixture_id
    solc = fc.pinned_solc()
    assert fc.load_expected(fixture_dir / "expected.json").solc == solc
    assert 'solc = "' + solc + '"' in (fixture_dir / "foundry.toml").read_text()


def test_harness_passes_the_static_checks() -> None:
    assert fc.harness_errors(fc.pinned_solc()) == []


# -- expected.json -----------------------------------------------------------------------------


def _example() -> dict[str, Any]:
    data: dict[str, Any] = json.loads((EXAMPLE / "expected.json").read_text())
    return data


def _load(tmp_path: Path, data: dict[str, Any]) -> fc.ExpectedFile:
    path = tmp_path / "expected.json"
    path.write_text(json.dumps(data))
    return fc.load_expected(path)


def _errors(tmp_path: Path, data: dict[str, Any]) -> list[str]:
    return fc.expected_errors(_load(tmp_path, data), "reentrancy/single_function", "0.8.36")


def test_example_expected_file_is_consistent(tmp_path: Path) -> None:
    assert _errors(tmp_path, _example()) == []


@pytest.mark.parametrize(
    ("path", "value"),
    [
        pytest.param(("extra",), 1, id="unknown-top-level-field"),
        pytest.param(("variants", "good", "note"), "x", id="unknown-variant-field"),
        pytest.param(("variants", "vulnerable", "verdict"), "REJECTED", id="verdict-on-vulnerable"),
        pytest.param(("schema_version",), 2, id="schema-version"),
        pytest.param(("class",), "reentrancy_x", id="unknown-class"),
        pytest.param(("solc",), "^0.8.36", id="solc-range"),
        pytest.param(("contract",), "../Vault.sol:Vault", id="contract-traversal"),
        pytest.param(("variants", "good", "replay"), "blocked", id="outcome-case"),
        pytest.param(("variants", "good", "applies"), "true", id="applies-string"),
        pytest.param(("variants", "good", "interface", "kinds"), ["storage"], id="unknown-kind"),
    ],
)
def test_schema_violations_are_rejected(
    tmp_path: Path, path: tuple[str, ...], value: object
) -> None:
    data = _example()
    target = data
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(fc.CheckError, match="does not match the schema"):
        _load(tmp_path, data)


def test_patch_without_reason_is_rejected(tmp_path: Path) -> None:
    data = _example()
    del data["variants"]["good"]["reason"]
    with pytest.raises(fc.CheckError):
        _load(tmp_path, data)


@pytest.mark.parametrize(
    ("variant", "key", "value", "message"),
    [
        ("overfit", "fuzz_variants", "BLOCKED", "replay, fuzz_variants, benign"),
        ("vulnerable", "replay", "BLOCKED", "replay, fuzz_variants, benign"),
        ("destructive", "benign", "pass", "replay, fuzz_variants, benign"),
        ("good", "verdict", "REJECTED", "verdict must be VERIFIED_WITHIN_BOUNDS"),
        ("overfit", "reason", "benign_test_failed", "reason"),
        ("regressing", "reason", "abi_changed", "reason"),
        ("good", "reason", "variant_found", "reason"),
        ("destructive", "reason", "special_casing", None),
        ("good", "applies", False, "applies must be true"),
    ],
)
def test_consistency_rules(
    tmp_path: Path, variant: str, key: str, value: object, message: str | None
) -> None:
    data = _example()
    data["variants"][variant][key] = value
    errors = _errors(tmp_path, data)
    if message is None:
        assert errors == []
    else:
        assert any(message in error for error in errors), errors


@pytest.mark.parametrize(
    ("variant", "interface", "message"),
    [
        ("good", {"status": "changed", "kinds": ["abi"]}, "status must be same"),
        ("regressing", {"status": "same", "kinds": []}, "status must be changed"),
        ("regressing", {"status": "changed", "kinds": []}, "non-empty exactly when changed"),
        ("good", {"status": "same", "kinds": ["abi"]}, "non-empty exactly when changed"),
        (
            "regressing",
            {"status": "changed", "kinds": ["layout", "layout"]},
            "duplicates",
        ),
    ],
)
def test_interface_rules(
    tmp_path: Path, variant: str, interface: dict[str, object], message: str
) -> None:
    data = _example()
    data["variants"][variant]["interface"] = interface
    assert any(message in error for error in _errors(tmp_path, data))


def test_fixture_class_and_solc_must_match(tmp_path: Path) -> None:
    data = _example()
    data["class"] = "dos"
    data["solc"] = "0.8.35"
    data["fixture"] = "reentrancy/other"
    errors = _errors(tmp_path, data)
    assert len(errors) == 3


# -- static rules for files --------------------------------------------------------------------

GOOD_SRC = fc.HEADER + "\n// SPDX-License-Identifier: MIT\npragma solidity 0.8.36;\ncontract A {}\n"


def test_source_file_rules() -> None:
    assert fc.solidity_errors("src/A.sol", GOOD_SRC, "0.8.36") == []
    no_header = GOOD_SRC.split("\n", 1)[1]
    assert fc.solidity_errors("src/A.sol", no_header, "0.8.36")
    assert fc.solidity_errors("test/A.t.sol", no_header, "0.8.36") == []
    ranged = GOOD_SRC.replace("pragma solidity 0.8.36;", "pragma solidity ^0.8.36;")
    assert fc.solidity_errors("src/A.sol", ranged, "0.8.36")
    inline = no_header + "/// forge-config: default.fuzz.runs = 1\n"
    assert fc.solidity_errors("test/A.t.sol", inline, "0.8.36")


@pytest.mark.parametrize(
    ("config", "ok"),
    [
        ('[profile.default]\nsolc = "0.8.36"\nffi = false\n', True),
        ('[profile.default]\nsolc = "0.8.36"\nffi = true\n', False),
        ('[profile.default]\nsolc = "0.8.36"\n', False),
        ('[profile.default]\nsolc = "0.8.35"\nffi = false\n', False),
        ('[profile.default]\nsolc = "0.8.36"\nffi = false\nfs_permissions = []\n', False),
        ('[profile.default]\nsolc = "0.8.36"\nffi = false\nremappings = ["x/=../x/"]\n', False),
        ('[profile.default]\nsolc = "0.8.36"\nffi = false\nremappings = ["x/=/opt/"]\n', False),
        ('[profile.default]\nsolc = "0.8.36"\nffi = false\nremappings = ["x/=src/x/"]\n', True),
        ('[profile.default]\nsolc = "0.8.36"\nffi = false\n[profile.ci]\nffi = true\n', False),
    ],
)
def test_foundry_toml_rules(tmp_path: Path, config: str, ok: bool) -> None:
    path = tmp_path / "foundry.toml"
    path.write_text(config)
    assert (fc.foundry_toml_errors(path, "0.8.36") == []) is ok


@pytest.mark.parametrize(
    ("numstat", "ok"),
    [
        ("3\t3\tsrc/Vault.sol\n", True),
        ("1\t0\tsrc/lib/Math.sol\n2\t2\tsrc/Vault.sol\n", True),
        ("1\t1\ttest/Vault.t.sol\n", False),
        ("1\t1\tpoc/Exploit.t.sol\n", False),
        ("1\t1\tfoundry.toml\n", False),
        ("1\t1\tsrc/../test/Vault.t.sol\n", False),
        ("0\t0\tsrc/{A.sol => B.sol}\n", False),
        ("garbage\n", False),
    ],
)
def test_patch_scope(numstat: str, ok: bool) -> None:
    assert (fc.patch_scope_errors(numstat) == []) is ok


# -- forge test output -------------------------------------------------------------------------


def _log(topic: str, address: str = TEST_CONTRACT, data: str = "0x") -> dict[str, object]:
    return {"address": address, "topics": [topic], "data": data}


def _case(
    status: str,
    *,
    reason: str | None = None,
    logs: list[dict[str, object]] | None = None,
    decoded: list[str] | None = None,
    counterexample: object = None,
    runs: int | None = None,
) -> dict[str, object]:
    kind: dict[str, object] = (
        {"Unit": {"gas": 1}} if runs is None else {"Fuzz": {"runs": runs, "mean_gas": 1}}
    )
    return {
        "status": status,
        "reason": reason,
        "counterexample": counterexample,
        "logs": logs or [],
        "decoded_logs": decoded or [],
        "kind": kind,
    }


def _cases(results: dict[str, dict[str, object]]) -> list[fc.ForgeCase]:
    text = json.dumps({"test/PoC.t.sol:PoC": {"duration": "1ms", "test_results": results}})
    return fc.parse_test_output(text)


REPLAY = "test_replay()"
FUZZ = "testFuzz_variants(uint256,uint256,uint256,uint256,uint256,uint256)"
MARKER = "ASSAY_PREDICATE|attacker_profit|eth:1->2"


def test_replay_with_predicate_is_exploited() -> None:
    cases = _cases({REPLAY: _case("Success", logs=[_log(PREDICATE)], decoded=[MARKER])})
    assert fc.replay_cell(cases, PREDICATE) == fc.Cell("EXPLOITED", MARKER)


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(_case("Success", decoded=[MARKER]), id="marker-without-event"),
        pytest.param(_case("Success", logs=[_log(PREDICATE)]), id="event-without-marker"),
        pytest.param(
            _case("Success", logs=[_log(PREDICATE, address=TARGET)], decoded=[MARKER]),
            id="event-from-the-target",
        ),
        pytest.param(_case("Success", logs=[_log(OTHER)], decoded=[MARKER]), id="other-event"),
        pytest.param(_case("Skipped"), id="skipped"),
    ],
)
def test_replay_without_trusted_predicate_is_an_error(case: dict[str, object]) -> None:
    assert fc.replay_cell(_cases({REPLAY: case}), PREDICATE).value == fc.ERROR


def test_failing_replay_is_blocked() -> None:
    cases = _cases({REPLAY: _case("Failure", reason="AssayNoPredicate()")})
    assert fc.replay_cell(cases, PREDICATE) == fc.Cell(
        "BLOCKED", "test_replay reverted: AssayNoPredicate()"
    )


def test_setup_failure_is_an_error_not_blocked() -> None:
    cases = _cases({"setUp()": _case("Failure", reason="EvmError: Revert")})
    assert fc.replay_cell(cases, PREDICATE).value == fc.ERROR
    assert fc.fuzz_cell(cases, PREDICATE, 256).value == fc.ERROR
    assert fc.benign_cell(cases).value == fc.ERROR


def test_variant_found_is_exploited() -> None:
    reason = "ASSAY_VARIANT_FOUND|attacker=0x1|balance=1|knobs=1,2,0,0"
    found = _case(
        "Failure",
        reason=reason,
        logs=[_log(PREDICATE)],
        counterexample={"Single": {}},
        runs=3,
    )
    assert fc.fuzz_cell(_cases({FUZZ: found}), PREDICATE, 256) == fc.Cell("EXPLOITED", reason)


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            _case("Failure", reason="EvmError: Revert", counterexample={}, runs=3),
            id="other-reason",
        ),
        pytest.param(
            _case("Failure", reason="ASSAY_VARIANT_FOUND|x", logs=[_log(PREDICATE)], runs=3),
            id="no-counterexample",
        ),
        pytest.param(
            _case("Failure", reason="ASSAY_VARIANT_FOUND|x", counterexample={}, runs=3),
            id="no-predicate-event",
        ),
        pytest.param(_case("Success", runs=100), id="fewer-runs"),
    ],
)
def test_unexplained_variant_results_are_errors(case: dict[str, object]) -> None:
    assert fc.fuzz_cell(_cases({FUZZ: case}), PREDICATE, 256).value == fc.ERROR


def test_variant_search_without_counterexample_is_blocked() -> None:
    cell = fc.fuzz_cell(_cases({FUZZ: _case("Success", runs=256)}), PREDICATE, 256)
    assert cell == fc.Cell("BLOCKED", "no variant in 256 runs")


def test_benign_results() -> None:
    passing = {"test_a()": _case("Success"), "test_b()": _case("Success")}
    assert fc.benign_cell(_cases(passing)).value == "pass"
    failing = {**passing, "test_c()": _case("Failure", reason="assertion failed")}
    assert fc.benign_cell(_cases(failing)) == fc.Cell("FAIL", "1 of 3 failed: test_c()")
    assert fc.benign_cell(_cases({})).value == fc.ERROR


def test_records_come_only_from_the_test_contract() -> None:
    record = {"address": TEST_CONTRACT, "topics": [RECORD, "0x" + "01" * 32], "data": "0xAB"}
    forged = {**record, "address": TARGET}
    cases = _cases({"test_a()": _case("Success", logs=[record, forged])})
    assert fc.records_of(cases, RECORD) == {
        "test/PoC.t.sol:PoC.test_a()": (("0x" + "01" * 32, "0xab"),)
    }


def test_malformed_forge_output_is_an_error() -> None:
    with pytest.raises(fc.CheckError):
        fc.parse_test_output("Compiler run failed")
    with pytest.raises(fc.CheckError):
        fc.parse_test_output(json.dumps({"suite": {"test_results": []}}))


# -- interface comparison ----------------------------------------------------------------------


def _layout(*entries: tuple[str, int, int, str]) -> str:
    types = {
        "t_uint256": {"label": "uint256", "numberOfBytes": "32", "encoding": "inplace"},
        "t_bool": {"label": "bool", "numberOfBytes": "1", "encoding": "inplace"},
        "t_address": {"label": "address", "numberOfBytes": "20", "encoding": "inplace"},
    }
    storage = [
        {"label": label, "slot": str(slot), "offset": offset, "type": kind, "astId": 1}
        for label, slot, offset, kind in entries
    ]
    return json.dumps({"storage": storage, "types": types})


def _function(name: str, inputs: list[str], mutability: str = "nonpayable") -> dict[str, object]:
    return {
        "type": "function",
        "name": name,
        "inputs": [{"name": "", "type": kind} for kind in inputs],
        "outputs": [],
        "stateMutability": mutability,
    }


def _event(name: str, indexed: list[bool]) -> dict[str, object]:
    return {
        "type": "event",
        "name": name,
        "inputs": [{"name": "", "type": "uint256", "indexed": flag} for flag in indexed],
        "anonymous": False,
    }


BASE_LAYOUT = _layout(("balance", 0, 0, "t_uint256"), ("owner", 1, 0, "t_address"))
BASE_ABI = [_function("withdraw", ["uint256"]), _event("Withdrawn", [False])]


def _interface(layout: str, abi: list[dict[str, object]]) -> fc.Interface:
    functions, events = fc.parse_abi(json.dumps(abi))
    return fc.Interface(layout=fc.parse_layout(layout), functions=functions, events=events)


BASE = _interface(BASE_LAYOUT, BASE_ABI)


@pytest.mark.parametrize(
    ("layout", "abi", "kinds", "additions"),
    [
        pytest.param(BASE_LAYOUT, BASE_ABI, (), (), id="identical"),
        pytest.param(
            _layout(
                ("balance", 0, 0, "t_uint256"),
                ("owner", 1, 0, "t_address"),
                ("locked", 2, 0, "t_bool"),
            ),
            BASE_ABI,
            (),
            ("storage locked (slot 2)",),
            id="appended-variable",
        ),
        pytest.param(
            _layout(
                ("balance", 0, 0, "t_uint256"),
                ("owner", 1, 0, "t_address"),
                ("locked", 1, 20, "t_bool"),
            ),
            BASE_ABI,
            ("layout",),
            (),
            id="packed-into-last-slot",
        ),
        pytest.param(
            _layout(
                ("locked", 0, 0, "t_bool"),
                ("balance", 1, 0, "t_uint256"),
                ("owner", 2, 0, "t_address"),
            ),
            BASE_ABI,
            ("layout",),
            (),
            id="inserted-variable",
        ),
        pytest.param(
            _layout(("balance", 0, 0, "t_uint256"), ("owner", 1, 0, "t_uint256")),
            BASE_ABI,
            ("layout",),
            (),
            id="type-change",
        ),
        pytest.param(
            _layout(("owner", 0, 0, "t_uint256"), ("balance", 1, 0, "t_address")),
            BASE_ABI,
            ("layout",),
            (),
            id="swapped-names",
        ),
        pytest.param(
            BASE_LAYOUT,
            [*BASE_ABI, _function("pause", [])],
            (),
            ("function pause()",),
            id="new-function",
        ),
        pytest.param(BASE_LAYOUT, [BASE_ABI[1]], ("abi",), (), id="removed-function"),
        pytest.param(
            BASE_LAYOUT,
            [_function("withdraw", ["uint128"]), BASE_ABI[1]],
            ("abi",),
            ("function withdraw(uint128)",),
            id="changed-signature",
        ),
        pytest.param(
            BASE_LAYOUT,
            [_function("withdraw", ["uint256"], "payable"), BASE_ABI[1]],
            ("abi",),
            (),
            id="changed-mutability",
        ),
        pytest.param(
            BASE_LAYOUT,
            [BASE_ABI[0], _event("Withdrawn", [True])],
            ("events",),
            (),
            id="changed-indexing",
        ),
        pytest.param(BASE_LAYOUT, [BASE_ABI[0]], ("events",), (), id="removed-event"),
        pytest.param(
            BASE_LAYOUT,
            [*BASE_ABI, _event("Paused", [])],
            (),
            ("event Paused()",),
            id="new-event",
        ),
        pytest.param(
            BASE_LAYOUT,
            [*BASE_ABI, {"type": "error", "name": "Nope", "inputs": []}],
            (),
            (),
            id="new-error-ignored",
        ),
    ],
)
def test_interface_comparison(
    layout: str, abi: list[dict[str, object]], kinds: tuple[str, ...], additions: tuple[str, ...]
) -> None:
    diff = fc.compare_interface(BASE, _interface(layout, abi))
    assert (diff.kinds, diff.additions) == (kinds, additions)


def test_tuple_parameters_use_canonical_types() -> None:
    abi = [
        {
            "type": "function",
            "name": "f",
            "inputs": [
                {
                    "name": "p",
                    "type": "tuple[]",
                    "components": [{"name": "a", "type": "uint256"}, {"name": "b", "type": "bool"}],
                }
            ],
            "outputs": [],
            "stateMutability": "view",
        }
    ]
    functions, _ = fc.parse_abi(json.dumps(abi))
    assert list(functions) == ["f((uint256,bool)[])"]


# -- rows --------------------------------------------------------------------------------------

RECORDS = {"t.a()": (("0x01", "0x02"),)}


def _observation(records: fc.Records = RECORDS, layout: str = BASE_LAYOUT) -> fc.Observation:
    return fc.Observation(
        applies=True,
        replay=fc.Cell("BLOCKED"),
        fuzz=fc.Cell("BLOCKED"),
        benign=fc.Cell("pass"),
        interface=_interface(layout, BASE_ABI),
        records=records,
    )


def _spec(variant: str) -> fc.VulnerableSpec:
    return fc.load_expected(EXAMPLE / "expected.json").variants.get(variant)


INVARIANT = "invariant_assay()"


def _invariant_case(status: str, runs: int, reasons: list[str]) -> dict[str, object]:
    case = _case(status)
    case["kind"] = {"Invariant": {"runs": runs, "calls": runs * 10, "reverts": 0}}
    case["invariant_failures"] = [
        {"kind": "predicate", "name": "invariant_assay", "reason": item} for item in reasons
    ]
    return case


def test_the_invariant_cell_reads_broken_holding_and_absent_invariants() -> None:
    broken = _cases({INVARIANT: _invariant_case("Failure", 3, ["ASSAY_INVARIANT_BROKEN|x"])})
    assert fc.invariant_cell(broken, 64) == fc.Cell("BROKEN", "ASSAY_INVARIANT_BROKEN|x")
    holding = _cases({INVARIANT: _invariant_case("Success", 64, [])})
    assert fc.invariant_cell(holding, 64).value == "holds"
    assert fc.invariant_cell(holding, 65).value == fc.ERROR
    other = _cases({INVARIANT: _invariant_case("Failure", 3, ["panic: overflow"])})
    assert fc.invariant_cell(other, 64).value == fc.ERROR
    assert fc.invariant_cell(_cases({REPLAY: _case("Success")}), 64).value == fc.NOT_RUN


@pytest.mark.parametrize(
    ("variant", "value", "matches"),
    [
        ("vulnerable", "BROKEN", True),
        ("vulnerable", "holds", False),
        ("good", "holds", True),
        ("good", "BROKEN", False),
        ("overfit", "BROKEN", True),
        ("overfit", "holds", True),
        ("destructive", fc.ERROR, False),
        ("good", fc.NOT_RUN, True),
    ],
)
def test_the_invariant_must_break_on_the_vulnerable_revision_and_hold_under_good(
    variant: str, value: str, matches: bool
) -> None:
    observed = _observation()
    if variant == "vulnerable":
        observed.replay = observed.fuzz = fc.Cell("EXPLOITED")
    elif variant == "overfit":
        observed.fuzz = fc.Cell("EXPLOITED")
    elif variant == "destructive":
        observed.benign = fc.Cell("FAIL")
    observed.invariant = fc.Cell(value, "detail")
    row = fc.build_row(variant, _spec(variant), observed, _observation())
    invariant_problems = [item for item in row.problems if item.startswith("invariant")]
    assert (not invariant_problems) is matches, row.problems


def test_poc_holds_at_most_one_invariant_and_test_holds_none() -> None:
    invariant = "contract I is AssayInvariant {}"
    sources = {
        "poc/P.t.sol": "contract P is AssayPoC {}",
        "poc/I.t.sol": invariant,
        "test/T.t.sol": "recordBehavior(",
    }
    assert fc.directory_role_errors(sources) == []
    two = {**sources, "poc/J.t.sol": "contract J is AssayInvariant {}"}
    assert any("at most one" in item for item in fc.directory_role_errors(two))
    in_test = {**sources, "test/I.t.sol": invariant}
    assert any("test/ must not" in item for item in fc.directory_role_errors(in_test))


def test_matching_row() -> None:
    row = fc.build_row("good", _spec("good"), _observation(), _observation())
    assert row.matches
    assert (row.interface, row.records) == ("same", "same")


def test_changed_records_reject_a_verified_patch_only() -> None:
    changed = _observation(records={"t.a()": (("0x01", "0x03"),)})
    row = fc.build_row("good", _spec("good"), changed, _observation())
    assert not row.matches
    assert row.records == "changed"
    inserted = _layout(("locked", 0, 0, "t_bool"), ("balance", 1, 0, "t_uint256"))
    regressing = _observation(records=changed.records or {}, layout=inserted)
    assert fc.build_row("regressing", _spec("regressing"), regressing, _observation()).matches


def test_errors_and_unapplied_patches_never_match() -> None:
    broken = fc.build_row("good", _spec("good"), fc.CheckError("boom"), _observation())
    assert not broken.matches
    unapplied = fc.build_row("good", _spec("good"), fc.Observation(applies=False), _observation())
    assert not unapplied.matches
    assert unapplied.applies == "no"
    no_baseline = fc.build_row("good", _spec("good"), _observation(), None)
    assert not no_baseline.matches


# -- stricter static rules ---------------------------------------------------------------------


def test_duplicate_keys_are_rejected(tmp_path: Path) -> None:
    text = (EXAMPLE / "expected.json").read_text()
    path = tmp_path / "expected.json"
    path.write_text(
        text.replace('"schema_version": 1,', '"schema_version": 1, "schema_version": 1,')
    )
    with pytest.raises(fc.CheckError, match="duplicate keys: schema_version"):
        fc.load_expected(path)


@pytest.mark.parametrize(
    ("relative", "line", "ok"),
    [
        ("src/Vault.sol", 'import {Math} from "./lib/Math.sol";', True),
        ("src/lib/Math.sol", 'import "../Vault.sol";', True),
        ("src/Vault.sol", 'import {Test} from "forge-std/Test.sol";', False),
        ("src/Vault.sol", 'import {console} from "forge-std/console.sol";', False),
        ("src/Vault.sol", 'import "../test/Helper.sol";', False),
        ("test/Vault.t.sol", 'import {Vault} from "../src/Vault.sol";', True),
        ("test/Vault.t.sol", 'import {Helper} from "./Helper.sol";', True),
        ("test/Vault.t.sol", 'import {Test, console} from "forge-std/Test.sol";', True),
        ("test/Vault.t.sol", 'import {AssayExploit} from "assay/AssayExploit.sol";', True),
        ("test/Vault.t.sol", "import {AssayExploit} from 'assay/AssayExploit.sol';", True),
        ("test/Vault.t.sol", 'import "../poc/Exploit.t.sol";', False),
        ("test/Vault.t.sol", 'import "../../outside/X.sol";', False),
        ("test/Vault.t.sol", 'import "lib/solmate/ERC20.sol";', False),
        ("poc/Exploit.t.sol", 'import {Vault} from "../src/Vault.sol";', True),
        ("poc/Exploit.t.sol", 'import {\n    AssayPoC\n} from "assay/AssayExploit.sol";', True),
        ("poc/Exploit.t.sol", 'import "../test/Vault.t.sol";', False),
        ("poc/Exploit.t.sol", 'import "assay/Other.sol";', False),
    ],
)
def test_import_rules(relative: str, line: str, ok: bool) -> None:
    assert (fc.import_errors(relative, line + "\ncontract A {}\n") == []) is ok


POC = "contract P is AssayPoC {}\n"
BENIGN = "contract T is AssayExploit { function test_a() public { recordBehavior(1, ''); } }\n"


@pytest.mark.parametrize(
    ("sources", "message"),
    [
        ({"poc/P.t.sol": POC, "test/T.t.sol": BENIGN}, None),
        ({"poc/P.t.sol": "contract P {}\n", "test/T.t.sol": BENIGN}, "found 0"),
        ({"poc/P.t.sol": POC + POC, "test/T.t.sol": BENIGN}, "found 2"),
        ({"poc/P.t.sol": POC, "test/T.t.sol": BENIGN + POC}, "must not contain"),
        ({"poc/P.t.sol": POC, "test/T.t.sol": "contract T {}\n"}, "never call recordBehavior"),
    ],
)
def test_directory_roles(sources: dict[str, str], message: str | None) -> None:
    errors = fc.directory_role_errors(sources)
    if message is None:
        assert errors == []
    else:
        assert any(message in error for error in errors), errors


def test_binary_patches_are_rejected() -> None:
    assert fc.patch_scope_errors("-\t-\tsrc/Image.bin\n")


# -- git apply on a copy -----------------------------------------------------------------------


def _copy(tmp_path: Path) -> Path:
    work = tmp_path / "work"
    for directory in ("src", "test", "poc"):
        shutil.copytree(EXAMPLE / directory, work / directory)
    return work


def test_patch_applies_to_the_copy(tmp_path: Path) -> None:
    work = _copy(tmp_path)
    before = (work / "src" / "Vault.sol").read_text()
    assert fc.apply_patch(work, (EXAMPLE / "patches" / "good.diff").read_bytes())
    assert (work / "src" / "Vault.sol").read_text() != before
    assert (EXAMPLE / "src" / "Vault.sol").read_text() == before


def test_patch_that_does_not_apply(tmp_path: Path) -> None:
    work = _copy(tmp_path)
    patch = (EXAMPLE / "patches" / "good.diff").read_text().replace("available - amount", "x")
    assert not fc.apply_patch(work, patch.encode())


def test_patch_outside_src_is_a_broken_fixture(tmp_path: Path) -> None:
    work = _copy(tmp_path)
    patch = (EXAMPLE / "patches" / "good.diff").read_text().replace("src/Vault.sol", "test/X.sol")
    (work / "test" / "X.sol").write_text((work / "src" / "Vault.sol").read_text())
    with pytest.raises(fc.CheckError, match="outside src/"):
        fc.apply_patch(work, patch.encode())


def test_user_git_configuration_does_not_change_the_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "gitconfig"
    config.write_text("[apply]\n\twhitespace = error\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    work = _copy(tmp_path)
    patch = (EXAMPLE / "patches" / "good.diff").read_text()
    patch = patch.replace(
        "+        totalDeposits -= amount;\n", "+        totalDeposits -= amount; \n"
    )
    assert fc.apply_patch(work, patch.encode())


# -- rows and command line ---------------------------------------------------------------------


def test_benign_tests_of_the_vulnerable_revision_must_record() -> None:
    observed = _observation(records={"t.a()": (("0x01", "0x02"),), "t.b()": ()})
    observed.replay = observed.fuzz = fc.Cell("EXPLOITED")
    row = fc.build_row("vulnerable", _spec("vulnerable"), observed, None)
    assert row.problems == ["benign tests that record nothing: t.b()"]


@pytest.mark.parametrize(
    "argv",
    [
        ["--fixtures", "/nonexistent/fixtures"],
        ["--only", "reentrancy/missing"],
        ["--fuzz-runs", "0"],
        ["--fuzz-seed", "seed"],
    ],
)
def test_invalid_arguments_exit_with_2_before_running_anything(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert fc.main(argv) == 2
    assert capsys.readouterr().err.startswith("error:")


def _tree(root: Path, *paths: str) -> Path:
    """Create directories (paths ending in `/`) and small files under `root`."""
    for path in paths:
        target = root / path
        if path.endswith("/"):
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("x")
    return root


def test_fixtures_are_discovered_two_levels_down(tmp_path: Path) -> None:
    _tree(
        tmp_path,
        "reentrancy/b/",
        "reentrancy/a/",
        "dos/payout_loop/",
        "reentrancy/.hidden/",
        ".cache/x/",
        ".DS_Store",
    )
    assert fc.discover_fixtures(tmp_path) == ["dos/payout_loop", "reentrancy/a", "reentrancy/b"]
    assert fc.layout_errors(tmp_path) == []


@pytest.mark.parametrize(
    ("paths", "message"),
    [
        (["notes.md"], "notes.md: not a class directory"),
        (["reentrancy/a/", "reentrancy/notes.md"], "reentrancy/notes.md: not a fixture directory"),
        (["reentrancy_old/a/"], "reentrancy_old/: not a class id"),
        (["rounding/"], "rounding/: holds no fixture"),
    ],
)
def test_foreign_entries_in_the_fixtures_root_are_reported(
    tmp_path: Path, paths: list[str], message: str
) -> None:
    _tree(tmp_path, *paths)
    errors = fc.layout_errors(tmp_path)
    assert len(errors) == 1
    assert errors[0].startswith(message)


def test_symlinks_in_the_fixtures_root_are_reported_not_followed(tmp_path: Path) -> None:
    _tree(tmp_path, "reentrancy/a/")
    (tmp_path / "reentrancy" / "link").symlink_to(tmp_path / "reentrancy" / "a")
    (tmp_path / "dos").symlink_to(tmp_path / "reentrancy")
    assert fc.discover_fixtures(tmp_path) == ["reentrancy/a"]
    assert fc.layout_errors(tmp_path) == [
        "dos: not a class directory",
        "reentrancy/link: not a fixture directory",
    ]


def test_summary_has_one_line_per_fixture() -> None:
    good = fc.build_row("good", _spec("good"), _observation(), _observation())
    bad = fc.build_row("overfit", _spec("overfit"), _observation(), _observation())
    reports = [
        fc.FixtureReport("reentrancy/single_function", [good] * 5, []),
        fc.FixtureReport("dos/payout_loop", [good] * 4 + [bad], []),
    ]
    assert fc.render_summary(reports) == [
        "summary",
        "  reentrancy/single_function  5/5 rows  match",
        "  dos/payout_loop             4/5 rows  MISMATCH",
    ]
    assert fc.render_summary([]) == []


def test_render_lists_rows_problems_and_details() -> None:
    good = fc.build_row("good", _spec("good"), _observation(), _observation())
    bad = fc.build_row("overfit", _spec("overfit"), _observation(), _observation())
    report = fc.FixtureReport("reentrancy/single_function", [good, bad], [])
    settings = fc.Settings(fuzz_seed="0x1", fuzz_runs=256)
    lines = fc.render(report, settings, verbose=False)
    assert lines[0] == (
        "reentrancy/single_function  (fuzz seed 0x1, 256 runs; invariant 64 runs of depth 25)"
    )
    assert lines[1].split() == list(fc.COLUMNS)
    assert lines[2].split() == [
        "good",
        "yes",
        "BLOCKED",
        "BLOCKED",
        "pass",
        "-",
        "same",
        "same",
        "match",
    ]
    assert lines[3].split()[-1] == "MISMATCH"
    assert lines[4] == "  overfit: fuzz_variants: expected EXPLOITED, observed BLOCKED"
    assert report.matched == 1


# -- the held-out root ---------------------------------------------------------------------------


def test_fixtures_of_other_roots_are_named_after_their_root(tmp_path: Path) -> None:
    assert fc.fixture_label(fc.FIXTURES_DIR, "dos/payout_loop") == "dos/payout_loop"
    assert fc.fixture_label(fc.HELDOUT_DIR, "dos/payout_loop") == "heldout:dos/payout_loop"
    assert fc.fixture_label(tmp_path / "extra", "dos/x") == "extra:dos/x"


def test_the_heldout_root_is_below_bench() -> None:
    assert fc.HELDOUT_DIR == fc.REPO_ROOT / "bench" / "heldout"


HELDOUT_FIXTURES = fc.discover_fixtures(fc.HELDOUT_DIR)
HELDOUT_EXPECTED = (
    "reentrancy/cross_function",
    "access_control/reinitializable",
    "unchecked_call/token_return",
    "signature_replay/cross_chain",
    "delegatecall/strategy_registry",
    "oracle_manipulation/donation_price",
    "dos/forced_ether",
    "rounding/fee_floor",
)


def test_heldout_fixtures_exist_one_per_class() -> None:
    assert set(HELDOUT_EXPECTED) == set(HELDOUT_FIXTURES)
    classes = [fixture_id.split("/", 1)[0] for fixture_id in HELDOUT_FIXTURES]
    assert sorted(classes) == sorted(fc.CLASS_IDS)


def test_heldout_fixtures_have_other_names_than_development_fixtures() -> None:
    assert not set(HELDOUT_FIXTURES) & set(FIXTURES)


def test_the_heldout_root_holds_only_fixtures() -> None:
    assert fc.layout_errors(fc.HELDOUT_DIR) == []


@pytest.mark.parametrize("fixture_id", HELDOUT_FIXTURES)
def test_heldout_fixture_passes_the_static_checks(fixture_id: str) -> None:
    assert fc.static_errors(fc.HELDOUT_DIR / fixture_id, fixture_id, fc.pinned_solc()) == []


@pytest.mark.parametrize("fixture_id", HELDOUT_FIXTURES)
def test_heldout_expected_json_matches_the_schema(fixture_id: str) -> None:
    fixture_dir = fc.HELDOUT_DIR / fixture_id
    expected = fc.load_expected(fixture_dir / "expected.json")
    assert fc.expected_errors(expected, fixture_id, fc.pinned_solc()) == []
    path, name = expected.contract.split(":")
    assert f"contract {name} " in (fixture_dir / "src" / path).read_text()
    for label in fc.PATCH_LABELS:
        assert (fixture_dir / "patches" / f"{label}.diff").read_bytes().strip(), label
    readme = (fixture_dir / "README.md").read_text()
    assert "Intentionally vulnerable" in readme.splitlines()[2]


def test_heldout_fixtures_share_no_source_file_with_development_fixtures() -> None:
    def digests(root: Path, ids: list[str]) -> dict[bytes, str]:
        found: dict[bytes, str] = {}
        for fixture_id in ids:
            for path in sorted((root / fixture_id / "src").glob("*.sol")):
                found[path.read_bytes()] = f"{fixture_id}/{path.name}"
        return found

    dev = digests(fc.FIXTURES_DIR, FIXTURES)
    held = digests(fc.HELDOUT_DIR, HELDOUT_FIXTURES)
    assert not set(dev) & set(held)
