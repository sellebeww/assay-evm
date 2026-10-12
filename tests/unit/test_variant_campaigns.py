"""Campaign profiles, seed derivation, generated replay tests and bounds statements (no Docker)."""

import hashlib
import json
import re
import tomllib
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from assay.analyzers.foundry import ForgeCall, parse_test_output
from assay.ledger import RevisionKind
from assay.oracles.variant import (
    PROFILE_NAMES,
    ModeBounds,
    ProfileError,
    VariantBounds,
    bounds_statement,
    derive_seeds,
    profile,
)
from assay.oracles.variant.poc import (
    BaseContract,
    FuzzInput,
    PocRejected,
    ReplayCall,
    base_contract,
    fuzz_input,
    render_fuzz,
    render_invariant,
    replay_calls,
    solc_version,
)
from assay.oracles.variant.profiles import parse_profiles
from assay.sandbox import SandboxRunner

ROOT = Path(__file__).resolve().parents[2]
PROFILES = ROOT / "src" / "assay" / "oracles" / "variant" / "profiles.toml"
HARNESS = (ROOT / "solidity" / "AssayExploit.sol").read_bytes()
BASE = BaseContract(name="VaultReentrancyPoC", path="VaultReentrancy.t.sol")
CALLDATA = "0xa167c778" + "".join(f"{value:064x}" for value in (1, 2, 3, 4, 5, 2**256 - 1))


# -- profiles and seeds ------------------------------------------------------------------------


def test_the_profiles_file_defines_three_growing_profiles() -> None:
    data = tomllib.loads(PROFILES.read_text())
    assert data["default"] == "standard"
    quick, standard, thorough = (profile(name) for name in PROFILE_NAMES)
    for field in ("seeds", "runs_per_seed", "invariant_runs", "invariant_depth"):
        assert getattr(quick, field) <= getattr(standard, field) <= getattr(thorough, field)
    assert quick.campaign_timeout_s <= standard.campaign_timeout_s <= thorough.campaign_timeout_s
    assert standard.seeds == 3
    assert standard.runs_per_seed == 256
    with pytest.raises(ProfileError, match="unknown profile"):
        profile("fast")


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ("seeds = 1\n", "seeds = 0\n", "malformed"),
        ("seeds = 1\n", "seeds = 1\nshrink = 3\n", "malformed"),
        ('default = "standard"', 'default = "quick"', "default profile"),
        ("[profiles.thorough]", "[profiles.extreme]", "malformed"),
        ("campaign_timeout_s = 180", "campaign_timeout_s = 1", "malformed"),
    ],
)
def test_a_malformed_profiles_file_is_refused(old: str, new: str, message: str) -> None:
    text = PROFILES.read_text()
    assert old in text
    with pytest.raises(ProfileError, match=message):
        parse_profiles(text.replace(old, new, 1))


def test_seeds_are_derived_from_the_base_seed_by_a_fixed_rule() -> None:
    seeds = derive_seeds("0x1", 3)
    expected = tuple(
        "0x"
        + hashlib.sha256(f"assay-variant-seed-v1\nsearch\n1\n{index}".encode()).hexdigest()[:16]
        for index in (1, 2, 3)
    )
    assert seeds == expected
    assert derive_seeds("0x1", 5)[:3] == seeds, "more seeds extend the same sequence"
    assert derive_seeds("0x2", 3) != seeds
    assert derive_seeds("0x1", 3, family="heldout") != seeds
    assert all(re.fullmatch(r"0x[0-9a-f]{16}", seed) for seed in seeds)


@given(base=st.integers(0, 2**64 - 1), count=st.integers(1, 64))
def test_seed_derivation_is_deterministic_and_well_formed(base: int, count: int) -> None:
    first = derive_seeds(f"0x{base:x}", count)
    assert first == derive_seeds(f"0x{base:x}", count)
    assert len(first) == count
    assert all(re.fullmatch(r"0x[0-9a-f]{16}", seed) for seed in first)


@pytest.mark.parametrize("base", ["1", "0x", "0X1", "0x1g", "0x" + "1" * 17, "0x1\n"])
def test_a_malformed_base_seed_or_count_is_refused(base: str) -> None:
    with pytest.raises(ProfileError):
        derive_seeds(base, 3)
    with pytest.raises(ProfileError):
        derive_seeds("0x1", 0)
    with pytest.raises(ProfileError):
        derive_seeds("0x1", 3, family="Bad Family")


# -- generated replay tests ----------------------------------------------------------------------


def test_a_fuzz_replay_test_holds_only_numbers_from_the_calldata() -> None:
    source = render_fuzz(BASE, fuzz_input(CALLDATA), solc_version(HARNESS))
    assert source.startswith("// SPDX-License-Identifier: MIT\npragma solidity 0.8.36;\n")
    assert 'import {VaultReentrancyPoC} from "./VaultReentrancy.t.sol";' in source
    assert "contract AssayVariantPoC is VaultReentrancyPoC {" in source
    assert "    function test_variant() public {" in source
    assert f"            0x{1:064x}," in source
    assert f"uint256(0x{2**256 - 1:064x})]" in source
    # Every hex literal is 64 digits long, so none can be read as an address literal.
    literals = re.findall(r"0x[0-9a-fA-F]+", source)
    assert literals
    assert {len(item) for item in literals} == {66}


def test_an_invariant_replay_test_replays_each_call_from_numbers() -> None:
    calls = replay_calls(
        [
            ForgeCall(
                calldata="0x133eebca" + f"{4515:064x}" + f"{401:064x}",
                args="4515, 401",
                sender="0x" + "ab" * 20,
                target="0x2e234dae75c793f67a35089c9d99245e1c58470b",
            ),
            ForgeCall(
                calldata="0x01020304", args=None, sender="0x" + "00" * 20, target="0x" + "11" * 20
            ),
        ]
    )
    base = BaseContract(name="VaultSolvencyInvariant", path="VaultSolvency.t.sol")
    source = render_invariant(base, calls, "0.8.36")
    assert source.count("assayReplayCall(") == 2
    assert f"address(uint160(uint256(0x{int('ab' * 20, 16):064x})))" in source
    assert "bytes4(uint32(0x133eebca))," in source
    assert f"uint256(0x{401:064x})" in source
    assert "bytes4(uint32(0x01020304))\n" in source
    assert source.rstrip().endswith("assayCheckInvariant();\n    }\n}")
    assert "4515, 401" not in source


@pytest.mark.parametrize(
    "suite",
    [
        "test/X.t.sol:Bad Name",
        'test/X.t.sol:A"; selfdestruct',
        "test/X.t.sol:",
        "src/X.sol:Name",
        "test/../src/X.sol:Name",
        "test/X.t.sol",
        "test/a b.t.sol:Name",
        'test/x".t.sol:Name',
        "test/X.txt:Name",
        "test/AssayVariantPoC.t.sol:Name",
        "test/X.t.sol:AssayVariantPoC",
        "test/X.t.sol:Name\nimport",
    ],
)
def test_a_suspicious_contract_name_or_file_is_rejected(suite: str) -> None:
    with pytest.raises(PocRejected):
        base_contract(suite)


def test_a_plain_contract_name_and_nested_file_are_accepted() -> None:
    assert base_contract("test/sub/Exploit.t.sol:ExploitPoC") == BaseContract(
        "ExploitPoC", "sub/Exploit.t.sol"
    )


@pytest.mark.parametrize(
    "calldata",
    [
        "0x" + "00" * 195,
        "0x" + "00" * 197,
        CALLDATA.upper().replace("0X", "0x"),
        CALLDATA + "0",
        'x"); selfdestruct(payable(0)); //',
        "",
    ],
)
def test_malformed_fuzz_calldata_is_rejected(calldata: str) -> None:
    with pytest.raises(PocRejected):
        fuzz_input(calldata)


@pytest.mark.parametrize(
    "call",
    [
        ForgeCall(calldata="0x0102", args=None, sender="0x" + "00" * 20, target="0x" + "11" * 20),
        ForgeCall(
            calldata="0x01020304" + "00" * 31,
            args=None,
            sender="0x" + "00" * 20,
            target="0x" + "11" * 20,
        ),
        ForgeCall(calldata="0x01020304", args=None, sender=None, target="0x" + "11" * 20),
        ForgeCall(calldata="0x01020304", args=None, sender="0x" + "00" * 20, target="0xzz"),
        ForgeCall(
            calldata="0x01020304",
            args=None,
            sender="0x" + "00" * 20,
            target="0x" + "11" * 20,
            warp="5",
        ),
        ForgeCall(
            calldata="0x01020304",
            args=None,
            sender="0x" + "00" * 20,
            target="0x" + "11" * 20,
            roll="0x1",
        ),
        ForgeCall(
            calldata="0x01020304" + "00" * 32 * 65,
            args=None,
            sender="0x" + "00" * 20,
            target="0x" + "11" * 20,
        ),
    ],
)
def test_a_sequence_call_that_cannot_be_replayed_is_rejected(call: ForgeCall) -> None:
    with pytest.raises(PocRejected):
        replay_calls([call])


def test_empty_or_too_long_sequences_and_bad_values_are_rejected() -> None:
    with pytest.raises(PocRejected):
        replay_calls([])
    call = ForgeCall(
        calldata="0x01020304", args=None, sender="0x" + "00" * 20, target="0x" + "11" * 20
    )
    with pytest.raises(PocRejected):
        replay_calls([call] * 257)
    with pytest.raises(PocRejected):
        render_fuzz(BASE, FuzzInput(2**256, 0, (0, 0, 0, 0)), "0.8.36")
    with pytest.raises(PocRejected):
        render_fuzz(BASE, FuzzInput(-1, 0, (0, 0, 0, 0)), "0.8.36")
    with pytest.raises(PocRejected):
        render_fuzz(BASE, FuzzInput(True, 0, (0, 0, 0, 0)), "0.8.36")  # type: ignore[arg-type]
    with pytest.raises(PocRejected):
        render_invariant(BASE, [ReplayCall(0, 0, 2**32, ())], "0.8.36")
    with pytest.raises(PocRejected):
        render_fuzz(BaseContract("A{", "X.t.sol"), FuzzInput(0, 0, (0, 0, 0, 0)), "0.8.36")
    with pytest.raises(PocRejected):
        render_fuzz(BaseContract("A", '../X";.sol'), FuzzInput(0, 0, (0, 0, 0, 0)), "0.8.36")
    with pytest.raises(PocRejected):
        render_fuzz(BASE, FuzzInput(0, 0, (0, 0, 0, 0)), "^0.8.0")


def test_the_solc_version_comes_from_the_exact_harness_pragma() -> None:
    assert solc_version(HARNESS) == "0.8.36"
    with pytest.raises(PocRejected):
        solc_version(b"pragma solidity ^0.8.0;\n")
    with pytest.raises(PocRejected):
        solc_version(b"pragma solidity 0.8.36;\npragma solidity 0.8.35;\n")


@given(values=st.lists(st.integers(0, 2**256 - 1), min_size=6, max_size=6))
def test_any_valid_input_gives_a_source_of_numbers_and_fixed_text(values: list[int]) -> None:
    calldata = "0xa167c778" + "".join(f"{value:064x}" for value in values)
    source = render_fuzz(BASE, fuzz_input(calldata), "0.8.36")
    template = re.sub(r"0x[0-9a-f]{64}", "<n>", source)
    assert template == re.sub(
        r"0x[0-9a-f]{64}", "<n>", render_fuzz(BASE, FuzzInput(0, 0, (0, 0, 0, 0)), "0.8.36")
    )


# -- parsing and running -----------------------------------------------------------------------


def test_forge_invariant_failures_are_parsed_strictly() -> None:
    raw = {
        "test/S.t.sol:S": {
            "test_results": {
                "invariant_assay()": {
                    "status": "Failure",
                    "reason": None,
                    "invariant_failures": [
                        {
                            "kind": "predicate",
                            "name": "invariant_assay",
                            "reason": "ASSAY_INVARIANT_BROKEN|x",
                            "counterexample": {
                                "Sequence": [
                                    5,
                                    [
                                        {
                                            "sender": "0x" + "AB" * 20,
                                            "addr": "0x" + "11" * 20,
                                            "calldata": "0x01020304",
                                            "raw_args": "",
                                            "warp": None,
                                            "roll": None,
                                        }
                                    ],
                                ]
                            },
                            "persisted_path": "/work/scratch/x",
                        }
                    ],
                    "logs": [],
                    "decoded_logs": [],
                    "kind": {"Invariant": {"runs": 2, "calls": 9, "reverts": 0}},
                }
            }
        }
    }
    (suite,) = parse_test_output(json.dumps(raw))
    (failure,) = suite.tests[0].invariant_failures
    assert failure.reason == "ASSAY_INVARIANT_BROKEN|x"
    assert failure.counterexample is not None
    assert failure.counterexample.unshrunk_length == 5
    assert failure.counterexample.calls[0].sender == "0x" + "ab" * 20
    bad = json.loads(json.dumps(raw))
    bad["test/S.t.sol:S"]["test_results"]["invariant_assay()"]["invariant_failures"][0][
        "counterexample"
    ] = {"Sequence": [[]], "Other": 1}
    with pytest.raises(ValueError, match="validation"):
        parse_test_output(json.dumps(bad))


def test_a_run_can_have_its_own_wall_clock_limit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    project, scratch = tmp_path / "project", tmp_path / "scratch"
    project.mkdir()
    scratch.mkdir()
    runner = SandboxRunner(docker="/nonexistent/docker")
    for value in (0, -1, 86_401):
        with pytest.raises(ValueError, match="timeout_s"):
            runner.run(
                ("forge", "build", "--json"),
                project_dir=project,
                scratch_dir=scratch,
                timeout_s=value,
            )
    seen: list[float] = []

    def execute(self: SandboxRunner, run_args: list[str], **fields: object) -> str:
        seen.append(fields["timeout_s"])  # type: ignore[arg-type]
        return "done"

    monkeypatch.setattr(SandboxRunner, "image_id", lambda self: "sha256:" + "0" * 64)
    monkeypatch.setattr(SandboxRunner, "docker_run_args", lambda self, *args, **kwargs: [])
    monkeypatch.setattr(SandboxRunner, "_execute", execute)
    argv = ("forge", "build", "--json")
    runner.run(argv, project_dir=project, scratch_dir=scratch)
    runner.run(argv, project_dir=project, scratch_dir=scratch, timeout_s=900)
    assert seen == [600.0, 900]


# -- bounds statements -------------------------------------------------------------------------


def _bounds(**patched: object) -> VariantBounds:
    def mode(revision: RevisionKind, name: str, **fields: object) -> ModeBounds:
        values: dict[str, object] = {
            "revision": revision,
            "mode": name,
            "available": True,
            "seeds_run": 3,
            "found_at_seed": None,
            "runs": 768 if name == "fuzz" else 192,
            "calls": None if name == "fuzz" else 1920,
        }
        values.update(fields)
        return ModeBounds.model_validate(values)

    return VariantBounds(
        profile="standard",
        base_seed="0x1",
        seeds=derive_seeds("0x1", 3),
        runs_per_seed=256,
        invariant_runs=64,
        invariant_depth=25,
        campaign_timeout_s=300,
        searches=(
            mode(RevisionKind.VULNERABLE, "fuzz", seeds_run=1, found_at_seed=1, runs=2),
            mode(
                RevisionKind.VULNERABLE, "invariant", seeds_run=1, found_at_seed=1, runs=3, calls=40
            ),
            mode(RevisionKind.PATCHED, "fuzz", **patched),
            mode(RevisionKind.PATCHED, "invariant"),
        ),
        confirmation_replays=3,
        replays_reproduced=None,
    )


def test_a_clean_search_states_exactly_what_ran_and_denies_more() -> None:
    statement = bounds_statement(_bounds())
    assert statement == (
        f"profile standard, base seed 0x1, seeds {', '.join(derive_seeds('0x1', 3))}; "
        "on the patched revision: fuzz: 3 of 3 seeds of 256 runs (768 runs), no variant found; "
        "invariant: 3 of 3 seeds of 64 sequences of up to 25 calls (192 sequences, 1920 calls), "
        "no variant found; no variant found within these runs; this is not a proof of absence"
    )


def test_the_statement_uses_the_runs_that_ran_not_the_configured_ones() -> None:
    statement = bounds_statement(_bounds(seeds_run=2, runs=300))
    assert "fuzz: 2 of 3 seeds of 256 runs (300 runs), stopped early" in statement
    assert "768 runs" not in statement


def test_a_found_variant_names_its_seed_and_its_confirmation() -> None:
    bounds = _bounds(seeds_run=2, found_at_seed=2, runs=300).model_copy(
        update={"replays_reproduced": 3}
    )
    statement = bounds_statement(bounds)
    assert (
        "fuzz: variant found with seed 2 of 3 (2 seeds of 256 runs, 300 runs), "
        "confirmed by 3 of 3 replays" in statement
    )
    assert "this is not a proof of absence" not in statement


def test_a_mode_that_was_ineffective_or_absent_is_named_as_such() -> None:
    bounds = _bounds()
    searches = list(bounds.searches)
    searches[1] = searches[1].model_copy(update={"found_at_seed": None})
    searches[3] = searches[3].model_copy(update={"available": False, "seeds_run": 0})
    statement = bounds_statement(bounds.model_copy(update={"searches": tuple(searches)}))
    assert "invariant: no invariant in the PoC directory" in statement
    unavailable = list(bounds.searches)
    unavailable[1] = unavailable[1].model_copy(update={"found_at_seed": None})
    statement = bounds_statement(bounds.model_copy(update={"searches": tuple(unavailable)}))
    assert "not counted: this mode found nothing on the vulnerable revision" in statement
