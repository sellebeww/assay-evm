"""The shared Solidity harness (solidity/AssayExploit.sol) against the real runner image.

tests/data/harness/test/AssayExploit.t.sol holds two test contracts that check the harness
directly, and small PoC contracts that forge also runs on their own, the way a fixture's PoC
runs. The run tree has the layout of the fixture checker: the harness under `assay/`.
"""

import re
import shutil
from pathlib import Path

import pytest

from assay.analyzers import foundry
from assay.analyzers.foundry import ForgeTestCase
from assay.ingest import create_snapshot
from assay.sandbox import SandboxRunner

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("runner")]

ROOT = Path(__file__).resolve().parents[2]
HARNESS_TESTS = ROOT / "tests" / "data" / "harness" / "test"
REPLAY = "test_replay()"
FUZZ = "testFuzz_variants(uint256,uint256,uint256,uint256,uint256,uint256)"
VARIANT = re.compile(
    r"ASSAY_VARIANT_FOUND\|attacker=0x[0-9a-fA-F]{40}\|balance=[0-9]+\|knobs=[0-9]+(,[0-9]+){3}"
)

Results = dict[str, dict[str, ForgeTestCase]]


@pytest.fixture(scope="module")
def results(runner: SandboxRunner, tmp_path_factory: pytest.TempPathFactory) -> Results:
    project = tmp_path_factory.mktemp("harness") / "project"
    shutil.copytree(HARNESS_TESTS, project / "test")
    (project / "assay").mkdir()
    for path in sorted((ROOT / "solidity").glob("*.sol")):
        shutil.copyfile(path, project / "assay" / path.name)
    snapshot = create_snapshot(project, project.parent / "snapshot")
    run = foundry.test(runner, snapshot.tree_dir)
    return {
        suite.name.removeprefix("test/AssayExploit.t.sol:"): {
            case.name: case for case in suite.tests
        }
        for suite in run.suites
    }


@pytest.mark.parametrize("contract", ["AssayHarnessTest", "AssayPoCModesTest"])
def test_direct_tests_of_the_harness_pass(results: Results, contract: str) -> None:
    cases = results[contract]
    assert len(cases) >= 8
    failed = {name: case.reason for name, case in cases.items() if case.status != "success"}
    assert failed == {}


def test_marker_lines(results: Results) -> None:
    assert results["AssayHarnessTest"]["test_markers()"].logs == (
        "ASSAY_PREDICATE|attacker_profit|eth:1->2",
        "ASSAY_PREDICATE|victim_loss|token.A:5->3",
        "ASSAY_PREDICATE|unauthorized_role_change|owner:"
        "0x0000000000000000000000000000000000000001->0x0000000000000000000000000000000000000002",
        "ASSAY_PREDICATE|invariant_broken|solvency",
        "ASSAY_REC|balances:alice|0x00ff",
    )


@pytest.mark.parametrize("contract", ["ProfitPoC", "LeakyPrankPoC", "DefaultsPoC"])
def test_an_effective_poc_replays_and_its_variant_search_fails(
    results: Results, contract: str
) -> None:
    replay, fuzz = results[contract][REPLAY], results[contract][FUZZ]
    assert replay.status == "success"
    assert any(line.startswith("ASSAY_PREDICATE|attacker_profit|") for line in replay.logs)
    assert fuzz.status == "failure"
    assert fuzz.reason is not None
    assert VARIANT.fullmatch(fuzz.reason), fuzz.reason


def test_replay_values_of_the_profit_poc(results: Results) -> None:
    assert results["ProfitPoC"][REPLAY].logs == (
        "ASSAY_PREDICATE|attacker_profit|eth:1000000000000000000->1000000000000000005",
    )


@pytest.mark.parametrize(
    ("contract", "reason"),
    [
        ("NoPredicatePoC", "AssayNoPredicate()"),
        ("LateDeclarationPoC", "AssayDeclarationClosed()"),
        ("KnobReadPoC", "AssayKnobIndex(4)"),
    ],
)
def test_a_poc_without_effect_fails_replay_and_finds_no_variant(
    results: Results, contract: str, reason: str
) -> None:
    replay, fuzz = results[contract][REPLAY], results[contract][FUZZ]
    assert (replay.status, replay.reason) == ("failure", reason)
    assert (fuzz.status, fuzz.runs) == ("success", 256)


@pytest.mark.parametrize(
    ("contract", "reason"),
    [
        ("KnobIndexPoC", "AssayKnobIndex(4)"),
        ("DuplicateKnobPoC", 'AssayAlreadyDeclared("b")'),
        ("DuplicateBalancePoC", 'AssayAlreadyDeclared("attacker_balance")'),
        ("RangePoC", 'AssayInvalidRange("k", 5, 6, 9)'),
        ("KnobNamePoC", 'AssayInvalidName("bad name")'),
    ],
)
def test_invalid_declarations_fail_set_up(results: Results, contract: str, reason: str) -> None:
    (case,) = results[contract].values()
    assert (case.name, case.status, case.reason) == ("setUp()", "failure", reason)
