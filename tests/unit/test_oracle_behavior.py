"""BehaviorOracle with a stand-in runner (no Docker): benign tests and recorded behavior."""

import json
from pathlib import Path

import pytest
from fake_forge import RECORD_TOPIC, Benign, BenignTests, FakeForge, abi_bytes, key_topic

from assay.analyzers.foundry import ForgeEvent
from assay.ingest import Snapshot, create_snapshot
from assay.ledger import RevisionKind, Verdict
from assay.oracles.base import OracleResult
from assay.oracles.behavior import (
    BEHAVIOR_DIFF_FILE,
    BehaviorContext,
    BehaviorOracle,
    SuiteSettings,
    decode_data,
    decode_key,
    records_of,
)
from assay.oracles.exploit import TEST_CONTRACT
from assay.oracles.runtree import load_harness

BASELINE: BenignTests = {
    "test_deposit()": ("Success", [("deposit", "0x01"), ("deposit", "0x02")]),
    "test_withdraw()": ("Success", [("withdraw", "0x03")]),
    "test_known_bug()": ("Failure", []),
}


def snapshot(tmp_path: Path, name: str, files: dict[str, str]) -> Snapshot:
    root = tmp_path / f"{name}-src"
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return create_snapshot(root, tmp_path / name)


def is_patched(tree: Path) -> bool:
    return "fixed" in (tree / "src" / "Target.sol").read_text()


def per_revision(patched: BenignTests | str) -> Benign:
    return lambda tree: patched if is_patched(tree) else BASELINE


def run(
    tmp_path: Path,
    benign: Benign,
    *,
    tests: bool = True,
    build_fails: object = None,
) -> tuple[OracleResult, FakeForge]:
    runner = FakeForge(
        lambda tree, number: "blocked",
        benign=benign,
        build_fails=build_fails or (lambda tree: False),  # type: ignore[arg-type]
    )
    files = {"src/Target.sol": "// VULNERABLE\n"}
    if tests:
        files["test/Target.t.sol"] = "contract TargetTest {}\n"
    work = tmp_path / "work"
    work.mkdir()
    context = BehaviorContext(
        runner=runner,
        vulnerable=snapshot(tmp_path, "vulnerable", files),
        patched=snapshot(tmp_path, "patched", {**files, "src/Target.sol": "// fixed\n"}),
        harness=load_harness(),
        work_dir=work,
    )
    return BehaviorOracle(SuiteSettings(fuzz_runs=10)).run(context), runner


def test_the_same_tests_and_records_pass(tmp_path: Path) -> None:
    result, runner = run(tmp_path, per_revision(BASELINE))
    assert result.verdict is Verdict.PASS, result
    assert "2 of 3 benign tests pass on the vulnerable revision; 1 fail there" in result.summary
    vulnerable, patched = result.executions
    assert (vulnerable.revision, patched.revision) == (
        RevisionKind.VULNERABLE,
        RevisionKind.PATCHED,
    )
    assert (
        vulnerable.argv
        == patched.argv
        == (
            "forge",
            "test",
            "--json",
            "-vv",
            "--threads",
            "1",
            "--fuzz-seed",
            "0x1",
            "--fuzz-runs",
            "10",
        )
    )
    assert len(runner.tests(None)) == 2
    assert runner.commands("inspect") == [
        ("forge", "inspect", "assay/AssayExploit.sol:AssayExploit", "events", "--json")
    ]


def test_a_benign_test_that_stops_passing_fails(tmp_path: Path) -> None:
    patched = {**BASELINE, "test_withdraw()": ("Failure", [])}
    result, _ = run(tmp_path, per_revision(patched))
    assert result.verdict is Verdict.FAIL
    assert result.codes() == ["benign_test_failed"]
    assert "test/Vault.t.sol:VaultBenignTest.test_withdraw()" in result.reasons[0].detail


def test_a_test_that_failed_before_is_not_compared(tmp_path: Path) -> None:
    patched = {**BASELINE, "test_known_bug()": ("Success", [("bug", "0x09")])}
    result, _ = run(tmp_path, per_revision(patched))
    assert result.verdict is Verdict.PASS


def test_a_missing_benign_test_fails(tmp_path: Path) -> None:
    patched = {name: item for name, item in BASELINE.items() if name != "test_deposit()"}
    result, _ = run(tmp_path, per_revision(patched))
    assert result.verdict is Verdict.FAIL
    assert "(not run)" in result.reasons[0].detail


@pytest.mark.parametrize(
    "records",
    [
        [("deposit", "0x01"), ("deposit", "0xff")],  # a value changed
        [("deposit", "0x01")],  # a value is missing
        [("deposit", "0x01"), ("deposit", "0x02"), ("extra", "0x00")],  # a new key
        [("deposit", "0x02"), ("deposit", "0x01")],  # the order changed
    ],
)
def test_a_changed_record_fails_with_a_diff(tmp_path: Path, records: list[tuple[str, str]]) -> None:
    patched = {**BASELINE, "test_deposit()": ("Success", records)}
    result, _ = run(tmp_path, per_revision(patched))
    assert result.verdict is Verdict.FAIL
    assert result.codes() == ["behavior_changed"]
    (diff,) = [item for item in result.executions[1].evidence if item.name == BEHAVIOR_DIFF_FILE]
    differences = json.loads(diff.data)["differences"]
    assert len(differences) == 1
    assert differences[0]["test"] == "test/Vault.t.sol:VaultBenignTest.test_deposit()"
    assert differences[0]["vulnerable"] == (
        ["0x01", "0x02"] if differences[0]["key"] == "deposit" else []
    )


def test_both_failures_are_reported(tmp_path: Path) -> None:
    patched: BenignTests = {
        "test_deposit()": ("Success", [("deposit", "0x07")]),
        "test_withdraw()": ("Failure", []),
    }
    result, _ = run(tmp_path, per_revision(patched))
    assert result.codes() == ["benign_test_failed", "behavior_changed"]


def test_benign_tests_that_do_not_compile_against_the_patch_fail(tmp_path: Path) -> None:
    result, runner = run(tmp_path, per_revision(BASELINE), build_fails=is_patched)
    assert result.verdict is Verdict.FAIL
    assert result.codes() == ["benign_test_failed"]
    assert "do not compile" in result.reasons[0].detail
    assert len(runner.tests(None)) == 1


@pytest.mark.parametrize(
    ("benign", "tests", "code"),
    [
        (per_revision(BASELINE), False, "no_benign_tests"),
        (lambda tree: {"test_a()": ("Failure", [])}, True, "no_benign_tests"),
        (lambda tree: "timeout", True, "timeout"),
    ],
)
def test_without_a_baseline_the_oracle_is_inconclusive(
    tmp_path: Path, benign: Benign, tests: bool, code: str
) -> None:
    result, runner = run(tmp_path, benign, tests=tests)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.codes() == [code]
    assert len(result.executions) == 1
    assert len(runner.tests(None)) <= 1


def test_a_patched_timeout_is_never_a_pass(tmp_path: Path) -> None:
    result, _ = run(tmp_path, per_revision("timeout"))
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.codes() == ["timeout"]


def test_a_vulnerable_revision_that_does_not_compile_is_inconclusive(tmp_path: Path) -> None:
    result, _ = run(tmp_path, per_revision(BASELINE), build_fails=lambda tree: not is_patched(tree))
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.codes() == ["benign_build_failed"]


# -- records ----------------------------------------------------------------------------------


def event(
    key: str, payload: str, *, address: str = TEST_CONTRACT, topic: str = RECORD_TOPIC
) -> ForgeEvent:
    return ForgeEvent(address=address, topics=(topic, key_topic(key)), data=abi_bytes(payload))


def test_only_records_of_the_test_contract_count() -> None:
    events = (
        event("deposit", "0x01"),
        event("deposit", "0x02", address="0x" + "12" * 20),
        event("deposit", "0x03", topic="0x" + "00" * 32),
        event("withdraw", "0xabcd"),
    )
    assert records_of(events, RECORD_TOPIC) == {"deposit": ("0x01",), "withdraw": ("0xabcd",)}


def test_keys_and_data_are_decoded_strictly() -> None:
    assert decode_key(key_topic("partial_withdraw")) == "partial_withdraw"
    odd = "0x" + "ff" * 32
    assert decode_key(odd) == odd
    assert decode_data(abi_bytes("0x" + "aa" * 40)) == "0x" + "aa" * 40
    assert decode_data(abi_bytes("0x")) == "0x"
    malformed = "0x" + "00" * 31 + "40" + "00" * 32
    assert decode_data(malformed) == malformed
    assert decode_data("0xzz") == "0xzz"
