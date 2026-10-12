"""SymbolicOracle with stand-in runners (no Docker): the strict parsing of Halmos's report, the
mapping of results to verdicts (a timeout or unknown result is never a pass), the sanity check
on the vulnerable revision, the confirmation of a counterexample, bounded equivalence, and the
bounds statement."""

import json
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
from fake_forge import FakeForge
from fake_halmos import FakeHalmos, HalmosAnswer, entry, model, report, sandbox_result

from assay.ingest import Snapshot, create_snapshot
from assay.ledger import RevisionKind, Verdict
from assay.oracles.runtree import load_harness
from assay.oracles.symbolic import (
    CheckResult,
    HalmosOutputError,
    HalmosSettings,
    SymbolicContext,
    SymbolicOracle,
    SymbolicOutcome,
    halmos_argv,
    interpret,
    max_calls,
    parameter_names,
    parse_report,
)
from assay.oracles.variant import VARIANT_POC_FILE
from assay.oracles.variant.poc import BaseContract, PocRejected, render_check
from assay.sandbox import check_argv

CONTRACT = "test/symbolic/TargetCheck.t.sol:TargetCheck"
EQUIV_CONTRACT = "test/symbolic/TargetEquivalence.t.sol:TargetEquivalence"
PAY = "check_variant_pay(address,uint256)"
PAY_ALL = "check_variant_payAll(address)"
EQUIV = "check_equiv_owner(uint256)"
CALLER = 0x00000000000000000000000000000000000000AA
AMOUNT = 7


WITNESS = model({"caller": ("address", 160, CALLER), "amount": ("uint256", 256, AMOUNT)})


# -- parsing -------------------------------------------------------------------------------------


def test_a_report_is_parsed_into_sorted_properties() -> None:
    checks = parse_report(
        report({CONTRACT: [entry(PAY_ALL, 0, loops=2), entry(PAY, 1, [WITNESS])]}, exitcode=1)
    )
    assert [item.signature for item in checks] == [PAY, PAY_ALL]
    pay, pay_all = checks
    assert pay.outcome == "counterexample"
    assert pay.parameter_types == ("address", "uint256")
    assert pay.calldata_bytes == 4 + 32 * 2
    assert pay.witnesses[0].value_of("caller") == CALLER
    assert pay.witnesses[0].value_of("amount") == AMOUNT
    assert pay_all.outcome == "no_counterexample"
    assert pay_all.bounded_loops == 2
    assert pay_all.paths == 6


@pytest.mark.parametrize("code", [2, 3, 4, 5])
def test_every_code_other_than_pass_or_counterexample_is_unknown(code: int) -> None:
    (check,) = parse_report(report({CONTRACT: [entry(PAY, code)]}))
    assert check.outcome == "unknown"


@pytest.mark.parametrize(
    ("data", "problem"),
    [
        pytest.param(b"", "malformed_json", id="empty"),
        pytest.param(b"{", "malformed_json", id="truncated"),
        pytest.param(b"\xff", "not_utf8", id="not-utf8"),
        pytest.param(
            b'{"exitcode": 0, "exitcode": 1, "test_results": {}}', "duplicate_key", id="dup"
        ),
        pytest.param(b'{"exitcode": NaN, "test_results": {}}', "malformed_json", id="nan"),
        pytest.param(b"[" * 100 + b"]" * 100, "too_deep", id="deep"),
        pytest.param(report({"../x.sol:X": [entry(PAY, 0)]}), "schema_mismatch", id="traversal"),
        pytest.param(report({"/abs/x.sol:X": [entry(PAY, 0)]}), "schema_mismatch", id="absolute"),
        pytest.param(report({CONTRACT: [entry("test_x()", 0)]}), "schema_mismatch", id="not-check"),
        pytest.param(report({CONTRACT: [entry(PAY, 1)]}), "schema_mismatch", id="no-model"),
        pytest.param(report({CONTRACT: [entry(PAY, 9)]}), "schema_mismatch", id="bad-code"),
        pytest.param(
            report({CONTRACT: [entry("check_variant_x(bytes)", 0)]}),
            "unsupported_signature",
            id="dynamic-type",
        ),
        pytest.param(
            report({CONTRACT: [entry("check_variant_x(uint256[])", 0)]}),
            "schema_mismatch",
            id="array-type",
        ),
        pytest.param(
            report({CONTRACT: [entry(PAY, 1, [model({"amount": ("uint8", 8, 256)})])]}),
            "schema_mismatch",
            id="value-too-large",
        ),
        pytest.param(
            report({CONTRACT: [entry(PAY, 1, [model({"a b": ("uint8", 8, 1)})])]}),
            "schema_mismatch",
            id="bad-name",
        ),
        pytest.param(
            report({CONTRACT: [entry(PAY, 0), entry(PAY, 0)]}), "duplicate_key", id="twice"
        ),
    ],
)
def test_an_unusable_report_is_refused(data: bytes, problem: str) -> None:
    with pytest.raises(HalmosOutputError) as caught:
        parse_report(data)
    assert caught.value.code == problem


def test_a_large_report_is_refused_before_parsing() -> None:
    with pytest.raises(HalmosOutputError) as caught:
        parse_report(b" " * (16 * 1024 * 1024 + 1))
    assert caught.value.code == "output_too_large"


def test_a_run_without_a_usable_result_is_a_problem_never_asandbox_result() -> None:
    settings = HalmosSettings()
    data = report({CONTRACT: [entry(PAY, 0)]})
    timed_out = interpret(sandbox_result(timed_out=True, exit_code=-9), data, settings)
    assert timed_out.problem == "timeout"
    assert timed_out.checks == ()
    assert "900 s" in timed_out.detail
    oom = interpret(sandbox_result(oom_killed=True, exit_code=137), data, settings)
    assert oom.problem == "out_of_memory"
    assert oom.checks == ()
    build = interpret(
        sandbox_result(exit_code=1, stderr="Error: Build failed: [...]"), None, settings
    )
    assert build.problem == "build_failed"
    missing = interpret(sandbox_result(exit_code=1), None, settings)
    assert missing.problem == "no_report"
    garbage = interpret(sandbox_result(), b"not json", settings)
    assert garbage.problem == "unusable_report"
    fine = interpret(sandbox_result(exit_code=1), data, settings)
    assert fine.problem is None
    assert len(fine.checks) == 1


def test_the_halmos_argv_passes_the_allowlist() -> None:
    for prefix in ("check_", "check_variant_", "check_equiv_"):
        argv = halmos_argv(prefix, HalmosSettings(loop=4, solver_timeout_s=30))
        assert check_argv(argv) == argv
        assert argv[argv.index("--loop") + 1] == "4"
        assert argv[argv.index("--solver-timeout-assertion") + 1] == "30s"
        assert "--ffi" not in argv


def test_the_call_limit_is_read_from_the_harness() -> None:
    assert max_calls(load_harness()) == 4


# -- parameter names and the replay test ---------------------------------------------------------


def _abi(*names: str, types: Sequence[str] = ("address", "uint256")) -> str:
    return json.dumps(
        [
            {
                "type": "function",
                "name": "check_variant_pay",
                "inputs": [
                    {"name": name, "type": kind, "internalType": kind}
                    for name, kind in zip(names, types, strict=True)
                ],
                "outputs": [],
                "stateMutability": "nonpayable",
            },
            {"type": "event", "name": "AssayPredicate", "inputs": [], "anonymous": False},
        ]
    )


def _check(signature: str = PAY) -> CheckResult:
    return CheckResult(
        contract=CONTRACT, signature=signature, code=1, paths=1, bounded_loops=0, witnesses=()
    )


def test_parameter_names_come_from_the_abi_in_order() -> None:
    assert parameter_names(_abi("caller", "amount"), _check()) == ("caller", "amount")


@pytest.mark.parametrize(
    "abi",
    [
        pytest.param(_abi("the_caller", "amount"), id="underscore"),
        pytest.param(_abi("", "amount"), id="unnamed"),
        pytest.param(_abi("caller", "caller"), id="repeated"),
        pytest.param(_abi("caller", "amount", types=("address", "uint128")), id="other-types"),
        pytest.param("{}", id="not-a-list"),
        pytest.param("[", id="malformed"),
    ],
)
def test_unusable_parameter_names_are_refused(abi: str) -> None:
    with pytest.raises(PocRejected):
        parameter_names(abi, _check())


def test_the_replay_test_holds_only_numbers_and_checked_names() -> None:
    base = BaseContract(name="TargetCheck", path="symbolic/TargetCheck.t.sol")
    source = render_check(base, "check_variant_pay", (CALLER, AMOUNT), "0.8.36")
    assert 'import {TargetCheck} from "./symbolic/TargetCheck.t.sol";' in source
    assert "contract AssayVariantPoC is TargetCheck {" in source
    assert "TargetCheck.check_variant_pay.selector," in source
    assert f"uint256(0x{CALLER:064x})," in source
    assert f"uint256(0x{AMOUNT:064x})" in source
    assert "assayReplayCheck(" in source
    assert "that Halmos reported" in source
    for bad in ("check_variant_pay();", "check variant", "test_x"):
        with pytest.raises(PocRejected):
            render_check(base, bad, (), "0.8.36")
    with pytest.raises(PocRejected):
        render_check(base, "check_variant_pay", (2**256,), "0.8.36")


# -- the oracle ----------------------------------------------------------------------------------


def _snapshot(tmp_path: Path, name: str, files: dict[str, str]) -> Snapshot:
    root = tmp_path / f"{name}-src"
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return create_snapshot(root, tmp_path / name)


CHECK_SOURCE = "contract TargetCheck {}\n"
POC_FILES = {
    "Exploit.t.sol": "contract ExploitPoC {}\n",
    "symbolic/TargetCheck.t.sol": CHECK_SOURCE,
    "symbolic/TargetEquivalence.t.sol": (
        "contract TargetEquivalence {\n"
        "    function check_equiv_owner(uint256 amount) public {}\n"
        "}\n"
    ),
}


def _abi_of(tree: Path, contract: str, field: str) -> str:
    assert field == "abi"
    assert contract == CONTRACT
    return _abi("caller", "amount")


def run_oracle(
    tmp_path: Path,
    answer: Callable[[RevisionKind, str], HalmosAnswer],
    *,
    confirm: Callable[[Path, int], str] | None = None,
    poc_files: dict[str, str] | None = None,
    patched_source: str = "// fixed\n",
) -> tuple[SymbolicOutcome, FakeForge, FakeHalmos]:
    forge = FakeForge(
        lambda tree, number: "blocked",
        confirm=confirm or (lambda tree, number: "reproduced"),
        interface=_abi_of,
    )
    halmos = FakeHalmos(answer)
    work = tmp_path / "work"
    work.mkdir()
    context = SymbolicContext(
        runner=forge,
        symbolic_runner=halmos,
        vulnerable=_snapshot(tmp_path, "vulnerable", {"src/Target.sol": "// VULNERABLE\n"}),
        patched=_snapshot(tmp_path, "patched", {"src/Target.sol": patched_source}),
        poc=_snapshot(tmp_path, "poc", poc_files if poc_files is not None else POC_FILES),
        harness=load_harness(),
        work_dir=work,
    )
    return SymbolicOracle(halmos_version="0.3.3").search(context), forge, halmos


def vulnerable_found(patched: HalmosAnswer) -> Callable[[RevisionKind, str], HalmosAnswer]:
    """The vulnerable revision has counterexamples of both variant properties."""
    found = report({CONTRACT: [entry(PAY, 1, [WITNESS]), entry(PAY_ALL, 1, [WITNESS])]}, 1)
    return lambda revision, prefix: found if revision is RevisionKind.VULNERABLE else patched


CLEAN = report({CONTRACT: [entry(PAY, 0), entry(PAY_ALL, 0)], EQUIV_CONTRACT: [entry(EQUIV, 0)]})


def test_no_counterexample_on_the_patched_revision_passes_within_the_bounds(
    tmp_path: Path,
) -> None:
    outcome, forge, halmos = run_oracle(tmp_path, vulnerable_found(CLEAN))
    result = outcome.result
    assert result.verdict is Verdict.PASS
    assert [item.verdict for item in result.executions] == [Verdict.PASS, Verdict.PASS]
    prefixes = [call[call.index("--function") + 1] for call in halmos.calls]
    assert prefixes == ["check_variant_", "check_"]
    statement = outcome.statement
    assert statement.startswith("symbolic: no counterexample within loop bound 3 for ")
    assert "check_variant_pay (calldata 4+32*2 bytes)" in statement
    assert "check_variant_payAll (calldata 4+32*1 bytes)" in statement
    assert "at most 4 calls of the target per property" in statement
    assert "Halmos 0.3.3" in statement
    assert statement.endswith("this is not a proof of absence")
    assert "proven" not in statement
    assert outcome.bounds.equivalence == "no_difference"
    assert outcome.equivalence_statement.startswith(
        "bounded equivalence: no difference from the vulnerable revision within loop bound 3"
    )
    assert result.warnings == ()
    assert forge.calls == []  # nothing to confirm


@pytest.mark.parametrize("problem", ["timeout", "oom", "build_failed", "no_report"])
def test_a_patched_run_without_a_result_is_never_a_pass(tmp_path: Path, problem: str) -> None:
    outcome, _, _ = run_oracle(tmp_path, vulnerable_found(problem))
    result = outcome.result
    assert result.verdict is Verdict.INCONCLUSIVE
    expected = {
        "timeout": "symbolic_unknown",
        "oom": "symbolic_unknown",
        "build_failed": "symbolic_build_failed",
        "no_report": "symbolic_output_unusable",
    }[problem]
    assert result.codes() == [expected]
    assert outcome.statement.startswith("symbolic: unknown (")
    assert outcome.bounds.equivalence == "unknown"


def test_a_timeout_names_the_limit_in_the_statement(tmp_path: Path) -> None:
    outcome, _, _ = run_oracle(tmp_path, vulnerable_found("timeout"))
    assert outcome.statement.startswith("symbolic: unknown (timeout 900 s); loop bound 3; ")
    assert "a timeout is never a pass" in outcome.result.reasons[0].detail


@pytest.mark.parametrize("code", [2, 3, 4, 5])
def test_an_unknown_property_result_is_inconclusive(tmp_path: Path, code: int) -> None:
    patched = report({CONTRACT: [entry(PAY, code), entry(PAY_ALL, 0)]})
    outcome, _, _ = run_oracle(tmp_path, vulnerable_found(patched))
    assert outcome.result.verdict is Verdict.INCONCLUSIVE
    assert outcome.result.codes() == ["symbolic_unknown"]
    assert outcome.statement.startswith("symbolic: unknown for check_variant_pay ")
    assert "solver timeout 60 s per query" in outcome.statement


def test_a_property_missing_on_the_patched_revision_is_inconclusive(tmp_path: Path) -> None:
    patched = report({CONTRACT: [entry(PAY_ALL, 0)]})
    outcome, _, _ = run_oracle(tmp_path, vulnerable_found(patched))
    assert outcome.result.verdict is Verdict.INCONCLUSIVE
    assert outcome.result.codes() == ["symbolic_unknown"]


def test_a_confirmed_counterexample_fails_with_variant_found(tmp_path: Path) -> None:
    patched = report({CONTRACT: [entry(PAY, 1, [WITNESS]), entry(PAY_ALL, 0)]}, 1)
    outcome, forge, _ = run_oracle(tmp_path, vulnerable_found(patched))
    result = outcome.result
    assert result.verdict is Verdict.FAIL
    assert result.codes() == ["variant_found"]
    detail = result.reasons[0].detail
    assert f"caller={CALLER:#x}" in detail
    assert f"amount={AMOUNT:#x}" in detail
    assert "confirmed by 3 of 3 replays" in detail
    assert len(forge.tests("^test_variant[(]")) == 3
    assert outcome.bounds.confirmed_property == PAY
    assert outcome.bounds.replays_reproduced == 3
    assert outcome.statement.startswith(
        "symbolic: counterexample of check_variant_pay within loop bound 3, confirmed by 3 of 3"
    )
    names = {item.name for item in result.executions[1].evidence}
    assert {"counterexample.json", VARIANT_POC_FILE} <= names
    source = next(
        item.data.decode()
        for item in result.executions[1].evidence
        if item.name == VARIANT_POC_FILE
    )
    assert "TargetCheck.check_variant_pay.selector" in source


def test_a_counterexample_that_does_not_replay_is_inconclusive(tmp_path: Path) -> None:
    patched = report({CONTRACT: [entry(PAY, 1, [WITNESS]), entry(PAY_ALL, 0)]}, 1)
    outcome, _, _ = run_oracle(
        tmp_path,
        vulnerable_found(patched),
        confirm=lambda tree, number: "reproduced" if number == 1 else "blocked",
    )
    assert outcome.result.verdict is Verdict.INCONCLUSIVE
    assert outcome.result.codes() == ["flaky_counterexample"]
    assert outcome.bounds.replays_reproduced == 1
    assert outcome.statement.startswith("symbolic: counterexample reported for check_variant_pay")


def test_a_counterexample_with_unusable_parameter_names_is_rejected(tmp_path: Path) -> None:
    patched = report({CONTRACT: [entry(PAY, 1, [WITNESS]), entry(PAY_ALL, 0)]}, 1)

    def abi(tree: Path, contract: str, field: str) -> str:
        return _abi("the_caller", "amount")

    forge = FakeForge(lambda tree, number: "blocked", interface=abi)
    halmos = FakeHalmos(vulnerable_found(patched))
    work = tmp_path / "work"
    work.mkdir()
    context = SymbolicContext(
        runner=forge,
        symbolic_runner=halmos,
        vulnerable=_snapshot(tmp_path, "vulnerable", {"src/Target.sol": "// VULNERABLE\n"}),
        patched=_snapshot(tmp_path, "patched", {"src/Target.sol": "// fixed\n"}),
        poc=_snapshot(tmp_path, "poc", POC_FILES),
        harness=load_harness(),
        work_dir=work,
    )
    result = SymbolicOracle().run(context)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.codes() == ["counterexample_rejected"]


def test_properties_without_a_counterexample_on_the_vulnerable_revision_are_not_counted(
    tmp_path: Path,
) -> None:
    nothing = report({CONTRACT: [entry(PAY, 0), entry(PAY_ALL, 0)]})
    outcome, _, _ = run_oracle(tmp_path, lambda revision, prefix: nothing)
    assert outcome.result.verdict is Verdict.INCONCLUSIVE
    assert outcome.result.codes() == ["symbolic_check_ineffective"]
    assert "no variant property found the exploit" in outcome.statement


def test_an_ineffective_property_is_a_warning_and_its_result_is_not_counted(
    tmp_path: Path,
) -> None:
    vulnerable = report({CONTRACT: [entry(PAY, 1, [WITNESS]), entry(PAY_ALL, 0)]}, 1)
    patched = report({CONTRACT: [entry(PAY, 0), entry(PAY_ALL, 2)]})
    outcome, _, _ = run_oracle(
        tmp_path,
        lambda revision, prefix: vulnerable if revision is RevisionKind.VULNERABLE else patched,
    )
    assert outcome.result.verdict is Verdict.PASS
    assert [item.code for item in outcome.result.warnings] == ["symbolic_check_ineffective"]
    assert "not counted: check_variant_payAll" in outcome.statement


def test_an_invalid_model_on_the_vulnerable_revision_does_not_count(tmp_path: Path) -> None:
    invalid = report({CONTRACT: [entry(PAY, 1, [model({}, valid=False)])]}, 1)
    patched = report({CONTRACT: [entry(PAY, 0)]})
    outcome, _, _ = run_oracle(
        tmp_path,
        lambda revision, prefix: invalid if revision is RevisionKind.VULNERABLE else patched,
    )
    assert outcome.result.codes() == ["symbolic_check_ineffective"]


@pytest.mark.parametrize("problem", ["timeout", "oom"])
def test_a_vulnerable_run_without_a_result_is_inconclusive(tmp_path: Path, problem: str) -> None:
    outcome, _, _ = run_oracle(
        tmp_path, lambda revision, prefix: problem if revision is RevisionKind.VULNERABLE else CLEAN
    )
    assert outcome.result.verdict is Verdict.INCONCLUSIVE
    assert "symbolic_unknown" in outcome.result.codes()


@pytest.mark.parametrize(
    ("equivalence", "status"),
    [(1, "difference"), (2, "unknown"), (4, "unknown")],
)
def test_equivalence_that_is_not_shown_is_a_warning_and_changes_no_verdict(
    tmp_path: Path, equivalence: int, status: str
) -> None:
    models = [model({"amount": ("uint256", 256, 5)})] if equivalence == 1 else []
    patched = report(
        {
            CONTRACT: [entry(PAY, 0), entry(PAY_ALL, 0)],
            EQUIV_CONTRACT: [entry(EQUIV, equivalence, models)],
        },
        1,
    )
    outcome, _, _ = run_oracle(tmp_path, vulnerable_found(patched))
    assert outcome.result.verdict is Verdict.PASS
    assert outcome.bounds.equivalence == status
    assert [item.code for item in outcome.result.warnings] == ["equivalence_not_shown"]
    assert "the verdict is unchanged" in outcome.equivalence_statement


def test_without_equivalence_properties_nothing_is_claimed(tmp_path: Path) -> None:
    patched = report({CONTRACT: [entry(PAY, 0), entry(PAY_ALL, 0)]})
    files = {key: value for key, value in POC_FILES.items() if "Equivalence" not in key}
    outcome, _, _ = run_oracle(tmp_path, vulnerable_found(patched), poc_files=files)
    assert outcome.bounds.equivalence == "none"
    assert outcome.result.warnings == ()


def test_without_symbolic_properties_nothing_runs(tmp_path: Path) -> None:
    outcome, _, halmos = run_oracle(
        tmp_path, vulnerable_found(CLEAN), poc_files={"Exploit.t.sol": "contract ExploitPoC {}\n"}
    )
    assert outcome.result.verdict is Verdict.INCONCLUSIVE
    assert outcome.result.codes() == ["no_symbolic_properties"]
    assert halmos.calls == []
    assert outcome.bounds.equivalence == "not_run"


@pytest.mark.parametrize(
    ("where", "files", "patched"),
    [
        (
            "property",
            {
                **POC_FILES,
                "symbolic/TargetCheck.t.sol": "/// @custom:halmos --ffi\ncontract C {}\n",
            },
            "// fixed\n",
        ),
        ("patched source", POC_FILES, "/// @Custom:Halmos --loop 1000\n"),
    ],
)
def test_inline_halmos_options_are_refused_before_anything_runs(
    tmp_path: Path, where: str, files: dict[str, str], patched: str
) -> None:
    outcome, _, halmos = run_oracle(
        tmp_path, vulnerable_found(CLEAN), poc_files=files, patched_source=patched
    )
    assert outcome.result.codes() == ["inline_halmos_config"]
    assert halmos.calls == []


def test_the_bounds_and_traces_are_deterministic(tmp_path: Path) -> None:
    outcomes = []
    for name in ("one", "two"):
        (tmp_path / name).mkdir()
        outcomes.append(run_oracle(tmp_path / name, vulnerable_found(CLEAN))[0])
    first, second = outcomes
    assert first.bounds == second.bounds
    assert first.statement == second.statement
    assert [item.trace for item in first.result.executions] == [
        item.trace for item in second.result.executions
    ]


def test_a_vulnerable_run_without_a_result_is_named_in_the_statement(tmp_path: Path) -> None:
    outcome, _, _ = run_oracle(
        tmp_path, lambda revision, prefix: "oom" if revision is RevisionKind.VULNERABLE else CLEAN
    )
    assert outcome.statement.startswith(
        "symbolic: unknown on the vulnerable revision (out of memory, limit 4096 MiB), so the "
        "patched revision's result is not counted"
    )


def test_without_equivalence_properties_a_failed_run_claims_no_equivalence(
    tmp_path: Path,
) -> None:
    files = {key: value for key, value in POC_FILES.items() if "Equivalence" not in key}
    outcome, _, _ = run_oracle(tmp_path, vulnerable_found("timeout"), poc_files=files)
    assert outcome.bounds.equivalence == "none"
    assert outcome.result.warnings == ()
