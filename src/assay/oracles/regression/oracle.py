"""RegressionOracle: no breaking interface change, and the whole test suite passes.

Both revisions run in benign trees (ADR 0011). The target contracts are every concrete contract
(not abstract, not an interface, not a library) declared in a Solidity file under `src/` of the
vulnerable revision, unless the caller names them. For each target the oracle reads the storage
layout and the ABI with `forge inspect` on both revisions and compares them
(`assay.oracles.regression.interface`):

- a breaking storage layout change: FAIL `layout_changed`; a variable appended after the last
  used slot is only a warning;
- a removed function, a changed parameter list, return types or state mutability: FAIL
  `abi_changed`; a new function is only a warning. A target contract that no longer exists as a
  concrete contract counts as `abi_changed`;
- a removed event or a change of its indexed parameters or anonymity: FAIL `event_changed`; a
  new event is only a warning.

On the patched revision the oracle also runs the project's whole test suite (`forge test` on the
benign tree, with the recorded fuzz seed and number of runs). Every test, and every `setUp()`,
must pass; otherwise FAIL `test_suite_failed`. A suite that does not compile against the patched
sources fails as well. A project without tests is INCONCLUSIVE `no_tests`.

Warnings appear in the report but never make the verdict FAIL. A breaking change found before a
later step timed out still fails; otherwise a timeout or unusable output is INCONCLUSIVE, never a
pass.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Final

from pydantic import JsonValue

from assay.analyzers import foundry
from assay.ingest import Snapshot
from assay.ledger import OracleName, RevisionKind, Verdict
from assay.oracles.base import Evidence, Execution, OracleResult, Reason, clip, reason
from assay.oracles.behavior import SuiteSettings
from assay.oracles.integrity.solidity import contracts
from assay.oracles.regression.interface import (
    Change,
    Interface,
    InterfaceError,
    compare_interface,
    parse_interface,
)
from assay.oracles.runtree import (
    SOURCE_DIR,
    Harness,
    RunTree,
    RunTreeError,
    benign_paths,
    build_benign_tree,
)
from assay.oracles.steps import (
    SETUP_PREFIX,
    Stop,
    build,
    cases,
    first_error,
    json_evidence,
    problem_of,
    results_evidence,
)
from assay.sandbox import ArgvRejected, SandboxRunner

CLAIM_VULNERABLE: Final = (
    "The storage layout, ABI and events of the target contracts are read on the vulnerable "
    "revision."
)
CLAIM_PATCHED: Final = (
    "The patched revision keeps the storage layout, ABI and events of the target contracts "
    "without a breaking change, and the project's whole test suite passes on it."
)
CHANGE_REASONS: Final = {
    "layout": "layout_changed",
    "abi": "abi_changed",
    "events": "event_changed",
}
ADDITION_WARNINGS: Final = {
    "layout": "storage_appended",
    "abi": "function_added",
    "events": "event_added",
}
_MAX_LISTED: Final = 10


def target_contracts(snapshot: Snapshot) -> tuple[str, ...]:
    """`<path>:<Name>` of every concrete contract declared in a Solidity file under `src/`."""
    found: list[str] = []
    for item in snapshot.files:
        path = PurePosixPath(item.path)
        if path.parts[:1] != (SOURCE_DIR,) or path.suffix != ".sol":
            continue
        text = (snapshot.tree_dir / item.path).read_bytes().decode("utf-8", errors="replace")
        found += [
            f"{item.path}:{contract.name}"
            for contract in contracts(text)
            if contract.kind == "contract"
        ]
    return tuple(sorted(set(found), key=lambda name: name.encode("utf-8")))


@dataclass(frozen=True, slots=True)
class RegressionContext:
    runner: SandboxRunner
    vulnerable: Snapshot
    patched: Snapshot
    harness: Harness
    work_dir: Path
    """An existing, empty directory for the run trees."""
    targets: tuple[str, ...]
    """The target contracts, as `<path>:<Name>`; see `target_contracts`."""


@dataclass
class _Side:
    """Observations on one revision."""

    revision: RevisionKind
    argv: tuple[str, ...] = ()
    interfaces: dict[str, Interface] = field(default_factory=dict)
    fails: list[Reason] = field(default_factory=list)
    unknowns: list[Reason] = field(default_factory=list)
    warnings: list[Reason] = field(default_factory=list)
    changes: list[dict[str, JsonValue]] = field(default_factory=list)
    suite: dict[str, str] = field(default_factory=dict)
    exit_code: int | None = None
    evidence: list[Evidence] = field(default_factory=list)


def _listed(items: Sequence[str]) -> str:
    shown = ", ".join(items[:_MAX_LISTED])
    return shown + (f" and {len(items) - _MAX_LISTED} more" if len(items) > _MAX_LISTED else "")


def _interface_document(interfaces: dict[str, Interface]) -> dict[str, JsonValue]:
    return {
        name: {
            "layout": [
                {
                    "label": item.label,
                    "slot": item.slot,
                    "offset": item.offset,
                    "type": item.type,
                    "size": item.size,
                }
                for item in interface.layout
            ],
            "functions": dict(sorted(interface.functions.items())),
            "events": dict(sorted(interface.events.items())),
        }
        for name, interface in sorted(interfaces.items())
    }


class RegressionOracle:
    name = OracleName.REGRESSION

    def __init__(self, settings: SuiteSettings | None = None) -> None:
        self.settings = settings if settings is not None else SuiteSettings()

    @property
    def suite_argv(self) -> tuple[str, ...]:
        return foundry.forge_test_argv(
            fuzz_seed=self.settings.fuzz_seed, fuzz_runs=self.settings.fuzz_runs
        )

    def run(self, context: RegressionContext) -> OracleResult:
        vulnerable = _Side(RevisionKind.VULNERABLE)
        if not context.targets:
            vulnerable.unknowns.append(
                reason("no_target_contracts", "no concrete contract is declared under src/")
            )
            return self._result(context, vulnerable, None)
        try:
            for target in context.targets:
                foundry.forge_inspect_argv(target, "abi")
        except ArgvRejected as exc:
            vulnerable.unknowns.append(reason("target_not_inspectable", str(exc)))
            return self._result(context, vulnerable, None)
        try:
            trees = (
                build_benign_tree(
                    context.vulnerable, context.harness, context.work_dir / "vulnerable"
                ),
                build_benign_tree(context.patched, context.harness, context.work_dir / "patched"),
            )
        except RunTreeError as exc:
            vulnerable.unknowns.append(reason("run_tree_rejected", str(exc)))
            return self._result(context, vulnerable, None)
        if trees[0].digest_outside("src") != trees[1].digest_outside("src"):
            vulnerable.unknowns.append(
                reason(
                    "run_tree_mismatch",
                    "the benign trees differ outside src/ between the revisions",
                )
            )
            return self._result(context, vulnerable, None)
        self._baseline(context, trees[0], vulnerable)
        if vulnerable.unknowns:
            return self._result(context, vulnerable, None)
        patched = _Side(RevisionKind.PATCHED)
        self._patched(context, trees[1], vulnerable, patched)
        return self._result(context, vulnerable, patched)

    def _inspect(self, runner: SandboxRunner, tree: RunTree, target: str, side: _Side) -> Interface:
        texts: list[str] = []
        for field_name in ("storageLayout", "abi"):
            side.argv = foundry.forge_inspect_argv(target, field_name)
            texts.append(
                foundry.inspect(runner, tree.tree, target, field_name, scratch_dir=tree.scratch)
            )
        try:
            return parse_interface(texts[0], texts[1])
        except InterfaceError as exc:
            raise Stop(reason("unusable_output", f"{target}: {exc}")) from exc

    def _baseline(self, context: RegressionContext, tree: RunTree, side: _Side) -> None:
        try:
            compiled = build(context.runner, tree)
            if not compiled.succeeded:
                side.argv, side.exit_code = compiled.argv, compiled.exit_code
                raise Stop(reason("vulnerable_build_failed", first_error(compiled)))
            for target in context.targets:
                side.interfaces[target] = self._inspect(context.runner, tree, target, side)
            side.exit_code = 0
        except Stop as stop:
            side.unknowns.append(stop.problem)
        except (foundry.ForgeTimeout, foundry.ForgeOutputError) as exc:
            problem, side.exit_code = problem_of(exc)
            side.unknowns.append(problem)
        if side.interfaces and not side.unknowns:
            side.evidence.append(
                json_evidence(
                    "regression: interface, vulnerable revision",
                    _interface_document(side.interfaces),
                    "interface-vulnerable.json",
                )
            )

    def _patched(
        self, context: RegressionContext, tree: RunTree, baseline: _Side, side: _Side
    ) -> None:
        runner = context.runner
        try:
            compiled = build(runner, tree)
        except (foundry.ForgeTimeout, foundry.ForgeOutputError) as exc:
            problem, side.exit_code = problem_of(exc)
            side.unknowns.append(problem)
            return
        if not compiled.succeeded:
            side.argv, side.exit_code = compiled.argv, compiled.exit_code
            side.fails.append(
                reason(
                    "test_suite_failed",
                    f"the project does not compile on the patched revision: "
                    f"{first_error(compiled)}",
                )
            )
            return
        present = set(target_contracts(context.patched))
        for target in context.targets:
            path = target.split(":", 1)[0]
            if target not in present:
                detail = f"{target}: the contract no longer exists as a concrete contract"
                side.fails.append(reason("abi_changed", detail, path=path))
                side.changes.append(
                    {"contract": target, "kind": "abi", "breaking": True, "detail": detail}
                )
                continue
            try:
                side.interfaces[target] = self._inspect(runner, tree, target, side)
            except Stop as stop:
                side.unknowns.append(stop.problem)
                continue
            except (foundry.ForgeTimeout, foundry.ForgeOutputError) as exc:
                problem, side.exit_code = problem_of(exc)
                side.unknowns.append(problem)
                continue
            self._record_changes(
                target,
                compare_interface(baseline.interfaces[target], side.interfaces[target]),
                side,
            )
        for added in sorted(present - set(context.targets)):
            side.warnings.append(
                reason("contract_added", f"new concrete contract {added}", path=added.split(":")[0])
            )
        if side.interfaces:
            side.evidence.append(
                json_evidence(
                    "regression: interface, patched revision",
                    _interface_document(side.interfaces),
                    "interface-patched.json",
                )
            )
        if side.changes:
            side.evidence.append(
                json_evidence(
                    "regression: interface changes",
                    {"changes": list(side.changes)},
                    "interface-changes.json",
                )
            )
        self._suite(context, tree, side)

    def _record_changes(self, target: str, changes: list[Change], side: _Side) -> None:
        path = target.split(":", 1)[0]
        for change in changes:
            detail = f"{target}: {change.detail}"
            side.changes.append(
                {
                    "contract": target,
                    "kind": change.kind,
                    "breaking": change.breaking,
                    "detail": change.detail,
                }
            )
            if change.breaking:
                side.fails.append(reason(CHANGE_REASONS[change.kind], detail, path=path))
            else:
                side.warnings.append(reason(ADDITION_WARNINGS[change.kind], detail, path=path))

    def _suite(self, context: RegressionContext, tree: RunTree, side: _Side) -> None:
        side.argv = self.suite_argv
        if not benign_paths(context.patched):
            side.unknowns.append(
                reason("no_tests", "the project has no test/ directory, so no test suite ran")
            )
            return
        try:
            run = foundry.test(
                context.runner,
                tree.tree,
                fuzz_seed=self.settings.fuzz_seed,
                fuzz_runs=self.settings.fuzz_runs,
                scratch_dir=tree.scratch,
            )
        except (foundry.ForgeTimeout, foundry.ForgeOutputError) as exc:
            problem, side.exit_code = problem_of(exc)
            side.unknowns.append(problem)
            return
        side.exit_code = run.exit_code
        side.evidence.append(
            results_evidence("regression: test suite results, patched revision", run)
        )
        all_cases = cases(run)
        side.suite = {name: case.status for name, case in all_cases}
        failed = [
            name + (f" ({clip(case.reason, 120)})" if case.reason else "")
            for name, case in all_cases
            if case.status == "failure"
        ]
        skipped = [name for name, case in all_cases if case.status == "skipped"]
        tests = [name for name, case in all_cases if not case.name.startswith(SETUP_PREFIX)]
        if failed:
            side.fails.append(
                reason(
                    "test_suite_failed",
                    f"{len(failed)} test(s) or setUp() of the project fail on the patched "
                    f"revision: {_listed(failed)}",
                )
            )
        elif not tests:
            side.unknowns.append(reason("no_tests", "the test suite contains no test"))
        if skipped:
            side.warnings.append(
                reason("tests_skipped", f"{len(skipped)} test(s) skipped: {_listed(skipped)}")
            )

    def _judge(self, side: _Side) -> tuple[Verdict, tuple[Reason, ...], str]:
        revision = side.revision.value
        if side.fails:
            codes = ", ".join(dict.fromkeys(item.code for item in side.fails))
            return Verdict.FAIL, tuple(side.fails), f"{revision}: {codes}"
        if side.unknowns:
            codes = ", ".join(dict.fromkeys(item.code for item in side.unknowns))
            return Verdict.INCONCLUSIVE, tuple(side.unknowns), f"{revision}: {codes}"
        count = len(side.interfaces)
        if side.revision is RevisionKind.VULNERABLE:
            return Verdict.PASS, (), f"interface of {count} target contract(s) read"
        summary = (
            f"no breaking interface change in {count} target contract(s); "
            f"{sum(status == 'success' for status in side.suite.values())} of "
            f"{len(side.suite)} test suite entries pass"
        )
        if side.warnings:
            summary += f"; {len(side.warnings)} warning(s)"
        return Verdict.PASS, (), f"patched: {summary}"

    def _result(
        self, context: RegressionContext, vulnerable: _Side, patched: _Side | None
    ) -> OracleResult:
        _, v_reasons, v_summary = self._judge(vulnerable)
        executions = [self._execution(context, vulnerable, CLAIM_VULNERABLE)]
        if patched is None:
            return OracleResult(
                oracle=self.name,
                verdict=Verdict.INCONCLUSIVE,
                reasons=v_reasons,
                summary=clip(f"{v_summary}; the patched revision was not run"),
                executions=tuple(executions),
            )
        executions.append(self._execution(context, patched, CLAIM_PATCHED))
        verdict, reasons, p_summary = self._judge(patched)
        return OracleResult(
            oracle=self.name,
            verdict=verdict,
            reasons=reasons,
            summary=clip(f"{v_summary}; {p_summary}"),
            executions=tuple(executions),
            warnings=tuple(patched.warnings),
        )

    def _execution(self, context: RegressionContext, side: _Side, claim: str) -> Execution:
        verdict, reasons, summary = self._judge(side)
        trace: dict[str, JsonValue] = {
            "targets": list(context.targets),
            "interfaces": _interface_document(side.interfaces),
        }
        if side.fails and side.unknowns:
            # The verdict is FAIL; the steps that did not finish stay visible in the trace.
            trace["incomplete"] = [item.model_dump(mode="json") for item in side.unknowns]
        if side.revision is RevisionKind.PATCHED:
            trace["changes"] = list(side.changes)
            trace["suite"] = dict(side.suite)
            trace["fuzz_seed"] = self.settings.fuzz_seed
            trace["fuzz_runs"] = self.settings.fuzz_runs
        suite_ran = side.argv[:2] == ("forge", "test")
        return Execution(
            revision=side.revision,
            claim=claim,
            argv=side.argv,
            seed=self.settings.seed if suite_ran else None,
            exit_code=side.exit_code,
            verdict=verdict,
            reasons=reasons,
            summary=clip(summary),
            trace=trace,
            evidence=tuple(side.evidence),
            warnings=tuple(side.warnings),
        )
