"""SymbolicOracle: Halmos properties on both revisions, within recorded bounds (ADR 0018).

Properties live in the `symbolic/` subdirectory of the PoC directory, in contracts deriving
from `AssayCheck` (`solidity/AssayCheck.sol`). Two kinds, told apart by name:

- `check_variant_*`: the exploit with symbolic parameters, ending in `assertNo*` wrappers of the
  PoC predicates. They run on the vulnerable revision (sanity check) and on the patched one.
- `check_equiv_*`: bounded equivalence of the patched revision with the vulnerable one (under
  `baseline/` in the symbolic tree), outside the exploit condition. They run on the patched
  revision only.

Halmos runs in the symbolic runner image (`halmos`); its report is parsed strictly. Per property
the result is one of: no counterexample on any explored path within the bounds, a
counterexample, or unknown (solver timeout, an unexplored path, every path reverting, an error).
A run that ends without a usable report (wall-clock timeout, out-of-memory kill, failed build)
makes every property of it unknown.

Sanity check: a variant property counts only when Halmos reports a counterexample with a valid
model on the vulnerable revision; a property that finds nothing there says nothing about the
patched revision (warning `symbolic_check_ineffective`).

Counterexample flow, on the patched revision, as for the VariantOracle: the model's values are
saved as `counterexample.json`, a concrete test `variant_poc.t.sol` replays the property with
those values through `assayReplayCheck`, and the test runs three times with Foundry in the
regular runner image. Only three reproductions of three confirm the variant.

Verdict:

- a counterexample on the patched revision, confirmed by three replays of three: FAIL
  `variant_found`;
- a counterexample whose replays disagree or reach no predicate: INCONCLUSIVE
  `flaky_counterexample`;
- a timeout, an out-of-memory kill, or an unknown result of a counted property: INCONCLUSIVE
  `symbolic_unknown`;
- no variant property finds the exploit on the vulnerable revision: INCONCLUSIVE
  `symbolic_check_ineffective`;
- every counted property without counterexample on the patched revision: PASS.

A timeout or unknown result is never a pass. Bounded equivalence never changes the verdict: its
outcome is recorded in the bounds and, when it is not a clean result, as a warning.
"""

import itertools
import re
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError

from assay.analysis.limits import AnalyzerOutputError, OutputLimits, load_json
from assay.analyzers import foundry
from assay.analyzers.foundry import ForgeTestRun
from assay.ingest import Snapshot
from assay.ledger import OracleName, RevisionKind, Verdict
from assay.oracles.base import Evidence, Execution, OracleResult, Reason, clip, reason
from assay.oracles.exploit.events import PREDICATE_EVENT, predicates
from assay.oracles.runtree import (
    Harness,
    RunTree,
    RunTreeError,
    build_symbolic_tree,
    symbolic_paths,
)
from assay.oracles.steps import (
    Stop,
    build,
    first_error,
    harness_topic,
    json_evidence,
    problem_of,
    results_evidence,
)
from assay.oracles.symbolic.halmos import (
    SOLVER,
    CheckResult,
    HalmosRun,
    HalmosSettings,
    Witness,
    halmos_argv,
    run_halmos,
)
from assay.oracles.variant.poc import (
    VARIANT_POC_CONTRACT,
    VARIANT_POC_FILE,
    VARIANT_POC_PATH,
    VARIANT_POC_TEST,
    PocRejected,
    base_contract,
    render_check,
    solc_version,
)
from assay.oracles.variant.profiles import DEFAULT_BASE_SEED, BaseSeed
from assay.sandbox import SandboxRunner, make_scratch_dir

VARIANT_PREFIX: Final = "check_variant_"
EQUIVALENCE_PREFIX: Final = "check_equiv_"
ALL_PREFIX: Final = "check_"
CONFIRMATION_REPLAYS: Final = 3
CHECK_HARNESS_FILE: Final = "AssayCheck.sol"
HARNESS_FILE: Final = "AssayExploit.sol"
COUNTEREXAMPLE_FILE: Final = "counterexample.json"
HALMOS_LABEL: Final = "halmos"
REPLAY_CONTRACT_FILTER: Final = f"^{VARIANT_POC_CONTRACT}$"
REPLAY_TEST_FILTER: Final = f"^{VARIANT_POC_TEST}[(]"
CLAIM_VULNERABLE: Final = (
    "Within the recorded bounds, Halmos reports a counterexample of a symbolic variant property "
    "on the vulnerable revision."
)
CLAIM_PATCHED: Final = (
    "Within the recorded bounds, Halmos reports no counterexample of the counted symbolic "
    "variant properties on the patched revision, and no counterexample was confirmed."
)
_MAX_CALLS: Final = re.compile(rb"uint256 internal constant ASSAY_MAX_CALLS = ([0-9]{1,3});")
_INLINE_CONFIG: Final = re.compile(rb"custom:halmos", re.IGNORECASE)
_PARAMETER_NAME: Final = re.compile(r"[A-Za-z][A-Za-z0-9]{0,63}")
_EQUIVALENCE_DECLARATION: Final = b"function check_equiv_"

EquivalenceStatus = Literal["no_difference", "difference", "unknown", "none", "not_run"]
CheckKind = Literal["variant", "equivalence"]


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class SymbolicSettings(_Model):
    """Bounds of the SymbolicOracle: Halmos's bounds and limits, and the fuzz seed that the
    Foundry replays of a counterexample run with (they draw nothing at random)."""

    halmos: HalmosSettings = Field(default_factory=HalmosSettings)
    fuzz_seed: BaseSeed = DEFAULT_BASE_SEED


@dataclass(frozen=True, slots=True)
class SymbolicContext:
    runner: SandboxRunner
    """The regular runner image: compiles and replays counterexamples with Foundry."""
    symbolic_runner: SandboxRunner
    """The symbolic runner image: runs Halmos."""
    vulnerable: Snapshot
    patched: Snapshot
    poc: Snapshot
    harness: Harness
    work_dir: Path
    """An existing, empty directory for the run trees."""


class CheckBounds(_Model):
    """What Halmos reported for one property on one revision. Deterministic."""

    revision: RevisionKind
    contract: str
    signature: str
    kind: CheckKind
    outcome: Literal["no_counterexample", "counterexample", "unknown", "not_reported"]
    halmos_code: int | None
    calldata_bytes: int
    paths: int | None
    bounded_loops: int | None


class RunBounds(_Model):
    """One Halmos run; `problem` says how a run without a usable report ended."""

    revision: RevisionKind
    prefix: str
    problem: str | None


class SymbolicBounds(_Model):
    """The bounds of the symbolic oracle, as numbers and names. Deterministic: no durations."""

    halmos_version: str | None
    solver: str
    loop_bound: int
    solver_timeout_s: int
    timeout_s: int
    memory_mib: int
    max_calls_per_property: int | None
    runs: tuple[RunBounds, ...]
    checks: tuple[CheckBounds, ...]
    confirmed_property: str | None
    confirmation_replays: int
    replays_reproduced: int | None
    equivalence: EquivalenceStatus


class RunTime(_Model):
    revision: RevisionKind
    what: Literal["halmos", "confirmation"]
    seconds: float


class SymbolicTiming(_Model):
    """Wall-clock durations of the symbolic oracle, rounded to 0.1 s; they vary between runs."""

    total_s: float
    runs: tuple[RunTime, ...]


@dataclass(frozen=True, slots=True)
class SymbolicOutcome:
    result: OracleResult
    bounds: SymbolicBounds
    timing: SymbolicTiming
    statement: str
    equivalence_statement: str


@dataclass
class _Confirmation:
    check: CheckResult
    witness: Witness
    status: Literal["confirmed", "flaky", "rejected", "failed"] = "failed"
    words: tuple[int, ...] = ()
    names: tuple[str, ...] = ()
    source: str | None = None
    reproduced: int = 0
    replays: list[dict[str, JsonValue]] = field(default_factory=list)
    results: list[ForgeTestRun] = field(default_factory=list)
    problem: Reason | None = None
    seconds: float = 0.0

    def trace(self) -> dict[str, JsonValue]:
        return {
            "property": self.check.signature,
            "contract": self.check.contract,
            "status": self.status,
            "reproduced": self.reproduced,
            "replays": list(self.replays),
            "problem": None if self.problem is None else self.problem.model_dump(mode="json"),
        }


@dataclass
class _Side:
    revision: RevisionKind
    run: HalmosRun | None = None
    problem: Reason | None = None
    confirmations: list[_Confirmation] = field(default_factory=list)
    has_equivalence: bool = False
    """The PoC directory declares equivalence properties (`function check_equiv_`)."""

    def checks(self, prefix: str) -> list[CheckResult]:
        if self.run is None:
            return []
        return [item for item in self.run.checks if item.name.startswith(prefix)]


def _seconds(started: float) -> float:
    return round(time.monotonic() - started, 1)


def max_calls(harness: Harness) -> int | None:
    """`ASSAY_MAX_CALLS` of the harness's `AssayCheck.sol`, or `None` if it cannot be read."""
    data = dict(harness.files).get(CHECK_HARNESS_FILE)
    found = _MAX_CALLS.findall(data or b"")
    return int(found[0]) if len(found) == 1 else None


def _calldata(size: int) -> str:
    return f"4+32*{(size - 4) // 32} bytes"


def _key(check: CheckResult | CheckBounds) -> tuple[str, str]:
    return check.contract, check.signature


def _effective(side: _Side) -> set[tuple[str, str]]:
    """Variant properties for which Halmos reported a counterexample with a valid model."""
    return {
        _key(item)
        for item in side.checks(VARIANT_PREFIX)
        if item.outcome == "counterexample" and any(w.valid for w in item.witnesses)
    }


def _run_problem(run: HalmosRun | None) -> Reason | None:
    if run is None or run.problem is None:
        return None
    if run.problem in ("timeout", "out_of_memory"):
        return reason("symbolic_unknown", f"{run.detail}; a timeout is never a pass")
    if run.problem == "build_failed":
        return reason("symbolic_build_failed", run.detail)
    return reason("symbolic_output_unusable", run.detail)


class SymbolicOracle:
    name = OracleName.SYMBOLIC

    def __init__(
        self, settings: SymbolicSettings | None = None, halmos_version: str | None = None
    ) -> None:
        self.settings = settings if settings is not None else SymbolicSettings()
        self.halmos_version = halmos_version
        self._directories = itertools.count(1)

    def _fresh_dir(self, parent: Path, stem: str) -> Path:
        path = parent / f"{stem}-{next(self._directories)}"
        path.mkdir()
        return path

    def run(self, context: SymbolicContext) -> OracleResult:
        return self.search(context).result

    def search(self, context: SymbolicContext) -> SymbolicOutcome:
        started = time.monotonic()
        vulnerable = _Side(RevisionKind.VULNERABLE)
        patched = _Side(RevisionKind.PATCHED)
        if not symbolic_paths(context.poc):
            vulnerable.problem = reason(
                "no_symbolic_properties",
                "the PoC directory has no symbolic/ subdirectory with properties; nothing was "
                "checked symbolically",
            )
            return self._outcome(vulnerable, None, context, started)
        inline = self._inline_config(context)
        if inline is not None:
            vulnerable.problem = inline
            return self._outcome(vulnerable, None, context, started)
        try:
            trees = (
                build_symbolic_tree(
                    context.vulnerable,
                    context.vulnerable,
                    context.poc,
                    context.harness,
                    context.work_dir / "vulnerable",
                ),
                build_symbolic_tree(
                    context.patched,
                    context.vulnerable,
                    context.poc,
                    context.harness,
                    context.work_dir / "patched",
                ),
            )
        except RunTreeError as exc:
            vulnerable.problem = reason("run_tree_rejected", str(exc))
            return self._outcome(vulnerable, None, context, started)
        patched.has_equivalence = any(
            _EQUIVALENCE_DECLARATION in (context.poc.tree_dir / path).read_bytes()
            for path in symbolic_paths(context.poc)
        )
        settings = self.settings.halmos
        vulnerable.run = run_halmos(
            context.symbolic_runner, trees[0].tree, trees[0].scratch, VARIANT_PREFIX, settings
        )
        vulnerable.problem = _run_problem(vulnerable.run)
        patched.run = run_halmos(
            context.symbolic_runner, trees[1].tree, trees[1].scratch, ALL_PREFIX, settings
        )
        patched.problem = _run_problem(patched.run)
        for check in patched.checks(VARIANT_PREFIX):
            if check.outcome != "counterexample":
                continue
            confirmation = self._confirm(context, trees[1], check)
            patched.confirmations.append(confirmation)
            if confirmation.status == "confirmed":
                break
        return self._outcome(vulnerable, patched, context, started)

    # -- checks before running -------------------------------------------------------------------

    def _inline_config(self, context: SymbolicContext) -> Reason | None:
        """Halmos reads `@custom:halmos` options from NatSpec, which could switch FFI on or change
        the bounds; such a tree is refused (as ingest refuses inline Foundry configuration)."""
        sources: list[tuple[str, bytes]] = [
            (f"poc/{item.path}", (context.poc.tree_dir / item.path).read_bytes())
            for item in context.poc.files
            if item.path.endswith(".sol")
        ]
        for label, snapshot in (("vulnerable", context.vulnerable), ("patched", context.patched)):
            sources += [
                (f"{label}: {item.path}", (snapshot.tree_dir / item.path).read_bytes())
                for item in snapshot.files
                if item.path.endswith(".sol")
            ]
        sources += [(f"harness: {name}", data) for name, data in context.harness.files]
        for label, data in sources:
            if _INLINE_CONFIG.search(data):
                return reason(
                    "inline_halmos_config",
                    f"{label} contains a Halmos option annotation (custom:halmos); Assay sets "
                    "the symbolic bounds itself",
                )
        return None

    # -- counterexample confirmation -------------------------------------------------------------

    def _confirm(
        self, context: SymbolicContext, tree: RunTree, check: CheckResult
    ) -> _Confirmation:
        started = time.monotonic()
        witnesses = [item for item in check.witnesses if item.valid] or list(check.witnesses)
        confirmation = _Confirmation(check=check, witness=witnesses[0])
        try:
            self._replay(context, tree, confirmation)
        finally:
            confirmation.seconds = _seconds(started)
        return confirmation

    def _replay(self, context: SymbolicContext, tree: RunTree, item: _Confirmation) -> None:
        check = item.check
        try:
            names = self._parameter_names(context.runner, tree, check)
            item.names = names
            item.words = tuple(item.witness.value_of(name) or 0 for name in names)
            harness = dict(context.harness.files).get(HARNESS_FILE)
            if harness is None:
                raise PocRejected(f"the harness has no {HARNESS_FILE}")
            item.source = render_check(
                base_contract(check.contract), check.name, item.words, solc_version(harness)
            )
        except PocRejected as exc:
            item.status = "rejected"
            item.problem = reason(
                "counterexample_rejected",
                f"the counterexample of {check.signature} cannot be written into a test: {exc}",
            )
            return
        except Stop as stop:
            item.problem = stop.problem
            return
        try:
            replay_tree = build_symbolic_tree(
                context.patched,
                context.vulnerable,
                context.poc,
                context.harness,
                context.work_dir / f"confirm-{next(self._directories)}",
                extra_tests=((VARIANT_POC_PATH, item.source.encode("ascii")),),
            )
            compiled = build(context.runner, replay_tree)
            if not compiled.succeeded:
                item.problem = reason("variant_poc_build_failed", first_error(compiled))
                return
            topic = harness_topic(context.runner, replay_tree, PREDICATE_EVENT)
        except RunTreeError as exc:
            item.problem = reason("variant_poc_rejected", str(exc))
            return
        except Stop as stop:
            item.problem = stop.problem
            return
        except (foundry.ForgeTimeout, foundry.ForgeOutputError) as exc:
            item.problem = problem_of(exc)[0]
            return
        for number in range(1, CONFIRMATION_REPLAYS + 1):
            entry: dict[str, JsonValue] = {"replay": number, "reproduced": False}
            try:
                run = foundry.test(
                    context.runner,
                    replay_tree.tree,
                    match_contract=REPLAY_CONTRACT_FILTER,
                    match_test=REPLAY_TEST_FILTER,
                    fuzz_seed=self.settings.fuzz_seed,
                    scratch_dir=replay_tree.scratch,
                    timeout_s=self.settings.halmos.timeout_s,
                )
            except (foundry.ForgeTimeout, foundry.ForgeOutputError) as exc:
                entry["problem"] = problem_of(exc)[0].code
                item.replays.append(entry)
                continue
            item.results.append(run)
            cases = [
                case
                for suite in run.suites
                for case in suite.tests
                if case.name.startswith(f"{VARIANT_POC_TEST}(")
            ]
            entry["exit_code"] = run.exit_code
            if len(cases) == 1:
                held = predicates(cases[0].events, topic)
                entry["status"] = cases[0].status
                entry["predicates"] = [found.kind for found in held]
                entry["reproduced"] = cases[0].status == "success" and bool(held)
            item.replays.append(entry)
            if entry["reproduced"]:
                item.reproduced += 1
        item.status = "confirmed" if item.reproduced == CONFIRMATION_REPLAYS else "flaky"
        if item.status == "flaky":
            item.problem = reason(
                "flaky_counterexample",
                f"the counterexample of {check.signature} reproduced in {item.reproduced} of "
                f"{CONFIRMATION_REPLAYS} replays of {VARIANT_POC_FILE} on the patched revision",
            )

    def _parameter_names(
        self, runner: SandboxRunner, tree: RunTree, check: CheckResult
    ) -> tuple[str, ...]:
        """The parameter names of a property, in order, from its ABI (`forge inspect`)."""
        scratch = make_scratch_dir(self._fresh_dir(tree.scratch.parent, "inspect"))
        try:
            text = foundry.inspect(runner, tree.tree, check.contract, "abi", scratch_dir=scratch)
        except (foundry.ForgeTimeout, foundry.ForgeOutputError) as exc:
            raise Stop(reason("symbolic_abi_unreadable", str(exc))) from exc
        return parameter_names(text, check)

    # -- verdict -----------------------------------------------------------------------------------

    def _judge_vulnerable(self, side: _Side) -> tuple[Verdict, tuple[Reason, ...], str]:
        if side.problem is not None:
            return Verdict.INCONCLUSIVE, (side.problem,), f"vulnerable: {side.problem.code}"
        effective = sorted(_effective(side))
        if effective:
            names = ", ".join(signature for _, signature in effective)
            return Verdict.PASS, (), f"vulnerable: counterexample found ({names})"
        detail = (
            "no symbolic variant property has a counterexample on the vulnerable revision; a "
            "property that finds nothing there says nothing about the patched revision"
        )
        return (
            Verdict.INCONCLUSIVE,
            (reason("symbolic_check_ineffective", detail),),
            "vulnerable: symbolic_check_ineffective",
        )

    def _judge_patched(
        self, side: _Side, effective: set[tuple[str, str]]
    ) -> tuple[Verdict, tuple[Reason, ...], str]:
        confirmed = [item for item in side.confirmations if item.status == "confirmed"]
        if confirmed:
            item = confirmed[0]
            values = ", ".join(
                f"{name}={word:#x}" for name, word in zip(item.names, item.words, strict=True)
            )
            detail = (
                f"Halmos counterexample of {item.check.signature} confirmed by "
                f"{item.reproduced} of {CONFIRMATION_REPLAYS} replays of {VARIANT_POC_FILE}: "
                f"{values or 'no arguments'}"
            )
            return (
                Verdict.FAIL,
                (reason("variant_found", detail),),
                f"patched: counterexample of {item.check.name}, confirmed "
                f"{item.reproduced}/{CONFIRMATION_REPLAYS}",
            )
        problems = [item.problem for item in side.confirmations if item.problem is not None]
        if side.problem is not None:
            problems.append(side.problem)
        reported = {_key(item): item for item in side.checks(VARIANT_PREFIX)}
        for key in sorted(effective):
            check = reported.get(key)
            if side.problem is None and check is None:
                problems.append(
                    reason("symbolic_unknown", f"{key[1]} was not reported on the patched revision")
                )
            elif check is not None and check.outcome == "unknown":
                problems.append(
                    reason(
                        "symbolic_unknown",
                        f"{check.signature}: {check.describe()} (solver timeout "
                        f"{self.settings.halmos.solver_timeout_s} s per query); an unknown "
                        "result is never a pass",
                    )
                )
        if problems:
            return Verdict.INCONCLUSIVE, tuple(problems), f"patched: {problems[0].code}"
        return Verdict.PASS, (), "patched: no counterexample"

    def _outcome(
        self,
        vulnerable: _Side,
        patched: _Side | None,
        context: SymbolicContext,
        started: float,
    ) -> SymbolicOutcome:
        effective = _effective(vulnerable)
        bounds = self._bounds(vulnerable, patched, context.harness)
        statement = bounds_statement(bounds)
        equivalence = equivalence_statement(bounds)
        v_verdict, v_reasons, v_summary = self._judge_vulnerable(vulnerable)
        executions = [
            self._execution(vulnerable, CLAIM_VULNERABLE, v_verdict, v_reasons, v_summary)
        ]
        timing = self._timing(vulnerable, patched, started)
        if patched is None:
            result = OracleResult(
                oracle=self.name,
                verdict=Verdict.INCONCLUSIVE,
                reasons=v_reasons,
                summary=clip(f"{v_summary}; the patched revision was not run"),
                executions=tuple(executions),
            )
            return SymbolicOutcome(result, bounds, timing, statement, equivalence)
        p_verdict, p_reasons, p_summary = self._judge_patched(patched, effective)
        executions.append(self._execution(patched, CLAIM_PATCHED, p_verdict, p_reasons, p_summary))
        verdict: Verdict
        if p_verdict is Verdict.FAIL:
            verdict, reasons = p_verdict, p_reasons
        elif v_verdict is not Verdict.PASS:
            verdict = Verdict.INCONCLUSIVE
            reasons = tuple({item.code: item for item in (*v_reasons, *p_reasons)}.values())
        else:
            verdict, reasons = p_verdict, p_reasons
        summary = f"{v_summary}; {p_summary}"
        if verdict is Verdict.PASS:
            summary = f"{v_summary}; patched: {statement}"
        result = OracleResult(
            oracle=self.name,
            verdict=verdict,
            reasons=reasons,
            summary=clip(summary),
            executions=tuple(executions),
            warnings=self._warnings(vulnerable, patched, bounds, equivalence),
        )
        return SymbolicOutcome(result, bounds, timing, statement, equivalence)

    def _warnings(
        self, vulnerable: _Side, patched: _Side, bounds: SymbolicBounds, equivalence: str
    ) -> tuple[Reason, ...]:
        warnings: list[Reason] = []
        effective = _effective(vulnerable)
        if effective and vulnerable.problem is None:
            for check in vulnerable.checks(VARIANT_PREFIX):
                if _key(check) not in effective:
                    warnings.append(
                        reason(
                            "symbolic_check_ineffective",
                            f"{check.signature} has no counterexample on the vulnerable "
                            "revision; its result on the patched revision is not counted",
                        )
                    )
        if bounds.equivalence in ("difference", "unknown"):
            warnings.append(reason("equivalence_not_shown", equivalence))
        return tuple(warnings)

    def _bounds(self, vulnerable: _Side, patched: _Side | None, harness: Harness) -> SymbolicBounds:
        checks: list[CheckBounds] = []
        runs: list[RunBounds] = []
        for side, prefix in ((vulnerable, VARIANT_PREFIX), (patched, ALL_PREFIX)):
            if side is None or side.run is None:
                continue
            runs.append(
                RunBounds(
                    revision=side.revision,
                    prefix=prefix,
                    problem=None if side.run.problem is None else side.run.problem,
                )
            )
            checks += [_check_bounds(side.revision, item) for item in side.checks(ALL_PREFIX)]
        if patched is not None:
            reported = {
                (item.contract, item.signature)
                for item in checks
                if item.revision is RevisionKind.PATCHED
            }
            for item in [c for c in checks if c.revision is RevisionKind.VULNERABLE]:
                if (item.contract, item.signature) not in reported:
                    checks.append(
                        item.model_copy(
                            update={
                                "revision": RevisionKind.PATCHED,
                                "outcome": "not_reported",
                                "halmos_code": None,
                                "paths": None,
                                "bounded_loops": None,
                            }
                        )
                    )
        confirmations = [] if patched is None else patched.confirmations
        confirmed = [item for item in confirmations if item.status == "confirmed"]
        replayed = confirmed[0] if confirmed else (confirmations[0] if confirmations else None)
        settings = self.settings.halmos
        return SymbolicBounds(
            halmos_version=self.halmos_version,
            solver=SOLVER,
            loop_bound=settings.loop,
            solver_timeout_s=settings.solver_timeout_s,
            timeout_s=settings.timeout_s,
            memory_mib=settings.memory_mib,
            max_calls_per_property=max_calls(harness),
            runs=tuple(runs),
            checks=tuple(checks),
            confirmed_property=None if not confirmed else confirmed[0].check.signature,
            confirmation_replays=CONFIRMATION_REPLAYS,
            replays_reproduced=None
            if replayed is None or replayed.status in ("rejected", "failed")
            else replayed.reproduced,
            equivalence=_equivalence(patched),
        )

    def _timing(self, vulnerable: _Side, patched: _Side | None, started: float) -> SymbolicTiming:
        runs: list[RunTime] = []
        for side in (vulnerable, patched):
            if side is None:
                continue
            if side.run is not None:
                runs.append(
                    RunTime(revision=side.revision, what="halmos", seconds=side.run.seconds)
                )
            runs += [
                RunTime(revision=side.revision, what="confirmation", seconds=item.seconds)
                for item in side.confirmations
            ]
        return SymbolicTiming(total_s=_seconds(started), runs=tuple(runs))

    def _execution(
        self,
        side: _Side,
        claim: str,
        verdict: Verdict,
        reasons: tuple[Reason, ...],
        summary: str,
    ) -> Execution:
        prefix = VARIANT_PREFIX if side.revision is RevisionKind.VULNERABLE else ALL_PREFIX
        run = side.run
        trace: dict[str, JsonValue] = {
            "prefix": prefix,
            "settings": self.settings.halmos.model_dump(mode="json"),
            "problem": None if side.problem is None else side.problem.model_dump(mode="json"),
            "run_problem": None if run is None else run.problem,
            "checks": [] if run is None else [_check_trace(item) for item in run.checks],
            "confirmations": [item.trace() for item in side.confirmations],
        }
        return Execution(
            revision=side.revision,
            claim=claim,
            argv=run.argv if run is not None else halmos_argv(prefix, self.settings.halmos),
            seed=None,
            exit_code=None if run is None else run.exit_code,
            verdict=verdict,
            reasons=reasons,
            summary=clip(summary),
            trace=trace,
            evidence=self._evidence(side),
        )

    def _evidence(self, side: _Side) -> tuple[Evidence, ...]:
        evidence: list[Evidence] = []
        if side.run is not None:
            evidence.append(
                json_evidence(
                    f"symbolic: Halmos results, {side.revision.value} revision",
                    [_check_trace(item) for item in side.run.checks],
                )
            )
        confirmed = [item for item in side.confirmations if item.status == "confirmed"]
        primary = (
            confirmed[0] if confirmed else (side.confirmations[0] if side.confirmations else None)
        )
        for item in side.confirmations:
            canonical = item is primary
            evidence.append(
                json_evidence(
                    f"symbolic: counterexample of {item.check.name}",
                    {
                        "mode": "symbolic",
                        "revision": side.revision.value,
                        "contract": item.check.contract,
                        "property": item.check.signature,
                        "valid_model": item.witness.valid,
                        "values": [
                            {"name": name, "type": kind, "value": f"{value:#x}"}
                            for name, kind, value in item.witness.values
                        ],
                        "arguments": [f"{word:#x}" for word in item.words],
                        "loop_bound": self.settings.halmos.loop,
                        "confirmation": item.trace(),
                    },
                    COUNTEREXAMPLE_FILE if canonical else None,
                )
            )
            if item.source is not None:
                evidence.append(
                    Evidence(
                        label=f"symbolic: {VARIANT_POC_FILE} for {item.check.name}",
                        media_type="text/plain",
                        data=item.source.encode("ascii"),
                        name=VARIANT_POC_FILE if canonical else None,
                    )
                )
            evidence += [
                results_evidence(f"symbolic: replay {number} of {VARIANT_POC_FILE}", run)
                for number, run in enumerate(item.results, start=1)
            ]
        return tuple(evidence)


def _check_bounds(revision: RevisionKind, item: CheckResult) -> CheckBounds:
    outcome = {"no_counterexample": "no_counterexample", "counterexample": "counterexample"}.get(
        item.outcome, "unknown"
    )
    return CheckBounds(
        revision=revision,
        contract=item.contract,
        signature=item.signature,
        kind="equivalence" if item.name.startswith(EQUIVALENCE_PREFIX) else "variant",
        outcome=outcome,  # type: ignore[arg-type]
        halmos_code=item.code,
        calldata_bytes=item.calldata_bytes,
        paths=item.paths,
        bounded_loops=item.bounded_loops,
    )


def _check_trace(item: CheckResult) -> dict[str, JsonValue]:
    return {
        "contract": item.contract,
        "property": item.signature,
        "halmos_code": item.code,
        "result": item.describe(),
        "paths": item.paths,
        "bounded_loops": item.bounded_loops,
        "calldata_bytes": item.calldata_bytes,
        "counterexamples": [
            {
                "valid_model": witness.valid,
                "values": [
                    {"name": name, "type": kind, "value": f"{value:#x}"}
                    for name, kind, value in witness.values
                ],
            }
            for witness in item.witnesses
        ],
    }


def _equivalence(patched: _Side | None) -> EquivalenceStatus:
    if patched is None or patched.run is None:
        return "not_run"
    if patched.problem is not None:
        return "unknown" if patched.has_equivalence else "none"
    checks = patched.checks(EQUIVALENCE_PREFIX)
    if not checks:
        return "none"
    if any(item.outcome == "counterexample" for item in checks):
        return "difference"
    if any(item.outcome == "unknown" for item in checks):
        return "unknown"
    return "no_difference"


class _AbiInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore", strict=True)
    name: str = Field(max_length=200)
    type: str = Field(max_length=200)


class _AbiEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore", strict=True)
    type: str = Field(max_length=40)
    name: str | None = Field(default=None, max_length=200)
    inputs: list[_AbiInput] | None = Field(default=None, max_length=64)


def parameter_names(abi_text: str, check: CheckResult) -> tuple[str, ...]:
    """The parameter names of `check` from the JSON ABI `forge inspect` printed (untrusted).

    Raises `PocRejected` when the property is missing, ambiguous, its types differ from the
    signature Halmos reported, or a parameter name is not a plain name without `_` (Halmos cuts
    a reported name at the first `_`, so the value could not be matched).
    """
    try:
        document = load_json(abi_text.encode("utf-8"), OutputLimits(max_bytes=4 * 1024 * 1024))
        entries = [_AbiEntry.model_validate(item) for item in _as_list(document)]
    except (AnalyzerOutputError, ValidationError, UnicodeEncodeError) as exc:
        raise PocRejected(f"the ABI of {check.contract} is unreadable") from exc
    found = [
        entry
        for entry in entries
        if entry.type == "function"
        and entry.name == check.name
        and tuple(item.type for item in entry.inputs or ()) == check.parameter_types
    ]
    if len(found) != 1:
        raise PocRejected(f"{check.signature} is not exactly once in the ABI")
    names = tuple(item.name for item in found[0].inputs or ())
    for name in names:
        if _PARAMETER_NAME.fullmatch(name) is None:
            raise PocRejected(
                f"parameter {name[:40]!r} of {check.name} is not a plain name without _"
            )
    if len(set(names)) != len(names):
        raise PocRejected(f"{check.name} repeats a parameter name")
    return names


def _as_list(document: object) -> list[object]:
    if not isinstance(document, list):
        raise PocRejected("the ABI is not a list")
    return document


def _properties(
    bounds: SymbolicBounds, revision: RevisionKind, kind: CheckKind
) -> list[CheckBounds]:
    return [item for item in bounds.checks if item.revision is revision and item.kind == kind]


def _limits(bounds: SymbolicBounds) -> str:
    calls = (
        f", at most {bounds.max_calls_per_property} calls of the target per property"
        if bounds.max_calls_per_property is not None
        else ""
    )
    version = f"Halmos {bounds.halmos_version}, " if bounds.halmos_version else ""
    return (
        f"{version}solver {bounds.solver} with {bounds.solver_timeout_s} s per query{calls}, "
        f"run limit {bounds.timeout_s} s and {bounds.memory_mib} MiB"
    )


def _listing(items: Sequence[CheckBounds]) -> str:
    parts = []
    for item in items:
        cut = f", {item.bounded_loops} loops cut at the bound" if item.bounded_loops else ""
        parts.append(
            f"{item.signature.split('(', 1)[0]} (calldata {_calldata(item.calldata_bytes)}{cut})"
        )
    return ", ".join(parts)


def _run_problem_text(problem: str, bounds: SymbolicBounds) -> str:
    return {
        "timeout": f"timeout {bounds.timeout_s} s",
        "out_of_memory": f"out of memory, limit {bounds.memory_mib} MiB",
        "build_failed": "the symbolic tree does not compile",
        "no_report": "Halmos wrote no report",
        "unusable_report": "the Halmos report is unusable",
    }.get(problem, problem)


def bounds_statement(bounds: SymbolicBounds) -> str:
    """What the symbolic oracle ran on the patched revision, worded as that and nothing more."""
    head = f"symbolic: loop bound {bounds.loop_bound}; {_limits(bounds)}"
    patched_run = [item for item in bounds.runs if item.revision is RevisionKind.PATCHED]
    if not patched_run:
        return f"symbolic: the patched revision was not checked ({_limits(bounds)})"
    if patched_run[0].problem is not None:
        return (
            f"symbolic: unknown ({_run_problem_text(patched_run[0].problem, bounds)}); loop "
            f"bound {bounds.loop_bound}; {_limits(bounds)}"
        )
    vulnerable_run = [item for item in bounds.runs if item.revision is RevisionKind.VULNERABLE]
    effective = {
        (item.contract, item.signature)
        for item in _properties(bounds, RevisionKind.VULNERABLE, "variant")
        if item.outcome == "counterexample"
    }
    patched = _properties(bounds, RevisionKind.PATCHED, "variant")
    counted = [item for item in patched if (item.contract, item.signature) in effective]
    found = [item for item in patched if item.outcome == "counterexample"]
    unknown = [item for item in counted if item.outcome in ("unknown", "not_reported")]
    if bounds.confirmed_property is not None:
        name = bounds.confirmed_property.split("(", 1)[0]
        return (
            f"symbolic: counterexample of {name} within loop bound {bounds.loop_bound}, "
            f"confirmed by {bounds.replays_reproduced} of {bounds.confirmation_replays} replays; "
            f"{_limits(bounds)}"
        )
    if vulnerable_run and vulnerable_run[0].problem is not None:
        return (
            f"symbolic: unknown on the vulnerable revision "
            f"({_run_problem_text(vulnerable_run[0].problem, bounds)}), so the patched "
            f"revision's result is not counted; loop bound {bounds.loop_bound}; {_limits(bounds)}"
        )
    if found:
        return (
            f"symbolic: counterexample reported for {_listing(found)}, not confirmed; "
            f"{_limits(bounds)}"
        )
    if unknown:
        return (
            f"symbolic: unknown for {_listing(unknown)} (solver timeout "
            f"{bounds.solver_timeout_s} s per query, loop bound {bounds.loop_bound}); "
            f"{_limits(bounds)}"
        )
    if not counted:
        return f"{head}; no variant property found the exploit on the vulnerable revision"
    ignored = [item for item in patched if item not in counted]
    tail = f"; not counted: {_listing(ignored)}" if ignored else ""
    return (
        f"symbolic: no counterexample within loop bound {bounds.loop_bound} for "
        f"{_listing(counted)}; {_limits(bounds)}{tail}; this is not a proof of absence"
    )


def equivalence_statement(bounds: SymbolicBounds) -> str:
    """The bounded-equivalence result, which adds to the BehaviorOracle's evidence only when no
    difference was found and never changes a verdict."""
    status = bounds.equivalence
    if status == "not_run":
        return "bounded equivalence: not run"
    if status == "none":
        return "bounded equivalence: no equivalence properties in the PoC directory"
    items = _properties(bounds, RevisionKind.PATCHED, "equivalence")
    if status == "no_difference":
        return (
            f"bounded equivalence: no difference from the vulnerable revision within loop bound "
            f"{bounds.loop_bound} for {_listing(items)}, outside the exploit condition; this is "
            "not a proof of equivalence"
        )
    if status == "difference":
        differing = [item for item in items if item.outcome == "counterexample"]
        return (
            f"bounded equivalence: Halmos reported a difference for {_listing(differing)} (not "
            "replayed); the verdict is unchanged"
        )
    run = [item for item in bounds.runs if item.revision is RevisionKind.PATCHED]
    why = (
        _run_problem_text(run[0].problem, bounds)
        if run and run[0].problem
        else (f"solver timeout {bounds.solver_timeout_s} s per query")
    )
    return f"bounded equivalence: unknown ({why}); the verdict is unchanged"
