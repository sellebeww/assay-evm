"""BehaviorOracle: the patch must keep the benign behavior of the project.

Both revisions run in benign trees (ADR 0011): `src/` of the revision, the project's `test/`
directory and the shared harness. On each revision the oracle compiles the tree and runs every
test (`forge test --json -vv` with the recorded fuzz seed and number of runs).

- The vulnerable revision sets the baseline: which tests pass, and what each passing test records
  with `recordBehavior` (the `AssayRecord(bytes32 key, bytes data)` events emitted by the test
  contract itself; console lines never count). Tests that fail there are not compared. Without a
  passing test there is no baseline: INCONCLUSIVE `no_benign_tests`.
- On the patched revision, every test that passes on the vulnerable revision must pass again;
  otherwise FAIL `benign_test_failed`. Benign tests that no longer compile against the patched
  sources fail as well.
- For every test that passes on both revisions, the recorded values are compared key by key: a
  key whose values differ, or that only one revision records, gives FAIL `behavior_changed`.
  The differences are stored as evidence (`behavior-diff.json`).

A timeout, unusable output or a vulnerable revision that does not compile gives INCONCLUSIVE,
never a pass. The oracle's verdict is the patched revision's verdict, or INCONCLUSIVE when the
vulnerable revision gave no baseline.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Final

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StringConstraints

from assay.analyzers import foundry
from assay.analyzers.foundry import ForgeEvent, ForgeTestRun
from assay.ingest import Snapshot
from assay.ingest.config import DEFAULT_FUZZ_SEED
from assay.ledger import OracleName, RevisionKind, Verdict
from assay.oracles.base import Evidence, Execution, OracleResult, Reason, clip, reason
from assay.oracles.exploit.events import RECORD_EVENT, TEST_CONTRACT
from assay.oracles.runtree import (
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
    failed_setups,
    first_error,
    harness_topic,
    json_evidence,
    problem_of,
    results_evidence,
)
from assay.sandbox import SandboxRunner

BEHAVIOR_DIFF_FILE: Final = "behavior-diff.json"
CLAIM_VULNERABLE: Final = (
    "The benign tests run on the vulnerable revision and set the baseline: which tests pass and "
    "what they record."
)
CLAIM_PATCHED: Final = (
    "Every benign test that passes on the vulnerable revision passes on the patched revision and "
    "records the same values for the same keys."
)
_KEY_CHARS: Final = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-:")
_WORD: Final = 32
_MAX_LISTED: Final = 10

Records = dict[str, dict[str, tuple[str, ...]]]
"""Per test, the recorded values per key, in the order they were recorded."""


class SuiteSettings(BaseModel):
    """Fuzz settings for runs of a project's own tests (fuzz tests among them)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    fuzz_seed: Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{1,16}$")] = DEFAULT_FUZZ_SEED
    fuzz_runs: int = Field(default=256, ge=1, le=1_000_000)

    @property
    def seed(self) -> int:
        return int(self.fuzz_seed, 16)


@dataclass(frozen=True, slots=True)
class BehaviorContext:
    runner: SandboxRunner
    vulnerable: Snapshot
    patched: Snapshot
    harness: Harness
    work_dir: Path
    """An existing, empty directory for the run trees."""


def decode_key(topic: str) -> str:
    """The text of a record key (a left-aligned `bytes32`), or its hex form if it is not text."""
    raw = bytes.fromhex(topic[2:]) if topic.startswith("0x") and len(topic) == 66 else b""
    text = raw.rstrip(b"\0")
    if text and all(byte in _KEY_CHARS for byte in text):
        return text.decode("ascii")
    return topic


def decode_data(data: str) -> str:
    """The payload of an ABI-encoded `bytes` value in lowercase hex, or `data` unchanged when it
    is not a well-formed encoding."""
    try:
        raw = bytes.fromhex(data[2:]) if data.startswith("0x") else None
    except ValueError:
        raw = None
    if raw is None or len(raw) < 2 * _WORD or int.from_bytes(raw[:_WORD], "big") != _WORD:
        return data
    length = int.from_bytes(raw[_WORD : 2 * _WORD], "big")
    end = 2 * _WORD + length
    if end > len(raw) or any(raw[end:]) or len(raw) != 2 * _WORD + -(-length // _WORD) * _WORD:
        return data
    return "0x" + raw[2 * _WORD : end].hex()


def records_of(events: tuple[ForgeEvent, ...], topic: str) -> dict[str, tuple[str, ...]]:
    """Recorded values per key, from `AssayRecord` events of the test contract itself."""
    found: dict[str, list[str]] = {}
    for event in events:
        if event.address != TEST_CONTRACT or len(event.topics) != 2 or event.topics[0] != topic:
            continue
        found.setdefault(decode_key(event.topics[1]), []).append(decode_data(event.data))
    return {key: tuple(values) for key, values in sorted(found.items())}


def passing(run: ForgeTestRun) -> list[str]:
    return [
        name
        for name, case in cases(run)
        if not case.name.startswith(SETUP_PREFIX) and case.status == "success"
    ]


def records_by_test(run: ForgeTestRun, topic: str) -> Records:
    return {
        name: records_of(case.events, topic)
        for name, case in cases(run)
        if not case.name.startswith(SETUP_PREFIX) and case.status == "success"
    }


@dataclass(frozen=True, slots=True)
class Comparison:
    failed: tuple[str, ...]
    """Tests that pass on the vulnerable revision and not on the patched one, with the cause."""
    diffs: tuple[dict[str, JsonValue], ...]
    compared_records: int


def compare(baseline: ForgeTestRun, patched: ForgeTestRun, topic: str) -> Comparison:
    """Compare the benign tests of the patched revision with the baseline."""
    after = dict(cases(patched))
    failed: list[str] = []
    for name in passing(baseline):
        case = after.get(name)
        if case is None:
            failed.append(f"{name} (not run)")
        elif case.status != "success":
            cause = f": {clip(case.reason, 120)}" if case.reason else ""
            failed.append(f"{name} ({case.status}{cause})")
    before_records = records_by_test(baseline, topic)
    after_records = records_by_test(patched, topic)
    diffs: list[dict[str, JsonValue]] = []
    compared = 0
    for name in sorted(before_records.keys() & after_records.keys()):
        before, now = before_records[name], after_records[name]
        for key in sorted(before.keys() | now.keys()):
            compared += 1
            if before.get(key) != now.get(key):
                diffs.append(
                    {
                        "test": name,
                        "key": key,
                        "vulnerable": list(before.get(key, ())),
                        "patched": list(now.get(key, ())),
                    }
                )
    return Comparison(failed=tuple(failed), diffs=tuple(diffs), compared_records=compared)


def _listed(items: list[str]) -> str:
    shown = ", ".join(items[:_MAX_LISTED])
    return shown + (f" and {len(items) - _MAX_LISTED} more" if len(items) > _MAX_LISTED else "")


@dataclass
class _Side:
    """Observations on one revision."""

    revision: RevisionKind
    argv: tuple[str, ...]
    run: ForgeTestRun | None = None
    build_error: str | None = None
    problem: Reason | None = None
    exit_code: int | None = None
    evidence: list[Evidence] = field(default_factory=list)


class BehaviorOracle:
    name = OracleName.BEHAVIOR

    def __init__(self, settings: SuiteSettings | None = None) -> None:
        self.settings = settings if settings is not None else SuiteSettings()

    @property
    def argv(self) -> tuple[str, ...]:
        return foundry.forge_test_argv(
            fuzz_seed=self.settings.fuzz_seed, fuzz_runs=self.settings.fuzz_runs
        )

    def run(self, context: BehaviorContext) -> OracleResult:
        vulnerable = _Side(RevisionKind.VULNERABLE, self.argv)
        if not benign_paths(context.vulnerable):
            vulnerable.argv = ()
            vulnerable.problem = reason(
                "no_benign_tests", "the project has no test/ directory with benign tests"
            )
            return self._result(vulnerable, None, None)
        try:
            trees = (
                build_benign_tree(
                    context.vulnerable, context.harness, context.work_dir / "vulnerable"
                ),
                build_benign_tree(context.patched, context.harness, context.work_dir / "patched"),
            )
        except RunTreeError as exc:
            vulnerable.problem = reason("run_tree_rejected", str(exc))
            return self._result(vulnerable, None, None)
        if trees[0].digest_outside("src") != trees[1].digest_outside("src"):
            vulnerable.problem = reason(
                "run_tree_mismatch", "the benign trees differ outside src/ between the revisions"
            )
            return self._result(vulnerable, None, None)
        topic = self._observe(context.runner, trees[0], vulnerable, None)
        if topic is None or self._judge_baseline(vulnerable)[0] is not Verdict.PASS:
            return self._result(vulnerable, None, None)
        patched = _Side(RevisionKind.PATCHED, self.argv)
        self._observe(context.runner, trees[1], patched, topic)
        return self._result(vulnerable, patched, topic)

    def _observe(
        self, runner: SandboxRunner, tree: RunTree, side: _Side, topic: str | None
    ) -> str | None:
        """Build the tree and run its tests; return the record topic, or `None` on a stop."""
        try:
            compiled = build(runner, tree)
            if not compiled.succeeded:
                side.argv, side.exit_code = compiled.argv, compiled.exit_code
                if side.revision is RevisionKind.PATCHED:
                    side.build_error = first_error(compiled)
                    return None
                raise Stop(reason("benign_build_failed", first_error(compiled)), compiled.exit_code)
            if topic is None:
                topic = harness_topic(runner, tree, RECORD_EVENT)
            run = foundry.test(
                runner,
                tree.tree,
                fuzz_seed=self.settings.fuzz_seed,
                fuzz_runs=self.settings.fuzz_runs,
                scratch_dir=tree.scratch,
            )
        except Stop as stop:
            side.problem, side.exit_code = stop.problem, stop.exit_code
            return None
        except (foundry.ForgeTimeout, foundry.ForgeOutputError) as exc:
            side.problem, side.exit_code = problem_of(exc)
            return None
        side.run, side.exit_code = run, run.exit_code
        side.evidence.append(
            results_evidence(f"behavior: benign test results, {side.revision} revision", run)
        )
        return topic

    def _judge_baseline(self, side: _Side) -> tuple[Verdict, tuple[Reason, ...], str]:
        if side.problem is not None:
            return Verdict.INCONCLUSIVE, (side.problem,), f"vulnerable: {side.problem.code}"
        assert side.run is not None
        names = [name for name, case in cases(side.run) if not case.name.startswith(SETUP_PREFIX)]
        passed = passing(side.run)
        if not passed:
            detail = "no benign test passes on the vulnerable revision, so there is no baseline"
            setups = failed_setups(side.run)
            if setups:
                detail += f"; setUp() failed: {clip(setups[0][1].reason or 'no reason', 200)}"
            return (
                Verdict.INCONCLUSIVE,
                (reason("no_benign_tests", detail),),
                "vulnerable: no_benign_tests",
            )
        summary = f"{len(passed)} of {len(names)} benign tests pass on the vulnerable revision"
        if len(passed) < len(names):
            summary += f"; {len(names) - len(passed)} fail there and are not compared"
        return Verdict.PASS, (), summary

    def _judge_patched(
        self, side: _Side, baseline: ForgeTestRun, topic: str
    ) -> tuple[Verdict, tuple[Reason, ...], str, Comparison | None]:
        if side.problem is not None:
            return Verdict.INCONCLUSIVE, (side.problem,), f"patched: {side.problem.code}", None
        expected = passing(baseline)
        if side.build_error is not None:
            detail = (
                f"the {len(expected)} benign tests that pass on the vulnerable revision do not "
                f"compile against the patched revision: {side.build_error}"
            )
            return (
                Verdict.FAIL,
                (reason("benign_test_failed", detail),),
                "patched: the benign tests do not compile",
                None,
            )
        assert side.run is not None
        comparison = compare(baseline, side.run, topic)
        reasons: list[Reason] = []
        if comparison.failed:
            detail = (
                f"{len(comparison.failed)} of {len(expected)} benign tests that pass on the "
                f"vulnerable revision do not pass on the patched revision: "
                f"{_listed(list(comparison.failed))}"
            )
            reasons.append(reason("benign_test_failed", detail))
        if comparison.diffs:
            keys = [f"{item['test']}:{item['key']}" for item in comparison.diffs]
            detail = (
                f"recorded values differ from the vulnerable revision for {len(keys)} key(s): "
                f"{_listed(keys)}"
            )
            reasons.append(reason("behavior_changed", detail))
        if reasons:
            codes = ", ".join(item.code for item in reasons)
            return Verdict.FAIL, tuple(reasons), f"patched: {codes}", comparison
        summary = (
            f"patched: all {len(expected)} benign tests pass with the same records "
            f"({comparison.compared_records} keys compared)"
        )
        return Verdict.PASS, (), summary, comparison

    def _result(self, vulnerable: _Side, patched: _Side | None, topic: str | None) -> OracleResult:
        v_verdict, v_reasons, v_summary = self._judge_baseline(vulnerable)
        executions = [
            self._execution(vulnerable, CLAIM_VULNERABLE, v_verdict, v_reasons, v_summary, None)
        ]
        if patched is None or topic is None:
            reasons = v_reasons or (reason("patched_not_run", "the patched revision was not run"),)
            return OracleResult(
                oracle=self.name,
                verdict=Verdict.INCONCLUSIVE,
                reasons=reasons,
                summary=clip(f"{v_summary}; the patched revision was not run"),
                executions=tuple(executions),
            )
        assert vulnerable.run is not None
        p_verdict, p_reasons, p_summary, comparison = self._judge_patched(
            patched, vulnerable.run, topic
        )
        if comparison is not None and comparison.diffs:
            patched.evidence.append(
                json_evidence(
                    "behavior: differences of the recorded values",
                    {"differences": list(comparison.diffs)},
                    BEHAVIOR_DIFF_FILE,
                )
            )
        executions.append(
            self._execution(patched, CLAIM_PATCHED, p_verdict, p_reasons, p_summary, topic)
        )
        return OracleResult(
            oracle=self.name,
            verdict=p_verdict,
            reasons=p_reasons,
            summary=clip(f"{v_summary}; {p_summary}"),
            executions=tuple(executions),
        )

    def _execution(
        self,
        side: _Side,
        claim: str,
        verdict: Verdict,
        reasons: tuple[Reason, ...],
        summary: str,
        topic: str | None,
    ) -> Execution:
        trace: dict[str, JsonValue] = {
            "fuzz_seed": self.settings.fuzz_seed,
            "fuzz_runs": self.settings.fuzz_runs,
            "tests": {}
            if side.run is None
            else {name: case.status for name, case in cases(side.run)},
        }
        if side.build_error is not None:
            trace["build_error"] = clip(side.build_error)
        return Execution(
            revision=side.revision,
            claim=claim,
            argv=side.argv,
            seed=self.settings.seed if side.argv else None,
            exit_code=side.exit_code,
            verdict=verdict,
            reasons=reasons,
            summary=clip(summary),
            trace=trace,
            evidence=tuple(side.evidence),
        )
