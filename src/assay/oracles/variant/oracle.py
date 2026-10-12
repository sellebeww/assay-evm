"""VariantOracle: search for a close variant of the exploit, within the bounds of a profile.

Both revisions run in PoC trees (ADR 0011) that differ only in `src/`; their Foundry
configuration carries the invariant runs and depth of the profile. Two search modes run on each
revision, one campaign per seed, the seeds derived from the recorded base seed (`profiles`):

- fuzz: the PoC's `testFuzz_variants` with the profile's runs per seed. The harness draws the
  attacker, its balance and the four knobs of the PoC. A variant is reported only when the test
  failed with `ASSAY_VARIANT_FOUND|attacker=...|balance=...|knobs=...`, forge reported the
  failing input, and the test contract itself emitted an `AssayPredicate` event;
- invariant: `invariant_assay` of a fixture invariant (`AssayInvariant`) in the PoC directory,
  with the profile's sequences and depth. A variant is reported when the invariant broke with
  `ASSAY_INVARIANT_BROKEN|<name>` and forge reported the shrunk sequence. A PoC directory without
  an invariant has no invariant mode.

In each mode the seeds run in order and stop at the first seed that finds something; a search
that finds nothing runs every seed. A campaign that cannot complete (a timeout of the profile's
limit, a failing `setUp()`, a failure for another reason, fewer runs than asked, unusable output)
ends its mode with a reason and is never a pass.

Sanity check, per mode: the mode must find the exploit on the vulnerable revision. A mode that
finds nothing there says nothing about the patched revision: it does not count towards a pass
(a warning says so). When no mode finds the exploit, the verdict is INCONCLUSIVE
`variant_search_ineffective`.

Counterexample flow, on the patched revision: the reported input (shrunk by forge for a
sequence) is saved as `counterexample.json`, a concrete test `variant_poc.t.sol` is written from
a template with the input's values as numeric constants (`poc`), and the test runs three times in
the sandbox on the patched revision. Only when all three runs pass with the predicate from the
test contract is the variant confirmed: FAIL `variant_found`. Runs that disagree, or a test that
reaches no predicate, give INCONCLUSIVE `flaky_counterexample`; an input that cannot be written
safely gives INCONCLUSIVE `counterexample_rejected`. The artifacts are kept either way.

Verdict: a confirmed variant gives FAIL whatever the sanity check gave. Otherwise any reason
above gives INCONCLUSIVE. Otherwise PASS, with a bounds statement built from what ran (`bounds`).
Durations are measured and reported apart from the verdict, the traces and the bounds, which are
deterministic.
"""

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from assay.analyzers import foundry
from assay.analyzers.foundry import ForgeCall, ForgeTestCase, ForgeTestRun
from assay.ingest import Snapshot
from assay.ingest.config import safe_foundry_toml
from assay.ledger import OracleName, RevisionKind, Verdict
from assay.oracles.base import Evidence, Execution, OracleResult, Reason, clip, reason
from assay.oracles.exploit.events import PREDICATE_EVENT, predicates
from assay.oracles.runtree import Harness, RunTree, RunTreeError, build_poc_tree
from assay.oracles.steps import (
    Stop,
    build,
    failed_setups,
    first_error,
    harness_topic,
    json_evidence,
    problem_of,
    results_evidence,
)
from assay.oracles.variant.poc import (
    VARIANT_POC_CONTRACT,
    VARIANT_POC_FILE,
    VARIANT_POC_PATH,
    VARIANT_POC_TEST,
    PocRejected,
    base_contract,
    fuzz_input,
    render_fuzz,
    render_invariant,
    replay_calls,
    solc_version,
)
from assay.oracles.variant.profiles import (
    DEFAULT_BASE_SEED,
    DEFAULT_PROFILE,
    BaseSeed,
    Profile,
    ProfileName,
    derive_seeds,
    profile,
)
from assay.sandbox import SandboxRunner

VARIANT_TEST: Final = "testFuzz_variants"
# Forge matches `--match-test` against the signature; the allowlist has no backslash, so the
# parenthesis is written as a character class.
VARIANT_FILTER: Final = "^testFuzz_variants[(]"
VARIANT_MARKER: Final = "ASSAY_VARIANT_FOUND|"
INVARIANT_TEST: Final = "invariant_assay"
INVARIANT_FILTER: Final = "^invariant_assay[(]"
INVARIANT_MARKER: Final = "ASSAY_INVARIANT_BROKEN|"
REPLAY_CONTRACT_FILTER: Final = f"^{VARIANT_POC_CONTRACT}$"
REPLAY_TEST_FILTER: Final = f"^{VARIANT_POC_TEST}[(]"
CONFIRMATION_REPLAYS: Final = 3
MAX_FUZZ_RUNS: Final = 1_000_000
DEFAULT_FUZZ_RUNS: Final = 256
HARNESS_FILE: Final = "AssayExploit.sol"
COUNTEREXAMPLE_FILE: Final = "counterexample.json"
SANITY_COUNTEREXAMPLE_FILE: Final = "sanity-counterexample.json"
CLAIM_VULNERABLE: Final = (
    "The variant search (the recorded profile, base seed and derived seeds) finds the exploit "
    "on the vulnerable revision."
)
CLAIM_PATCHED: Final = (
    "The variant search (the recorded profile, base seed and derived seeds) finds no confirmed "
    "variant of the exploit on the patched revision."
)
_NUMBER: Final = r"([0-9]{1,78})"
_VARIANT_REASON: Final = re.compile(
    r"ASSAY_VARIANT_FOUND\|attacker=(0x[0-9a-fA-F]{40})\|balance=" + _NUMBER + r"\|knobs="
    rf"{_NUMBER},{_NUMBER},{_NUMBER},{_NUMBER}"
)
_INVARIANT_REASON: Final = re.compile(r"ASSAY_INVARIANT_BROKEN\|([A-Za-z0-9_.\-]{1,32})")

Mode = Literal["fuzz", "invariant"]
MODES: Final[tuple[Mode, ...]] = ("fuzz", "invariant")
Outcome = Literal[
    "found",
    "none",
    "incomplete",
    "unconfirmed",
    "failed",
    "setup_failed",
    "not_found",
    "ambiguous",
    "skipped",
]
_ERROR_REASONS: Final[dict[Mode, dict[Outcome, tuple[str, str]]]] = {
    "fuzz": {
        "incomplete": ("variant_search_incomplete", "testFuzz_variants stopped early"),
        "unconfirmed": (
            "variant_unconfirmed",
            "testFuzz_variants reported a variant without a counterexample, without a "
            "well-formed variant reason, or without an AssayPredicate event from the test "
            "contract",
        ),
        "failed": ("variant_search_failed", "testFuzz_variants failed without reporting a variant"),
        "setup_failed": ("poc_setup_failed", "setUp() of the PoC failed"),
        "not_found": ("poc_not_found", "no testFuzz_variants test was found in the PoC directory"),
        "ambiguous": ("poc_ambiguous", "more than one testFuzz_variants test in the PoC directory"),
        "skipped": ("poc_skipped", "testFuzz_variants was skipped"),
    },
    "invariant": {
        "incomplete": ("invariant_search_incomplete", "invariant_assay stopped early"),
        "unconfirmed": (
            "invariant_unconfirmed",
            "invariant_assay broke without a well-formed reason or without a call sequence",
        ),
        "failed": ("invariant_search_failed", "invariant_assay failed without breaking"),
        "setup_failed": ("invariant_setup_failed", "setUp() of the invariant failed"),
        "not_found": ("invariant_not_found", "no invariant_assay test on this revision"),
        "ambiguous": ("invariant_ambiguous", "more than one invariant_assay test"),
        "skipped": ("invariant_skipped", "invariant_assay was skipped"),
    },
}


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class VariantSettings(_Model):
    """Bounds of the VariantOracle: a profile, a recorded base seed, and optionally a number of
    fuzz runs per seed that replaces the profile's."""

    profile: Profile = Field(default_factory=lambda: profile(DEFAULT_PROFILE))
    base_seed: BaseSeed = DEFAULT_BASE_SEED
    runs_per_seed: int | None = Field(default=None, ge=1, le=MAX_FUZZ_RUNS)

    @property
    def fuzz_runs(self) -> int:
        return self.runs_per_seed if self.runs_per_seed is not None else self.profile.runs_per_seed

    @property
    def seeds(self) -> tuple[str, ...]:
        return derive_seeds(self.base_seed, self.profile.seeds)

    @property
    def seed(self) -> int:
        return int(self.base_seed, 16)

    def foundry_toml(self) -> bytes:
        return safe_foundry_toml(
            invariant_runs=self.profile.invariant_runs,
            invariant_depth=self.profile.invariant_depth,
        )


@dataclass(frozen=True, slots=True)
class VariantContext:
    runner: SandboxRunner
    vulnerable: Snapshot
    patched: Snapshot
    poc: Snapshot
    harness: Harness
    work_dir: Path
    """An existing, empty directory for the run trees."""


class Counterexample(_Model):
    """A variant reported by `testFuzz_variants`, checked field by field."""

    suite: str
    test: str
    attacker: str
    attacker_balance_wei: str
    knobs: tuple[str, str, str, str]
    calldata: str | None
    fuzz_run: int | None
    """1-based index of the failing run, as forge reports it."""
    predicates: tuple[tuple[str, str], ...]

    def describe(self) -> str:
        return (
            f"attacker {self.attacker}, balance {self.attacker_balance_wei} wei, knobs "
            f"{', '.join(self.knobs)}"
        )

    def document(self) -> dict[str, JsonValue]:
        return {
            "mode": "fuzz",
            "test": self.test,
            "fuzz_run": self.fuzz_run,
            "attacker": self.attacker,
            "attacker_balance_wei": self.attacker_balance_wei,
            "knobs": list(self.knobs),
            "calldata": self.calldata,
            "predicates": [{"kind": kind, "detail": detail} for kind, detail in self.predicates],
        }


class SequenceCounterexample(_Model):
    """A call sequence that broke the fixture invariant, as forge shrunk it."""

    suite: str
    test: str
    invariant: str
    calls: tuple[ForgeCall, ...]
    unshrunk_length: int | None

    def describe(self) -> str:
        before = (
            f" (shrunk from {self.unshrunk_length})" if self.unshrunk_length is not None else ""
        )
        return f"invariant {self.invariant} broken by {len(self.calls)} calls{before}"

    def document(self) -> dict[str, JsonValue]:
        return {
            "mode": "invariant",
            "test": self.test,
            "invariant": self.invariant,
            "unshrunk_length": self.unshrunk_length,
            "calls": [
                {
                    "sender": call.sender,
                    "target": call.target,
                    "calldata": call.calldata,
                    "args": call.args,
                }
                for call in self.calls
            ],
        }


@dataclass(frozen=True, slots=True)
class Search:
    """One campaign's `forge test` run, classified."""

    exit_code: int
    outcome: Outcome
    reason: str | None
    runs: int | None
    counterexample: Counterexample | SequenceCounterexample | None = None
    calls: int | None = None

    def trace(self) -> dict[str, JsonValue]:
        return {
            "exit_code": self.exit_code,
            "outcome": self.outcome,
            "reason": self.reason,
            "runs": self.runs,
            "calls": self.calls,
            "counterexample": None
            if self.counterexample is None
            else self.counterexample.model_dump(mode="json"),
        }


def _clipped(text: str | None) -> str | None:
    return None if text is None else clip(text)


def _single(run: ForgeTestRun, test: str) -> tuple[str, Search | None, ForgeTestCase | None]:
    """The suite and case of the one test named `test`, or a `Search` saying why there is none."""
    setups = failed_setups(run)
    if setups:
        return "", Search(run.exit_code, "setup_failed", _clipped(setups[0][1].reason), None), None
    found = [
        (suite.name, case)
        for suite in run.suites
        for case in suite.tests
        if case.name.startswith(f"{test}(")
    ]
    if len(found) != 1:
        outcome: Outcome = "not_found" if not found else "ambiguous"
        return "", Search(run.exit_code, outcome, None, None), None
    return found[0][0], None, found[0][1]


def classify_search(run: ForgeTestRun, topic: str, runs: int) -> Search:
    """Classify a fuzz campaign: `forge test` of the PoC tree filtered to `testFuzz_variants`."""
    suite, stop, found = _single(run, VARIANT_TEST)
    if stop is not None:
        return stop
    case = found
    assert case is not None
    if case.status == "success":
        outcome: Outcome = "none" if case.runs is not None and case.runs >= runs else "incomplete"
        return Search(run.exit_code, outcome, None, case.runs)
    if case.status != "failure":
        return Search(run.exit_code, "skipped", _clipped(case.reason), case.runs)
    text = case.reason or ""
    if not text.startswith(VARIANT_MARKER):
        return Search(run.exit_code, "failed", _clipped(text) or None, case.runs)
    match = _VARIANT_REASON.fullmatch(text)
    held = predicates(case.events, topic)
    if match is None or case.counterexample is None or not held:
        return Search(run.exit_code, "unconfirmed", clip(text), case.runs)
    calls = case.counterexample.calls
    counterexample = Counterexample(
        suite=suite,
        test=case.name,
        attacker=match.group(1),
        attacker_balance_wei=match.group(2),
        knobs=(match.group(3), match.group(4), match.group(5), match.group(6)),
        calldata=calls[0].calldata if len(calls) == 1 else None,
        fuzz_run=calls[0].run if len(calls) == 1 else None,
        predicates=tuple((item.kind, clip(item.detail)) for item in held),
    )
    return Search(run.exit_code, "found", clip(text), case.runs, counterexample)


def classify_invariant(run: ForgeTestRun, runs: int) -> Search:
    """Classify an invariant campaign: `forge test` filtered to `invariant_assay`."""
    suite, stop, found = _single(run, INVARIANT_TEST)
    if stop is not None:
        return stop
    case = found
    assert case is not None
    if case.status == "success":
        outcome: Outcome = "none" if case.runs is not None and case.runs >= runs else "incomplete"
        return Search(run.exit_code, outcome, None, case.runs, calls=case.calls)
    if case.status != "failure":
        return Search(run.exit_code, "skipped", _clipped(case.reason), case.runs, calls=case.calls)
    broken = [item for item in case.invariant_failures if item.name == INVARIANT_TEST]
    text = (broken[0].reason or "") if len(broken) == 1 else (case.reason or "")
    if not text.startswith(INVARIANT_MARKER):
        return Search(run.exit_code, "failed", _clipped(text) or None, case.runs, calls=case.calls)
    match = _INVARIANT_REASON.fullmatch(text)
    sequence = broken[0].counterexample if len(broken) == 1 else None
    if match is None or sequence is None or not sequence.calls:
        return Search(run.exit_code, "unconfirmed", clip(text), case.runs, calls=case.calls)
    counterexample = SequenceCounterexample(
        suite=suite,
        test=case.name,
        invariant=match.group(1),
        calls=sequence.calls,
        unshrunk_length=sequence.unshrunk_length,
    )
    return Search(run.exit_code, "found", clip(text), case.runs, counterexample, calls=case.calls)


@dataclass
class Campaign:
    """One campaign: a mode, a seed, what it found, and how long it took."""

    mode: Mode
    index: int
    """1-based position of the seed in the profile's seeds."""
    seed: str
    argv: tuple[str, ...]
    search: Search | None = None
    problem: Reason | None = None
    seconds: float = 0.0

    def trace(self) -> dict[str, JsonValue]:
        return {
            "mode": self.mode,
            "seed_index": self.index,
            "seed": self.seed,
            "argv": list(self.argv),
            "problem": None if self.problem is None else self.problem.model_dump(mode="json"),
            "search": None if self.search is None else self.search.trace(),
        }


ConfirmationStatus = Literal["confirmed", "flaky", "rejected", "failed"]


@dataclass
class Confirmation:
    """The replays of one reported variant through a generated test."""

    campaign: Campaign
    status: ConfirmationStatus
    reproduced: int = 0
    replays: list[dict[str, JsonValue]] = field(default_factory=list)
    source: str | None = None
    problem: Reason | None = None
    results: list[ForgeTestRun] = field(default_factory=list)
    seconds: float = 0.0

    def trace(self) -> dict[str, JsonValue]:
        return {
            "mode": self.campaign.mode,
            "seed_index": self.campaign.index,
            "status": self.status,
            "reproduced": self.reproduced,
            "replays": list(self.replays),
            "problem": None if self.problem is None else self.problem.model_dump(mode="json"),
        }


@dataclass
class _Side:
    """Observations on one revision."""

    revision: RevisionKind
    argv: tuple[str, ...] = ()
    problem: Reason | None = None
    exit_code: int | None = None
    campaigns: dict[Mode, list[Campaign]] = field(
        default_factory=lambda: {"fuzz": [], "invariant": []}
    )
    available: dict[Mode, bool] = field(default_factory=lambda: {"fuzz": True, "invariant": True})
    results: list[tuple[str, ForgeTestRun]] = field(default_factory=list)
    confirmations: list[Confirmation] = field(default_factory=list)

    def found(self, mode: Mode) -> Campaign | None:
        for campaign in self.campaigns[mode]:
            if campaign.search is not None and campaign.search.outcome == "found":
                return campaign
        return None

    def problems(self) -> list[Reason]:
        found = [] if self.problem is None else [self.problem]
        for mode in MODES:
            found += [item.problem for item in self.campaigns[mode] if item.problem is not None]
        return found


class ModeBounds(_Model):
    """What one search mode ran on one revision."""

    revision: RevisionKind
    mode: Mode
    available: bool
    seeds_run: int
    found_at_seed: int | None
    runs: int
    """Fuzz runs, or invariant sequences, as forge reported them, summed over the campaigns."""
    calls: int | None
    """Calls of the invariant sequences, summed over the campaigns."""


class VariantBounds(_Model):
    """The bounds of a variant search, as numbers. Deterministic: no durations."""

    profile: ProfileName
    base_seed: str
    seeds: tuple[str, ...]
    runs_per_seed: int
    invariant_runs: int
    invariant_depth: int
    campaign_timeout_s: int
    searches: tuple[ModeBounds, ...]
    confirmation_replays: int
    replays_reproduced: int | None


class CampaignTime(_Model):
    revision: RevisionKind
    mode: Literal["fuzz", "invariant", "confirmation"]
    seed_index: int
    seconds: float


class VariantTiming(_Model):
    """Wall-clock durations of a variant search, rounded to 0.1 s. They vary between runs."""

    total_s: float
    campaigns: tuple[CampaignTime, ...]


@dataclass(frozen=True, slots=True)
class VariantOutcome:
    result: OracleResult
    bounds: VariantBounds
    timing: VariantTiming
    statement: str


def _seconds(started: float) -> float:
    return round(time.monotonic() - started, 1)


def _mode_phrase(item: ModeBounds, bounds: VariantBounds, effective: bool) -> str:
    total = len(bounds.seeds)
    if not item.available:
        return f"{item.mode}: no invariant in the PoC directory"
    if item.mode == "fuzz":
        size = f"{bounds.runs_per_seed} runs"
        done = f"{item.runs} runs"
    else:
        size = f"{bounds.invariant_runs} sequences of up to {bounds.invariant_depth} calls"
        done = f"{item.runs} sequences, {item.calls or 0} calls"
    if item.found_at_seed is not None:
        replays = (
            f", confirmed by {bounds.replays_reproduced} of {bounds.confirmation_replays} replays"
            if bounds.replays_reproduced is not None
            else ""
        )
        return (
            f"{item.mode}: variant found with seed {item.found_at_seed} of {total} "
            f"({item.seeds_run} seeds of {size}, {done}){replays}"
        )
    if item.seeds_run == 0:
        return f"{item.mode}: not run"
    ran = f"{item.mode}: {item.seeds_run} of {total} seeds of {size} ({done})"
    if not effective:
        return f"{ran}, not counted: this mode found nothing on the vulnerable revision"
    if item.seeds_run < total:
        return f"{ran}, stopped early"
    return f"{ran}, no variant found"


def bounds_statement(bounds: VariantBounds) -> str:
    """What the search on the patched revision ran, worded as that and nothing more."""
    effective = {
        item.mode
        for item in bounds.searches
        if item.revision is RevisionKind.VULNERABLE and item.found_at_seed is not None
    }
    patched = [item for item in bounds.searches if item.revision is RevisionKind.PATCHED]
    parts = [
        _mode_phrase(item, bounds, item.mode in effective or item.found_at_seed is not None)
        for item in patched
    ]
    head = (
        f"profile {bounds.profile}, base seed {bounds.base_seed}, seeds {', '.join(bounds.seeds)}"
    )
    found = any(item.found_at_seed is not None for item in patched)
    tail = "" if found else "; no variant found within these runs; this is not a proof of absence"
    body = "; ".join(parts) if parts else "the patched revision was not searched"
    return f"{head}; on the patched revision: {body}{tail}"


class VariantOracle:
    name = OracleName.VARIANT

    def __init__(self, settings: VariantSettings | None = None) -> None:
        self.settings = settings if settings is not None else VariantSettings()

    def argv(self, mode: Mode, seed: str) -> tuple[str, ...]:
        if mode == "fuzz":
            return foundry.forge_test_argv(
                match_test=VARIANT_FILTER, fuzz_seed=seed, fuzz_runs=self.settings.fuzz_runs
            )
        return foundry.forge_test_argv(match_test=INVARIANT_FILTER, fuzz_seed=seed)

    def run(self, context: VariantContext) -> OracleResult:
        return self.search(context).result

    def search(self, context: VariantContext) -> VariantOutcome:
        started = time.monotonic()
        vulnerable = _Side(RevisionKind.VULNERABLE)
        patched = _Side(RevisionKind.PATCHED)
        config = self.settings.foundry_toml()
        try:
            trees = (
                build_poc_tree(
                    context.vulnerable,
                    context.poc,
                    context.harness,
                    context.work_dir / "vulnerable",
                    config=config,
                ),
                build_poc_tree(
                    context.patched,
                    context.poc,
                    context.harness,
                    context.work_dir / "patched",
                    config=config,
                ),
            )
        except RunTreeError as exc:
            vulnerable.problem = reason("run_tree_rejected", str(exc))
            return self._outcome(vulnerable, None, started)
        if trees[0].digest_outside("src") != trees[1].digest_outside("src"):
            vulnerable.problem = reason(
                "run_tree_mismatch", "the PoC trees differ outside src/ between the revisions"
            )
            return self._outcome(vulnerable, None, started)
        topic = self._prepare(context.runner, trees[0], vulnerable, None, "poc_build_failed")
        if topic is not None:
            for mode in MODES:
                self._campaigns(context.runner, trees[0], vulnerable, mode, topic)
        patched_topic = self._prepare(
            context.runner, trees[1], patched, topic, "patched_build_failed"
        )
        if patched_topic is not None:
            topic = patched_topic
            if vulnerable.problem is None:
                patched.available["invariant"] = vulnerable.available["invariant"]
            for mode in MODES:
                if not patched.available[mode]:
                    continue
                self._campaigns(
                    context.runner,
                    trees[1],
                    patched,
                    mode,
                    topic,
                    probe=vulnerable.problem is not None,
                )
                found = patched.found(mode)
                if found is not None:
                    confirmation = self._confirm(context, found, topic)
                    patched.confirmations.append(confirmation)
                    if confirmation.status == "confirmed":
                        break
        return self._outcome(vulnerable, patched, started)

    # -- campaigns -----------------------------------------------------------------------------

    def _prepare(
        self,
        runner: SandboxRunner,
        tree: RunTree,
        side: _Side,
        topic: str | None,
        build_code: str,
    ) -> str | None:
        """Build the tree; return the predicate topic, or `None` when the side cannot run."""
        try:
            compiled = build(runner, tree)
            if not compiled.succeeded:
                side.argv = compiled.argv
                raise Stop(reason(build_code, first_error(compiled)), compiled.exit_code)
            return topic if topic is not None else harness_topic(runner, tree, PREDICATE_EVENT)
        except Stop as stop:
            side.problem, side.exit_code = stop.problem, stop.exit_code
            return None
        except (foundry.ForgeTimeout, foundry.ForgeOutputError) as exc:
            side.problem, side.exit_code = problem_of(exc)
            return None

    def _campaigns(
        self,
        runner: SandboxRunner,
        tree: RunTree,
        side: _Side,
        mode: Mode,
        topic: str,
        *,
        probe: bool = True,
    ) -> None:
        """Run the seeds of `mode` in order until one finds something or cannot complete.

        With `probe`, an invariant mode whose first campaign finds no `invariant_assay` test is
        marked unavailable (the PoC directory has no invariant) instead of failing.
        """
        profile_ = self.settings.profile
        for index, seed in enumerate(self.settings.seeds, start=1):
            campaign = Campaign(mode=mode, index=index, seed=seed, argv=self.argv(mode, seed))
            if not side.argv:
                side.argv = campaign.argv
            started = time.monotonic()
            try:
                if mode == "fuzz":
                    run = foundry.test(
                        runner,
                        tree.tree,
                        match_test=VARIANT_FILTER,
                        fuzz_seed=seed,
                        fuzz_runs=self.settings.fuzz_runs,
                        scratch_dir=tree.scratch,
                        timeout_s=profile_.campaign_timeout_s,
                    )
                else:
                    run = foundry.test(
                        runner,
                        tree.tree,
                        match_test=INVARIANT_FILTER,
                        fuzz_seed=seed,
                        scratch_dir=tree.scratch,
                        timeout_s=profile_.campaign_timeout_s,
                    )
            except (foundry.ForgeTimeout, foundry.ForgeOutputError) as exc:
                campaign.problem, side.exit_code = problem_of(exc)
                if isinstance(exc, foundry.ForgeTimeout):
                    campaign.problem = reason(
                        "timeout",
                        f"{mode} campaign with seed {index} exceeded the profile's limit of "
                        f"{profile_.campaign_timeout_s} s; a timeout is never a pass",
                    )
                campaign.seconds = _seconds(started)
                side.campaigns[mode].append(campaign)
                return
            campaign.seconds = _seconds(started)
            if mode == "fuzz":
                search = classify_search(run, topic, self.settings.fuzz_runs)
            else:
                search = classify_invariant(run, profile_.invariant_runs)
            campaign.search = search
            if mode == "invariant" and search.outcome == "not_found" and index == 1 and probe:
                side.available["invariant"] = False
                return
            side.campaigns[mode].append(campaign)
            side.exit_code = run.exit_code
            side.results.append(
                (f"variant: {mode} campaign with seed {index}, {side.revision} revision", run)
            )
            if search.outcome in _ERROR_REASONS[mode]:
                code, detail = _ERROR_REASONS[mode][search.outcome]
                if search.outcome == "incomplete":
                    expected = (
                        self.settings.fuzz_runs if mode == "fuzz" else profile_.invariant_runs
                    )
                    detail = f"{detail}: {search.runs} of {expected} runs with seed {index}"
                elif search.reason:
                    detail = f"{detail}: {search.reason}"
                campaign.problem = reason(code, detail)
                return
            if search.outcome == "found":
                return

    # -- counterexample confirmation -------------------------------------------------------------

    def _confirm(self, context: VariantContext, campaign: Campaign, topic: str) -> Confirmation:
        started = time.monotonic()
        confirmation = self._replay(context, campaign, topic)
        confirmation.seconds = _seconds(started)
        return confirmation

    def _source(self, context: VariantContext, campaign: Campaign) -> str:
        assert campaign.search is not None
        assert campaign.search.counterexample is not None
        counterexample = campaign.search.counterexample
        harness = dict(context.harness.files).get(HARNESS_FILE)
        if harness is None:
            raise PocRejected(f"the harness has no {HARNESS_FILE}")
        solc = solc_version(harness)
        base = base_contract(counterexample.suite)
        if isinstance(counterexample, Counterexample):
            if counterexample.calldata is None:
                raise PocRejected("forge reported no calldata for the failing input")
            return render_fuzz(base, fuzz_input(counterexample.calldata), solc)
        return render_invariant(base, replay_calls(counterexample.calls), solc)

    def _replay(self, context: VariantContext, campaign: Campaign, topic: str) -> Confirmation:
        try:
            source = self._source(context, campaign)
        except PocRejected as exc:
            return Confirmation(
                campaign,
                "rejected",
                problem=reason(
                    "counterexample_rejected",
                    f"the {campaign.mode} counterexample cannot be written into a test: {exc}",
                ),
            )
        confirmation = Confirmation(campaign, "failed", source=source)
        try:
            tree = build_poc_tree(
                context.patched,
                context.poc,
                context.harness,
                context.work_dir / f"confirm-{campaign.mode}",
                config=self.settings.foundry_toml(),
                extra_tests=((VARIANT_POC_PATH, source.encode("ascii")),),
            )
            compiled = build(context.runner, tree)
        except RunTreeError as exc:
            confirmation.problem = reason("variant_poc_rejected", str(exc))
            return confirmation
        except (foundry.ForgeTimeout, foundry.ForgeOutputError) as exc:
            confirmation.problem = problem_of(exc)[0]
            return confirmation
        if not compiled.succeeded:
            confirmation.problem = reason("variant_poc_build_failed", first_error(compiled))
            return confirmation
        for number in range(1, CONFIRMATION_REPLAYS + 1):
            entry: dict[str, JsonValue] = {"replay": number, "reproduced": False}
            try:
                run = foundry.test(
                    context.runner,
                    tree.tree,
                    match_contract=REPLAY_CONTRACT_FILTER,
                    match_test=REPLAY_TEST_FILTER,
                    fuzz_seed=self.settings.base_seed,
                    scratch_dir=tree.scratch,
                    timeout_s=self.settings.profile.campaign_timeout_s,
                )
            except (foundry.ForgeTimeout, foundry.ForgeOutputError) as exc:
                entry["problem"] = problem_of(exc)[0].code
                confirmation.replays.append(entry)
                continue
            confirmation.results.append(run)
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
                entry["predicates"] = [item.kind for item in held]
                entry["reproduced"] = cases[0].status == "success" and bool(held)
            confirmation.replays.append(entry)
            if entry["reproduced"]:
                confirmation.reproduced += 1
        confirmation.status = (
            "confirmed" if confirmation.reproduced == CONFIRMATION_REPLAYS else "flaky"
        )
        if confirmation.status == "flaky":
            confirmation.problem = reason(
                "flaky_counterexample",
                f"the {campaign.mode} variant found with seed {campaign.index} reproduced in "
                f"{confirmation.reproduced} of {CONFIRMATION_REPLAYS} replays of "
                f"{VARIANT_POC_FILE} on the patched revision",
            )
        return confirmation

    # -- verdict ---------------------------------------------------------------------------------

    def _judge_vulnerable(self, side: _Side) -> tuple[Verdict, tuple[Reason, ...], str]:
        problems = side.problems()
        found = [mode for mode in MODES if side.found(mode) is not None]
        if found:
            seeds = ", ".join(
                f"{mode} with seed {campaign.index}"
                for mode in found
                if (campaign := side.found(mode)) is not None
            )
            return Verdict.PASS, (), f"vulnerable: the search found the exploit ({seeds})"
        if problems:
            return Verdict.INCONCLUSIVE, tuple(problems), f"vulnerable: {problems[0].code}"
        detail = (
            f"no search mode found the exploit on the vulnerable revision with the "
            f"{self.settings.profile.name} profile ({len(self.settings.seeds)} seeds); a search "
            "that finds nothing there says nothing about the patched revision"
        )
        return (
            Verdict.INCONCLUSIVE,
            (reason("variant_search_ineffective", detail),),
            "vulnerable: variant_search_ineffective",
        )

    def _judge_patched(self, side: _Side) -> tuple[Verdict, tuple[Reason, ...], str]:
        confirmed = [item for item in side.confirmations if item.status == "confirmed"]
        if confirmed:
            item = confirmed[0]
            search = item.campaign.search
            assert search is not None
            assert search.counterexample is not None
            detail = (
                f"{item.campaign.mode} variant found with seed {item.campaign.index} and "
                f"confirmed by {item.reproduced} of {CONFIRMATION_REPLAYS} replays of "
                f"{VARIANT_POC_FILE}: {search.counterexample.describe()}"
            )
            summary = (
                f"patched: {item.campaign.mode} variant found with seed {item.campaign.index}, "
                f"confirmed {item.reproduced}/{CONFIRMATION_REPLAYS}"
            )
            return Verdict.FAIL, (reason("variant_found", detail),), summary
        problems = [item.problem for item in side.confirmations if item.problem is not None]
        problems += side.problems()
        if problems:
            return Verdict.INCONCLUSIVE, tuple(problems), f"patched: {problems[0].code}"
        return Verdict.PASS, (), "patched: no variant found"

    def _bounds(self, vulnerable: _Side, patched: _Side | None) -> VariantBounds:
        searches = []
        for side in (vulnerable, patched):
            if side is None:
                continue
            for mode in MODES:
                campaigns = side.campaigns[mode]
                found = side.found(mode)
                searches.append(
                    ModeBounds(
                        revision=side.revision,
                        mode=mode,
                        available=side.available[mode],
                        seeds_run=len(campaigns),
                        found_at_seed=None if found is None else found.index,
                        runs=sum(
                            (item.search.runs or 0) for item in campaigns if item.search is not None
                        ),
                        calls=None
                        if mode == "fuzz"
                        else sum(
                            (item.search.calls or 0)
                            for item in campaigns
                            if item.search is not None
                        ),
                    )
                )
        confirmations = [] if patched is None else patched.confirmations
        confirmed = [item for item in confirmations if item.status == "confirmed"]
        replayed = confirmed[0] if confirmed else (confirmations[0] if confirmations else None)
        settings = self.settings
        return VariantBounds(
            profile=settings.profile.name,
            base_seed=settings.base_seed,
            seeds=settings.seeds,
            runs_per_seed=settings.fuzz_runs,
            invariant_runs=settings.profile.invariant_runs,
            invariant_depth=settings.profile.invariant_depth,
            campaign_timeout_s=settings.profile.campaign_timeout_s,
            searches=tuple(searches),
            confirmation_replays=CONFIRMATION_REPLAYS,
            replays_reproduced=None
            if replayed is None or replayed.status in ("rejected", "failed")
            else replayed.reproduced,
        )

    def _timing(self, vulnerable: _Side, patched: _Side | None, started: float) -> VariantTiming:
        entries = []
        for side in (vulnerable, patched):
            if side is None:
                continue
            for mode in MODES:
                entries += [
                    CampaignTime(
                        revision=side.revision,
                        mode=mode,
                        seed_index=item.index,
                        seconds=item.seconds,
                    )
                    for item in side.campaigns[mode]
                ]
            entries += [
                CampaignTime(
                    revision=side.revision,
                    mode="confirmation",
                    seed_index=item.campaign.index,
                    seconds=item.seconds,
                )
                for item in side.confirmations
            ]
        return VariantTiming(total_s=_seconds(started), campaigns=tuple(entries))

    def _warnings(self, vulnerable: _Side, patched: _Side | None) -> tuple[Reason, ...]:
        if patched is None:
            return ()
        found = {mode for mode in MODES if vulnerable.found(mode) is not None}
        warnings = []
        for mode in MODES:
            if (
                vulnerable.available[mode]
                and mode not in found
                and found
                and not vulnerable.problems()
            ):
                warnings.append(
                    reason(
                        f"{mode}_search_ineffective",
                        f"the {mode} mode found nothing on the vulnerable revision; its result "
                        "on the patched revision is not counted",
                    )
                )
        return tuple(warnings)

    def _outcome(self, vulnerable: _Side, patched: _Side | None, started: float) -> VariantOutcome:
        bounds = self._bounds(vulnerable, patched)
        statement = bounds_statement(bounds)
        v_verdict, v_reasons, v_summary = self._judge_vulnerable(vulnerable)
        executions = [self._execution(vulnerable, CLAIM_VULNERABLE, self._judge_vulnerable)]
        if patched is None:
            reasons = v_reasons or (reason("patched_not_run", "the patched revision was not run"),)
            result = OracleResult(
                oracle=self.name,
                verdict=Verdict.INCONCLUSIVE,
                reasons=reasons,
                summary=clip(f"{v_summary}; the patched revision was not run"),
                executions=tuple(executions),
            )
            return VariantOutcome(
                result, bounds, self._timing(vulnerable, None, started), statement
            )
        executions.append(self._execution(patched, CLAIM_PATCHED, self._judge_patched))
        p_verdict, p_reasons, p_summary = self._judge_patched(patched)
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
            warnings=self._warnings(vulnerable, patched),
        )
        return VariantOutcome(result, bounds, self._timing(vulnerable, patched, started), statement)

    def _evidence(self, side: _Side) -> tuple[Evidence, ...]:
        evidence = [results_evidence(label, run) for label, run in side.results]
        patched = side.revision is RevisionKind.PATCHED
        if not patched:
            for mode in MODES:
                found = side.found(mode)
                if found is not None and found.search is not None and found.search.counterexample:
                    evidence.append(
                        json_evidence(
                            f"variant: {mode} counterexample, vulnerable revision",
                            self._document(found, side),
                            SANITY_COUNTEREXAMPLE_FILE if mode == "fuzz" else None,
                        )
                    )
            return tuple(evidence)
        confirmed = [item for item in side.confirmations if item.status == "confirmed"]
        primary = (
            confirmed[0] if confirmed else (side.confirmations[0] if side.confirmations else None)
        )
        for item in side.confirmations:
            canonical = item is primary
            evidence.append(
                json_evidence(
                    f"variant: {item.campaign.mode} counterexample, patched revision",
                    {**self._document(item.campaign, side), "confirmation": item.trace()},
                    COUNTEREXAMPLE_FILE if canonical else None,
                )
            )
            if item.source is not None:
                evidence.append(
                    Evidence(
                        label=f"variant: {VARIANT_POC_FILE} for the {item.campaign.mode} variant",
                        media_type="text/plain",
                        data=item.source.encode("ascii"),
                        name=VARIANT_POC_FILE if canonical else None,
                    )
                )
            evidence += [
                results_evidence(f"variant: replay {number} of {VARIANT_POC_FILE}", run)
                for number, run in enumerate(item.results, start=1)
            ]
        return tuple(evidence)

    def _document(self, campaign: Campaign, side: _Side) -> dict[str, JsonValue]:
        assert campaign.search is not None
        assert campaign.search.counterexample is not None
        settings = self.settings
        return {
            "revision": side.revision.value,
            "profile": settings.profile.name,
            "base_seed": settings.base_seed,
            "seed_index": campaign.index,
            "seed": campaign.seed,
            "runs_per_seed": settings.fuzz_runs,
            "invariant_runs": settings.profile.invariant_runs,
            "invariant_depth": settings.profile.invariant_depth,
            **campaign.search.counterexample.document(),
        }

    def _execution(
        self,
        side: _Side,
        claim: str,
        judge: Callable[[_Side], tuple[Verdict, tuple[Reason, ...], str]],
    ) -> Execution:
        verdict, reasons, summary = judge(side)
        settings = self.settings
        return Execution(
            revision=side.revision,
            claim=claim,
            argv=side.argv or self.argv("fuzz", settings.seeds[0]),
            seed=settings.seed,
            exit_code=side.exit_code,
            verdict=verdict,
            reasons=reasons,
            summary=clip(summary),
            trace={
                "profile": settings.profile.name,
                "base_seed": settings.base_seed,
                "seeds": list(settings.seeds),
                "runs_per_seed": settings.fuzz_runs,
                "invariant_runs": settings.profile.invariant_runs,
                "invariant_depth": settings.profile.invariant_depth,
                "problem": None if side.problem is None else side.problem.model_dump(mode="json"),
                "invariant_available": side.available["invariant"],
                "campaigns": [item.trace() for mode in MODES for item in side.campaigns[mode]],
                "confirmations": [item.trace() for item in side.confirmations],
            },
            evidence=self._evidence(side),
        )
