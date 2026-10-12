"""Symbolic results per fixture and patch (`make symbolic-report`).

For every development fixture whose PoC directory holds symbolic properties (`poc/symbolic/`),
this tool runs the SymbolicOracle alone (the same code as `assay verify --symbolic`, in the
runner images) on the vulnerable revision and on each labelled patch, and records the verdict,
the bounds, the per-property results and the bounded-equivalence outcome. Fixtures without
symbolic properties are listed with the reason recorded in `UNSUPPORTED`. The tool renders
`docs/symbolic.md` from those results, so that the page is never written by hand.

Expectations follow the labels: an `overfit` patch leaves a variant open, so a property that
covers it should report a counterexample; `good`, `destructive` and `regressing` patches close the
hole, so a counterexample for one of them contradicts its label (or shows a wrong property) and is
a finding. An INCONCLUSIVE result (a timeout or an unknown result) is reported as it is: it never
counts as a pass.

Exit status: 0 when every run finished and no hole-closing patch got a confirmed counterexample,
1 when one did, 2 when the fixtures, the runner images or the arguments cannot be used.
"""

import argparse
import hashlib
import sys
import tempfile
import textwrap
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

import fixture_check
from assay import __version__
from assay.analyzers.foundry import ForgeOutOfMemory
from assay.ingest import IngestError, create_snapshot
from assay.ingest.patch import prepare_patched_revision
from assay.oracles.runtree import load_harness, symbolic_paths
from assay.oracles.symbolic import (
    HalmosSettings,
    SymbolicContext,
    SymbolicOracle,
    SymbolicOutcome,
    max_calls,
    symbolic_runner,
)
from assay.report.bundle import EnvironmentUnavailable, read_versions_lock, tool_versions
from assay.sandbox import DEFAULT_IMAGE, DEFAULT_SYMBOLIC_IMAGE, SandboxError, SandboxRunner

REPO_ROOT: Final = fixture_check.REPO_ROOT
FIXTURES_DIR: Final = fixture_check.FIXTURES_DIR
CLASS_IDS: Final = fixture_check.CLASS_IDS
LABELS: Final = ("good", "overfit", "destructive", "regressing")
DEFAULT_OUT: Final = REPO_ROOT / "docs" / "symbolic.md"
RESULT_PREFIX: Final = "SYMBOLIC REPORT:"
NOT_RUN: Final = "-"

# Fixtures without symbolic properties, and why. The reason is a property of the attack, not of
# the oracle: the oracle runs whatever properties a PoC directory holds.
UNSUPPORTED: Final[dict[str, str]] = {
    "reentrancy/single_function": (
        "callback recursion: the attack re-enters the vault from the attacker contract's "
        "`receive` function, so every path nests calls through code that the property would "
        "have to model as an unknown callee, and the depth of the nesting is the attack"
    ),
    "signature_replay/missing_nonce": (
        "`ecrecover`: the attack replays a signed claim, and Halmos treats `ecrecover` as an "
        "uninterpreted function, so a counterexample over signatures and signers would not "
        "correspond to a real signature that a replay could reproduce"
    ),
    "oracle_manipulation/spot_price": (
        "AMM arithmetic: the collateral value is a product and quotient of pool reserves after "
        "a symbolic swap, non-linear 256-bit arithmetic in several steps that the solver cannot "
        "settle within useful bounds"
    ),
    "dos/payout_loop": (
        "a payout loop over a list of recipients whose length is the attack: a property would "
        "have to fix the list length to the loop unrolling bound, so the bound, not the patch, "
        "would decide the result"
    ),
}

Label = Literal["good", "overfit", "destructive", "regressing"]
Verdict = Literal["PASS", "FAIL", "INCONCLUSIVE"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class PropertyResult(_Strict):
    revision: Literal["vulnerable", "patched"]
    signature: str
    kind: Literal["variant", "equivalence"]
    outcome: str
    calldata_bytes: int
    bounded_loops: int | None


class PatchResult(_Strict):
    fixture: str
    label: Label
    verdict: Verdict | None
    reasons: tuple[str, ...]
    statement: str
    equivalence: str
    equivalence_statement: str
    properties: tuple[PropertyResult, ...]
    seconds: float = Field(ge=0)
    error: str | None = None


class Unsupported(_Strict):
    fixture: str
    reason: str


class SymbolicResults(_Strict):
    schema_version: Literal[1] = 1
    assay_version: str
    tool_versions: dict[str, str]
    symbolic_tool_versions: dict[str, str]
    versions_lock_sha256: str
    loop_bound: int
    solver_timeout_s: int
    timeout_s: int
    memory_mib: int
    max_calls_per_property: int | None
    total_seconds: float = Field(ge=0)
    results: tuple[PatchResult, ...]
    unsupported: tuple[Unsupported, ...]


def _class_order(fixture: str) -> tuple[int, str]:
    class_id = fixture.split("/", 1)[0]
    index = CLASS_IDS.index(class_id) if class_id in CLASS_IDS else len(CLASS_IDS)
    return index, fixture


def summarize(fixture: str, label: str, outcome: SymbolicOutcome, seconds: float) -> PatchResult:
    result = outcome.result
    properties = tuple(
        PropertyResult(
            revision=item.revision.value,
            signature=item.signature,
            kind=item.kind,
            outcome=item.outcome,
            calldata_bytes=item.calldata_bytes,
            bounded_loops=item.bounded_loops,
        )
        for item in outcome.bounds.checks
    )
    return PatchResult(
        fixture=fixture,
        label=label,  # type: ignore[arg-type]
        verdict=result.verdict.value,
        reasons=tuple(result.codes()),
        statement=outcome.statement,
        equivalence=outcome.bounds.equivalence,
        equivalence_statement=outcome.equivalence_statement,
        properties=properties,
        seconds=round(seconds, 1),
    )


def check_patch(
    runner: SandboxRunner,
    halmos: SandboxRunner,
    fixtures_dir: Path,
    fixture: str,
    label: str,
    work: Path,
) -> PatchResult:
    """Run the SymbolicOracle on one patch."""
    base_dir = fixtures_dir / fixture
    started = time.monotonic()
    try:
        base = create_snapshot(base_dir, work / "base")
        poc = create_snapshot(base_dir / "poc", work / "poc")
        patch = (base_dir / "patches" / f"{label}.diff").read_bytes()
        prepared = prepare_patched_revision(base, patch, work / "patched")
        if prepared.snapshot is None:
            raise OSError(f"the {label} patch of {fixture} does not apply")
        patched = prepared.snapshot
        (work / "symbolic").mkdir()
        version = halmos.image_labels().get("assay.halmos.version")
        outcome = SymbolicOracle(halmos_version=version).search(
            SymbolicContext(
                runner=runner,
                symbolic_runner=halmos,
                vulnerable=base,
                patched=patched,
                poc=poc,
                harness=load_harness(),
                work_dir=work / "symbolic",
            )
        )
    except (IngestError, OSError) as exc:
        return PatchResult(
            fixture=fixture,
            label=label,  # type: ignore[arg-type]
            verdict=None,
            reasons=(),
            statement="",
            equivalence="not_run",
            equivalence_statement="",
            properties=(),
            seconds=round(time.monotonic() - started, 1),
            error=str(exc)[:300],
        )
    return summarize(fixture, label, outcome, time.monotonic() - started)


def has_properties(fixtures_dir: Path, fixture: str, work: Path) -> bool:
    poc = create_snapshot(fixtures_dir / fixture / "poc", work)
    return bool(symbolic_paths(poc))


def collect(
    fixtures_dir: Path, runner: SandboxRunner, halmos: SandboxRunner, settings: HalmosSettings
) -> SymbolicResults:
    fixtures = sorted(fixture_check.discover_fixtures(fixtures_dir), key=_class_order)
    found: list[PatchResult] = []
    unsupported: list[Unsupported] = []
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="assay-symbolic-", ignore_cleanup_errors=True) as tmp:
        index = 0
        for fixture in fixtures:
            index += 1
            if not has_properties(fixtures_dir, fixture, Path(tmp) / f"probe-{index:03d}"):
                reason = UNSUPPORTED.get(fixture, "no symbolic properties have been written yet")
                unsupported.append(Unsupported(fixture=fixture, reason=reason))
                print(f"{fixture}: not supported ({reason})", file=sys.stderr, flush=True)
                continue
            for label in LABELS:
                index += 1
                work = Path(tmp) / f"{index:03d}"
                work.mkdir()
                item = check_patch(runner, halmos, fixtures_dir, fixture, label, work)
                found.append(item)
                print(
                    f"{fixture} {label}: {item.verdict or 'ERROR'} "
                    f"({item.error or ', '.join(item.reasons) or 'no reason'}; equivalence "
                    f"{item.equivalence}; {item.seconds} s)",
                    file=sys.stderr,
                    flush=True,
                )
    lock = read_versions_lock().encode("utf-8")
    return SymbolicResults(
        assay_version=__version__,
        tool_versions=tool_versions(runner.image_labels()),
        symbolic_tool_versions=tool_versions(halmos.image_labels()),
        versions_lock_sha256=hashlib.sha256(lock).hexdigest(),
        loop_bound=settings.loop,
        solver_timeout_s=settings.solver_timeout_s,
        timeout_s=settings.timeout_s,
        memory_mib=settings.memory_mib,
        max_calls_per_property=max_calls(load_harness()),
        total_seconds=round(time.monotonic() - started, 1),
        results=tuple(found),
        unsupported=tuple(unsupported),
    )


def _paragraph(text: str) -> str:
    return textwrap.fill(text, width=100, break_long_words=False, break_on_hyphens=False)


def _duration(seconds: float) -> str:
    minutes, rest = divmod(round(seconds), 60)
    return f"{minutes} min {rest} s" if minutes else f"{rest} s"


def contradictions(results: SymbolicResults) -> list[PatchResult]:
    """Hole-closing patches with a confirmed counterexample."""
    return [
        item
        for item in results.results
        if item.label != "overfit" and item.verdict == "FAIL" and "variant_found" in item.reasons
    ]


def result_line(results: SymbolicResults) -> str:
    def count(label: str, verdict: str) -> str:
        rows = [item for item in results.results if item.label == label]
        return f"{sum(item.verdict == verdict for item in rows)}/{len(rows)}"

    supported = len({item.fixture for item in results.results})
    return (
        f"{RESULT_PREFIX} {supported} fixtures with properties, {len(results.unsupported)} "
        f"without; overfit FAIL {count('overfit', 'FAIL')}; good PASS {count('good', 'PASS')}; "
        f"INCONCLUSIVE {sum(item.verdict == 'INCONCLUSIVE' for item in results.results)}; "
        f"contradictions {len(contradictions(results))}"
    )


INTRODUCTION: Final = (
    "The symbolic oracle runs Halmos on properties that a fixture's PoC directory holds in "
    "`symbolic/`. A variant property (`check_variant_*`) is the exploit with symbolic "
    "parameters: Halmos explores every value of every parameter at once, along every path "
    "within the loop unrolling bound, and reports a counterexample when some input makes the "
    "PoC's predicate hold. An equivalence property (`check_equiv_*`) runs the same calls on the "
    "patched and on the vulnerable revision, outside the exploit condition, and asserts that "
    "results and observable state agree."
)
WHAT_IT_SHOWS: Final = (
    "A PASS states that Halmos found no counterexample on any path it explored, within the "
    "stated bounds: the loop unrolling bound, the calldata of each property (4 bytes of "
    "selector and one 32-byte word per parameter), at most the stated number of calls of the "
    "target per property, the solver time per query and the run limits, starting from the "
    "state that the property's `setUp()` builds. A counterexample counts only after a "
    "generated Foundry test (`variant_poc.t.sol`) reproduced it three times out of three."
)
WHAT_IT_DOES_NOT: Final = (
    "It is not a proof that the patch is correct. Paths longer than the loop bound are cut and "
    "listed; inputs outside a property's assumptions, other initial states, other callers and "
    "call sequences the property does not make are not covered; a property covers only the "
    "attack it was written for. A timeout, an out-of-memory kill or an unknown solver result "
    "is INCONCLUSIVE (`symbolic_unknown`), never a pass. A property that finds no "
    "counterexample on the vulnerable revision is not counted. Halmos deploys contracts at "
    "other addresses than Foundry, so a counterexample that names a deployed contract cannot be "
    "replayed and stays INCONCLUSIVE (`flaky_counterexample`). Bounded equivalence only adds "
    "to the BehaviorOracle's evidence when it shows no difference; a difference or an unknown "
    "result is noted and changes no verdict."
)
BOUNDS_TEXT: Final = (
    "The loop bound is the number of iterations Halmos explores per loop; a path that would "
    "iterate further is cut, and the number of cut loops is reported. The calldata of a "
    "property is fixed by its parameters, which are static types only. The call limit "
    "(`ASSAY_MAX_CALLS` in `solidity/AssayCheck.sol`) caps the calls a property makes through "
    "`assayCall`; paths beyond it end without a counterexample."
)


def _verdict(item: PatchResult) -> str:
    if item.error is not None or item.verdict is None:
        return "ERROR"
    if item.reasons:
        return f"{item.verdict} ({', '.join(item.reasons)})"
    return item.verdict


def _properties(item: PatchResult, kind: str) -> str:
    rows = [p for p in item.properties if p.revision == "patched" and p.kind == kind]
    if not rows:
        return NOT_RUN
    return "; ".join(
        f"`{p.signature.split('(', 1)[0]}` {p.outcome.replace('_', ' ')}"
        + (f", {p.bounded_loops} loops cut" if p.bounded_loops else "")
        for p in rows
    )


def render_markdown(results: SymbolicResults) -> str:
    """The page `docs/symbolic.md`, from the results of one run."""
    tools = ", ".join(f"{name} {version}" for name, version in results.tool_versions.items())
    symbolic_tools = ", ".join(
        f"{name} {version}"
        for name, version in results.symbolic_tool_versions.items()
        if name in ("halmos", "z3", "foundry", "solc")
    )
    calls = (
        str(results.max_calls_per_property)
        if results.max_calls_per_property is not None
        else NOT_RUN
    )
    lines = [
        "# Symbolic checks",
        "",
        _paragraph(
            "`make symbolic-report` writes this page from one run of the symbolic oracle over "
            "the development fixtures, with `tools/symbolic_report.py`. It is not edited by hand. "
            "How the oracle works and how to use it with `assay verify --symbolic`: "
            "[oracles](oracles.md#symbolicoracle); why Halmos runs in a linux/amd64 image: "
            "[ADR 0018](adr/0018-halmos-in-a-linux-amd64-image.md)."
        ),
        "",
        _paragraph(INTRODUCTION),
        "",
        "## What a result shows",
        "",
        _paragraph(WHAT_IT_SHOWS),
        "",
        "## What it does not show",
        "",
        _paragraph(WHAT_IT_DOES_NOT),
        "",
        "## Bounds",
        "",
        _paragraph(BOUNDS_TEXT),
        "",
        "| Bound | Value |",
        "|---|---|",
        f"| Loop unrolling bound | {results.loop_bound} |",
        f"| Calls of the target per property | at most {calls} |",
        "| Calldata per property | 4 + 32 * (number of parameters) bytes |",
        f"| Solver time per query | {results.solver_timeout_s} s |",
        f"| Limit per Halmos run | {results.timeout_s} s, {results.memory_mib} MiB |",
        "",
        "## Result",
        "",
        f"`{result_line(results)}`",
        "",
        "| Class | Fixture | Patch | Verdict | Variant properties (patched) | Equivalence | Time |",
        "|---|---|---|---|---|---|---|",
    ]
    rows = sorted(
        results.results, key=lambda item: (_class_order(item.fixture), LABELS.index(item.label))
    )
    for item in rows:
        class_id, name = item.fixture.split("/", 1)
        equivalence = item.equivalence.replace("_", " ")
        lines.append(
            f"| `{class_id}` | `{name}` | `{item.label}` | {_verdict(item)} | "
            f"{_properties(item, 'variant')} | {equivalence} | {_duration(item.seconds)} |"
        )
    lines += ["", "Bounds statements, as `assay verify --symbolic` reports them:", ""]
    for item in rows:
        if item.error is not None:
            lines.append(f"- `{item.fixture}` `{item.label}`: could not run: {item.error}")
            continue
        lines.append(f"- `{item.fixture}` `{item.label}`: {item.statement}")
        if item.equivalence not in ("none", "not_run"):
            lines.append(f"  {item.equivalence_statement}")
    found = contradictions(results)
    lines += ["", "## Findings", ""]
    if found:
        lines += [
            f"- `{item.fixture}` `{item.label}`: a confirmed counterexample on a patch that "
            "closes the hole; to investigate"
            for item in found
        ]
    else:
        lines.append(
            _paragraph(
                "No patch that closes the hole got a confirmed counterexample in this run. "
                "INCONCLUSIVE rows are what they say: the oracle could not decide within the "
                "bounds, and they count as neither pass nor fail."
            )
        )
    lines += [
        "",
        "## Fixtures without symbolic properties",
        "",
        _paragraph(
            "These fixtures have no `symbolic/` properties. With `--symbolic`, `assay verify` "
            "reports the symbolic oracle as INCONCLUSIVE (`no_symbolic_properties`) for them."
        ),
        "",
        "| Class | Fixture | Reason |",
        "|---|---|---|",
    ]
    for entry in results.unsupported:
        class_id, name = entry.fixture.split("/", 1)
        lines.append(f"| `{class_id}` | `{name}` | {entry.reason} |")
    lines += [
        "",
        "## Run",
        "",
        "| Item | Value |",
        "|---|---|",
        f"| Assay version | `{results.assay_version}` |",
        f"| Tools in the runner image | {tools or NOT_RUN} |",
        f"| Tools in the symbolic image | {symbolic_tools or NOT_RUN} |",
        f"| `versions.lock` sha256 | `{results.versions_lock_sha256}` |",
        f"| Total time | {_duration(results.total_seconds)}, one patch after the other |",
        "",
        _paragraph(
            "On an arm64 host the symbolic image runs under emulation, which makes every Halmos "
            "run slower; the times are for orientation only. Verdicts and bounds repeat for the "
            "same inputs and images."
        ),
        "",
        "## Reproduce",
        "",
        "```sh",
        "make image",
        "make symbolic-report",
        "```",
        "",
    ]
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="symbolic_report.py",
        description="Run the symbolic oracle on every patch of the fixtures with properties.",
    )
    parser.add_argument("--image", default=DEFAULT_IMAGE, help="runner image")
    parser.add_argument(
        "--symbolic-image", default=DEFAULT_SYMBOLIC_IMAGE, help="symbolic runner image"
    )
    parser.add_argument("--fixtures", type=Path, default=FIXTURES_DIR, help="fixtures root")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Markdown page to write")
    parser.add_argument("--results", type=Path, default=None, help="also write results JSON")
    parser.add_argument(
        "--from-results", type=Path, default=None, help="render from results JSON, no runs"
    )
    args = parser.parse_args(argv)

    if args.from_results is not None:
        try:
            results = SymbolicResults.model_validate_json(args.from_results.read_bytes())
        except (OSError, ValidationError) as exc:
            print(f"error: the results cannot be read: {exc}", file=sys.stderr)
            return 2
    else:
        settings = HalmosSettings()
        try:
            results = collect(
                args.fixtures,
                SandboxRunner(image=args.image),
                symbolic_runner(settings, image=args.symbolic_image),
                settings,
            )
        except (
            SandboxError,
            EnvironmentUnavailable,
            ForgeOutOfMemory,
            IngestError,
            OSError,
        ) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.results is not None and args.from_results is None:
        args.results.parent.mkdir(parents=True, exist_ok=True)
        args.results.write_text(results.model_dump_json(indent=2) + "\n", encoding="utf-8")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render_markdown(results), encoding="utf-8")
    print(f"wrote {args.out}")
    print(result_line(results))
    found = contradictions(results)
    for item in found:
        print(f"FINDING: a confirmed counterexample on the {item.label} patch of {item.fixture}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
