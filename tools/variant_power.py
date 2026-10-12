"""Power of the variant search per campaign profile (`make variant-power`).

For the `overfit` and the `good` patch of every development fixture, and for each profile given
with `--profiles`, this tool runs the VariantOracle alone (the same code as in `assay verify`,
in the sandbox runner) on the vulnerable revision and the patched one, and records whether a
confirmed variant was found, in which search mode and with which seed, and how long the search
took. It renders `docs/variant-power.md` from those results, so that the page is never written
by hand.

An overfit patch leaves a variant open by construction (docs/fixture-spec.md, section 2): a
search that misses it shows the limit of that profile, nothing else. A good patch closes the
hole: a variant reported for one is a finding to investigate, and makes the exit status 1.

Exit status: 0 when every search ran and no good patch got a variant, 1 when a good patch got a
variant, 2 when the fixtures, the runner image or the arguments cannot be used.
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
from assay.ledger import RevisionKind
from assay.oracles.runtree import load_harness
from assay.oracles.variant import (
    DEFAULT_BASE_SEED,
    PROFILE_NAMES,
    VariantContext,
    VariantOracle,
    VariantOutcome,
    VariantSettings,
    profile,
)
from assay.report.bundle import EnvironmentUnavailable, read_versions_lock, tool_versions
from assay.sandbox import DEFAULT_IMAGE, SandboxError, SandboxRunner

REPO_ROOT: Final = fixture_check.REPO_ROOT
FIXTURES_DIR: Final = fixture_check.FIXTURES_DIR
CLASS_IDS: Final = fixture_check.CLASS_IDS
LABELS: Final = ("overfit", "good")
DEFAULT_OUT: Final = REPO_ROOT / "docs" / "variant-power.md"
RESULT_PREFIX: Final = "VARIANT POWER:"
NOT_RUN: Final = "-"

ProfileName = Literal["quick", "standard", "thorough"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class SearchResult(_Strict):
    """One variant search: a patch, a profile, and what the search gave."""

    fixture: str
    label: Literal["overfit", "good"]
    profile: ProfileName
    verdict: Literal["PASS", "FAIL", "INCONCLUSIVE"] | None
    reasons: tuple[str, ...]
    found: bool
    """A variant was found and confirmed by every replay (FAIL `variant_found`)."""
    mode: Literal["fuzz", "invariant"] | None
    seed_index: int | None
    seeds: int
    seconds: float = Field(ge=0)
    error: str | None = None


class ProfileValues(_Strict):
    name: ProfileName
    seeds: int
    runs_per_seed: int
    invariant_runs: int
    invariant_depth: int
    campaign_timeout_s: int


class PowerResults(_Strict):
    schema_version: Literal[1] = 1
    assay_version: str
    tool_versions: dict[str, str]
    versions_lock_sha256: str
    base_seed: str
    profiles: tuple[ProfileValues, ...]
    total_seconds: float = Field(ge=0)
    results: tuple[SearchResult, ...]


def _class_order(fixture: str) -> tuple[int, str]:
    class_id = fixture.split("/", 1)[0]
    index = CLASS_IDS.index(class_id) if class_id in CLASS_IDS else len(CLASS_IDS)
    return index, fixture


def summarize(
    fixture: str, label: str, name: str, outcome: VariantOutcome, seconds: float
) -> SearchResult:
    result = outcome.result
    codes = tuple(result.codes())
    found = result.verdict.value == "FAIL" and "variant_found" in codes
    mode = None
    seed_index = None
    if found:
        for item in outcome.bounds.searches:
            if item.revision is RevisionKind.PATCHED and item.found_at_seed is not None:
                mode, seed_index = item.mode, item.found_at_seed
                break
    return SearchResult(
        fixture=fixture,
        label=label,  # type: ignore[arg-type]
        profile=name,  # type: ignore[arg-type]
        verdict=result.verdict.value,
        reasons=codes,
        found=found,
        mode=mode,
        seed_index=seed_index,
        seeds=len(outcome.bounds.seeds),
        seconds=round(seconds, 1),
    )


def search(
    runner: SandboxRunner, fixtures_dir: Path, fixture: str, label: str, name: str, work: Path
) -> SearchResult:
    """Run the VariantOracle on one patch with one profile."""
    base_dir = fixtures_dir / fixture
    started = time.monotonic()
    try:
        base = create_snapshot(base_dir, work / "base")
        poc = create_snapshot(base_dir / "poc", work / "poc")
        patch = (base_dir / "patches" / f"{label}.diff").read_bytes()
        prepared = prepare_patched_revision(base, patch, work / "patched")
        if prepared.snapshot is None:
            raise OSError(f"the {label} patch of {fixture} does not apply")
        (work / "variant").mkdir()
        outcome = VariantOracle(VariantSettings(profile=profile(name))).search(
            VariantContext(
                runner=runner,
                vulnerable=base,
                patched=prepared.snapshot,
                poc=poc,
                harness=load_harness(),
                work_dir=work / "variant",
            )
        )
    except (IngestError, OSError) as exc:
        return SearchResult(
            fixture=fixture,
            label=label,  # type: ignore[arg-type]
            profile=name,  # type: ignore[arg-type]
            verdict=None,
            reasons=(),
            found=False,
            mode=None,
            seed_index=None,
            seeds=profile(name).seeds,
            seconds=round(time.monotonic() - started, 1),
            error=str(exc)[:300],
        )
    return summarize(fixture, label, name, outcome, time.monotonic() - started)


def collect(
    fixtures_dir: Path, runner: SandboxRunner, names: Sequence[ProfileName]
) -> PowerResults:
    fixtures = sorted(fixture_check.discover_fixtures(fixtures_dir), key=_class_order)
    found: list[SearchResult] = []
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="assay-power-", ignore_cleanup_errors=True) as tmp:
        index = 0
        for name in names:
            for fixture in fixtures:
                for label in LABELS:
                    index += 1
                    work = Path(tmp) / f"{index:03d}"
                    work.mkdir()
                    item = search(runner, fixtures_dir, fixture, label, name, work)
                    found.append(item)
                    where = (
                        f"{item.mode} seed {item.seed_index} of {item.seeds}"
                        if item.found
                        else item.error or ", ".join(item.reasons) or "no variant"
                    )
                    print(
                        f"[{name}] {fixture} {label}: {item.verdict or 'ERROR'} ({where}, "
                        f"{item.seconds} s)",
                        file=sys.stderr,
                        flush=True,
                    )
    labels = runner.image_labels()
    lock = read_versions_lock().encode("utf-8")
    return PowerResults(
        assay_version=__version__,
        tool_versions=tool_versions(labels),
        versions_lock_sha256=hashlib.sha256(lock).hexdigest(),
        base_seed=DEFAULT_BASE_SEED,
        profiles=tuple(ProfileValues.model_validate(profile(name).model_dump()) for name in names),
        total_seconds=round(time.monotonic() - started, 1),
        results=tuple(found),
    )


def _paragraph(text: str) -> str:
    return textwrap.fill(text, width=100, break_long_words=False, break_on_hyphens=False)


def _duration(seconds: float) -> str:
    minutes, rest = divmod(round(seconds), 60)
    return f"{minutes} min {rest} s" if minutes else f"{rest} s"


def counts(results: PowerResults, name: str) -> tuple[int, int, int, int]:
    """(overfit found, overfit total, good with a variant, good total) for one profile."""
    rows = [item for item in results.results if item.profile == name]
    overfit = [item for item in rows if item.label == "overfit"]
    good = [item for item in rows if item.label == "good"]
    return (
        sum(item.found for item in overfit),
        len(overfit),
        sum(item.found for item in good),
        len(good),
    )


def result_line(results: PowerResults) -> str:
    parts = []
    for item in results.profiles:
        found, total, wrong, goods = counts(results, item.name)
        parts.append(
            f"{item.name}: {found}/{total} overfit patches with a variant, "
            f"{wrong}/{goods} good patches with a variant"
        )
    return f"{RESULT_PREFIX} " + "; ".join(parts)


INTRODUCTION: Final = (
    "This page shows what the variant search of `assay verify` finds with each campaign profile "
    "on the patches of the development fixtures. An `overfit` patch blocks the original PoC but "
    "leaves a close variant open; a `good` patch closes the hole. For each patch and profile the "
    "VariantOracle ran on the vulnerable and the patched revision, with the seeds derived from "
    "the base seed below. A variant counts as found only when the generated test "
    "`variant_poc.t.sol` reproduced it in three replays out of three (FAIL `variant_found`)."
)
LIMITS: Final = (
    "These numbers describe the reach of the search, not a guarantee. A profile can miss a "
    "variant that exists: the `quick` profile runs fewer seeds, runs and sequences, and can pass "
    "a patch that `standard` or `thorough` reject. A search that finds nothing states only that "
    "nothing was found within the runs it made; it is not a proof of absence. The fixtures, "
    "their patches and the oracles were written by the same author, so the numbers say nothing "
    "about other code."
)
GOOD_NOTE: Final = (
    "No good patch may get a variant: a variant for a good patch would mean that the patch, its "
    "label or the search is wrong, and is investigated rather than accepted."
)


def _seed_cell(item: SearchResult) -> str:
    if item.error is not None or item.verdict is None:
        return NOT_RUN
    if not item.found or item.seed_index is None:
        return f"none of {item.seeds}"
    return f"{item.seed_index} of {item.seeds}"


def render_markdown(results: PowerResults) -> str:
    """The page `docs/variant-power.md`, from the results of one run."""
    tools = ", ".join(f"{name} {version}" for name, version in results.tool_versions.items())
    names = [item.name for item in results.profiles]
    lines = [
        "# Variant search power",
        "",
        _paragraph(
            "`make variant-power` writes this page from one run of the variant search over the "
            "development fixtures, with `tools/variant_power.py`. It is not edited by hand."
        ),
        "",
        _paragraph(INTRODUCTION),
        "",
        "## What these numbers mean",
        "",
        _paragraph(LIMITS),
        "",
        _paragraph(GOOD_NOTE),
        "",
        "## Result",
        "",
        f"`{result_line(results)}`",
        "",
        "| Profile | Overfit patches with a variant | Good patches with a variant | Time |",
        "|---|---|---|---|",
    ]
    for name in names:
        found, total, wrong, goods = counts(results, name)
        seconds = sum(item.seconds for item in results.results if item.profile == name)
        lines.append(f"| `{name}` | {found}/{total} | {wrong}/{goods} | {_duration(seconds)} |")
    missed = [
        item
        for item in results.results
        if item.label == "overfit" and not item.found and item.error is None
    ]
    lines += ["", "## Overfit patches without a variant", ""]
    if missed:
        lines.append(
            _paragraph(
                "These searches did not find the variant that the overfit patch leaves open. "
                "They mark the limit of the profile, and the verdict of such a search is "
                "`VERIFIED_WITHIN_BOUNDS` or `INCONCLUSIVE`, never a statement that no variant "
                "exists:"
            )
        )
        lines.append("")
        lines += [
            f"- `{item.fixture}` with the `{item.profile}` profile: "
            f"{item.verdict} ({', '.join(item.reasons) or 'no reason'})"
            for item in missed
        ]
    else:
        lines.append(
            _paragraph(
                "Every profile found the variant of every overfit patch in this run. That holds "
                "for these fixtures, these seeds and this run only: with other seeds or other "
                "code, a smaller profile can miss a variant that a larger one finds."
            )
        )
    lines += [
        "",
        "## Searches",
        "",
        "| Class | Fixture | Patch | Profile | Verdict | Variant found | Mode | Seed | Time |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    order = {name: index for index, name in enumerate(names)}
    rows = sorted(
        results.results,
        key=lambda item: (
            _class_order(item.fixture),
            LABELS.index(item.label),
            order.get(item.profile, 99),
        ),
    )
    for item in rows:
        class_id, fixture_name = item.fixture.split("/", 1)
        verdict: str = item.verdict or "ERROR"
        if item.reasons and not item.found:
            verdict += f" ({', '.join(item.reasons)})"
        lines.append(
            f"| `{class_id}` | `{fixture_name}` | `{item.label}` | `{item.profile}` | {verdict} | "
            f"{'yes' if item.found else 'no'} | {item.mode or NOT_RUN} | {_seed_cell(item)} | "
            f"{_duration(item.seconds)} |"
        )
    errors = [item for item in rows if item.error is not None]
    if errors:
        lines += ["", "Searches that could not run:", ""]
        lines += [
            f"- `{item.fixture}` `{item.label}` `{item.profile}`: {item.error}" for item in errors
        ]
    lines += [
        "",
        "## Run",
        "",
        "| Profile | Seeds | Fuzz runs per seed | Invariant sequences per seed | Calls per "
        "sequence | Limit per campaign |",
        "|---|---|---|---|---|---|",
    ]
    lines += [
        f"| `{item.name}` | {item.seeds} | {item.runs_per_seed} | {item.invariant_runs} | "
        f"{item.invariant_depth} | {item.campaign_timeout_s} s |"
        for item in results.profiles
    ]
    lines += [
        "",
        "| Item | Value |",
        "|---|---|",
        f"| Assay version | `{results.assay_version}` |",
        f"| Tools in the image | {tools or NOT_RUN} |",
        f"| `versions.lock` sha256 | `{results.versions_lock_sha256}` |",
        f"| Base seed | `{results.base_seed}` |",
        f"| Total time | {_duration(results.total_seconds)}, one search after the other |",
        "",
        _paragraph(
            "Times depend on the machine and are given for orientation only; every other "
            "number repeats exactly for the same base seed, profile and runner image."
        ),
        "",
        "## Reproduce",
        "",
        "```sh",
        "make image",
        f'make variant-power PROFILES="{" ".join(names)}"',
        "```",
        "",
    ]
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="variant_power.py",
        description="Run the variant search on every overfit and good patch per profile.",
    )
    parser.add_argument("--image", default=DEFAULT_IMAGE, help="runner image")
    parser.add_argument("--fixtures", type=Path, default=FIXTURES_DIR, help="fixtures root")
    parser.add_argument(
        "--profiles", default="quick standard thorough", help="profiles, separated by spaces"
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Markdown page to write")
    parser.add_argument("--results", type=Path, default=None, help="also write results JSON")
    parser.add_argument(
        "--from-results", type=Path, default=None, help="render from results JSON, no searches"
    )
    args = parser.parse_args(argv)

    if args.from_results is not None:
        try:
            results = PowerResults.model_validate_json(args.from_results.read_bytes())
        except (OSError, ValidationError) as exc:
            print(f"error: the results cannot be read: {exc}", file=sys.stderr)
            return 2
    else:
        names = args.profiles.split()
        unknown = [name for name in names if name not in PROFILE_NAMES]
        if not names or unknown or len(set(names)) != len(names):
            print(
                f"error: --profiles takes distinct names of {', '.join(PROFILE_NAMES)}",
                file=sys.stderr,
            )
            return 2
        try:
            results = collect(args.fixtures, SandboxRunner(image=args.image), names)
        except (SandboxError, EnvironmentUnavailable, ForgeOutOfMemory, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.results is not None and args.from_results is None:
        args.results.parent.mkdir(parents=True, exist_ok=True)
        args.results.write_text(results.model_dump_json(indent=2) + "\n", encoding="utf-8")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render_markdown(results), encoding="utf-8")
    print(f"wrote {args.out}")
    print(result_line(results))
    wrong = [item for item in results.results if item.label == "good" and item.found]
    for item in wrong:
        print(f"FINDING: a variant for the good patch of {item.fixture} ({item.profile})")
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(main())
