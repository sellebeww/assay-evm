"""The benchmark report: `docs/results.md` and `docs/results.json` from stored run folders.

The report is deterministic: the same result folders, protocol and findings give byte-identical
files. It holds no timestamps, host paths or user names. Held-out results are marked held-out only
if the oracle hash recorded in the run equals `bench/FROZEN_HASH`; the findings section is
rendered from the results and `bench/findings.json`, never written by hand.
"""

import json
import re
import textwrap
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from pydantic import ValidationError

from assay.bench.ablation import accepts
from assay.bench.freeze import FreezeError, read_frozen, tree_hash
from assay.bench.models import (
    BAD_LABELS,
    CLASS_IDS,
    CONFIGS,
    PATCH_LABELS,
    SPLIT_NAMES,
    CaseResult,
    Findings,
    RunInfo,
)
from assay.bench.run import CASES_DIR, RUN_FILE
from assay.bench.stats import rate_json, rate_text

FINDINGS_FILE: Final = Path("bench") / "findings.json"
PROTOCOL_FILE: Final = Path("bench") / "PROTOCOL.md"
RESULTS_PAGE: Final = Path("docs") / "results.md"
RESULTS_JSON: Final = Path("docs") / "results.json"
NOT_COMPUTED: Final = "not computed"
CONFIG_TEXT: Final = {
    "V0": "tests only",
    "V1": "V0 and the original PoC is blocked",
    "V2": "V1 and no variant is found",
    "V3": "all non-symbolic oracles (full configuration)",
    "V4": "V3 and the symbolic oracle",
}


class ReportError(Exception):
    """The result folders, the findings or the protocol cannot be used."""


@dataclass(frozen=True)
class Run:
    folder: str
    info: RunInfo
    cases: tuple[CaseResult, ...]
    held_out: bool | None
    """`True` or `False` for the held-out split, `None` for the development split."""
    status: str


def _case_matches(case: CaseResult) -> bool:
    if case.final_verdict != case.expected_verdict:
        return False
    return case.expected_reason is None or case.expected_reason in case.reasons


def _order(case: CaseResult) -> tuple[int, str, int]:
    class_id = case.fixture.split("/", 1)[0]
    index = CLASS_IDS.index(class_id) if class_id in CLASS_IDS else len(CLASS_IDS)
    return index, case.fixture, PATCH_LABELS.index(case.label)


def load_run(root: Path, folder: Path) -> Run:
    """Read and validate one result folder."""
    try:
        info = RunInfo.model_validate_json((folder / RUN_FILE).read_bytes())
    except (OSError, ValueError, ValidationError) as exc:
        raise ReportError(f"{folder.name}: run.json cannot be read: {exc}") from exc
    files = sorted((folder / CASES_DIR).glob("*.json"))
    try:
        cases = tuple(CaseResult.model_validate_json(item.read_bytes()) for item in files)
    except (OSError, ValueError, ValidationError) as exc:
        raise ReportError(f"{folder.name}: a case file cannot be read: {exc}") from exc
    if len(cases) != info.cases:
        raise ReportError(f"{folder.name}: run.json says {info.cases} cases, found {len(cases)}")
    if info.run_id != folder.name:
        raise ReportError(f"{folder.name}: run.json names the run {info.run_id!r}")
    if len({(item.fixture, item.label) for item in cases}) != len(cases):
        raise ReportError(f"{folder.name}: a case occurs twice")
    held_out: bool | None = None
    status = "development split; not held-out by definition"
    if info.split == "heldout":
        try:
            frozen = read_frozen(root)
        except FreezeError as exc:
            raise ReportError(str(exc)) from exc
        if frozen is None:
            held_out, status = False, "NOT HELD-OUT: the oracles were never frozen"
        elif frozen != info.oracle_tree_sha256:
            held_out, status = (
                False,
                "NOT HELD-OUT: the oracle hash of the run differs from bench/FROZEN_HASH",
            )
        else:
            held_out = True
            status = "HELD-OUT: the oracle hash of the run equals bench/FROZEN_HASH"
    return Run(folder.name, info, tuple(sorted(cases, key=_order)), held_out, status)


def load_findings(root: Path) -> Findings:
    path = root / FINDINGS_FILE
    if not path.is_file():
        return Findings(result_version="v1")
    try:
        return Findings.model_validate_json(path.read_bytes())
    except (OSError, ValueError, ValidationError) as exc:
        raise ReportError(f"{FINDINGS_FILE.as_posix()} cannot be read: {exc}") from exc


def _protocol_section(root: Path, number: int) -> list[str]:
    """The body of `## <number>. ...` of the protocol, so that the report cannot drift from it."""
    try:
        text = (root / PROTOCOL_FILE).read_text(encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"{PROTOCOL_FILE.as_posix()} cannot be read: {exc}") from exc
    match = re.search(rf"^## {number}\. .*?\n(.*?)(?=^## |\Z)", text, re.MULTILINE | re.DOTALL)
    if match is None:
        raise ReportError(f"{PROTOCOL_FILE.as_posix()} has no section {number}")
    return match.group(1).strip().splitlines()


def _paragraph(text: str) -> str:
    return textwrap.fill(text, width=100, break_long_words=False, break_on_hyphens=False)


def _split_runs(runs: Sequence[Run]) -> dict[str, Run]:
    by_split: dict[str, Run] = {}
    for run in runs:
        if run.info.split in by_split:
            raise ReportError(f"two result folders for the split {run.info.split}")
        by_split[run.info.split] = run
    return by_split


def ablation_counts(cases: Sequence[CaseResult], config: str) -> dict[str, tuple[int, int]]:
    """For each bad label and for all bad patches: accepted over computable; for `good`:
    rejected over computable. Cases the configuration cannot judge are left out."""
    counts: dict[str, tuple[int, int]] = {}
    for label in (*BAD_LABELS, "bad", "good"):
        chosen = [
            item
            for item in cases
            if (item.label == label) or (label == "bad" and item.label in BAD_LABELS)
        ]
        verdicts = [accepts(item, config) for item in chosen]
        known = [value for value in verdicts if value is not None]
        wrong = sum(value is False for value in known) if label == "good" else sum(known)
        counts[label] = (wrong, len(known))
    return counts


def _not_computed(cases: Sequence[CaseResult], config: str) -> int:
    return sum(accepts(item, config) is None for item in cases)


def _active_configs(cases: Sequence[CaseResult]) -> list[str]:
    return [
        config
        for config in CONFIGS
        if config != "V4" or any(accepts(item, "V4") is not None for item in cases)
    ]


def _cell(text: str) -> str:
    return text.replace("\\", "\\\\").replace("|", "\\|")


def _code(text: str | None) -> str:
    return "-" if text is None else f"`{_cell(text)}`"


def _verdict_text(case: CaseResult) -> str:
    if case.final_verdict is None:
        return "error"
    return (
        f"{case.final_verdict} ({', '.join(case.reasons)})" if case.reasons else case.final_verdict
    )


def _expected_text(case: CaseResult) -> str:
    if case.expected_reason is None:
        return case.expected_verdict
    return f"{case.expected_verdict} ({case.expected_reason})"


def _case_id(case: CaseResult) -> str:
    return f"{case.fixture}/{case.label}"


def per_class(cases: Sequence[CaseResult], config: str) -> dict[str, tuple[int, int, int, int]]:
    """Per class: bad accepted, bad computable, good rejected, good computable."""
    table: dict[str, tuple[int, int, int, int]] = {}
    for class_id in CLASS_IDS:
        selected = [item for item in cases if item.fixture.split("/", 1)[0] == class_id]
        if not selected:
            continue
        bad = [accepts(i, config) for i in selected if i.label in BAD_LABELS]
        good = [accepts(i, config) for i in selected if i.label == "good"]
        bad_known = [v for v in bad if v is not None]
        good_known = [v for v in good if v is not None]
        table[class_id] = (
            sum(bad_known),
            len(bad_known),
            sum(v is False for v in good_known),
            len(good_known),
        )
    return table


def _run_section(run: Run) -> list[str]:
    info = run.info
    cases = run.cases
    matching = sum(_case_matches(item) for item in cases)
    lines = [
        f"## Split `{info.split}`",
        "",
        f"Status: **{run.status}**.",
        "",
        f"Verdicts equal to the label: {rate_text(matching, len(cases), lower_is_better=False)}.",
        "",
        "| Patch label | Expected verdict | Expected reason | Matching |",
        "|---|---|---|---|",
    ]
    expected_by_label = {
        "good": ("VERIFIED_WITHIN_BOUNDS", "none"),
        "overfit": ("REJECTED", "`variant_found`"),
        "destructive": ("REJECTED", "`benign_test_failed` or an integrity reason"),
        "regressing": ("REJECTED", "`layout_changed`, `abi_changed` or `event_changed`"),
    }
    for label in PATCH_LABELS:
        chosen = [item for item in cases if item.label == label]
        ok = sum(_case_matches(item) for item in chosen)
        verdict, reason = expected_by_label[label]
        lines.append(f"| `{label}` | `{verdict}` | {reason} | {ok}/{len(chosen)} |")

    configs = _active_configs(cases)
    lines += [
        "",
        f"### Ablations on `{info.split}`",
        "",
        _paragraph(
            "Each cell is the number of wrong decisions over the number of cases the "
            "configuration could judge, with the Wilson 95 % interval. For bad patches a wrong "
            "decision is an acceptance (false accept); for good patches it is a rejection "
            "(false reject). Percentages are rounded away from the favorable direction."
        ),
        "",
        "| Config | Accepts a case when | Overfit accepted | Destructive accepted "
        "| Regressing accepted | All bad accepted | Good rejected |",
        "|---|---|---|---|---|---|---|",
    ]
    for config in configs:
        counts = ablation_counts(cases, config)
        cells = [
            rate_text(*counts[key], lower_is_better=True)
            for key in ("overfit", "destructive", "regressing", "bad", "good")
        ]
        lines.append(f"| {config} | {CONFIG_TEXT[config]} | " + " | ".join(cells) + " |")
    skipped = {config: _not_computed(cases, config) for config in configs}
    if any(skipped.values()):
        listing = ", ".join(f"{c}: {n}" for c, n in skipped.items() if n)
        lines += ["", f"Cases a configuration could not judge (left out of its counts): {listing}."]
    if "V4" not in configs:
        lines += ["", "V4 (symbolic oracle) is not part of this run."]

    lines += [
        "",
        f"### Per class on `{info.split}`",
        "",
        "Each cell: bad patches accepted out of the bad patches of the class, and good patches "
        "rejected out of the good patches of the class.",
        "",
        "| Class | " + " | ".join(configs) + " |",
        "|---|" + "---|" * len(configs),
    ]
    tables = {config: per_class(cases, config) for config in configs}
    for class_id in CLASS_IDS:
        if class_id not in tables[configs[0]]:
            continue
        cells = []
        for config in configs:
            bad_wrong, bad_n, good_wrong, good_n = tables[config][class_id]
            cells.append(f"{bad_wrong}/{bad_n} bad, {good_wrong}/{good_n} good")
        lines.append(f"| `{class_id}` | " + " | ".join(cells) + " |")

    lines += [
        "",
        f"### Cases on `{info.split}`",
        "",
        "| Class | Fixture | Patch | Expected | Actual | Result |",
        "|---|---|---|---|---|---|",
    ]
    for case in cases:
        class_id, name = case.fixture.split("/", 1)
        lines.append(
            f"| `{class_id}` | `{name}` | `{case.label}` | {_code(_expected_text(case))} "
            f"| {_code(_verdict_text(case))} | {'match' if _case_matches(case) else 'MISMATCH'} |"
        )
    return lines


def _findings_section(runs: dict[str, Run], findings: Findings) -> list[str]:
    mismatches = [
        (split, case)
        for split in SPLIT_NAMES
        if split in runs
        for case in runs[split].cases
        if not _case_matches(case)
    ]
    by_case = {(item.split, item.case): item for item in findings.findings if item.case}
    lines = [
        "## Findings",
        "",
        f"Result version: `{findings.result_version}`. Every mismatch between a verdict and a "
        "label is listed with its cause. The causes are read from `bench/findings.json`; a "
        "mismatch without a recorded cause is shown as unexplained.",
        "",
    ]
    if not mismatches:
        lines += ["Mismatches between a verdict and a label: none.", ""]
    else:
        lines += [
            "| Id | Split | Case | Expected | Actual | Kind | Status | Cause |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for split, case in mismatches:
            found = by_case.get((split, _case_id(case)))
            ident = found.id if found else "-"
            kind = found.kind if found else "unexplained"
            status = found.status if found else "open"
            cause = _cell(found.cause) if found else "no cause recorded yet"
            lines.append(
                f"| {ident} | `{split}` | `{_case_id(case)}` | {_code(_expected_text(case))} "
                f"| {_code(_verdict_text(case))} | {kind} | {status} | {cause} |"
            )
        lines.append("")
    matched = {(item.split, item.case) for item in findings.findings if item.case}
    shown = {(split, _case_id(case)) for split, case in mismatches}
    others = [
        item
        for item in findings.findings
        if (item.split, item.case) not in shown or item.case is None
    ]
    if others:
        lines += ["### Other findings", ""]
        for item in others:
            lines.append(
                f"- **{item.id}** ({item.kind}, `{item.split}`"
                f"{'' if item.case is None else f', `{item.case}`'}, {item.status}): "
                f"{_cell(item.summary)} {_cell(item.cause)}"
            )
        lines.append("")
    stale = matched - shown
    if stale:
        lines += [
            _paragraph(
                "Findings that name a case which now matches: "
                + ", ".join(f"`{case}`" for _, case in sorted(stale))
                + ". They stay for the record."
            ),
            "",
        ]
    if findings.corrections:
        lines += ["### Corrections of fixtures", ""]
        for fix in findings.corrections:
            lines.append(f"- `{fix.fixture}` (`{fix.split}`, after run `{fix.run}`): {fix.what}")
        lines.append("")
    return lines


def render_markdown(runs: dict[str, Run], findings: Findings, protocol_threats: list[str]) -> str:
    ordered = [runs[name] for name in SPLIT_NAMES if name in runs]
    lines = [
        "# Benchmark results",
        "",
        _paragraph(
            "`assay bench report` writes this page from stored result folders, with the "
            "findings of `bench/findings.json` and the threats of `bench/PROTOCOL.md`. It is not "
            "edited by hand."
        ),
        "",
        "## What these results mean",
        "",
        _paragraph(
            "This is a self-validation of the oracles on synthetic fixtures, not an independent "
            "benchmark and not a measurement of detection quality on real contracts. The "
            "development fixtures were used to build the oracles. The held-out fixtures were "
            "written after the oracles were frozen and without running the oracles on them, but "
            "by the same party that wrote the oracles. Each verdict covers only the checks and "
            "bounds that ran; `VERIFIED_WITHIN_BOUNDS` means that nothing was found within them "
            "and is not a proof of absence ([Oracles](oracles.md))."
        ),
        "",
        "## Runs",
        "",
        "| Split | Status | Cases | Profile | Oracle tree hash | Result folder |",
        "|---|---|---|---|---|---|",
    ]
    for run in ordered:
        info = run.info
        lines.append(
            f"| `{info.split}` | {run.status} | {info.cases} | `{info.profile}` "
            f"| `{info.oracle_tree_sha256[:16]}` | `bench/results/{run.folder}` |"
        )
    for run in ordered:
        lines += ["", *_run_section(run)]
    lines += ["", *_findings_section(runs, findings)]
    lines += ["## Threats to validity", "", *protocol_threats, ""]
    lines += ["## Run details", ""]
    for run in ordered:
        info = run.info
        tools = ", ".join(
            f"{name} {version}" for name, version in sorted(info.tool_versions.items())
        )
        lines += [
            f"### `{info.split}`",
            "",
            "| Item | Value |",
            "|---|---|",
            f"| Assay version | `{_cell(info.assay_version)}` |",
            f"| Git commit | {_code(info.git_commit)} |",
            f"| Runner image (local image id) | `{info.image_digest}` |",
            f"| Tools in the image | {_cell(tools) or '-'} |",
            f"| `versions.lock` sha256 | `{info.versions_lock_sha256}` |",
            f"| Oracle tree sha256 | `{info.oracle_tree_sha256}` |",
            f"| Fixtures tree sha256 | `{info.fixtures_tree_sha256}` |",
            f"| Split file sha256 | `{info.split_file_sha256}` |",
            f"| Machine architecture | `{_cell(info.machine)}` |",
            f"| Campaign profile | `{info.profile}` |",
            f"| Base seed | `{_cell(info.fuzz_seed)}` |",
            f"| Seeds per search mode | {info.variant_seeds} |",
            f"| Fuzz runs per campaign | {info.fuzz_runs} |",
            f"| Invariant runs and depth | {info.invariant_runs} sequences of up to "
            f"{info.invariant_depth} calls |",
            f"| Replays of the PoC per revision | {info.exploit_replays} |",
            f"| Symbolic oracle | {'yes' if info.symbolic else 'no'} |",
            f"| Total time | {_duration(info.total_seconds)} for {info.cases} verifications, "
            "one after the other |",
            "",
        ]
    lines += [
        _paragraph(
            "The image id identifies a local build of the runner image; images built on another "
            "machine or platform have other ids ([ADR 0008](adr/0008-runner-platform.md)). Times "
            "depend on the machine and are given for orientation only."
        ),
        "",
        "## Reproduce",
        "",
        "```sh",
        "make image",
    ]
    for run in ordered:
        symbolic = " SYMBOLIC=1" if run.info.symbolic else ""
        lines.append(
            f"make bench-oracles SPLIT={run.info.split} PROFILE={run.info.profile}{symbolic}"
        )
        if run.info.split == "dev" and "heldout" in runs:
            lines.append(
                "# bench/FROZEN_HASH was created by `make bench-freeze` before the next line"
            )
    folders = " ".join(f"bench/results/{run.folder}" for run in ordered)
    lines += [f'make bench-report RESULTS="{folders}"', "```", ""]
    lines += [
        _paragraph(
            "The runs take between ten minutes and about two hours per split, depending on the "
            "machine. The report is a function of the result folders, `bench/findings.json` and "
            "`bench/PROTOCOL.md`: the same inputs give the same files."
        ),
        "",
    ]
    return "\n".join(lines)


def _duration(seconds: float) -> str:
    total = round(seconds)
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours} h {minutes:02d} min"
    return f"{minutes} min {secs:02d} s"


def results_data(runs: dict[str, Run], findings: Findings) -> dict[str, object]:
    splits: dict[str, object] = {}
    for name in SPLIT_NAMES:
        if name not in runs:
            continue
        run = runs[name]
        cases = run.cases
        matching = sum(_case_matches(item) for item in cases)
        ablations: dict[str, object] = {}
        for config in _active_configs(cases):
            counts = ablation_counts(cases, config)
            ablations[config] = {
                "overfit_accepted": rate_json(*counts["overfit"]),
                "destructive_accepted": rate_json(*counts["destructive"]),
                "regressing_accepted": rate_json(*counts["regressing"]),
                "bad_accepted": rate_json(*counts["bad"]),
                "good_rejected": rate_json(*counts["good"]),
                "not_computed": _not_computed(cases, config),
            }
        splits[name] = {
            "status": run.status,
            "held_out": run.held_out,
            "run": run.info.model_dump(mode="json"),
            "match": rate_json(matching, len(cases)),
            "ablations": ablations,
            "cases": [
                {
                    "case": _case_id(item),
                    "expected": _expected_text(item),
                    "actual": _verdict_text(item),
                    "match": _case_matches(item),
                    "accepted_by": {
                        config: accepts(item, config) for config in _active_configs(cases)
                    },
                }
                for item in cases
            ],
        }
    return {
        "schema_version": 1,
        "result_version": findings.result_version,
        "splits": splits,
        "findings": [item.model_dump(mode="json") for item in findings.findings],
        "corrections": [item.model_dump(mode="json") for item in findings.corrections],
    }


def build_report(root: Path, folders: Sequence[Path]) -> tuple[str, str, list[str]]:
    """The Markdown page, the JSON file, and warnings, for the given result folders."""
    runs = _split_runs([load_run(root, folder) for folder in folders])
    if not runs:
        raise ReportError("no result folder given")
    findings = load_findings(root)
    threats = _protocol_section(root, 9)
    warnings: list[str] = []
    try:
        current = tree_hash(root)
    except FreezeError as exc:
        raise ReportError(str(exc)) from exc
    for run in runs.values():
        if run.info.oracle_tree_sha256 != current:
            warnings.append(
                f"the frozen paths changed after the {run.info.split} run; the run was made "
                "with other oracles than the current ones"
            )
    markdown = render_markdown(runs, findings, threats)
    data = json.dumps(results_data(runs, findings), indent=2, sort_keys=True) + "\n"
    return markdown, data, warnings
