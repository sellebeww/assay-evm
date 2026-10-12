"""`assay fix`: a bounded loop that asks a model for a patch and lets the oracles decide."""

import json
import os
import re
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Final, NoReturn

import typer

from assay.analyzers.foundry import ForgeOutOfMemory
from assay.cli.documents import FIX_FORMAT, RUN_FORMAT, FixDocument
from assay.cli.exit_codes import ExitCode
from assay.cli.prove import DEFAULT_POC_ROOT
from assay.cli.text import printable
from assay.cli.verify import DEFAULT_LEDGER, ProfileChoice, render
from assay.ledger import CassetteMode, FinalVerdict, FindingId, Ledger, LedgerError
from assay.llm import (
    Budget,
    BudgetExceeded,
    CassetteError,
    CassetteMissing,
    ConsentRequired,
    LlmClient,
    LlmConfig,
    LlmConfigError,
    LlmError,
    StructuredOutputError,
    load_config,
)
from assay.llm.cassette import DEFAULT_CASSETTE_DIR
from assay.llm.client import Recorder
from assay.llm.patcher import (
    DEFAULT_MAX_CHANGED_LINES,
    DEFAULT_MAX_DIFF_BYTES,
    DEFAULT_MAX_FILES,
    PatchConfig,
)
from assay.oracles.runtree import HarnessUnavailable
from assay.oracles.symbolic import symbolic_runner
from assay.oracles.variant import DEFAULT_BASE_SEED
from assay.orchestrator.fix import (
    DEFAULT_ATTEMPTS,
    FixOutcome,
    FixRequest,
    run_fix,
)
from assay.orchestrator.models import VerifySettings
from assay.orchestrator.prove import MAX_ATTEMPTS_CAP, ProveInputError
from assay.orchestrator.verify import BundleRequest
from assay.report.bundle import (
    BundleError,
    Environment,
    EnvironmentUnavailable,
    Sanitizer,
    check_bundle_dir,
    environment,
    read_versions_lock,
)
from assay.sandbox import SandboxError, SandboxRunner, SandboxUnavailable

_SEED: Final = re.compile(r"0x[0-9a-f]{1,16}")
DEFAULT_FIX_CALLS: Final = 12
DEFAULT_FIX_TOKENS: Final = 200_000
LIMITS_NOTE: Final = (
    "VERIFIED_WITHIN_BOUNDS means that nothing was found within the bounds listed above; it is "
    "not a proof of absence, and a model proposal is judged only by the oracles"
)
_VERDICT_EXIT: Final = {
    FinalVerdict.VERIFIED_WITHIN_BOUNDS: ExitCode.SUCCESS,
    FinalVerdict.REJECTED: ExitCode.NEGATIVE,
    FinalVerdict.INCONCLUSIVE: ExitCode.INCONCLUSIVE,
}


def fail(code: ExitCode, message: str) -> NoReturn:
    typer.echo(printable(message), err=True)
    raise typer.Exit(int(code))


def fix_exit_code(outcome: FixOutcome) -> ExitCode:
    """5 when the deciding patch was an integrity violation, otherwise 0, 1 or 3 by the verdict."""
    if outcome.integrity_violation:
        return ExitCode.INTEGRITY
    return _VERDICT_EXIT[outcome.verdict]


def llm_setup(
    mode: CassetteMode,
    allow_llm: bool,
    llm_dry_run: bool,
    budget_calls: int,
    budget_tokens: int,
) -> tuple[LlmConfig | None, Budget]:
    """The endpoint configuration (only for `record` and `live`) and the budget, or exit 2."""
    config = None
    if mode is not CassetteMode.REPLAY and not llm_dry_run:
        if not allow_llm:
            fail(
                ExitCode.USAGE,
                f"mode '{mode.value}' sends code to the configured endpoint; pass --allow-llm "
                "to allow it, or --llm-dry-run to see what would be sent",
            )
        try:
            config = load_config(os.environ)
        except LlmConfigError as exc:
            fail(ExitCode.USAGE, str(exc))
    try:
        return config, Budget(max_calls=budget_calls, max_tokens=budget_tokens)
    except LlmError as exc:
        fail(ExitCode.USAGE, str(exc))


def client_factory(
    mode: CassetteMode,
    allow_llm: bool,
    config: LlmConfig | None,
    budget: Budget,
    cassette_dir: Path,
) -> Callable[[Recorder], LlmClient]:
    def make_client(recorder: Recorder) -> LlmClient:
        return LlmClient(
            mode=mode,
            allow_llm=allow_llm,
            config=config,
            budget=budget,
            cassette_dir=cassette_dir,
            recorder=recorder,
        )

    return make_client


def make_settings(profile: ProfileChoice, seed: str, symbolic: bool) -> VerifySettings:
    if _SEED.fullmatch(seed) is None:
        fail(ExitCode.USAGE, f"error: --seed must be 0x and 1 to 16 lowercase hex digits: {seed}")
    return VerifySettings(profile=profile.value, fuzz_seed=seed, symbolic=symbolic)


def make_patch_config(max_changed_lines: int, max_files: int, max_diff_bytes: int) -> PatchConfig:
    try:
        return PatchConfig(
            max_changed_lines=max_changed_lines, max_files=max_files, max_diff_bytes=max_diff_bytes
        )
    except LlmError as exc:
        fail(ExitCode.USAGE, f"error: {exc}")


def bundle_request(
    runner: SandboxRunner,
    halmos: SandboxRunner | None,
    dest: Path,
    work: Path,
    project: Path,
    poc: Path,
    ledger_path: Path,
) -> BundleRequest:
    def record_environment() -> Environment:
        return environment(runner.image_id(), runner.image_labels(), read_versions_lock())

    def record_symbolic() -> Environment:
        assert halmos is not None
        return environment(halmos.image_id(), halmos.image_labels(), read_versions_lock())

    paths = [
        (work, "<work>"),
        (project.resolve(), "<base>"),
        (poc.resolve(), "<poc>"),
        (dest.resolve(), "<bundle>"),
        (ledger_path.resolve().parent, "<ledger-dir>"),
        (Path.cwd(), "<cwd>"),
        (Path(tempfile.gettempdir()), "<tmp>"),
        (Path.home(), "<home>"),
    ]
    return BundleRequest(
        dest=dest,
        environment=record_environment,
        sanitizer=Sanitizer(paths),
        symbolic_environment=None if halmos is None else record_symbolic,
    )


def default_poc_dir(ledger_path: Path, finding_id: int) -> Path:
    """`.assay/poc/finding-<id>`, or the directory `assay prove --class` used for the class."""
    direct = DEFAULT_POC_ROOT / f"finding-{finding_id}"
    if direct.is_dir() or not ledger_path.exists():
        return direct
    try:
        with Ledger.open(ledger_path, read_only=True) as ledger:
            by_class = (
                DEFAULT_POC_ROOT / f"finding-{ledger.get_finding(FindingId(finding_id)).vuln_class}"
            )
    except LedgerError:
        return direct
    return by_class if by_class.is_dir() else direct


def render_fix(outcome: FixOutcome) -> str:
    """The attempts, the final verdict and its bounds, as plain text."""
    history = outcome.history
    lines = [f"finding: {outcome.finding_id} ({outcome.vuln_class}), reproduced by `assay prove`"]
    for item in history.attempts:
        if item.outcome == "model_output_invalid":
            codes = ", ".join(problem.code for problem in item.problems)
            lines.append(f"attempt {item.number}: the model reply was not a usable patch ({codes})")
            continue
        assert item.in_loop_verdict is not None
        assert item.diff_sha256 is not None
        failed = [
            f"{row.oracle} {row.verdict}"
            + (f" ({', '.join(r.code for r in row.reasons)})" if row.reasons else "")
            for row in item.oracles
            if row.verdict in ("FAIL", "INCONCLUSIVE")
        ]
        extra = f": {'; '.join(failed)}" if failed else ""
        lines.append(
            f"attempt {item.number}: patch {item.diff_sha256[:12]}: "
            f"{item.in_loop_verdict.value} in the loop{extra}"
        )
    final = history.final
    lines += [
        f"attempts: {final.attempts_used} of {history.limits.max_attempts}",
        f"decision: {final.statement}",
        "",
        f"final verdict: {outcome.verdict.value}",
        f"reason: {'; '.join(outcome.reasons)}",
        f"finding state: {outcome.state.value} (evidence level {outcome.evidence_level})",
    ]
    if outcome.report is not None:
        lines += ["", "deciding verification:", render(outcome.report)]
    lines += [f"note: {note}" for note in outcome.notes]
    lines.append(f"limits: {LIMITS_NOTE}")
    return printable("\n".join(lines))


def fix_document(outcome: FixOutcome, *, command: str = "fix") -> dict[str, object]:
    """The `--json` document of `assay fix` (or `assay run`), checked against `FixDocument`."""
    document = {
        "format": RUN_FORMAT if command == "run" else FIX_FORMAT,
        "finding": int(outcome.finding_id),
        "vuln_class": outcome.vuln_class,
        "final_verdict": outcome.verdict.value,
        "reasons": list(outcome.reasons),
        "finding_state": outcome.state.value,
        "evidence_level": outcome.evidence_level.value,
        "history": outcome.history.model_dump(mode="json"),
        "report": None if outcome.report is None else outcome.report.model_dump(mode="json"),
        "bundle_manifest_sha256": outcome.manifest_sha256,
        "notes": list(outcome.notes),
    }
    checked: dict[str, object] = FixDocument.model_validate(document).model_dump(mode="json")
    return checked


def fix_command(
    project: Annotated[
        Path, typer.Argument(help="Foundry project directory.", exists=True, file_okay=False)
    ],
    finding: Annotated[
        int, typer.Option("--finding", help="Ledger id of a REPRODUCED finding (`assay prove`).")
    ],
    mode: Annotated[
        CassetteMode, typer.Option("--mode", help="replay (default), record or live.")
    ] = CassetteMode.REPLAY,
    allow_llm: Annotated[
        bool, typer.Option("--allow-llm", help="Allow sending redacted code to the endpoint.")
    ] = False,
    llm_dry_run: Annotated[
        bool,
        typer.Option(
            "--llm-dry-run", help="Print size and hash of the first payload; send nothing."
        ),
    ] = False,
    max_attempts: Annotated[
        int, typer.Option("--max-attempts", help=f"Patch attempts, 1 to {MAX_ATTEMPTS_CAP}.")
    ] = DEFAULT_ATTEMPTS,
    profile: Annotated[
        ProfileChoice,
        typer.Option(
            "--profile", help="Campaign profile of the variant search (see docs/oracles.md)."
        ),
    ] = ProfileChoice.STANDARD,
    symbolic: Annotated[
        bool, typer.Option("--symbolic", help="Also run the symbolic oracle (Halmos) per attempt.")
    ] = False,
    bundle_out: Annotated[
        Path | None,
        typer.Option(
            "--bundle-out",
            help="Write the evidence bundle of the final verification, with the attempt "
            "history, into this directory, which must be empty or absent.",
        ),
    ] = None,
    poc_dir: Annotated[
        Path | None,
        typer.Option(
            "--poc-dir",
            help="Directory of the PoC that reproduced the finding (default: where `assay prove` "
            "wrote it).",
            file_okay=False,
        ),
    ] = None,
    seed: Annotated[
        str,
        typer.Option(
            "--seed",
            help="Base seed of the loop (0x and 1 to 16 hex digits). The seed of the final "
            "decision is derived from it in a different family and is never shown to the model.",
        ),
    ] = DEFAULT_BASE_SEED,
    max_changed_lines: Annotated[
        int,
        typer.Option("--max-changed-lines", help="Most added plus removed lines of a patch."),
    ] = DEFAULT_MAX_CHANGED_LINES,
    max_files: Annotated[
        int, typer.Option("--max-files", help="Most files a patch may change.")
    ] = DEFAULT_MAX_FILES,
    max_diff_bytes: Annotated[
        int, typer.Option("--max-diff-bytes", help="Largest patch, in bytes.")
    ] = DEFAULT_MAX_DIFF_BYTES,
    cassette_dir: Annotated[
        Path, typer.Option("--cassette-dir", help="Directory of the cassettes.", file_okay=False)
    ] = DEFAULT_CASSETTE_DIR,
    budget_calls: Annotated[
        int, typer.Option("--budget-calls", help="Most requests.")
    ] = DEFAULT_FIX_CALLS,
    budget_tokens: Annotated[
        int, typer.Option("--budget-tokens", help="Most tokens (in plus out).")
    ] = DEFAULT_FIX_TOKENS,
    json_output: Annotated[
        bool, typer.Option("--json", help="Print the result as JSON instead of text.")
    ] = False,
    ledger_path: Annotated[
        Path, typer.Option("--ledger", help="Ledger database.", dir_okay=False)
    ] = DEFAULT_LEDGER,
) -> None:
    """Ask a model for a patch for a REPRODUCED finding and verify it, within bounds.

    Each attempt runs the IntegrityOracle first (a patch that touches a protected path, leaves the
    scope, is too large or special-cases the PoC never runs), then the whole verification:
    integrity, exploit, variant, behavior and regression, plus symbolic with --symbolic. A patch
    that fails gives the model structured, redacted feedback, quoted as data. At most
    --max-attempts attempts (3 by default, 5 at most). A patch that passes is verified once more
    with a held-out seed that no attempt and no prompt has seen; that final run decides, and the
    output says when it differs from the loop. The model only proposes; the oracles decide.
    Modes `record` and `live` send redacted code to the configured endpoint and need --allow-llm
    (see docs/llm.md and docs/fix-loop.md).

    \b
    Example:
      assay fix fixtures/reentrancy/single_function --finding 1 --max-attempts 3 \\
        --bundle-out out/fix

    Exit codes: 0 VERIFIED_WITHIN_BOUNDS; 1 REJECTED; 2 usage error; 3 INCONCLUSIVE (also: no
    patch could be judged, or a budget limit); 4 infrastructure problem (Docker, runner image,
    ledger, no cassette, endpoint failure); 5 an integrity violation (the deciding patch touched
    a protected or out-of-scope path, or used traversal, a symlink or a binary file; or the
    inputs or a cassette were rejected).
    """
    config, budget = llm_setup(mode, allow_llm, llm_dry_run, budget_calls, budget_tokens)
    settings = make_settings(profile, seed, symbolic)
    patch_config = make_patch_config(max_changed_lines, max_files, max_diff_bytes)
    target_poc = poc_dir if poc_dir is not None else default_poc_dir(ledger_path, finding)
    if not target_poc.is_dir():
        fail(
            ExitCode.USAGE,
            f"error: the PoC directory {target_poc} does not exist; run `assay prove` or pass "
            "--poc-dir",
        )
    if bundle_out is not None:
        try:
            check_bundle_dir(bundle_out, inputs=(project, target_poc))
        except BundleError as exc:
            fail(ExitCode.USAGE, f"error: {exc}")
    request = FixRequest(
        project, target_poc, finding, max_attempts, settings=settings, patch=patch_config
    )
    runner = SandboxRunner()
    halmos = symbolic_runner() if symbolic else None
    try:
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with (
            Ledger.open(ledger_path) as ledger,
            tempfile.TemporaryDirectory(prefix="assay-fix-", ignore_cleanup_errors=True) as tmp,
        ):
            bundle = (
                None
                if bundle_out is None
                else bundle_request(
                    runner, halmos, bundle_out, Path(tmp), project, target_poc, ledger_path
                )
            )
            result = run_fix(
                request,
                ledger=ledger,
                make_client=client_factory(mode, allow_llm, config, budget, cassette_dir),
                runner=runner,
                work_dir=Path(tmp),
                symbolic_runner=halmos,
                bundle=bundle,
                dry_run=llm_dry_run,
            )
    except ProveInputError as exc:
        fail(ExitCode.INTEGRITY if exc.kind == "rejected" else ExitCode.USAGE, str(exc))
    except ConsentRequired as exc:
        fail(ExitCode.USAGE, str(exc))
    except BundleError as exc:
        fail(ExitCode.USAGE, f"error: {exc}")
    except (BudgetExceeded, StructuredOutputError) as exc:
        fail(ExitCode.INCONCLUSIVE, f"INCONCLUSIVE: {exc}")
    except CassetteError as exc:
        fail(ExitCode.INTEGRITY, str(exc))
    except ForgeOutOfMemory as exc:
        fail(ExitCode.INFRASTRUCTURE, f"error: {exc}")
    except (
        CassetteMissing,
        LlmError,
        LedgerError,
        SandboxUnavailable,
        SandboxError,
        HarnessUnavailable,
        EnvironmentUnavailable,
        OSError,
    ) as exc:
        fail(ExitCode.INFRASTRUCTURE, str(exc))
    if isinstance(result, FixOutcome):
        if json_output:
            typer.echo(json.dumps(fix_document(result), indent=2, sort_keys=True))
        else:
            typer.echo(render_fix(result))
            if result.manifest_sha256 is not None:
                typer.echo(f"bundle: written, manifest sha256 {result.manifest_sha256}")
        raise typer.Exit(int(fix_exit_code(result)))
    plan = LlmClient(mode=mode).dry_run(result)
    redactions = ", ".join(f"{k} {n}" for k, n in plan.redactions.items()) or "none"
    typer.echo(
        f"dry run: nothing was sent\nmode: {mode.value}\nmessages: {plan.messages}\n"
        f"payload: {plan.payload_bytes} bytes\npayload sha256: {plan.payload_sha256}\n"
        f"redactions: {redactions}"
    )
