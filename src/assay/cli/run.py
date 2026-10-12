"""`assay run`: the whole flow for one class: scan, prove, fix and bundle."""

import json
import tempfile
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from assay.analyzers.foundry import ForgeOutOfMemory
from assay.cli.exit_codes import ExitCode
from assay.cli.fix import (
    DEFAULT_FIX_CALLS,
    DEFAULT_FIX_TOKENS,
    bundle_request,
    client_factory,
    fail,
    fix_document,
    fix_exit_code,
    llm_setup,
    make_patch_config,
    make_settings,
    render_fix,
)
from assay.cli.prove import DEFAULT_POC_ROOT
from assay.cli.text import printable
from assay.cli.verify import DEFAULT_LEDGER, ProfileChoice
from assay.ingest import IngestError
from assay.ledger import CassetteMode, FindingState, Ledger, LedgerError
from assay.llm import (
    BudgetExceeded,
    CassetteError,
    CassetteMissing,
    ConsentRequired,
    LlmError,
    StructuredOutputError,
)
from assay.llm.cassette import DEFAULT_CASSETTE_DIR
from assay.llm.patcher import (
    DEFAULT_MAX_CHANGED_LINES,
    DEFAULT_MAX_DIFF_BYTES,
    DEFAULT_MAX_FILES,
)
from assay.oracles.runtree import HarnessUnavailable
from assay.oracles.symbolic import symbolic_runner
from assay.oracles.variant import DEFAULT_BASE_SEED
from assay.orchestrator.fix import DEFAULT_ATTEMPTS, FixOutcome, FixRequest, run_fix
from assay.orchestrator.prove import (
    MAX_ATTEMPTS_CAP,
    ProveInputError,
    ProveOutcome,
    ProveRequest,
    run_prove,
)
from assay.orchestrator.scan import ScanInfrastructureError, ScanOutcome, run_scan
from assay.report.bundle import BundleError, EnvironmentUnavailable, check_bundle_dir
from assay.sandbox import SandboxError, SandboxRunner, SandboxUnavailable

_PROVE_EXIT = {
    FindingState.REPRODUCED: ExitCode.SUCCESS,
    FindingState.NOT_REPRODUCED: ExitCode.NEGATIVE,
}


def _stage(text: str) -> None:
    typer.echo(printable(text), err=True)


def _scan_line(outcome: ScanOutcome, vuln_class: str) -> str:
    found = [item for item in outcome.report.findings if item.vuln_class == vuln_class]
    state = "complete" if outcome.report.complete else "incomplete"
    return (
        f"scan: {len(outcome.report.findings)} candidate findings (unverified), "
        f"{len(found)} of class {vuln_class}; scan {state}"
    )


def _prove_line(outcome: ProveOutcome) -> str:
    return (
        f"prove: finding {outcome.finding_id} {outcome.state.value} "
        f"(evidence level {outcome.evidence_level}) after {len(outcome.attempts)} of "
        f"{outcome.max_attempts} attempts"
    )


def _abort(message: str, code: ExitCode) -> NoReturn:
    fail(code, message)


def run_command(
    project: Annotated[
        Path, typer.Argument(help="Foundry project directory.", exists=True, file_okay=False)
    ],
    vuln_class: Annotated[
        str, typer.Option("--class", help="Class of the candidate finding to prove and fix.")
    ],
    mode: Annotated[
        CassetteMode, typer.Option("--mode", help="replay (default), record or live.")
    ] = CassetteMode.REPLAY,
    allow_llm: Annotated[
        bool, typer.Option("--allow-llm", help="Allow sending redacted code to the endpoint.")
    ] = False,
    max_attempts: Annotated[
        int,
        typer.Option(
            "--max-attempts",
            help=f"Attempts of the PoC loop and of the patch loop, 1 to {MAX_ATTEMPTS_CAP}.",
        ),
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
            "--poc-dir", help="Where the PoC is written; outside the project.", file_okay=False
        ),
    ] = None,
    seed: Annotated[
        str, typer.Option("--seed", help="Base seed of the fix loop (0x and 1 to 16 hex digits).")
    ] = DEFAULT_BASE_SEED,
    max_changed_lines: Annotated[
        int, typer.Option("--max-changed-lines", help="Most added plus removed lines of a patch.")
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
        int, typer.Option("--budget-calls", help="Most requests of the whole flow.")
    ] = 2 * DEFAULT_FIX_CALLS,
    budget_tokens: Annotated[
        int, typer.Option("--budget-tokens", help="Most tokens (in plus out) of the whole flow.")
    ] = 2 * DEFAULT_FIX_TOKENS,
    json_output: Annotated[
        bool, typer.Option("--json", help="Print the final result as JSON instead of text.")
    ] = False,
    ledger_path: Annotated[
        Path, typer.Option("--ledger", help="Ledger database.", dir_okay=False)
    ] = DEFAULT_LEDGER,
) -> None:
    """Run the whole flow for one class: scan, prove, fix and bundle.

    A thin wrapper over the other commands: `assay scan` records the candidate findings, `assay
    prove` reproduces the first candidate of --class with a model-written PoC, and `assay fix`
    asks for a patch and verifies it (see `assay fix --help`). The stages are listed on standard
    error; the final result is printed as `assay fix` prints it. Modes `record` and `live` send
    redacted code to the configured endpoint and need --allow-llm. --max-attempts applies to both
    loops; the budget covers the whole flow.

    \b
    Example:
      assay run fixtures/reentrancy/single_function --class reentrancy --bundle-out out/run

    Exit codes as for `assay fix`; a finding that is not reproduced ends the flow: 1
    NOT_REPRODUCED, 3 INCONCLUSIVE or still HYPOTHESIZED, 2 when the project has no candidate of
    the class.
    """
    config, budget = llm_setup(mode, allow_llm, False, budget_calls, budget_tokens)
    settings = make_settings(profile, seed, symbolic)
    patch_config = make_patch_config(max_changed_lines, max_files, max_diff_bytes)
    target_poc = poc_dir if poc_dir is not None else DEFAULT_POC_ROOT / f"finding-{vuln_class}"
    if bundle_out is not None:
        try:
            check_bundle_dir(bundle_out, inputs=(project, target_poc))
        except BundleError as exc:
            fail(ExitCode.USAGE, f"error: {exc}")
    make_client = client_factory(mode, allow_llm, config, budget, cassette_dir)
    runner = SandboxRunner()
    halmos = symbolic_runner() if symbolic else None
    try:
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with (
            Ledger.open(ledger_path) as ledger,
            tempfile.TemporaryDirectory(prefix="assay-run-", ignore_cleanup_errors=True) as tmp,
        ):
            work = Path(tmp)
            for name in ("scan", "prove", "fix"):
                (work / name).mkdir(mode=0o700)
            scanned = run_scan(project, runner=runner, ledger=ledger, work_dir=work / "scan")
            _stage(_scan_line(scanned, vuln_class))
            proved = run_prove(
                ProveRequest(project, target_poc, None, vuln_class, max_attempts),
                ledger=ledger,
                make_client=make_client,
                runner=runner,
                work_dir=work / "prove",
            )
            assert isinstance(proved, ProveOutcome)
            _stage(_prove_line(proved))
            if proved.state is not FindingState.REPRODUCED:
                raise typer.Exit(int(_PROVE_EXIT.get(proved.state, ExitCode.INCONCLUSIVE)))
            bundle = (
                None
                if bundle_out is None
                else bundle_request(
                    runner, halmos, bundle_out, work, project, target_poc, ledger_path
                )
            )
            result = run_fix(
                FixRequest(
                    project,
                    target_poc,
                    int(proved.finding_id),
                    max_attempts,
                    settings=settings,
                    patch=patch_config,
                ),
                ledger=ledger,
                make_client=make_client,
                runner=runner,
                work_dir=work / "fix",
                symbolic_runner=halmos,
                bundle=bundle,
                hypothesis=proved.hypothesis,
            )
    except ProveInputError as exc:
        _abort(str(exc), ExitCode.INTEGRITY if exc.kind == "rejected" else ExitCode.USAGE)
    except ConsentRequired as exc:
        _abort(str(exc), ExitCode.USAGE)
    except BundleError as exc:
        _abort(f"error: {exc}", ExitCode.USAGE)
    except (BudgetExceeded, StructuredOutputError) as exc:
        _abort(f"INCONCLUSIVE: {exc}", ExitCode.INCONCLUSIVE)
    except (CassetteError, IngestError) as exc:
        _abort(str(exc), ExitCode.INTEGRITY)
    except ForgeOutOfMemory as exc:
        _abort(f"error: {exc}", ExitCode.INFRASTRUCTURE)
    except (
        CassetteMissing,
        LlmError,
        LedgerError,
        ScanInfrastructureError,
        SandboxUnavailable,
        SandboxError,
        HarnessUnavailable,
        EnvironmentUnavailable,
        OSError,
    ) as exc:
        _abort(str(exc), ExitCode.INFRASTRUCTURE)
    assert isinstance(result, FixOutcome)
    if json_output:
        typer.echo(json.dumps(fix_document(result, command="run"), indent=2, sort_keys=True))
    else:
        typer.echo(render_fix(result))
        if result.manifest_sha256 is not None:
            typer.echo(f"bundle: written, manifest sha256 {result.manifest_sha256}")
    raise typer.Exit(int(fix_exit_code(result)))
