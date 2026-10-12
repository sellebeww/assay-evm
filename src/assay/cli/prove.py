"""`assay prove`: a hypothesis, a PoC and a bounded repair loop for one candidate finding."""

import json
import os
import tempfile
from pathlib import Path
from typing import Annotated, Final, NoReturn

import typer

from assay.cli.documents import PROVE_FORMAT, ProveDocument
from assay.cli.exit_codes import ExitCode
from assay.cli.text import printable
from assay.ledger import CassetteMode, FindingState, Ledger, LedgerError
from assay.llm import (
    Budget,
    BudgetExceeded,
    CassetteError,
    CassetteMissing,
    ConsentRequired,
    LlmClient,
    LlmConfigError,
    LlmError,
    StructuredOutputError,
    load_config,
)
from assay.llm.cassette import DEFAULT_CASSETTE_DIR
from assay.llm.client import Recorder
from assay.llm.hypothesize import hypothesis_messages
from assay.oracles.runtree import HarnessUnavailable
from assay.orchestrator.prove import (
    DEFAULT_ATTEMPTS,
    MAX_ATTEMPTS_CAP,
    ProveInputError,
    ProveOutcome,
    ProveRequest,
    run_prove,
)
from assay.sandbox import SandboxError, SandboxRunner, SandboxUnavailable

DEFAULT_LEDGER: Final = Path(".assay") / "ledger.db"
DEFAULT_POC_ROOT: Final = Path(".assay") / "poc"
_STATE_EXIT: Final = {
    FindingState.REPRODUCED: ExitCode.SUCCESS,
    FindingState.NOT_REPRODUCED: ExitCode.NEGATIVE,
}


def _fail(code: ExitCode, message: str) -> NoReturn:
    typer.echo(printable(message), err=True)
    raise typer.Exit(int(code))


def _report(outcome: ProveOutcome, poc_dir: Path) -> None:
    h = outcome.hypothesis
    lines = [
        f"finding: {outcome.finding_id} ({outcome.vuln_class}), candidate from `assay scan`",
        f"hypothesis (model proposal, unverified, E0): {h.target_function}, "
        f"expected predicate {h.predicate_kind}",
    ]
    for item in outcome.attempts:
        extra = f" ({', '.join(item.codes)})" if item.codes else ""
        text = {
            "static_check_rejected": "rejected by the static checker, not run",
            "model_output_invalid": "the model reply was not a valid answer",
            "poc_rejected_at_ingest": "rejected at ingest, not run",
        }.get(item.outcome, f"exploit run {item.outcome}")
        lines.append(f"attempt {item.number}: {text}{extra}")
    lines.append(f"final state: {outcome.state.value} (evidence level {outcome.evidence_level})")
    lines.append(f"attempts: {len(outcome.attempts)} of {outcome.max_attempts}")
    if outcome.stopped == "budget":
        lines.append("stopped early: the model budget is used up (raise --budget-calls)")
    if outcome.state is FindingState.REPRODUCED:
        lines.append(f"PoC: {poc_dir}")
    typer.echo(printable("\n".join(lines)))


def prove_document(outcome: ProveOutcome, poc_dir: Path) -> dict[str, object]:
    """The `--json` document of `assay prove`, checked against `ProveDocument`."""
    document = {
        "format": PROVE_FORMAT,
        "finding": int(outcome.finding_id),
        "stable_id": outcome.stable_id,
        "vuln_class": outcome.vuln_class,
        "final_state": outcome.state.value,
        "evidence_level": outcome.evidence_level.value,
        "hypothesis": outcome.hypothesis.model_dump(mode="json"),
        "attempts": [
            {"number": item.number, "outcome": item.outcome, "codes": list(item.codes)}
            for item in outcome.attempts
        ],
        "max_attempts": outcome.max_attempts,
        "stopped": outcome.stopped,
        "poc_dir": str(poc_dir) if outcome.state is FindingState.REPRODUCED else None,
        "notes": list(outcome.notes),
    }
    checked: dict[str, object] = ProveDocument.model_validate(document).model_dump(mode="json")
    return checked


def prove_command(
    project: Annotated[
        Path, typer.Argument(help="Foundry project directory.", exists=True, file_okay=False)
    ],
    finding: Annotated[
        int | None, typer.Option("--finding", help="Ledger id of the candidate finding.")
    ] = None,
    vuln_class: Annotated[
        str | None,
        typer.Option("--class", help="Class of the finding; the first candidate of it is used."),
    ] = None,
    mode: Annotated[
        CassetteMode, typer.Option("--mode", help="replay (default), record or live.")
    ] = CassetteMode.REPLAY,
    allow_llm: Annotated[
        bool, typer.Option("--allow-llm", help="Allow sending redacted code to the endpoint.")
    ] = False,
    json_output: Annotated[
        bool, typer.Option("--json", help="Print the result as JSON instead of text.")
    ] = False,
    llm_dry_run: Annotated[
        bool,
        typer.Option(
            "--llm-dry-run", help="Print size and hash of the first payload; send nothing."
        ),
    ] = False,
    max_attempts: Annotated[
        int,
        typer.Option("--max-attempts", help=f"PoC attempts, 1 to {MAX_ATTEMPTS_CAP}."),
    ] = DEFAULT_ATTEMPTS,
    poc_dir: Annotated[
        Path | None,
        typer.Option(
            "--poc-dir", help="Where the PoC is written; outside the project.", file_okay=False
        ),
    ] = None,
    cassette_dir: Annotated[
        Path, typer.Option("--cassette-dir", help="Directory of the cassettes.", file_okay=False)
    ] = DEFAULT_CASSETTE_DIR,
    budget_calls: Annotated[int, typer.Option("--budget-calls", help="Most requests.")] = 12,
    budget_tokens: Annotated[
        int, typer.Option("--budget-tokens", help="Most tokens (in plus out).")
    ] = 100_000,
    ledger_path: Annotated[
        Path, typer.Option("--ledger", help="Ledger database.", dir_okay=False)
    ] = DEFAULT_LEDGER,
) -> None:
    """Try to reproduce a candidate finding with a model-written PoC, within bounds.

    The model proposes a hypothesis and PoC files; a static checker and the ExploitOracle decide.
    A PoC the checker rejects never runs. The finding ends REPRODUCED (exploit run PASS),
    NOT_REPRODUCED, INCONCLUSIVE, or stays HYPOTHESIZED when no PoC passed the checker. Modes
    `record` and `live` send redacted code to the configured endpoint and need --allow-llm (see
    docs/llm.md).

    \b
    Example:
      assay scan fixtures/reentrancy/single_function
      assay prove fixtures/reentrancy/single_function --class reentrancy

    Exit codes: 0 REPRODUCED; 1 NOT_REPRODUCED; 2 usage error; 3 INCONCLUSIVE,
    HYPOTHESIZED, a budget limit or an unusable model reply; 4 infrastructure problem (Docker,
    runner image, ledger, no cassette, endpoint failure); 5 the project or the target was
    rejected, or a cassette is damaged.
    """
    if (finding is None) == (vuln_class is None):
        _fail(ExitCode.USAGE, "give exactly one of --finding and --class")
    if json_output and llm_dry_run:
        _fail(ExitCode.USAGE, "--json cannot be combined with --llm-dry-run")
    config = None
    if mode is not CassetteMode.REPLAY and not llm_dry_run:
        if not allow_llm:
            _fail(
                ExitCode.USAGE,
                f"mode '{mode.value}' sends code to the configured endpoint; pass --allow-llm "
                "to allow it, or --llm-dry-run to see what would be sent",
            )
        try:
            config = load_config(os.environ)
        except LlmConfigError as exc:
            _fail(ExitCode.USAGE, str(exc))
    try:
        budget = Budget(max_calls=budget_calls, max_tokens=budget_tokens)
    except LlmError as exc:
        _fail(ExitCode.USAGE, str(exc))
    target_poc = (
        poc_dir if poc_dir is not None else DEFAULT_POC_ROOT / f"finding-{finding or vuln_class}"
    )

    def make_client(recorder: Recorder) -> LlmClient:
        return LlmClient(
            mode=mode,
            allow_llm=allow_llm,
            config=config,
            budget=budget,
            cassette_dir=cassette_dir,
            recorder=recorder,
        )

    request = ProveRequest(project, target_poc, finding, vuln_class, max_attempts)
    try:
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with (
            Ledger.open(ledger_path) as ledger,
            tempfile.TemporaryDirectory(prefix="assay-", ignore_cleanup_errors=True) as tmp,
        ):
            result = run_prove(
                request,
                ledger=ledger,
                make_client=make_client,
                runner=SandboxRunner(),
                work_dir=Path(tmp),
                dry_run=llm_dry_run,
            )
    except ProveInputError as exc:
        _fail(ExitCode.INTEGRITY if exc.kind == "rejected" else ExitCode.USAGE, str(exc))
    except ConsentRequired as exc:
        _fail(ExitCode.USAGE, str(exc))
    except (BudgetExceeded, StructuredOutputError) as exc:
        _fail(ExitCode.INCONCLUSIVE, f"INCONCLUSIVE: {exc}")
    except CassetteError as exc:
        _fail(ExitCode.INTEGRITY, str(exc))
    except (
        CassetteMissing,
        LlmError,
        LedgerError,
        SandboxUnavailable,
        SandboxError,
        HarnessUnavailable,
        OSError,
    ) as exc:
        _fail(ExitCode.INFRASTRUCTURE, str(exc))
    if isinstance(result, ProveOutcome):
        if json_output:
            typer.echo(json.dumps(prove_document(result, target_poc), indent=2, sort_keys=True))
        else:
            _report(result, target_poc)
        raise typer.Exit(int(_STATE_EXIT.get(result.state, ExitCode.INCONCLUSIVE)))
    plan = LlmClient(mode=mode).dry_run(hypothesis_messages(result))
    redactions = ", ".join(f"{k} {n}" for k, n in plan.redactions.items()) or "none"
    typer.echo(
        f"dry run: nothing was sent\nmode: {mode.value}\nmessages: {plan.messages}\n"
        f"payload: {plan.payload_bytes} bytes\npayload sha256: {plan.payload_sha256}\n"
        f"redactions: {redactions}"
    )
