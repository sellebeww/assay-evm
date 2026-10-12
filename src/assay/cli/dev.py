"""Hidden developer commands. Their output format may change between versions."""

import json
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from assay.analysis import (
    ANALYZERS,
    Analyzer,
    AnalyzerFailed,
    AnalyzerName,
    AnalyzerOutOfMemory,
    AnalyzerOutputError,
    AnalyzerTimeout,
    RawAnalysis,
)
from assay.analyzers import foundry
from assay.cli.exit_codes import ExitCode
from assay.cli.text import printable as _printable
from assay.ingest import IngestError, create_snapshot
from assay.ledger import (
    CassetteMode,
    Ledger,
    LedgerError,
    ObservationInput,
    ScanLocation,
    ScanTool,
)
from assay.ledger.demo import DEMO_NOTE, populate_demo
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
    ask_structured,
    load_config,
)
from assay.llm.ask import AskAnswer, ask_messages
from assay.llm.budget import DEFAULT_MAX_CALLS, DEFAULT_MAX_TOKENS
from assay.llm.cassette import DEFAULT_CASSETTE_DIR
from assay.llm.recording import ledger_recorder
from assay.sandbox import (
    SandboxError,
    SandboxResult,
    SandboxRunner,
    SandboxUnavailable,
    make_scratch_dir,
)

app = typer.Typer(
    help="Developer commands (unstable output).",
    no_args_is_help=True,
    add_completion=False,
)

_EXCERPT_LINES = 20
_EXCERPT_LINE_CHARS = 500
_DEFAULT_LEDGER = Path(".assay") / "ledger.db"
_ANALYZE_PROJECT = "analyze"


def _stderr_excerpt(result: SandboxResult) -> str:
    lines = result.stderr.strip().splitlines()[-_EXCERPT_LINES:]
    return "\n".join(line[:_EXCERPT_LINE_CHARS] for line in lines)


def _fail(code: ExitCode, message: str, detail: str = "") -> NoReturn:
    typer.echo(_printable(message), err=True)
    if detail:
        typer.echo(_printable(detail), err=True)
    raise typer.Exit(int(code))


@app.command("forge-test")
def forge_test(
    project: Annotated[
        Path,
        typer.Argument(help="Foundry project directory.", exists=True, file_okay=False),
    ],
) -> None:
    """Snapshot PROJECT, run `forge test` in the sandbox and print normalized JSON.

    The JSON holds the snapshot's tree_sha256 and the normalized test results, without
    durations or host paths. Exit codes: 0 every test passed; 1 a test failed or forge failed
    before producing results; 2 usage error; 3 inconclusive (timeout, unusable output, no test
    passed); 4 infrastructure problem (Docker, runner image, out of memory); 5 the project was
    rejected at ingest.
    """
    with tempfile.TemporaryDirectory(prefix="assay-", ignore_cleanup_errors=True) as tmp:
        work = Path(tmp)
        try:
            snapshot = create_snapshot(project, work / "snapshot")
        except IngestError as exc:
            _fail(ExitCode.INTEGRITY, f"project rejected: {exc}")
        try:
            run = foundry.test(
                SandboxRunner(), snapshot.tree_dir, scratch_dir=make_scratch_dir(work)
            )
        except foundry.ForgeTimeout as exc:
            _fail(ExitCode.INCONCLUSIVE, f"INCONCLUSIVE: {exc}")
        except foundry.ForgeOutOfMemory as exc:
            _fail(ExitCode.INFRASTRUCTURE, str(exc))
        except foundry.ForgeOutputError as exc:
            code = ExitCode.NEGATIVE if exc.problem == "failed" else ExitCode.INCONCLUSIVE
            _fail(code, str(exc), _stderr_excerpt(exc.result))
        except (SandboxUnavailable, SandboxError) as exc:
            _fail(ExitCode.INFRASTRUCTURE, str(exc))

    payload = {"tree_sha256": snapshot.tree_sha256, **run.model_dump(mode="json")}
    typer.echo(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True))
    if run.exit_code != 0 or run.summary.failed:
        raise typer.Exit(int(ExitCode.NEGATIVE))
    if run.summary.passed == 0:
        _fail(ExitCode.INCONCLUSIVE, "INCONCLUSIVE: no test passed")


@app.command("ledger-demo")
def ledger_demo(
    database: Annotated[
        Path,
        typer.Argument(
            help="Path of the new ledger database; it must not exist yet.", dir_okay=False
        ),
    ],
) -> None:
    """Create a small, synthetic ledger at DATABASE.

    It holds one finding (REPRODUCED), claim 1 left `asserted` on purpose, and claim 2 promoted
    to `trusted` through an oracle run. Blobs go to `blobs/` next to DATABASE. No project is
    built and no oracle is executed. Claim 1 shows that the database itself rejects
    `UPDATE claim SET status = 'trusted' WHERE id = 1`. Exit codes: 0 created; 2 DATABASE
    already exists or its directory is missing.
    """
    if database.exists() or database.is_symlink():
        _fail(ExitCode.USAGE, f"refusing to overwrite an existing path: {database}")
    if not database.parent.is_dir():
        _fail(ExitCode.USAGE, f"directory does not exist: {database.parent}")
    with Ledger.open(database) as ledger:
        summary = populate_demo(ledger)
        blob_dir = ledger.blobs.root
    typer.echo(_printable(f"created {database} (blobs in {blob_dir})"))
    typer.echo(DEMO_NOTE)
    typer.echo(
        f"finding {summary.finding_id} {summary.stable_id}: {summary.state} "
        f"({summary.evidence_level})"
    )
    typer.echo(f"claim {summary.asserted_claim_id}: asserted (left unpromoted on purpose)")
    typer.echo(
        f"claim {summary.trusted_claim_id}: {summary.trusted_claim_status} "
        f"(oracle_run {summary.oracle_run_id}, exploit PASS)"
    )
    typer.echo(f"audit_log: {summary.audit_rows} rows, chain OK")


@app.command("ledger-verify")
def ledger_verify(
    database: Annotated[
        Path,
        typer.Argument(help="Ledger database to check.", exists=True, dir_okay=False),
    ],
) -> None:
    """Check the hash chain of the audit_log in DATABASE, without changing the file.

    Prints OK and the number of rows, or the sequence number of the first row that breaks the
    chain and the problem found there. The chain is tamper-evident, not a signature: rows
    removed from its end are not detected. Exit codes: 0 chain intact; 2 usage error; 5 chain
    broken, or DATABASE is not a readable ledger.
    """
    try:
        with Ledger.open(database, read_only=True) as ledger:
            report = ledger.verify_chain()
    except (LedgerError, sqlite3.DatabaseError) as exc:
        _fail(ExitCode.INTEGRITY, f"not a readable ledger: {exc}")
    if report.violation is not None:
        typer.echo(
            _printable(
                f"VIOLATION at audit_log seq {report.violation.seq}: {report.violation.problem}"
            )
        )
        raise typer.Exit(int(ExitCode.INTEGRITY))
    typer.echo(f"OK: audit_log chain intact ({report.rows} rows)")


def _store_raw(ledger: Ledger, raw: RawAnalysis) -> str | None:
    if not raw.output:
        return None
    return ledger.store_blob(
        raw.output, media_type="application/json", label=f"{raw.tool.value} raw output"
    )


def _raw_lines(raw: RawAnalysis, blob: str | None) -> list[str]:
    stored = f"sha256 {blob} ({len(raw.output)} bytes)" if blob else "none"
    return [
        f"tool: {raw.tool.value} {raw.tool_version}",
        f"exit code: {raw.exit_code}",
        f"duration: {raw.duration_s:.1f} s",
        f"raw output: {stored}",
    ]


@app.command("analyze")
def analyze(
    tool: Annotated[AnalyzerName, typer.Argument(help="Analyzer to run: slither or aderyn.")],
    project: Annotated[
        Path,
        typer.Argument(help="Foundry project directory.", exists=True, file_okay=False),
    ],
    ledger_path: Annotated[
        Path,
        typer.Option("--ledger", help="Ledger database; created if missing.", dir_okay=False),
    ] = _DEFAULT_LEDGER,
) -> None:
    """Run TOOL on a snapshot of PROJECT in the sandbox and record its raw output.

    The raw JSON output is stored as a blob in the ledger, parsed with strict limits and
    recorded as a scan with one observation per result. Results are candidate (unverified)
    hints: recording them creates no finding and no claim. Prints the tool and its version,
    the number of results, the duration, the tree hash and the hash of the raw output.
    Exit codes: 0 recorded; 1 the tool failed; 2 usage error; 3 time limit or unusable
    output; 4 infrastructure problem (Docker, runner image, ledger, out of memory); 5 the
    project was rejected at ingest.
    """
    analyzer = ANALYZERS[tool]()
    with tempfile.TemporaryDirectory(prefix="assay-", ignore_cleanup_errors=True) as tmp:
        work = Path(tmp)
        try:
            snapshot = create_snapshot(project, work / "snapshot")
        except IngestError as exc:
            _fail(ExitCode.INTEGRITY, f"project rejected: {exc}")
        try:
            ledger_path.parent.mkdir(parents=True, exist_ok=True)
            with Ledger.open(ledger_path) as ledger:
                _analyze(ledger, analyzer, snapshot.tree_dir, snapshot.tree_sha256, work)
        except (SandboxUnavailable, SandboxError, LedgerError, OSError) as exc:
            _fail(ExitCode.INFRASTRUCTURE, str(exc))


def _analyze(
    ledger: Ledger, analyzer: Analyzer, tree_dir: Path, tree_sha256: str, work: Path
) -> None:
    try:
        raw = analyzer.run(SandboxRunner(), tree_dir, make_scratch_dir(work))
    except AnalyzerOutOfMemory as exc:
        _fail(ExitCode.INFRASTRUCTURE, str(exc))
    except (AnalyzerTimeout, AnalyzerFailed) as exc:
        lines = [] if exc.raw is None else _raw_lines(exc.raw, _store_raw(ledger, exc.raw))
        detail = "" if exc.raw is None else exc.raw.stderr.strip()[-2000:]
        code = ExitCode.INCONCLUSIVE if isinstance(exc, AnalyzerTimeout) else ExitCode.NEGATIVE
        _fail(code, "\n".join([str(exc), *lines]), detail)
    blob = _store_raw(ledger, raw)
    try:
        observations = analyzer.parse(raw.output)
    except AnalyzerOutputError as exc:
        _fail(
            ExitCode.INCONCLUSIVE,
            "\n".join([f"unusable output: {exc.code}: {exc.detail}", *_raw_lines(raw, blob)]),
        )
    assert blob is not None
    project_id = ledger.add_project(_ANALYZE_PROJECT, f"tree:{tree_sha256[:16]}")
    scan_id = ledger.record_scan(
        project_id,
        tool=ScanTool(raw.tool.value),
        tool_version=raw.tool_version,
        raw_blob_sha256=blob,
        input_tree_sha256=tree_sha256,
        observations=[
            ObservationInput(
                rule_id=item.rule_id,
                severity_reported=item.severity_reported,
                message=item.message,
                locations=tuple(
                    ScanLocation(path=loc.path, start_line=loc.start_line, end_line=loc.end_line)
                    for loc in item.locations
                ),
            )
            for item in observations
        ],
    )
    lines = [
        *_raw_lines(raw, blob),
        f"tree sha256: {tree_sha256}",
        f"results: {len(observations)} candidate (unverified)",
        f"scan: {scan_id} recorded",
    ]
    typer.echo(_printable("\n".join(lines)))


@app.command("llm-ask")
def llm_ask(
    text: Annotated[str, typer.Argument(help="A short, neutral question. Do not paste code.")],
    mode: Annotated[
        CassetteMode,
        typer.Option("--mode", help="replay (default), record or live."),
    ] = CassetteMode.REPLAY,
    allow_llm: Annotated[
        bool,
        typer.Option("--allow-llm", help="Allow sending the question to the configured endpoint."),
    ] = False,
    llm_dry_run: Annotated[
        bool,
        typer.Option("--llm-dry-run", help="Print the size and hash of the payload; send nothing."),
    ] = False,
    cassette_dir: Annotated[
        Path,
        typer.Option("--cassette-dir", help="Directory of the cassettes.", file_okay=False),
    ] = DEFAULT_CASSETTE_DIR,
    budget_calls: Annotated[
        int, typer.Option("--budget-calls", help="Most requests to the endpoint.")
    ] = DEFAULT_MAX_CALLS,
    budget_tokens: Annotated[
        int, typer.Option("--budget-tokens", help="Most tokens (in plus out) reported.")
    ] = DEFAULT_MAX_TOKENS,
    ledger_path: Annotated[
        Path,
        typer.Option("--ledger", help="Ledger database; created if missing.", dir_okay=False),
    ] = _DEFAULT_LEDGER,
) -> None:
    """Ask the model one question through the whole LLM path (redaction, cassette, budget).

    The reply must be a JSON object `{"answer": "..."}`; anything else is rejected after one
    repair attempt. Modes: `replay` answers from a cassette and needs no configuration (a
    missing cassette is an error, never a network call); `record` and `live` send the redacted
    question to the endpoint named by ASSAY_LLM_BASE_URL, ASSAY_LLM_API_KEY and ASSAY_LLM_MODEL
    and need --allow-llm. `record` also writes the cassette. Each call is recorded in the
    ledger as a model_run. Exit codes: 0 answered (or dry run); 2 usage error (consent,
    configuration, options); 3 a budget limit was reached or the reply was not valid JSON for
    the expected format; 4 no cassette, endpoint failure or ledger problem; 5 a cassette is
    damaged.
    """
    config = None
    if mode is not CassetteMode.REPLAY and not llm_dry_run:
        if not allow_llm:
            _fail(ExitCode.USAGE, str(ConsentRequired(_consent_message(mode))))
        try:
            config = load_config(os.environ)
        except LlmConfigError as exc:
            _fail(ExitCode.USAGE, str(exc))
    try:
        budget = Budget(max_calls=budget_calls, max_tokens=budget_tokens)
    except LlmError as exc:
        _fail(ExitCode.USAGE, str(exc))
    messages = ask_messages(text)
    try:
        if llm_dry_run:
            plan = LlmClient(mode=mode, cassette_dir=cassette_dir).dry_run(messages)
            redactions = ", ".join(f"{kind} {n}" for kind, n in plan.redactions.items()) or "none"
            typer.echo(
                f"dry run: nothing was sent\nmode: {mode.value}\nmessages: {plan.messages}\n"
                f"payload: {plan.payload_bytes} bytes\npayload sha256: {plan.payload_sha256}\n"
                f"redactions: {redactions}"
            )
            return
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with Ledger.open(ledger_path) as ledger:
            client = LlmClient(
                mode=mode,
                allow_llm=allow_llm,
                config=config,
                budget=budget,
                cassette_dir=cassette_dir,
                recorder=ledger_recorder(ledger),
            )
            result = ask_structured(client, messages, AskAnswer)
    except ConsentRequired as exc:
        _fail(ExitCode.USAGE, str(exc))
    except (BudgetExceeded, StructuredOutputError) as exc:
        _fail(ExitCode.INCONCLUSIVE, f"INCONCLUSIVE: {exc}")
    except CassetteError as exc:
        _fail(ExitCode.INTEGRITY, str(exc))
    except (CassetteMissing, LlmError, LedgerError, OSError) as exc:
        _fail(ExitCode.INFRASTRUCTURE, str(exc))
    last = result.completions[-1]
    label = " (synthetic cassette, not a model answer)" if last.synthetic else ""
    typer.echo(
        _printable(
            f"answer: {result.value.answer}\n"
            f"mode: {last.mode.value}{label}\n"
            f"model (as returned): {last.model}\n"
            f"calls: {len(result.completions)}, tokens: {budget.tokens}\n"
            f"cassette key: {last.cassette_key}"
        )
    )


def _consent_message(mode: CassetteMode) -> str:
    return (
        f"mode '{mode.value}' sends data to the configured endpoint; pass --allow-llm to allow "
        "it, or --llm-dry-run to see what would be sent"
    )


@app.command("ledger-audit")
def ledger_audit(
    database: Annotated[
        Path, typer.Argument(help="Ledger database to audit.", exists=True, dir_okay=False)
    ],
) -> None:
    """Check the global invariants of DATABASE, without changing the file.

    Checks that no claim is trusted, refuted or inconclusive without an oracle run of that claim,
    that no finding is REPRODUCED or VERIFIED_WITHIN_BOUNDS (or at a later state) without oracle
    runs, that no status rests on a model run, and that the audit chain is intact. Prints OK, or
    one line per violation. Exit codes: 0 all invariants hold; 2 usage error; 5 a violation was
    found, or DATABASE is not a readable ledger.
    """
    try:
        with Ledger.open(database, read_only=True) as ledger:
            violations = ledger.check_invariants()
    except (LedgerError, sqlite3.DatabaseError) as exc:
        _fail(ExitCode.INTEGRITY, f"not a readable ledger: {exc}")
    if violations:
        for item in violations:
            typer.echo(_printable(f"VIOLATION {item.invariant}: {item.detail}"))
        raise typer.Exit(int(ExitCode.INTEGRITY))
    typer.echo("OK: all ledger invariants hold")
