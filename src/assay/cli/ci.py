"""`assay ci verify`: verify the Solidity diff of a pull request against the PoCs of a project.

The command uses no model and reads no secret. The base revision comes from git objects, the
patch is the diff from base to head limited to the scope, and the PoCs are read from the PoC
directory of the checked-out head. Every PoC is verified like `assay verify` does, with a bundle
per PoC under `<out>/bundles/`, and a Markdown summary is written to `<out>/summary.md`.
"""

import json
import tempfile
from pathlib import Path
from typing import Annotated, Final, NoReturn

import typer

from assay.analyzers.foundry import ForgeOutOfMemory
from assay.ci.gitdiff import DiffError, ScopedDiff, changed_under, export_tree, scoped_diff
from assay.ci.pocs import Poc, PocDirError, discover
from assay.ci.policy import DEFAULT_FAIL_ON, FailOn
from assay.ci.policy import exit_code as policy_exit_code
from assay.ci.summary import (
    NO_CHANGES,
    CiRun,
    PocResult,
    overall_verdict,
    render_summary,
    result_verdict,
    slug,
)
from assay.cli.exit_codes import ExitCode
from assay.cli.text import printable
from assay.cli.verify import ProfileChoice, bundle_sanitizer, exit_code
from assay.ledger import Ledger, LedgerError
from assay.oracles.runtree import HarnessUnavailable
from assay.oracles.symbolic import symbolic_runner
from assay.orchestrator.verify import (
    BundleRequest,
    VerifyInputError,
    VerifyRequest,
    VerifySettings,
    run_verification,
)
from assay.report.bundle import (
    BundleError,
    Environment,
    EnvironmentUnavailable,
    Sanitizer,
    check_bundle_dir,
    environment,
    read_versions_lock,
)
from assay.sandbox import SandboxError, SandboxRunner

RESULT_FORMAT: Final = "assay-ci-verify/1"
SUMMARY_FILE: Final = "summary.md"
RESULT_FILE: Final = "result.json"
BUNDLES_DIR: Final = "bundles"
LEDGER_FILE: Final = "ledger.db"


def _fail(code: ExitCode, message: str) -> NoReturn:
    typer.echo(printable(message), err=True)
    raise typer.Exit(int(code))


def _line(text: str) -> None:
    """One line of output that starts with a fixed word, so that text from a pull request can
    never begin a GitHub workflow command (a line that starts with two colons)."""
    typer.echo(printable(text).replace("\n", " "))


def _write(out: Path, run: CiRun, verdict: str, code: ExitCode, summary_file: Path | None) -> None:
    summary = render_summary(run)
    out.mkdir(parents=True, exist_ok=True)
    (out / SUMMARY_FILE).write_text(summary, encoding="utf-8")
    document = {
        "format": RESULT_FORMAT,
        "verdict": verdict,
        "exit_code": int(code),
        "fail_on": run.fail_on,
        "scope": run.scope,
        "base": run.base_sha,
        "head": run.head_sha,
        "pocs": [
            {
                "name": item.name,
                "verdict": result_verdict(item),
                "exit_code": int(item.code),
                "bundle": f"{BUNDLES_DIR}/{item.slug}" if item.report is not None else None,
            }
            for item in run.results
        ],
    }
    (out / RESULT_FILE).write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if summary_file is not None:
        summary_file.parent.mkdir(parents=True, exist_ok=True)
        with summary_file.open("a", encoding="utf-8") as handle:
            handle.write(summary + "\n")


def _empty_run(
    scope: str,
    profile: str,
    symbolic: bool,
    fail_on: FailOn,
    diff: ScopedDiff | None,
    results: tuple[PocResult, ...] = (),
) -> CiRun:
    return CiRun(
        scope=scope,
        base_sha=diff.base_sha if diff else "unknown",
        head_sha=diff.head_sha if diff else "unknown",
        profile=profile,
        symbolic=symbolic,
        fail_on=fail_on.value,
        changes=diff.changes if diff else (),
        results=results,
    )


def _verify_one(
    poc: Poc,
    *,
    base_dir: Path,
    patch: Path,
    work_dir: Path,
    ledger: Ledger,
    ledger_path: Path,
    runner: SandboxRunner,
    halmos: SandboxRunner | None,
    settings: VerifySettings,
    bundle_dir: Path,
    taken: list[str],
) -> PocResult:
    name = slug(poc.name, taken)
    taken.append(name)
    request = VerifyRequest(base=base_dir, patch=patch, poc=poc.path)
    sanitizer: Sanitizer = bundle_sanitizer(work_dir, request, bundle_dir / name, ledger_path)

    def record() -> Environment:
        return environment(runner.image_id(), runner.image_labels(), read_versions_lock())

    def record_symbolic() -> Environment:
        assert halmos is not None
        return environment(halmos.image_id(), halmos.image_labels(), read_versions_lock())

    try:
        check_bundle_dir(bundle_dir / name, inputs=(poc.path,))
        outcome = run_verification(
            request,
            runner=runner,
            ledger=ledger,
            work_dir=work_dir,
            settings=settings,
            bundle=BundleRequest(
                dest=bundle_dir / name,
                environment=record,
                sanitizer=sanitizer,
                symbolic_environment=None if halmos is None else record_symbolic,
            ),
            symbolic_runner=halmos,
        )
    except VerifyInputError as exc:
        code = ExitCode.INTEGRITY if exc.kind == "rejected" else ExitCode.USAGE
        return PocResult(poc.name, name, code, None, sanitizer.text(str(exc)))
    except BundleError as exc:
        return PocResult(poc.name, name, ExitCode.USAGE, None, sanitizer.text(str(exc)))
    except (
        ForgeOutOfMemory,
        SandboxError,
        HarnessUnavailable,
        EnvironmentUnavailable,
        LedgerError,
        OSError,
    ) as exc:
        return PocResult(poc.name, name, ExitCode.INFRASTRUCTURE, None, sanitizer.text(str(exc)))
    return PocResult(poc.name, name, exit_code(outcome.report), outcome.report)


ci_app = typer.Typer(
    name="ci",
    help="Continuous integration: verify the patch of a pull request without a model or secrets.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)


@ci_app.command("verify")
def ci_verify_command(
    project: Annotated[
        Path,
        typer.Option(
            "--project",
            help="Directory of the Foundry project inside a git work tree.",
            exists=True,
            file_okay=False,
        ),
    ],
    poc_dir: Annotated[
        Path,
        typer.Option(
            "--poc-dir",
            help="Directory with the PoCs: either one PoC (Solidity files directly inside) or one "
            "subdirectory per PoC. Read from the checked-out head.",
            exists=True,
            file_okay=False,
        ),
    ],
    base: Annotated[str, typer.Option("--base", help="Base revision (the vulnerable one).")],
    head: Annotated[str, typer.Option("--head", help="Head revision (with the patch).")],
    scope: Annotated[
        str,
        typer.Option("--scope", help="Directory of the project whose changes are the patch."),
    ] = "src",
    profile: Annotated[
        ProfileChoice, typer.Option("--profile", help="Campaign profile of the variant search.")
    ] = ProfileChoice.STANDARD,
    symbolic: Annotated[
        bool,
        typer.Option("--symbolic", help="Also run the symbolic oracle (see docs/symbolic.md)."),
    ] = False,
    fail_on: Annotated[
        FailOn,
        typer.Option(
            "--fail-on",
            help="Which results give a non-zero exit code: rejected (REJECTED and integrity "
            "violations), inconclusive (also INCONCLUSIVE) or never. Usage and infrastructure "
            "problems always fail.",
        ),
    ] = DEFAULT_FAIL_ON,
    out: Annotated[
        Path,
        typer.Option("--out", help="Output directory (empty or absent): bundles, summary, result."),
    ] = Path("assay-out"),
    summary_file: Annotated[
        Path | None,
        typer.Option(
            "--summary-file",
            help="Also append the Markdown summary to this file (for example "
            "$GITHUB_STEP_SUMMARY).",
            dir_okay=False,
        ),
    ] = None,
) -> None:
    """Verify the Solidity changes of a pull request against the PoCs of the project.

    Computes the diff from BASE to HEAD limited to the scope, as text only: binary files,
    symlinks, submodules, renames across the scope boundary and unsafe paths are refused (exit
    code 5). Then runs `assay verify` for every PoC, writes a bundle per PoC to OUT/bundles/, a
    Markdown summary to OUT/summary.md and OUT/result.json. Without changes in the scope it
    prints "no changes in scope" and exits 0. The command uses no model and reads no secret.

    \b
    Example:
      assay ci verify --project . --poc-dir poc --base origin/main --head HEAD \\
        --scope src --fail-on inconclusive --out assay-out

    Exit codes: 0 nothing failed under --fail-on (or no changes in scope); 1 REJECTED;
    2 usage error; 3 INCONCLUSIVE; 4 infrastructure problem; 5 integrity violation.
    """
    try:
        pocs = discover(poc_dir)
    except PocDirError as exc:
        _fail(ExitCode.INTEGRITY if exc.kind == "rejected" else ExitCode.USAGE, f"error: {exc}")
    try:
        check_bundle_dir(out, inputs=(poc_dir,))
    except BundleError as exc:
        _fail(ExitCode.USAGE, f"error: the output directory: {exc}")
    settings = VerifySettings(profile=profile.value, symbolic=symbolic)

    diff: ScopedDiff | None = None
    try:
        diff = scoped_diff(project, base, head, scope)
    except DiffError as exc:
        if exc.kind == "usage":
            _fail(ExitCode.USAGE, f"error: {exc}")
        code = ExitCode.INTEGRITY if exc.kind == "rejected" else ExitCode.INFRASTRUCTURE
        failed = PocResult("diff", "diff", code, None, str(exc))
        run = _empty_run(scope.rstrip("/"), profile.value, symbolic, fail_on, None, (failed,))
        final = policy_exit_code([code], fail_on)
        _write(out, run, overall_verdict((failed,)), final, summary_file)
        typer.echo(printable(f"error: {exc}"), err=True)
        raise typer.Exit(int(final)) from None

    scope_name = scope.rstrip("/")
    if not diff.changes:
        run = _empty_run(scope_name, profile.value, symbolic, fail_on, diff)
        _write(out, run, NO_CHANGES, ExitCode.SUCCESS, summary_file)
        _line("no changes in scope")
        raise typer.Exit(0)

    _line(
        f"ci verify: scope {scope_name!r}, base {diff.base_sha[:12]}, head {diff.head_sha[:12]}, "
        f"{len(diff.changes)} changed files, {len(pocs)} PoCs"
    )
    results: list[PocResult] = []
    taken: list[str] = []
    runner = SandboxRunner()
    halmos = symbolic_runner() if symbolic else None
    bundle_dir = out / BUNDLES_DIR
    try:
        with tempfile.TemporaryDirectory(prefix="assay-ci-", ignore_cleanup_errors=True) as tmp:
            root = Path(tmp)
            base_dir = root / "base"
            base_dir.mkdir()
            export_tree(project, diff.base_sha, base_dir)
            patch = root / "patch.diff"
            patch.write_bytes(diff.patch)
            ledger_dir = root / "ledger"
            ledger_dir.mkdir()
            with Ledger.open(ledger_dir / LEDGER_FILE) as ledger:
                for number, poc in enumerate(pocs, start=1):
                    work = root / f"work-{number}"
                    work.mkdir()
                    result = _verify_one(
                        poc,
                        base_dir=base_dir,
                        patch=patch,
                        work_dir=work,
                        ledger=ledger,
                        ledger_path=ledger_dir / LEDGER_FILE,
                        runner=runner,
                        halmos=halmos,
                        settings=settings,
                        bundle_dir=bundle_dir,
                        taken=taken,
                    )
                    results.append(result)
                    _line(
                        f"poc {result.name!a}: {result_verdict(result)} (exit {int(result.code)})"
                    )
    except DiffError as exc:
        code = ExitCode.INTEGRITY if exc.kind == "rejected" else ExitCode.INFRASTRUCTURE
        results.append(PocResult("base revision", "base", code, None, str(exc)))
    except (LedgerError, OSError) as exc:
        results.append(PocResult("ledger", "ledger", ExitCode.INFRASTRUCTURE, None, str(exc)))

    poc_changed = changed_under(diff, poc_dir, project)
    run = CiRun(
        scope=scope_name,
        base_sha=diff.base_sha,
        head_sha=diff.head_sha,
        profile=profile.value,
        symbolic=symbolic,
        fail_on=fail_on.value,
        changes=diff.changes,
        results=tuple(results),
        poc_changed=poc_changed,
    )
    final = policy_exit_code([item.code for item in results], fail_on)
    verdict = overall_verdict(results)
    _write(out, run, verdict, final, summary_file)
    _line(f"ci verify: {verdict}, exit code {int(final)} (fail on {fail_on.value})")
    raise typer.Exit(int(final))
