"""`assay ci verify` end to end with the verification stubbed out (no Docker, no model)."""

import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from ci_support import VAULT, commit, git, init_repo, make_report, write
from typer.testing import CliRunner

from assay.cli import ci as ci_module
from assay.cli.main import app
from assay.orchestrator.verify import VerifyInputError, VerifyOutcome, VerifyRequest

runner = CliRunner()
SOURCE_ROOT = Path(__file__).resolve().parents[2] / "src" / "assay"
KNOWN_PREFIXES = ("poc ", "ci verify:", "no changes in scope", "error:")


class FakeRunner:
    def image_id(self) -> str:
        return "sha256:" + "0" * 64


class Calls:
    def __init__(self) -> None:
        self.requests: list[VerifyRequest] = []
        self.seen: list[dict[str, Any]] = []


def install(
    monkeypatch: pytest.MonkeyPatch,
    behavior: Callable[[VerifyRequest], VerifyOutcome | Exception],
) -> Calls:
    calls = Calls()

    def fake(request: VerifyRequest, **kwargs: Any) -> VerifyOutcome:
        calls.requests.append(request)
        calls.seen.append(
            {
                "patch": request.patch.read_text(),
                "base_vault": (request.base / "src" / "Vault.sol").read_text(),
                "poc": sorted(item.name for item in request.poc.iterdir()),
                "settings": kwargs["settings"],
                "symbolic_runner": kwargs.get("symbolic_runner"),
            }
        )
        result = behavior(request)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(ci_module, "run_verification", fake)
    monkeypatch.setattr(ci_module, "SandboxRunner", FakeRunner)
    return calls


def outcome(verdict: str, integrity: bool = False) -> VerifyOutcome:
    return VerifyOutcome(report=make_report("", verdict, integrity), verification_id=1)


@pytest.fixture
def project(tmp_path: Path) -> tuple[Path, str]:
    repo = init_repo(tmp_path / "repo")
    write(repo, "src/Vault.sol", VAULT)
    write(repo, "test/Vault.t.sol", "contract T {}\n")
    write(repo, "poc/Exploit.t.sol", "contract E {}\n")
    return repo, commit(repo, "base")


def patch_vault(repo: Path) -> None:
    write(repo, "src/Vault.sol", VAULT.replace("total;", "total;\n    uint256 public extra;"))
    commit(repo, "patch")


def invoke(repo: Path, base: str, out: Path, *extra: str, poc_dir: Path | None = None) -> Any:
    return runner.invoke(
        app,
        [
            "ci", "verify", "--project", str(repo), "--poc-dir", str(poc_dir or repo / "poc"),
            "--base", base, "--head", "HEAD", "--out", str(out), *extra,
        ],
    )  # fmt: skip


def result_json(out: Path) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((out / "result.json").read_text())
    return document


def test_no_changes_in_scope_exits_zero_without_verifying(
    project: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base = project
    write(repo, "test/Vault.t.sol", "contract T { uint256 x; }\n")
    commit(repo)
    calls = install(monkeypatch, lambda _r: outcome("REJECTED"))
    out = tmp_path / "out"
    result = invoke(repo, base, out, "--fail-on", "inconclusive")
    assert result.exit_code == 0
    assert result.output.strip() == "no changes in scope"
    assert calls.requests == []
    assert result_json(out)["verdict"] == "NO_CHANGES_IN_SCOPE"
    assert "no changes in scope" in (out / "summary.md").read_text()


@pytest.mark.parametrize(
    ("verdict", "fail_on", "code"),
    [
        ("VERIFIED_WITHIN_BOUNDS", "inconclusive", 0),
        ("VERIFIED_WITHIN_BOUNDS", "rejected", 0),
        ("REJECTED", "rejected", 1),
        ("REJECTED", "inconclusive", 1),
        ("REJECTED", "never", 0),
        ("INCONCLUSIVE", "rejected", 0),
        ("INCONCLUSIVE", "inconclusive", 3),
        ("INCONCLUSIVE", "never", 0),
    ],
)
def test_exit_code_follows_the_verdict_and_fail_on(
    project: tuple[Path, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    verdict: str,
    fail_on: str,
    code: int,
) -> None:
    repo, base = project
    patch_vault(repo)
    install(monkeypatch, lambda _r: outcome(verdict))
    out = tmp_path / "out"
    result = invoke(repo, base, out, "--fail-on", fail_on)
    assert result.exit_code == code, result.output
    document = result_json(out)
    assert document["verdict"] == verdict
    assert document["exit_code"] == code
    assert document["pocs"][0]["bundle"] == "bundles/poc"
    assert f"**{verdict}**" in (out / "summary.md").read_text()


def test_the_default_fails_on_an_inconclusive_verdict(
    project: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base = project
    patch_vault(repo)
    install(monkeypatch, lambda _r: outcome("INCONCLUSIVE"))
    assert invoke(repo, base, tmp_path / "out").exit_code == 3


def test_the_verification_gets_the_base_tree_the_scoped_patch_and_the_poc(
    project: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base = project
    patch_vault(repo)
    write(repo, "test/Vault.t.sol", "contract T { uint256 x; }\n")
    commit(repo)
    calls = install(monkeypatch, lambda _r: outcome("VERIFIED_WITHIN_BOUNDS"))
    result = invoke(repo, base, tmp_path / "out", "--profile", "quick", "--symbolic")
    assert result.exit_code == 0, result.output
    [seen] = calls.seen
    assert seen["base_vault"] == VAULT
    assert "+    uint256 public extra;" in seen["patch"]
    assert "test/" not in seen["patch"]
    assert seen["poc"] == ["Exploit.t.sol"]
    assert seen["settings"].profile == "quick"
    assert seen["settings"].symbolic is True


def test_every_poc_is_verified_and_the_worst_result_decides(
    project: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base = project
    (repo / "poc" / "Exploit.t.sol").unlink()
    write(repo, "poc/reentrancy/A.t.sol", "contract A {}\n")
    write(repo, "poc/overflow/B.t.sol", "contract B {}\n")
    write(repo, "poc/notes/README.md", "no Solidity here\n")
    base = commit(repo, "pocs")
    patch_vault(repo)
    verdicts = {"overflow": "VERIFIED_WITHIN_BOUNDS", "reentrancy": "REJECTED"}
    install(monkeypatch, lambda request: outcome(verdicts[request.poc.name]))
    out = tmp_path / "out"
    result = invoke(repo, base, out, "--fail-on", "rejected")
    assert result.exit_code == 1, result.output
    assert [item["name"] for item in result_json(out)["pocs"]] == ["overflow", "reentrancy"]
    assert result_json(out)["verdict"] == "REJECTED"
    assert result.output.count("poc '") == 2


def test_the_summary_is_appended_to_the_summary_file(
    project: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base = project
    patch_vault(repo)
    install(monkeypatch, lambda _r: outcome("VERIFIED_WITHIN_BOUNDS"))
    target = tmp_path / "step_summary.md"
    target.write_text("earlier step\n")
    result = invoke(repo, base, tmp_path / "out", "--summary-file", str(target))
    assert result.exit_code == 0, result.output
    text = target.read_text()
    assert text.startswith("earlier step\n")
    assert "## Assay patch verification" in text
    assert text.count("## Assay patch verification") == 1


def test_binary_file_in_scope_is_an_integrity_violation(
    project: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base = project
    write(repo, "src/blob.bin", b"\x00\x01binary")
    commit(repo)
    calls = install(monkeypatch, lambda _r: outcome("VERIFIED_WITHIN_BOUNDS"))
    out = tmp_path / "out"
    assert invoke(repo, base, out, "--fail-on", "rejected").exit_code == 5
    assert calls.requests == []
    assert "integrity violation" in (out / "summary.md").read_text()
    assert result_json(out)["verdict"] == "REJECTED"
    assert invoke(repo, base, tmp_path / "out2", "--fail-on", "never").exit_code == 0


def test_a_symlink_in_scope_is_an_integrity_violation(
    project: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base = project
    os.symlink("/etc/passwd", repo / "src" / "Link.sol")
    commit(repo)
    install(monkeypatch, lambda _r: outcome("VERIFIED_WITHIN_BOUNDS"))
    assert invoke(repo, base, tmp_path / "out").exit_code == 5


def test_inputs_rejected_at_ingest_are_integrity_violations(
    project: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base = project
    patch_vault(repo)
    install(
        monkeypatch, lambda _r: VerifyInputError("rejected", "the PoC directory holds a symlink")
    )
    out = tmp_path / "out"
    assert invoke(repo, base, out).exit_code == 5
    assert "holds a symlink" in (out / "summary.md").read_text()


def test_infrastructure_problems_always_fail(
    project: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from assay.sandbox import SandboxError

    repo, base = project
    patch_vault(repo)
    install(monkeypatch, lambda _r: SandboxError("docker is not running"))
    out = tmp_path / "out"
    result = invoke(repo, base, out, "--fail-on", "never")
    assert result.exit_code == 4
    assert result_json(out)["verdict"] == "ERROR"


@pytest.mark.parametrize(
    "override",
    [
        {"--base": "no-such-ref"},
        {"--base": "--upload-pack=touch x"},
        {"--head": "main..HEAD"},
        {"--scope": "../test"},
        {"--scope": "/etc"},
    ],
)
def test_usage_errors_exit_two(
    project: tuple[Path, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    override: dict[str, str],
) -> None:
    repo, base = project
    patch_vault(repo)
    calls = install(monkeypatch, lambda _r: outcome("REJECTED"))
    options = {
        "--project": str(repo),
        "--poc-dir": str(repo / "poc"),
        "--base": base,
        "--head": "HEAD",
        "--out": str(tmp_path / "out"),
        **override,
    }
    command = ["ci", "verify", *(part for pair in options.items() for part in pair)]
    result = runner.invoke(app, command)
    assert result.exit_code == 2, result.output
    assert calls.requests == []


def test_an_output_directory_with_content_is_a_usage_error(
    project: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base = project
    patch_vault(repo)
    install(monkeypatch, lambda _r: outcome("REJECTED"))
    out = tmp_path / "out"
    out.mkdir()
    (out / "old.txt").write_text("x")
    assert invoke(repo, base, out).exit_code == 2


def test_a_poc_directory_without_solidity_is_a_usage_error(
    project: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base = project
    patch_vault(repo)
    install(monkeypatch, lambda _r: outcome("REJECTED"))
    empty = tmp_path / "empty"
    empty.mkdir()
    assert invoke(repo, base, tmp_path / "out", poc_dir=empty).exit_code == 2


def test_a_symlinked_poc_directory_is_an_integrity_violation(
    project: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base = project
    patch_vault(repo)
    install(monkeypatch, lambda _r: outcome("REJECTED"))
    link = tmp_path / "link"
    os.symlink(repo / "poc", link)
    assert invoke(repo, base, tmp_path / "out", poc_dir=link).exit_code == 5


def test_output_lines_can_not_be_workflow_commands(
    project: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base = project
    (repo / "poc" / "Exploit.t.sol").unlink()
    hostile = "::set-output name=x::y"
    write(repo, f"poc/{hostile}/A.t.sol", "contract A {}\n")
    base = commit(repo, "pocs")
    patch_vault(repo)
    install(monkeypatch, lambda _r: outcome("REJECTED"))
    result = invoke(repo, base, tmp_path / "out")
    assert result.exit_code == 1
    lines = [line for line in result.output.splitlines() if line]
    assert lines
    assert all(line.startswith(KNOWN_PREFIXES) for line in lines), lines
    summary = (tmp_path / "out" / "summary.md").read_text()
    assert "\n::" not in summary


def test_a_changed_poc_is_flagged_in_the_summary(
    project: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, base = project
    patch_vault(repo)
    write(repo, "poc/Exploit.t.sol", "contract E { uint256 x; }\n")
    commit(repo)
    install(monkeypatch, lambda _r: outcome("VERIFIED_WITHIN_BOUNDS"))
    out = tmp_path / "out"
    invoke(repo, base, out)
    assert "changes files of the PoC directory" in (out / "summary.md").read_text()


def test_nothing_in_the_command_uses_a_model_or_reads_a_secret() -> None:
    files = [SOURCE_ROOT / "cli" / "ci.py", *sorted((SOURCE_ROOT / "ci").glob("*.py"))]
    for path in files:
        text = path.read_text()
        for forbidden in (
            "ASSAY_LLM",
            "assay.llm",
            "httpx",
            "getenv",
            "import secrets",
            "environ[",
            'environ.get("ASSAY',
        ):
            assert forbidden not in text, f"{path.name} mentions {forbidden}"
    assert git is not None  # keeps the helper import used when the list above changes


def test_the_environment_of_git_is_fixed() -> None:
    from assay.ci import gitdiff

    env = gitdiff._git_env()
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull
    assert env["GIT_CONFIG_SYSTEM"] == os.devnull
    assert env["GIT_LITERAL_PATHSPECS"] == "1"
    assert set(env) <= {
        "PATH", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM",
        "GIT_ATTR_NOSYSTEM", "GIT_LITERAL_PATHSPECS", "GIT_TERMINAL_PROMPT", "GIT_PAGER",
        "GIT_OPTIONAL_LOCKS",
    }  # fmt: skip


def test_help_has_an_example_and_the_exit_codes_and_a_snapshot() -> None:
    result = CliRunner(env={"COLUMNS": "100", "LINES": "50", "TERM": "dumb"}).invoke(
        app, ["ci", "verify", "--help"]
    )
    assert result.exit_code == 0
    text = result.output
    assert "Example" in text
    assert "assay ci verify" in text
    assert "Exit codes" in text
    path = Path(__file__).parent / "snapshots" / "help_ci_verify.txt"
    if os.environ.get("ASSAY_UPDATE_GOLDEN") == "1":
        path.write_text(text, encoding="utf-8")
    assert text == path.read_text(encoding="utf-8"), (
        "help_ci_verify.txt differs; if the change is intended, run with ASSAY_UPDATE_GOLDEN=1"
    )


def test_docs_cli_lists_the_command() -> None:
    text = (SOURCE_ROOT.parents[1] / "docs" / "cli.md").read_text(encoding="utf-8")
    assert "`assay ci verify" in text
    assert "## assay ci verify" in text
