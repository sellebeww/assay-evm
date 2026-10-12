"""`assay ci verify` on a git copy of the demo project, against the real runner image.

The demo project is committed as the base revision; the head revision applies one of the
fixture's patches. The expected verdicts are the ones of the classification matrix.
"""

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from ci_support import commit, git, init_repo
from typer.testing import CliRunner

from assay.cli.main import app

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("runner")]

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "examples" / "demo-project"
PATCHES = ROOT / "fixtures" / "reentrancy" / "single_function" / "patches"

cli = CliRunner()


@pytest.fixture(scope="module")
def repo(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, str]:
    root = init_repo(tmp_path_factory.mktemp("ci") / "repo")
    shutil.copytree(DEMO, root / "examples" / "demo-project")
    return root, commit(root, "base")


def run_ci(repo: Path, base: str, out: Path, *extra: str) -> Any:
    project = repo / "examples" / "demo-project"
    return cli.invoke(
        app,
        [
            "ci", "verify", "--project", str(project), "--poc-dir", str(project / "poc"),
            "--base", base, "--head", "HEAD", "--profile", "quick", "--out", str(out), *extra,
        ],
    )  # fmt: skip


def result(out: Path) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((out / "result.json").read_text())
    return document


def apply(repo: Path, label: str) -> None:
    git(repo, "checkout", "-q", "-B", f"patch-{label}", "main")
    git(repo, "apply", "--directory=examples/demo-project", str(PATCHES / f"{label}.diff"))
    commit(repo, label)


def test_no_change_in_the_scope(repo: tuple[Path, str], tmp_path: Path) -> None:
    root, base = repo
    git(root, "checkout", "-q", "-B", "main")
    outcome = run_ci(root, base, tmp_path / "out")
    assert outcome.exit_code == 0, outcome.output
    assert outcome.output.strip() == "no changes in scope"
    assert result(tmp_path / "out")["verdict"] == "NO_CHANGES_IN_SCOPE"


def test_the_good_patch_is_verified_within_bounds_and_the_bundle_replays(
    repo: tuple[Path, str], tmp_path: Path
) -> None:
    root, base = repo
    apply(root, "good")
    out = tmp_path / "out"
    outcome = run_ci(root, base, out, "--fail-on", "inconclusive")
    assert outcome.exit_code == 0, outcome.output
    document = result(out)
    assert document["verdict"] == "VERIFIED_WITHIN_BOUNDS"
    assert [item["name"] for item in document["pocs"]] == ["poc"]
    summary = (out / "summary.md").read_text()
    assert "**VERIFIED_WITHIN_BOUNDS**" in summary
    assert "assay replay bundles/poc" in summary
    assert "not a proof of absence" in summary
    assert str(tmp_path) not in summary
    assert str(root) not in summary
    replay = cli.invoke(app, ["replay", str(out / "bundles" / "poc")])
    assert replay.exit_code == 0, replay.output


def test_the_overfit_patch_is_rejected_and_fail_on_decides_the_exit_code(
    repo: tuple[Path, str], tmp_path: Path
) -> None:
    root, base = repo
    apply(root, "overfit")
    out = tmp_path / "out"
    outcome = run_ci(root, base, out, "--fail-on", "rejected")
    assert outcome.exit_code == 1, outcome.output
    assert result(out)["verdict"] == "REJECTED"
    assert "variant_found" in (out / "summary.md").read_text()
    never = run_ci(root, base, tmp_path / "never", "--fail-on", "never")
    assert never.exit_code == 0, never.output
    assert result(tmp_path / "never")["verdict"] == "REJECTED"


def test_a_binary_file_in_the_scope_stops_before_anything_runs(
    repo: tuple[Path, str], tmp_path: Path
) -> None:
    root, base = repo
    git(root, "checkout", "-q", "-B", "binary", "main")
    (root / "examples" / "demo-project" / "src" / "blob.bin").write_bytes(b"\x00\x01\x02")
    commit(root, "binary")
    outcome = run_ci(root, base, tmp_path / "out")
    assert outcome.exit_code == 5, outcome.output
    assert "binary" in (tmp_path / "out" / "summary.md").read_text()
