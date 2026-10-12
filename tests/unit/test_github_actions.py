"""The Action, the demo workflow and the repository's workflows: actionlint, pinning, privileges.

These tests read the files as data. They do not run GitHub Actions; `make lint-actions` runs the
pinned actionlint, and this module runs it as well (it is skipped only when the binary cannot be
downloaded, for example offline).
"""

import filecmp
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

import lint_actions

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
ACTION = ROOT / "action.yml"
ALL_FILES = [*WORKFLOWS, ACTION]
USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<ref>\S+)(?P<rest>.*)$", re.MULTILINE)
PINNED = re.compile(r"^[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40}$")


def load(path: Path) -> dict[str, Any]:
    document: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return document


def triggers(workflow: dict[str, Any]) -> dict[str, Any]:
    on = workflow.get("on", workflow.get(True))  # YAML 1.1 reads the key `on` as True
    return on if isinstance(on, dict) else dict.fromkeys([on] if isinstance(on, str) else on)


def steps_of(path: Path) -> list[dict[str, Any]]:
    document = load(path)
    if path == ACTION:
        return list(document["runs"]["steps"])
    return [step for job in document["jobs"].values() for step in job["steps"]]


# --- actionlint ---------------------------------------------------------------------------------


def run_lint(root: Path) -> tuple[int, str]:
    try:
        binary = lint_actions.ensure_actionlint()
    except lint_actions.LintToolError as exc:
        pytest.skip(f"actionlint is not available: {exc}")
    return lint_actions.lint(root, binary)


def test_workflows_and_action_pass_actionlint() -> None:
    status, report = run_lint(ROOT)
    assert status == 0, report
    assert {path.name for path in lint_actions.targets()} >= {
        "action.yml",
        "action-demo.yml",
        "ci.yml",
    }


def write_repo(root: Path, action: str) -> None:
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / "action.yml").write_text(action, encoding="utf-8")


BAD_EXPRESSION = """\
name: bad
description: a composite action with a mistake
inputs:
  thing:
    description: a thing
runs:
  using: composite
  steps:
    - shell: bash
      run: echo "$X"
      env:
        X: ${{ inputs.no_such_input_name }} ${{ steps.nothing.outputs.x }} ${{ github.nope }}
"""
UNQUOTED_SCRIPT = """\
name: bad
description: a composite action with a mistake
inputs:
  thing:
    description: a thing
runs:
  using: composite
  steps:
    - shell: bash
      run: echo ${{ github.event.pull_request.title }}
"""


def test_the_lint_of_the_action_finds_a_wrong_expression(tmp_path: Path) -> None:
    write_repo(tmp_path, BAD_EXPRESSION)
    status, report = run_lint(tmp_path)
    assert status != 0
    assert "action.yml (steps)" in report
    assert "nope" in report or "no_such_input_name" in report


def test_the_lint_of_the_action_finds_a_script_injection(tmp_path: Path) -> None:
    write_repo(tmp_path, UNQUOTED_SCRIPT)
    status, report = run_lint(tmp_path)
    assert status != 0
    assert "injection" in report


def test_the_lint_of_the_action_checks_its_structure(tmp_path: Path) -> None:
    write_repo(tmp_path, "name: x\nruns:\n  using: node20\n  main: x.js\n")
    status, report = run_lint(tmp_path)
    assert status == 1
    assert "missing description" in report
    assert "runs.using must be composite" in report


def test_structure_problems() -> None:
    good = load(ACTION)
    assert lint_actions.structure_problems(good) == []
    broken = load(ACTION)
    del broken["runs"]["steps"][0]["shell"]
    del broken["outputs"]["verdict"]["value"]
    del broken["inputs"]["scope"]["description"]
    problems = lint_actions.structure_problems(broken)
    assert any("no shell" in item for item in problems)
    assert any("output verdict has no value" in item for item in problems)
    assert any("input scope has no description" in item for item in problems)
    assert lint_actions.structure_problems([]) == ["the file is not a mapping"]


# --- privileges and pinning ---------------------------------------------------------------------


def without_comments(text: str) -> str:
    return "\n".join(re.sub(r"(^|\s)#.*$", "", line) for line in text.splitlines())


@pytest.mark.parametrize("path", ALL_FILES, ids=lambda path: path.name)
def test_no_pull_request_target_and_no_secrets(path: Path) -> None:
    text = without_comments(path.read_text(encoding="utf-8"))
    assert "pull_request_target" not in text
    assert "workflow_run" not in text
    assert not re.search(r"\bsecrets\s*[.\[]", text)
    assert "toJSON(secrets" not in text
    if path != ACTION:
        assert "pull_request_target" not in triggers(load(path))


@pytest.mark.parametrize("path", ALL_FILES, ids=lambda path: path.name)
def test_third_party_actions_are_pinned_to_a_full_commit_with_a_version_comment(path: Path) -> None:
    found = USES.findall(path.read_text(encoding="utf-8"))
    for ref, rest in found:
        if ref.startswith("./"):
            continue
        assert PINNED.fullmatch(ref), f"{path.name}: {ref} is not pinned to a full commit sha"
        assert re.fullmatch(r"\s*#\s*v\d+\.\d+\.\d+\s*", rest), (
            f"{path.name}: {ref} lacks a version comment"
        )


@pytest.mark.parametrize("path", ALL_FILES, ids=lambda path: path.name)
def test_scripts_do_not_interpolate_expressions(path: Path) -> None:
    for step in steps_of(path):
        assert "${{" not in step.get("run", ""), step.get("name")


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_every_workflow_has_permissions_and_timeouts(path: Path) -> None:
    workflow = load(path)
    assert "permissions" in workflow, "set permissions at the top of the workflow"
    for name, job in workflow["jobs"].items():
        assert "timeout-minutes" in job, name
    for step in steps_of(path):
        if str(step.get("uses", "")).startswith("actions/checkout@"):
            assert step["with"]["persist-credentials"] is False


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_no_workflow_grants_write_permissions_beyond_the_demo_comment(path: Path) -> None:
    workflow = load(path)
    granted = [workflow.get("permissions") or {}]
    granted += [job.get("permissions") or {} for job in workflow["jobs"].values()]
    for permissions in granted:
        assert isinstance(permissions, dict)
        for scope, level in permissions.items():
            if level == "write":
                assert (path.name, scope) == ("action-demo.yml", "pull-requests")
            else:
                assert (scope, level) == ("contents", "read")


# --- the demo workflow --------------------------------------------------------------------------


def test_the_demo_workflow() -> None:
    workflow = load(ROOT / ".github" / "workflows" / "action-demo.yml")
    assert list(triggers(workflow)) == ["pull_request"]
    assert triggers(workflow)["pull_request"] == {"paths": ["examples/**"]}
    assert workflow["permissions"] == {}
    assert workflow["concurrency"]["cancel-in-progress"] is True
    assert "pull_request.number" in workflow["concurrency"]["group"]
    [job] = workflow["jobs"].values()
    assert job["permissions"] == {"contents": "read", "pull-requests": "write"}
    assert job["timeout-minutes"] <= 60
    [action_step] = [step for step in job["steps"] if step.get("uses") == "./"]
    assert action_step["with"]["project-dir"] == "examples/demo-project"
    assert action_step["with"]["poc-dir"] == "examples/demo-project/poc"
    assert "env" not in job
    assert "secrets" not in str(job)


def test_dependabot_covers_github_actions() -> None:
    config = load(ROOT / ".github" / "dependabot.yml")
    ecosystems = {item["package-ecosystem"]: item for item in config["updates"]}
    assert ecosystems["github-actions"]["directory"] == "/"
    assert ecosystems["github-actions"]["schedule"]["interval"]


# --- the Action ---------------------------------------------------------------------------------


def named(name: str) -> dict[str, Any]:
    [step] = [step for step in steps_of(ACTION) if step.get("name") == name]
    return step


def test_the_action_interface() -> None:
    action = load(ACTION)
    assert action["runs"]["using"] == "composite"
    assert set(action["inputs"]) == {
        "project-dir",
        "poc-dir",
        "scope",
        "base-ref",
        "profile",
        "symbolic",
        "fail-on",
        "comment",
        "upload-sarif",
    }
    assert set(action["outputs"]) == {"verdict", "exit-code", "bundle-path"}
    assert action["inputs"]["poc-dir"]["required"] is True
    assert action["inputs"]["fail-on"]["default"] == "inconclusive"
    assert action["inputs"]["comment"]["default"] == "false"
    assert action["inputs"]["upload-sarif"]["default"] == "false"
    assert "pull_request.base.sha" in action["inputs"]["base-ref"]["default"]


def test_assay_is_installed_from_the_code_of_the_action() -> None:
    step = named("Install Assay")
    assert step["env"]["ACTION_PATH"] == "${{ github.action_path }}"
    assert "--locked" in step["run"]
    assert "--no-dev" in step["run"]
    assert "inputs." not in str(step)
    assert "workspace" not in str(step)


def test_the_verify_step_has_no_token_and_no_secret() -> None:
    step = named("Verify the patch")
    assert not [key for key in step["env"] if "TOKEN" in key.upper()]
    assert "github.token" not in str(step)
    assert "secrets" not in str(step)
    assert "GITHUB_STEP_SUMMARY" in step["run"]
    assert step["run"].rstrip().endswith("exit 0")


def test_only_the_comment_and_sarif_steps_get_the_token() -> None:
    holders = [step["name"] for step in steps_of(ACTION) if "github.token" in yaml.safe_dump(step)]
    assert holders == ["Comment on the pull request", "Decide whether to upload SARIF"]


def test_the_comment_is_for_pull_requests_of_the_same_repository_only() -> None:
    condition = named("Comment on the pull request")["if"]
    assert "inputs.comment == 'true'" in condition
    assert "github.event.pull_request.head.repo.full_name == github.repository" in condition
    script = named("Comment on the pull request")["run"]
    assert "<!-- assay-ci-verify -->" in script
    assert "github-actions[bot]" in script
    assert "PATCH" in script
    assert "POST" in script


def test_sarif_is_only_uploaded_on_request_and_skipped_with_a_message() -> None:
    for name in ("Decide whether to upload SARIF", "Scan the project for SARIF", "Upload SARIF"):
        assert (
            "inputs.upload-sarif == 'true'" in named(name)["if"] or "steps.s" in named(name)["if"]
        )
    script = named("Decide whether to upload SARIF")["run"]
    assert "::notice::SARIF upload skipped" in script
    assert "fork" in script
    assert "private repository" in script


def test_images_are_built_with_buildx_and_the_actions_cache() -> None:
    step = named("Build the sandbox image")
    assert step["with"]["tags"] == "assay-runner:dev"
    assert step["with"]["cache-from"].startswith("type=gha")
    assert step["with"]["cache-to"].startswith("type=gha")
    assert step["with"]["load"] is True
    assert step["with"]["push"] is False
    assert step["with"]["context"].startswith("${{ github.action_path }}/")
    symbolic = named("Build the symbolic sandbox image")
    assert symbolic["if"] == "${{ inputs.symbolic == 'true' }}"
    assert symbolic["with"]["platforms"] == "linux/amd64"


def test_the_bundle_folder_is_uploaded_and_the_result_applied_last() -> None:
    names = [step["name"] for step in steps_of(ACTION)]
    assert names.index("Upload the evidence bundles") < names.index("Apply the result")
    assert names[-1] == "Apply the result"
    assert names.index("Verify the patch") < names.index("Upload the evidence bundles")


# --- the example project ------------------------------------------------------------------------


def test_the_demo_project_is_a_copy_of_the_fixture_without_patches_and_expectations() -> None:
    demo = ROOT / "examples" / "demo-project"
    fixture = ROOT / "fixtures" / "reentrancy" / "single_function"
    assert not any(item.is_symlink() for item in demo.rglob("*"))
    assert not (demo / "patches").exists()
    assert not (demo / "expected.json").exists()
    assert (demo / "README.md").is_file()
    for name in ("src", "test", "poc"):
        comparison = filecmp.dircmp(demo / name, fixture / name)
        assert not comparison.left_only
        assert not comparison.right_only
        assert not comparison.diff_files
    assert (demo / "foundry.toml").read_bytes() == (fixture / "foundry.toml").read_bytes()
    for source in (demo / "src").rglob("*.sol"):
        first = source.read_text(encoding="utf-8").splitlines()[0]
        assert first == "// INTENTIONALLY VULNERABLE: test fixture, do not deploy"
