"""S8: symlinks out of the tree and path traversal are rejected at ingest, and an argument vector
outside the allowlist is rejected before Docker is called.

Docker calls are recorded on the real runner (`docker_calls`); a rejection must leave the list
empty, while an allowed command produces the full call sequence.
"""

from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.cli.main import app
from assay.ingest import Snapshot, UnsafePathError, safe_relative_path
from assay.sandbox import ArgvRejected, SandboxRunner, make_scratch_dir

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("runner")]

SnapshotOf = Callable[[Path], Snapshot]
MakeProject = Callable[[str, dict[str, str]], Path]

MARKER = "outside-marker-6f1d"

PASSING_TEST = """\
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

contract PassingTest {
    function test_Passes() public pure {}
}
"""
HALMOS = [
    "halmos",
    "--root",
    "/work/project",
    "--forge-build-out",
    "/work/scratch/out",
    "--json-output",
    "/work/scratch/halmos.json",
]


@pytest.fixture
def outside(tmp_path: Path) -> Path:
    """A directory next to the project, holding a file the project must never read."""
    directory = tmp_path / "outside"
    directory.mkdir()
    (directory / "Secret.sol").write_text(f"// {MARKER}\ncontract Secret {{}}\n")
    return directory


@pytest.mark.parametrize(
    ("links", "code"),
    [
        ({"src/Link.sol": "{outside}/Secret.sol"}, "symlink_outside_tree"),
        ({"src/Link.sol": "../../outside/Secret.sol"}, "symlink_outside_tree"),
        ({"src/lib": "../../outside"}, "symlink_outside_tree"),
        ({"src/A.sol": "B.sol", "src/B.sol": "../../outside/Secret.sol"}, "symlink_outside_tree"),
        ({"src/Missing.sol": "../../outside/Missing.sol"}, "symlink_outside_tree"),
        ({"src/Env.sol": "../.env"}, "symlink_to_excluded_path"),
    ],
)
def test_symlinks_out_of_the_tree_are_rejected_before_anything_runs(
    links: dict[str, str],
    code: str,
    outside: Path,
    make_project: MakeProject,
    docker_calls: list[str],
) -> None:
    project = make_project(
        "project", {"test/Passing.t.sol": PASSING_TEST, ".env": f"KEY={MARKER}\n"}
    )
    for link, target in links.items():
        path = project / link
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target.format(outside=outside))

    result = CliRunner().invoke(app, ["dev", "forge-test", str(project)])

    assert result.exit_code == 5
    assert code in result.stderr
    assert MARKER not in result.stdout + result.stderr
    assert docker_calls == []


@pytest.mark.parametrize(
    "path",
    [
        "..",
        "../outside/Secret.sol",
        "src/../../outside/Secret.sol",
        "src/../..",
        "/etc/passwd",
        "src\\..\\..\\Secret.sol",
    ],
)
def test_path_traversal_is_rejected(path: str) -> None:
    with pytest.raises(UnsafePathError):
        safe_relative_path(path)


@pytest.mark.parametrize(
    "argv",
    [
        ["solc", "--version"],
        ["forge", "script", "script/Deploy.s.sol"],
        ["forge", "test", "--ffi"],
        ["forge", "test", "--config-path", "/work/scratch/foundry.toml"],
        ["forge", "test", "--root", "/"],
        ["forge", "test", "--fork-url", "http://127.0.0.1:8545"],
        ["forge", "test", "--match-path", "../../etc/*"],
        ["forge", "test", "--match-test=test_Passes"],
        ["forge", "test", "--match-test", "test_A test_B"],
        ["forge", "build", "--json", "--json"],
        ["forge", "test", "test/Passing.t.sol"],
        "forge test",
        [*HALMOS, "--ffi"],
        [*HALMOS, "--config", "/work/project/halmos.toml"],
        [*HALMOS, "--solver-command", "/bin/sh"],
        [*HALMOS[:-2], "--json-output", "/work/project/out.json"],
        ["halmos", "--version"],
    ],
)
def test_argv_outside_the_allowlist_never_reaches_docker(
    argv: list[str] | str, tmp_path: Path, runner: SandboxRunner, docker_calls: list[str]
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    with pytest.raises(ArgvRejected):
        runner.run(argv, project_dir=project, scratch_dir=make_scratch_dir(tmp_path))
    assert docker_calls == []


def test_allowed_argv_is_recorded_as_docker_calls(
    tmp_path: Path,
    runner: SandboxRunner,
    snapshot_of: SnapshotOf,
    make_project: MakeProject,
    docker_calls: list[str],
) -> None:
    # Control for the tests above: the recorder sees every call of an allowed run.
    tree = snapshot_of(make_project("project", {"test/Passing.t.sol": PASSING_TEST})).tree_dir
    result = runner.run(
        ["forge", "test", "--json"], project_dir=tree, scratch_dir=make_scratch_dir(tmp_path)
    )

    assert result.exit_code == 0
    assert docker_calls == ["image", "run", "ps", "events"]
