"""S1: a hostile project configuration has no effect.

The project's own `foundry.toml` enables FFI and grants read-write access to the whole
filesystem. Ingest replaces it with the snapshot configuration, so the cheatcodes that would
rely on those settings fail inside the runner. The other ways to configure forge from inside a
project (`remappings.txt` in any letter case, inline configuration) do not take effect either.
"""

from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.analyzers import foundry
from assay.cli.main import app
from assay.ingest import Snapshot, safe_foundry_toml
from assay.sandbox import SandboxRunner, make_scratch_dir

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("runner")]

SnapshotOf = Callable[[Path], Snapshot]
MakeProject = Callable[[str, dict[str, str]], Path]

HEADER = "// SPDX-License-Identifier: MIT\npragma solidity 0.8.36;\n"

HOSTILE_CONFIG = """\
[profile.default]
ffi = true
fs_permissions = [{ access = "read-write", path = "/" }]
allow_paths = ["/"]
"""

HOSTILE_TEST = (
    HEADER
    + """
import {Test} from "forge-std/Test.sol";

contract HostileTest is Test {
    function test_Control() public pure {}

    function test_Ffi() public {
        string[] memory command = new string[](2);
        command[0] = "forge";
        command[1] = "--version";
        vm.ffi(command);
    }

    function test_ReadSystemFile() public view {
        vm.readFile("/etc/passwd");
    }

    function test_ReadProjectFile() public view {
        vm.readFile("test/Hostile.t.sol");
    }

    function test_WriteScratch() public {
        vm.writeFile("/work/scratch/written.txt", "x");
    }
}
"""
)

FAKE_FORGE_STD = HEADER + "\ncontract Test {}\n"

USES_FORGE_STD = (
    HEADER
    + """
import {Test} from "forge-std/Test.sol";

contract UsesTest is Test {
    function test_Asserts() public pure {
        assertEq(uint256(1), 1);
    }
}
"""
)

INLINE_CONFIG_TEST = (
    HEADER
    + """
contract InlineTest {
    /// forge-config: default.fs_permissions = [{ access = "read", path = "/" }]
    function test_Inline() public pure {}
}
"""
)


@pytest.mark.parametrize("config_name", ["foundry.toml", "Foundry.toml", "FOUNDRY.TOML"])
def test_hostile_foundry_toml_does_not_enable_ffi_or_file_access(
    config_name: str,
    tmp_path: Path,
    runner: SandboxRunner,
    snapshot_of: SnapshotOf,
    make_project: MakeProject,
) -> None:
    project = make_project(
        "hostile", {config_name: HOSTILE_CONFIG, "test/Hostile.t.sol": HOSTILE_TEST}
    )
    snapshot = snapshot_of(project)
    assert sorted(entry.name for entry in snapshot.tree_dir.iterdir()) == ["foundry.toml", "test"]
    assert (snapshot.tree_dir / "foundry.toml").read_bytes() == safe_foundry_toml()
    assert [item.path for item in snapshot.project_config] == [config_name]
    assert (snapshot.evidence_dir / config_name).read_text() == HOSTILE_CONFIG

    scratch = make_scratch_dir(tmp_path)
    run = foundry.test(runner, snapshot.tree_dir, scratch_dir=scratch)
    tests = {case.name: case for suite in run.suites for case in suite.tests}

    assert tests["test_Control()"].status == "success"
    assert tests["test_Ffi()"].status == "failure"
    assert "FFI is disabled" in (tests["test_Ffi()"].reason or "")
    for name in ("test_ReadSystemFile()", "test_ReadProjectFile()", "test_WriteScratch()"):
        assert tests[name].status == "failure", name
        assert "is not allowed to be accessed" in (tests[name].reason or ""), name
    assert not (scratch / "written.txt").exists()


@pytest.mark.parametrize("name", ["remappings.txt", "Remappings.txt", "REMAPPINGS.TXT"])
def test_project_remappings_do_not_replace_forge_std(
    name: str, runner: SandboxRunner, snapshot_of: SnapshotOf, make_project: MakeProject
) -> None:
    # If forge read the project's remappings, forge-std would resolve to the fake library,
    # which has no assertEq, and the project would not compile. On a case-insensitive
    # filesystem forge opens `Remappings.txt` when it looks for `remappings.txt`.
    project = make_project(
        "remapped",
        {
            name: "forge-std/=lib/fake/\n",
            "lib/fake/Test.sol": FAKE_FORGE_STD,
            "test/Uses.t.sol": USES_FORGE_STD,
        },
    )
    snapshot = snapshot_of(project)
    assert [item.path for item in snapshot.project_config] == [name]

    run = foundry.test(runner, snapshot.tree_dir)
    assert (run.summary.passed, run.summary.failed) == (1, 0)


def test_inline_configuration_is_rejected_before_anything_runs(
    make_project: MakeProject, docker_calls: list[str]
) -> None:
    project = make_project("inline", {"test/Inline.t.sol": INLINE_CONFIG_TEST})
    result = CliRunner().invoke(app, ["dev", "forge-test", str(project)])

    assert result.exit_code == 5
    assert "inline_config" in result.stderr
    assert docker_calls == []
