"""S7: the root filesystem and the project mount are read-only.

Only the scratch directory and the `/tmp` tmpfs accept writes. The project is mounted directly
with a `foundry.toml` that grants read-write access to `/`, so forge's own file permissions do
not stop any write: every denial below comes from the container.

Creating or removing an entry on a read-only mount fails with EROFS before file permissions are
looked at, which makes those cases evidence of the read-only mounts themselves. Overwriting an
existing file of the image is denied as well; there the permission check of the non-root user
(EACCES) may come first.
"""

from collections.abc import Callable
from pathlib import Path

import pytest

from assay.analyzers import foundry
from assay.sandbox import SandboxRunner, make_scratch_dir

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("runner")]

MakeProject = Callable[[str, dict[str, str]], Path]

PERMISSIVE_CONFIG = """\
[profile.default]
src = "src"
test = "test"
libs = []
remappings = ["forge-std/=/opt/assay/lib/forge-std/src/"]
out = "/work/scratch/out"
cache_path = "/work/scratch/cache"
fs_permissions = [{ access = "read-write", path = "/" }]
"""

WRITES_TEST = """\
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Test} from "forge-std/Test.sol";

contract WritesTest is Test {
    function test_WriteScratch() public {
        vm.writeFile("/work/scratch/probe.txt", "scratch");
    }

    function test_WriteTmp() public {
        vm.writeFile("/tmp/probe.txt", "tmp");
    }

    function test_CreateFileInRoot() public {
        vm.writeFile("/probe.txt", "x");
    }

    function test_CreateFileInEtc() public {
        vm.writeFile("/etc/probe.txt", "x");
    }

    function test_CreateFileInWork() public {
        vm.writeFile("/work/probe.txt", "x");
    }

    function test_CreateFileInToolchain() public {
        vm.writeFile("/opt/assay/bin/probe", "x");
    }

    function test_CreateDirInToolchain() public {
        vm.createDir("/opt/assay/lib/probe", false);
    }

    function test_RemoveSystemFile() public {
        vm.removeFile("/etc/passwd");
    }

    function test_RemoveCompiler() public {
        vm.removeFile("/opt/assay/bin/solc");
    }

    function test_CreateFileInProject() public {
        vm.writeFile("/work/project/test/Injected.t.sol", "x");
    }

    function test_CreateDirInProject() public {
        vm.createDir("/work/project/src", false);
    }

    function test_RemoveProjectFile() public {
        vm.removeFile("/work/project/test/Writes.t.sol");
    }

    function test_OverwriteCompiler() public {
        vm.writeFile("/opt/assay/bin/solc", "x");
    }

    function test_OverwriteForge() public {
        vm.writeFile("/usr/local/bin/forge", "x");
    }

    function test_OverwriteSystemFile() public {
        vm.writeFile("/etc/passwd", "x");
    }
}
"""

WRITABLE = {"test_WriteScratch()", "test_WriteTmp()"}
READ_ONLY = {
    "test_CreateFileInRoot()",
    "test_CreateFileInEtc()",
    "test_CreateFileInWork()",
    "test_CreateFileInToolchain()",
    "test_CreateDirInToolchain()",
    "test_RemoveSystemFile()",
    "test_RemoveCompiler()",
    "test_CreateFileInProject()",
    "test_CreateDirInProject()",
    "test_RemoveProjectFile()",
}
OVERWRITE = {"test_OverwriteCompiler()", "test_OverwriteForge()", "test_OverwriteSystemFile()"}

EROFS = "Read-only file system (os error 30)"
EACCES = "Permission denied (os error 13)"


def _files(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_writes_succeed_only_in_scratch_and_tmp(
    tmp_path: Path, runner: SandboxRunner, make_project: MakeProject
) -> None:
    project = make_project(
        "writes", {"foundry.toml": PERMISSIVE_CONFIG, "test/Writes.t.sol": WRITES_TEST}
    )
    before = _files(project)
    scratch = make_scratch_dir(tmp_path)

    run = foundry.test(runner, project, scratch_dir=scratch)
    tests = {case.name: case for suite in run.suites for case in suite.tests}

    assert set(tests) == WRITABLE | READ_ONLY | OVERWRITE
    for name in WRITABLE:
        assert tests[name].status == "success", (name, tests[name].reason)
    for name in READ_ONLY:
        assert tests[name].status == "failure", name
        assert EROFS in (tests[name].reason or ""), (name, tests[name].reason)
    for name in OVERWRITE:
        reason = tests[name].reason or ""
        assert tests[name].status == "failure", name
        assert EROFS in reason or EACCES in reason, (name, reason)
    assert (scratch / "probe.txt").read_text() == "scratch"
    assert _files(project) == before
