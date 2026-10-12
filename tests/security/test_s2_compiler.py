"""S2: a project configuration that points at another compiler is ignored.

The project ships `tools/solc`, a file that is not a compiler, and names it (or another solc
version, which would need a download) in its `foundry.toml`. Had forge used that setting, the
build would fail. The build artifacts record the compiler that ran, which must be the solc
pinned in `docker/runner/versions.lock`.

The setting is checked twice: through ingest, which replaces the configuration, and with the
project mounted directly, where only the runner's `FOUNDRY_SOLC` environment variable stands
between the project's setting and forge.
"""

import json
import re
from collections.abc import Callable
from pathlib import Path

import pytest

from assay.analyzers import foundry
from assay.ingest import Snapshot
from assay.sandbox import SandboxRunner, make_scratch_dir

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("runner")]

SnapshotOf = Callable[[Path], Snapshot]
MakeProject = Callable[[str, dict[str, str]], Path]

VERSIONS_LOCK = Path(__file__).resolve().parents[2] / "docker" / "runner" / "versions.lock"

SOURCE = """\
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

contract Vault {
    function deposit() external payable {}
}
"""

# Written into the project mounted directly; the mount is read-only, so build output goes to
# the scratch directory.
DIRECT_MOUNT_CONFIG = """\
[profile.default]
src = "src"
libs = []
out = "/work/scratch/out"
cache_path = "/work/scratch/cache"
"""

COMPILER_SETTINGS = [
    'solc = "tools/solc"',
    'solc = "/work/project/tools/solc"',
    'solc_version = "0.8.20"',
    'solc = "0.8.20"\nauto_detect_solc = true',
]


def pinned_compiler() -> str:
    match = re.search(r"^SOLC_BUILD=v(\S+)$", VERSIONS_LOCK.read_text(), re.MULTILINE)
    assert match is not None, "SOLC_BUILD missing from versions.lock"
    return match.group(1)


def compiler_of_artifact(scratch: Path) -> str:
    artifact = json.loads((scratch / "out" / "Vault.sol" / "Vault.json").read_text())
    version = artifact["metadata"]["compiler"]["version"]
    assert isinstance(version, str)
    return version


@pytest.mark.parametrize("setting", COMPILER_SETTINGS)
def test_project_compiler_setting_is_ignored_after_ingest(
    setting: str,
    tmp_path: Path,
    runner: SandboxRunner,
    snapshot_of: SnapshotOf,
    make_project: MakeProject,
) -> None:
    project = make_project(
        "compiler",
        {
            "foundry.toml": f"[profile.default]\n{setting}\n",
            "tools/solc": "not a compiler\n",
            "src/Vault.sol": SOURCE,
        },
    )
    scratch = make_scratch_dir(tmp_path)
    build = foundry.build(runner, snapshot_of(project).tree_dir, scratch_dir=scratch)

    assert build.succeeded, build.errors
    assert compiler_of_artifact(scratch) == pinned_compiler()


@pytest.mark.parametrize("setting", COMPILER_SETTINGS)
def test_runner_environment_overrides_the_compiler_setting(
    setting: str, tmp_path: Path, runner: SandboxRunner, make_project: MakeProject
) -> None:
    project = make_project(
        "compiler",
        {
            "foundry.toml": f"{DIRECT_MOUNT_CONFIG}{setting}\n",
            "tools/solc": "not a compiler\n",
            "src/Vault.sol": SOURCE,
        },
    )
    (project / "tools" / "solc").chmod(0o755)
    scratch = make_scratch_dir(tmp_path)
    build = foundry.build(runner, project, scratch_dir=scratch)

    assert build.succeeded, build.errors
    assert compiler_of_artifact(scratch) == pinned_compiler()
