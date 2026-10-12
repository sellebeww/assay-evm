"""SandboxRunner limits against the real runner image."""

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from assay.ingest import Snapshot
from assay.sandbox import SandboxLimits, SandboxRunner, make_scratch_dir

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("runner")]

SnapshotOf = Callable[[Path], Snapshot]
MakeProject = Callable[[str, dict[str, str]], Path]

HEADER = "// SPDX-License-Identifier: MIT\npragma solidity 0.8.36;\n"

SPIN_TEST = (
    HEADER
    + """
contract SpinTest {
    function testFuzz_Spin(uint256 x) public pure {
        for (uint256 i = 0; i < 10_000; ++i) {
            unchecked {
                x = x * 31 + i;
            }
        }
    }
}
"""
)

# Raises forge's EVM gas and memory limits so that the allocation below reaches the
# container's memory limit. The snapshot configuration keeps forge's defaults, which stop
# the allocation inside the EVM, so this project is mounted directly instead of through ingest.
MEMORY_CONFIG = """\
[profile.default]
src = "src"
test = "test"
libs = []
out = "/work/scratch/out"
cache_path = "/work/scratch/cache"
gas_limit = 9223372036854775807
memory_limit = 4000000000
"""

MEMORY_TEST = (
    HEADER
    + """
contract MemoryTest {
    function test_Allocate() public pure {
        bytes memory data = new bytes(1_500_000_000);
        data[0] = 0x01;
    }
}
"""
)


def test_timeout_kills_and_removes_the_container(
    tmp_path: Path, snapshot_of: SnapshotOf, make_project: MakeProject
) -> None:
    tree = snapshot_of(make_project("spin", {"test/Spin.t.sol": SPIN_TEST})).tree_dir
    runner = SandboxRunner(limits=SandboxLimits(timeout_s=8))
    before = runner.list_containers()

    result = runner.run(
        ["forge", "test", "--fuzz-runs", "9999999"],
        project_dir=tree,
        scratch_dir=make_scratch_dir(tmp_path),
    )

    assert result.timed_out
    assert 8 <= result.duration_s < 60
    assert runner.list_containers() == before


def test_output_is_truncated_at_the_limit(
    tmp_path: Path, snapshot_of: SnapshotOf, data_dir: Path
) -> None:
    limit = 64 * 1024
    runner = SandboxRunner(limits=SandboxLimits(output_limit_bytes=limit))
    # A forced JSON build of the smoke project prints well over 1 MB of artifacts.
    result = runner.run(
        ["forge", "build", "--json", "--force"],
        project_dir=snapshot_of(data_dir / "smoke").tree_dir,
        scratch_dir=make_scratch_dir(tmp_path),
    )

    assert result.truncated
    assert result.exit_code == 0
    assert 0 < len(result.stdout) <= limit
    assert not result.timed_out


def test_out_of_memory_kill_is_reported(tmp_path: Path, make_project: MakeProject) -> None:
    project = make_project(
        "memory", {"foundry.toml": MEMORY_CONFIG, "test/Memory.t.sol": MEMORY_TEST}
    )
    runner = SandboxRunner(limits=SandboxLimits(memory_mib=512))
    result = runner.run(
        ["forge", "test"], project_dir=project, scratch_dir=make_scratch_dir(tmp_path)
    )

    assert result.oom_killed
    assert result.exit_code == 137
    assert not result.timed_out


def test_forge_inspect_reports_layout_and_abi(
    runner: SandboxRunner, tmp_path: Path, snapshot_of: SnapshotOf, data_dir: Path
) -> None:
    tree = snapshot_of(data_dir / "smoke").tree_dir
    scratch = make_scratch_dir(tmp_path)

    layout = runner.run(
        ["forge", "inspect", "src/Counter.sol:Counter", "storageLayout", "--json"],
        project_dir=tree,
        scratch_dir=scratch,
    )
    abi = runner.run(
        ["forge", "inspect", "src/Counter.sol:Counter", "abi", "--json"],
        project_dir=tree,
        scratch_dir=scratch,
    )

    assert layout.exit_code == 0, layout.stderr
    storage = json.loads(layout.stdout)["storage"]
    assert [(item["label"], item["slot"], item["offset"]) for item in storage] == [
        ("number", "0", 0)
    ]
    assert abi.exit_code == 0, abi.stderr
    assert sorted(item["name"] for item in json.loads(abi.stdout)) == ["increment", "number"]
