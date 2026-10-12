"""Foundry adapter logic with a stand-in runner (no Docker)."""

import stat
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from assay.analyzers import foundry
from assay.sandbox import ArgvRejected, SandboxResult, SandboxRunner

DATA = Path(__file__).resolve().parents[1] / "data" / "forge"
IMAGE_ID = "sha256:" + "cd" * 32


class StubRunner(SandboxRunner):
    def __init__(self, **result: Any) -> None:
        super().__init__(docker="unused")
        self.result = result
        self.calls: list[tuple[tuple[str, ...], Path, Path]] = []
        self.scratch_modes: list[int] = []

    def run(self, argv: Sequence[str], *, project_dir: Path, scratch_dir: Path) -> SandboxResult:
        self.calls.append((tuple(argv), project_dir, scratch_dir))
        self.scratch_modes.append(stat.S_IMODE(scratch_dir.stat().st_mode))
        fields: dict[str, Any] = {
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "truncated": False,
            "timed_out": False,
            "oom_killed": False,
            "duration_s": 1.0,
            "image_id": IMAGE_ID,
        }
        fields.update(self.result)
        return SandboxResult(argv=tuple(argv), **fields)


def test_results_are_parsed_and_failures_are_a_result(tmp_path: Path) -> None:
    stub = StubRunner(exit_code=1, stdout=(DATA / "probe-test.json").read_text(encoding="utf-8"))
    run = foundry.test(stub, tmp_path)

    assert run.argv == foundry.TEST_ARGV == ("forge", "test", "--json", "-vv", "--threads", "1")
    assert run.exit_code == 1
    assert run.image_id == IMAGE_ID
    assert (run.summary.passed, run.summary.failed, run.summary.skipped) == (4, 2, 1)
    assert "duration" not in run.model_dump_json()


def test_a_fresh_writable_scratch_directory_is_used(tmp_path: Path) -> None:
    stub = StubRunner(stdout="{}")
    foundry.test(stub, tmp_path)
    foundry.test(stub, tmp_path)
    (_, project, first), (_, _, second) = stub.calls
    assert project == tmp_path
    assert first != second
    assert stub.scratch_modes == [0o777, 0o777]
    assert not first.exists()


def test_given_scratch_directory_is_used(tmp_path: Path) -> None:
    stub = StubRunner(stdout="{}")
    foundry.test(stub, tmp_path / "project", scratch_dir=tmp_path)
    assert stub.calls[0][2] == tmp_path


def test_filters_are_added_to_the_argv(tmp_path: Path) -> None:
    stub = StubRunner(stdout="{}")
    foundry.test(stub, tmp_path, match_test="test_A", match_contract="ATest", match_path="test/*")
    assert stub.calls[0][0] == (
        *foundry.TEST_ARGV,
        "--match-test",
        "test_A",
        "--match-contract",
        "ATest",
        "--match-path",
        "test/*",
    )


def test_unsafe_filter_is_rejected_before_running(tmp_path: Path) -> None:
    stub = StubRunner()
    with pytest.raises(ArgvRejected):
        foundry.test(stub, tmp_path, match_test="x; rm -rf /")
    assert stub.calls == []


def test_no_matching_test_gives_an_empty_result(tmp_path: Path) -> None:
    run = foundry.test(StubRunner(exit_code=0, stdout=""), tmp_path)
    assert run.suites == ()
    assert run.summary.passed == 0


@pytest.mark.parametrize(
    ("result", "problem"),
    [
        ({"exit_code": 1, "stdout": "", "stderr": "Error: Compiler run failed"}, "failed"),
        ({"exit_code": 0, "stdout": '{"partial', "truncated": True}, "truncated"),
        ({"exit_code": 1, "stdout": "not json"}, "invalid"),
    ],
)
def test_unusable_output_is_an_error(tmp_path: Path, result: dict[str, Any], problem: str) -> None:
    with pytest.raises(foundry.ForgeOutputError) as info:
        foundry.test(StubRunner(**result), tmp_path)
    assert info.value.problem == problem
    assert info.value.result.argv == foundry.TEST_ARGV


def test_timeout_is_never_a_result(tmp_path: Path) -> None:
    with pytest.raises(foundry.ForgeTimeout):
        foundry.test(StubRunner(timed_out=True, exit_code=137, stdout="{}"), tmp_path)


def test_out_of_memory_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(foundry.ForgeOutOfMemory):
        foundry.test(StubRunner(oom_killed=True, exit_code=137), tmp_path)


def test_successful_build_does_not_parse_its_output(tmp_path: Path) -> None:
    run = foundry.build(StubRunner(exit_code=0, stdout='{"contracts": ', truncated=True), tmp_path)
    assert run.succeeded
    assert run.errors == ()
    assert run.argv == foundry.BUILD_ARGV == ("forge", "build", "--json")


def test_failed_build_reports_compiler_errors(tmp_path: Path) -> None:
    stdout = (DATA / "broken-build.json").read_text(encoding="utf-8")
    run = foundry.build(StubRunner(exit_code=1, stdout=stdout), tmp_path)
    assert not run.succeeded
    assert [(error.type, error.file) for error in run.errors] == [
        ("DeclarationError", "test/Broken.t.sol")
    ]


def test_failed_build_without_output_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(foundry.ForgeOutputError) as info:
        foundry.build(StubRunner(exit_code=1, stdout=""), tmp_path)
    assert info.value.problem == "failed"


def test_fuzz_settings_are_added_to_the_argv(tmp_path: Path) -> None:
    stub = StubRunner(stdout="{}")
    foundry.test(stub, tmp_path, match_test="^test_replay[(][)]$", fuzz_seed="0x1", fuzz_runs=64)
    assert stub.calls[0][0] == (
        *foundry.TEST_ARGV,
        "--match-test",
        "^test_replay[(][)]$",
        "--fuzz-seed",
        "0x1",
        "--fuzz-runs",
        "64",
    )
    with pytest.raises(ArgvRejected):
        foundry.forge_test_argv(fuzz_seed="1; rm -rf /")


def test_inspect_returns_the_output_unparsed(tmp_path: Path) -> None:
    stub = StubRunner(stdout='{"E()": "0x00"}')
    text = foundry.inspect(stub, tmp_path, "assay/AssayExploit.sol:AssayExploit", "events")
    assert text == '{"E()": "0x00"}'
    assert stub.calls[0][0] == (
        "forge",
        "inspect",
        "assay/AssayExploit.sol:AssayExploit",
        "events",
        "--json",
    )


@pytest.mark.parametrize(
    ("result", "problem"), [({"exit_code": 1}, "failed"), ({"truncated": True}, "truncated")]
)
def test_inspect_failures_are_errors(tmp_path: Path, result: dict[str, Any], problem: str) -> None:
    with pytest.raises(foundry.ForgeOutputError) as info:
        foundry.inspect(StubRunner(**result), tmp_path, "A", "abi")
    assert info.value.problem == problem
    with pytest.raises(ArgvRejected):
        foundry.forge_inspect_argv("../A.sol:A", "abi")
