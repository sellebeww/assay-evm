"""A stand-in for the symbolic runner: answers `halmos` runs without Docker.

Every argv still goes through the real allowlist. `answer(revision, prefix)` returns the JSON
report Halmos would write, or one of `timeout`, `oom`, `build_failed`, `no_report`.
`revision_of(tree)` tells which revision a run tree holds.
"""

import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from assay.ledger import RevisionKind
from assay.oracles.symbolic import HalmosSettings, halmos_argv
from assay.sandbox import SandboxResult, SandboxRunner, check_argv

HalmosAnswer = bytes | str
IMAGE_ID = "sha256:" + "5a" * 32


def model(values: dict[str, tuple[str, int, int]], valid: bool = True) -> dict[str, Any]:
    """A Halmos model: name -> (Solidity type, size in bits, value)."""
    return {
        "model": {
            f"p_{name}_{kind}_{index:02}_00": {
                "full_name": f"p_{name}_{kind}_{index:02}_00",
                "variable_name": name,
                "solidity_type": kind,
                "smt_type": f"BitVec {bits}",
                "size_bits": bits,
                "value": value,
            }
            for index, (name, (kind, bits, value)) in enumerate(values.items())
        },
        "is_valid": valid,
    }


def entry(name: str, code: int, models: Sequence[dict[str, Any]] = (), loops: int = 0) -> Any:
    return {
        "name": name,
        "exitcode": code,
        "num_models": len(models),
        "models": list(models),
        "num_paths": [6, 4, 0],
        "time": [0.5, 0.25, 0.25],
        "num_bounded_loops": loops,
    }


def report(tests: dict[str, list[Any]], exitcode: int = 0) -> bytes:
    return json.dumps({"exitcode": exitcode, "test_results": tests}).encode()


def sandbox_result(**changes: Any) -> SandboxResult:
    fields: dict[str, Any] = {
        "argv": halmos_argv("check_", HalmosSettings()),
        "exit_code": 0,
        "stdout": "",
        "stderr": "",
        "truncated": False,
        "timed_out": False,
        "oom_killed": False,
        "duration_s": 3.0,
        "image_id": IMAGE_ID,
    }
    fields.update(changes)
    return SandboxResult(**fields)


def target_revision(tree: Path) -> RevisionKind:
    vulnerable = "VULNERABLE" in (tree / "src" / "Target.sol").read_text()
    return RevisionKind.VULNERABLE if vulnerable else RevisionKind.PATCHED


class FakeHalmos(SandboxRunner):
    """Answers `halmos` runs: `answer(revision, prefix)` gives the report or a problem."""

    def __init__(
        self,
        answer: Callable[[RevisionKind, str], HalmosAnswer],
        revision_of: Callable[[Path], RevisionKind] = target_revision,
    ) -> None:
        super().__init__(docker="unused")
        self.answer = answer
        self.revision_of = revision_of
        self.calls: list[tuple[str, ...]] = []

    def image_id(self) -> str:
        return IMAGE_ID

    def image_labels(self) -> dict[str, str]:
        return {"assay.halmos.version": "0.3.3"}

    def run(
        self,
        argv: Sequence[str],
        *,
        project_dir: Path,
        scratch_dir: Path,
        timeout_s: float | None = None,
    ) -> SandboxResult:
        command = check_argv(argv)
        assert command[0] == "halmos"
        self.calls.append(command)
        assert (project_dir / "baseline").is_dir()
        assert (project_dir / "test" / "symbolic").is_dir()
        revision = self.revision_of(project_dir)
        answer = self.answer(revision, command[command.index("--function") + 1])
        fields: dict[str, Any] = {"exit_code": 1}
        if answer == "timeout":
            fields.update(timed_out=True, exit_code=-9)
        elif answer == "oom":
            fields.update(oom_killed=True, exit_code=137)
        elif answer == "build_failed":
            fields.update(stderr="Build failed: forge build")
        elif isinstance(answer, bytes):
            (scratch_dir / "halmos.json").write_bytes(answer)
        return sandbox_result(argv=command, **fields)
