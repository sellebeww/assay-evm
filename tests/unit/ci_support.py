"""Helpers for the tests of `assay ci verify`: a throwaway git repository."""

import os
import subprocess
from pathlib import Path

from report_support import _rows

from assay.ledger import FinalVerdict
from assay.orchestrator.models import ORACLE_ORDER, Bounds, Inputs, Timing, VerifyReport

GIT_ENV = {
    "PATH": os.environ.get("PATH", os.defpath),
    "HOME": "/nonexistent",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.invalid",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
}

VAULT = """// INTENTIONALLY VULNERABLE: test fixture, do not deploy
pragma solidity ^0.8.20;

contract Vault {
    uint256 public total;
}
"""


def git(repo: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", *args], cwd=repo, env=GIT_ENV, capture_output=True, check=True, text=True
    )
    return done.stdout.strip()


def init_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q", "-b", "main")
    return path


def write(root: Path, relative: str, content: str | bytes) -> None:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, str):
        target.write_text(content, encoding="utf-8")
    else:
        target.write_bytes(content)


def commit(repo: Path, message: str = "change") -> str:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message, "--allow-empty")
    return git(repo, "rev-parse", "HEAD")


def make_report(
    payload: str = "", verdict: str = "REJECTED", integrity: bool = False
) -> VerifyReport:
    """A synthetic verification report; `payload` replaces every text that could come from a PR."""
    final = FinalVerdict(verdict)
    return VerifyReport(
        inputs=Inputs(
            base_tree_sha256="1" * 64,
            poc_tree_sha256="2" * 64,
            patch_sha256="3" * 64,
            patched_tree_sha256="4" * 64,
            harness_sha256="5" * 64,
        ),
        oracles=_rows(payload, final),
        final_verdict=final,
        reasons=("variant_found",) if final is FinalVerdict.REJECTED else (),
        integrity_violation=integrity,
        bounds=Bounds(
            exploit_replays_per_revision=3,
            profile="quick",
            fuzz_seed="0x1",
            fuzz_runs=16,
            interface_contracts=("src/Vault.sol:Vault",),
            oracles_run=tuple(ORACLE_ORDER),
            oracles_not_run=(),
            variant=None,
        ),
        bounds_statement=payload or "exploit: 3 replays per revision; variant: profile quick",
        timing=Timing(total_s=1.5, oracles={}, variant=None),
        evidence_level="E3" if final is FinalVerdict.VERIFIED_WITHIN_BOUNDS else "E1",
        annotations=(),
    )
