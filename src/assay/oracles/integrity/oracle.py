"""IntegrityOracle: protects the evidence and the rules of the game.

The oracle judges a patch that ingest has already tried to apply (`PreparedPatch`). It runs
nothing in the sandbox. It fails when

- the patch was not accepted: path traversal, a symlink, a binary file, a protected path, a path
  outside the scope, a malformed or oversized patch, a patch that does not apply, or a patched
  tree that ingest rejects;
- a protected path (tests, PoC, harness, configuration) differs between the vulnerable and the
  patched revision;
- a content check finds a vacuous patch, special-casing or environment sniffing
  (`assay.oracles.integrity.checks`).

Reasons in `HARD_REASONS` are integrity violations: verification stops and nothing from the
patch runs.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final

from pydantic import JsonValue

from assay.ingest import Snapshot, tree_digest
from assay.ingest.patch import PatchPolicy, PreparedPatch, in_scope, is_protected
from assay.ledger import OracleName, RevisionKind, Verdict
from assay.oracles.base import Execution, OracleResult, Reason, reason
from assay.oracles.integrity.checks import (
    sniffing_reasons,
    special_casing_reasons,
    vacuous_reasons,
)
from assay.oracles.runtree import CONFIG_FILE, Harness

HARD_REASONS: Final = frozenset(
    {
        "path_traversal",
        "symlink",
        "binary_file",
        "protected_path_modified",
        "out_of_scope",
        "ingest_rejected",
    }
)
CLAIM: Final = (
    "The patch stays within its scope, leaves the protected paths unchanged, and shows none of "
    "the checked signs of a vacuous, special-cased or environment-sniffing change."
)
_SOLIDITY: Final = ".sol"


@dataclass(frozen=True, slots=True)
class IntegrityContext:
    base: Snapshot
    """The vulnerable revision."""
    poc: Snapshot
    """The PoC directory."""
    prepared: PreparedPatch
    policy: PatchPolicy
    harness: Harness


def _sources(snapshot: Snapshot, policy: PatchPolicy) -> dict[str, str]:
    return {
        item.path: (snapshot.tree_dir / item.path).read_bytes().decode("utf-8", errors="replace")
        for item in snapshot.files
        if item.path.endswith(_SOLIDITY) and in_scope(item.path, policy)
    }


def _protected(snapshot: Snapshot, policy: PatchPolicy) -> dict[str, str]:
    """Protected files of a revision and their sha256. The rewritten config is the same in
    every snapshot and is left out."""
    return {
        item.path: item.sha256
        for item in snapshot.files
        if item.path != CONFIG_FILE and is_protected(PurePosixPath(item.path), policy)
    }


def _digest(files: Mapping[str, str]) -> str:
    return tree_digest(files.items())


class IntegrityOracle:
    name = OracleName.INTEGRITY

    def run(self, context: IntegrityContext) -> OracleResult:
        prepared = context.prepared
        reasons: list[Reason] = [
            reason(problem.code, problem.detail, path=problem.path) for problem in prepared.problems
        ]
        base_protected = _protected(context.base, context.policy)
        trace: dict[str, JsonValue] = {
            "patch_sha256": prepared.sha256,
            "changed_paths": [] if prepared.patch is None else list(prepared.patch.paths),
            "scope": list(context.policy.scope),
            "protected": list(context.policy.protected),
            "vulnerable_tree_sha256": context.base.tree_sha256,
            "vulnerable_protected_sha256": _digest(base_protected),
            "poc_tree_sha256": context.poc.tree_sha256,
            "harness_sha256": context.harness.sha256,
        }
        patched = prepared.snapshot
        if patched is not None and prepared.patch is not None:
            trace["patched_tree_sha256"] = patched.tree_sha256
            patched_protected = _protected(patched, context.policy)
            trace["patched_protected_sha256"] = _digest(patched_protected)
            changed = sorted(
                path
                for path in base_protected.keys() | patched_protected.keys()
                if base_protected.get(path) != patched_protected.get(path)
            )
            for path in changed:
                reasons.append(
                    reason(
                        "protected_path_modified",
                        "protected file differs from the vulnerable revision",
                        path=path,
                    )
                )
            base_sources = _sources(context.base, context.policy)
            patched_sources = _sources(patched, context.policy)
            poc_sources = {
                item.path: (context.poc.tree_dir / item.path)
                .read_bytes()
                .decode("utf-8", errors="replace")
                for item in context.poc.files
                if item.path.endswith(_SOLIDITY)
            }
            reasons += vacuous_reasons(base_sources, patched_sources)
            reasons += special_casing_reasons(
                base_sources, patched_sources, poc_sources, prepared.patch.added_lines()
            )
            reasons += sniffing_reasons(patched_sources)
        reasons = list(dict.fromkeys(reasons))
        verdict = Verdict.FAIL if reasons else Verdict.PASS
        if reasons:
            codes = ", ".join(dict.fromkeys(item.code for item in reasons))
            summary = f"{len(reasons)} integrity problem(s): {codes}"
        else:
            summary = (
                "patch within scope; protected paths unchanged; no vacuous change, "
                "special-casing or environment sniffing detected"
            )
        execution = Execution(
            revision=RevisionKind.PATCHED if patched is not None else RevisionKind.VULNERABLE,
            claim=CLAIM,
            argv=(),
            seed=None,
            exit_code=None,
            verdict=verdict,
            reasons=tuple(reasons),
            summary=summary,
            trace=trace,
        )
        return OracleResult(
            oracle=self.name,
            verdict=verdict,
            reasons=tuple(reasons),
            summary=summary,
            executions=(execution,),
        )


def is_hard(result: OracleResult) -> bool:
    """True when the result holds an integrity violation that stops verification."""
    return any(item.code in HARD_REASONS for item in result.reasons)
