"""Synthetic evidence bundles for the report tests: fixed content, optionally hostile text.

`build_bundle` writes a valid bundle (every file listed in the manifest with its sha256) without
running anything. With a `payload`, every place that carries text from a target project, a patch,
a PoC or a model holds the payload instead of a harmless sentence.
"""

import hashlib
import json
from pathlib import Path
from typing import Literal

from assay.ledger import FinalVerdict, OracleName, Verdict
from assay.oracles.base import Reason
from assay.orchestrator.fix import (
    FixHistory,
    HistoryAttempt,
    HistoryBounds,
    HistoryFinal,
    HistoryLimits,
    HistoryOracle,
)
from assay.orchestrator.models import Bounds, Inputs, OracleRow, Timing
from assay.report.bundle import (
    Environment,
    Manifest,
    ManifestFile,
    ManifestSettings,
    Sanitizer,
    manifest_bytes,
)

LOCK = "# pinned\nFOUNDRY_VERSION=v1.8.4\nSOLC_VERSION=0.8.36\n"
HEX = "ab" * 32


def _poc(payload: str) -> str:
    note = payload or "reenter once and drain the vault"
    return (
        "// INTENTIONALLY VULNERABLE: test fixture, do not deploy\n"
        "contract VaultReentrancy is AssayPoC {\n"
        f"    // {note}\n"
        f"    function {('attack' if not payload else 'attack_')}() external {{}}\n"
        f'    string constant NOTE = "{note}";\n'
        "}\n"
    )


def _diff(payload: str) -> str:
    note = payload or "guard the external call"
    return (
        "--- a/src/Vault.sol\n"
        "+++ b/src/Vault.sol\n"
        "@@ -3,5 +3,6 @@ contract Vault {\n"
        "     uint256 public total;\n"
        f"-    // old: {note}\n"
        "--- removed line that starts with dashes\n"
        f"+    // new: {note}\n"
        "+    bool private locked;\n"
        "     function withdraw() external {\n"
        "         total -= 1;\n"
        "     }\n"
    )


def _reasons(payload: str) -> tuple[Reason, ...]:
    detail = payload or "a variant of the exploit reproduced on the patched revision"
    return (Reason(code="variant_found", detail=detail, path=payload or "src/Vault.sol", line=7),)


def _rows(payload: str, verdict: FinalVerdict) -> tuple[OracleRow, ...]:
    fail = verdict is FinalVerdict.REJECTED
    unsure = verdict is FinalVerdict.INCONCLUSIVE
    rows = []
    for oracle in (
        OracleName.INTEGRITY,
        OracleName.EXPLOIT,
        OracleName.VARIANT,
        OracleName.BEHAVIOR,
        OracleName.REGRESSION,
    ):
        row_verdict = Verdict.PASS
        reasons: tuple[Reason, ...] = ()
        if oracle is OracleName.VARIANT and fail:
            row_verdict, reasons = Verdict.FAIL, _reasons(payload)
        if oracle is OracleName.REGRESSION and unsure:
            row_verdict = Verdict.INCONCLUSIVE
            reasons = (Reason(code="no_target_contracts", detail=payload or "none found"),)
        rows.append(
            OracleRow(
                oracle=oracle,
                status="ran",
                verdict=row_verdict,
                reasons=reasons,
                summary=payload or f"{oracle.value} finished",
                warnings=(
                    (Reason(code="function_added", detail=payload or "a new function"),)
                    if oracle is OracleName.REGRESSION
                    else ()
                ),
            )
        )
    return tuple(rows)


def _history(payload: str, verdict: FinalVerdict) -> FixHistory:
    text = payload or "the patch of attempt 2 passed every oracle"
    bounds = HistoryBounds(profile="quick", fuzz_seed="0x1", fuzz_runs=16, symbolic=False)
    return FixHistory(
        vuln_class="reentrancy",
        limits=HistoryLimits(
            max_attempts=3, max_changed_lines=40, max_files=2, max_diff_bytes=8000, scope=("src",)
        ),
        loop_bounds=bounds,
        held_out_bounds=bounds,
        attempts=(
            HistoryAttempt(
                number=1,
                outcome="evaluated",
                diff_sha256=HEX,
                in_loop_verdict=FinalVerdict.REJECTED,
                oracles=(
                    HistoryOracle(
                        oracle="variant",
                        status="ran",
                        verdict="FAIL",
                        reasons=_reasons(payload),
                    ),
                ),
            ),
            HistoryAttempt(
                number=2,
                outcome="model_output_invalid",
                diff_sha256=None,
                in_loop_verdict=None,
                problems=(Reason(code="not_a_diff", detail=text),),
            ),
        ),
        final=HistoryFinal(
            decision="held_out_run",
            verdict=verdict,
            in_loop_verdict=verdict,
            differs_from_in_loop=False,
            decisive_attempt=2,
            diff_sha256=HEX,
            reasons=(),
            stopped=None,
            attempts_used=2,
            statement=text,
        ),
    )


def build_bundle(
    root: Path,
    *,
    payload: str = "",
    verdict: FinalVerdict = FinalVerdict.REJECTED,
    fix_loop: bool = False,
    variant_poc: bool = True,
    tool_name: str = "foundry",
) -> Path:
    """Write the bundle into `root` (created) and return it."""
    contents: dict[str, bytes] = {
        "patch.diff": _diff(payload).encode(),
        "poc/VaultReentrancy.t.sol": _poc(payload).encode(),
        "base/src/Vault.sol": b"// INTENTIONALLY VULNERABLE: test fixture, do not deploy\n",
        "harness/AssayExploit.sol": b"// harness\n",
        "evidence/variant/result.json": b"{}\n",
    }
    if variant_poc:
        contents["evidence/variant/variant_poc.t.sol"] = (
            _poc(payload).replace("VaultReentrancy", "VariantPoc").encode()
        )
    history = _history(payload, verdict)
    if fix_loop:
        contents["fix/history.json"] = history.to_bytes()
    files = tuple(
        ManifestFile(path=path, sha256=hashlib.sha256(data).hexdigest(), size=len(data))
        for path, data in sorted(contents.items())
    )
    level: Literal["E1", "E2", "E3"] = {
        FinalVerdict.REJECTED: "E1",
        FinalVerdict.INCONCLUSIVE: "E2",
        FinalVerdict.VERIFIED_WITHIN_BOUNDS: "E3",
    }[verdict]
    manifest = Manifest(
        assay_version="0.0.0-test",
        environment=Environment(
            image_digest="sha256:" + "1" * 64,
            tool_versions={tool_name: payload or "v1.8.4", "solc": "0.8.36"},
            versions_lock=LOCK,
            versions_lock_sha256=hashlib.sha256(LOCK.encode()).hexdigest(),
        ),
        settings=ManifestSettings(
            exploit_replays=3,
            profile="quick",
            fuzz_seed="0x1",
            fuzz_runs=None,
            scope=("src",),
            protected=("test",),
        ),
        inputs=Inputs(
            base_tree_sha256="1" * 64,
            poc_tree_sha256="2" * 64,
            patch_sha256="3" * 64,
            patched_tree_sha256="4" * 64,
            harness_sha256="5" * 64,
        ),
        oracles=_rows(payload, verdict),
        final_verdict=verdict,
        reasons=("variant_found",) if verdict is FinalVerdict.REJECTED else (),
        integrity_violation=False,
        bounds=Bounds(
            exploit_replays_per_revision=3,
            profile="quick",
            fuzz_seed="0x1",
            fuzz_runs=16,
            interface_contracts=("src/Vault.sol:Vault",),
            oracles_run=(
                OracleName.INTEGRITY,
                OracleName.EXPLOIT,
                OracleName.VARIANT,
                OracleName.BEHAVIOR,
                OracleName.REGRESSION,
            ),
            oracles_not_run=(),
            variant=None,
        ),
        bounds_statement=payload or "exploit: 3 replays per revision; variant: profile quick",
        timing=Timing(total_s=1.5, oracles={}, variant=None),
        evidence_level=level,
        annotations=(payload,) if payload else (),
        files=files,
    )
    root.mkdir(parents=True)
    for path, data in contents.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    (root / "manifest.json").write_bytes(manifest_bytes(manifest, Sanitizer([])))
    return root


def rewrite_manifest_files(root: Path) -> None:
    """Recompute the listed hashes after a test edited bundle files, so the bundle stays valid."""
    path = root / "manifest.json"
    document = json.loads(path.read_text())
    for item in document["files"]:
        data = (root / item["path"]).read_bytes()
        item["sha256"] = hashlib.sha256(data).hexdigest()
        item["size"] = len(data)
    path.write_text(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
