# Claims and evidence

Every claim that the README and the documentation make about Assay is listed here with the
evidence for it and a status. `make claims-check` (`tools/claims_check.py`) verifies that every
evidence path exists and that every claim area the README marks is present in the table; it runs
as part of `make check`.

The status values are:

- **met**: the repository backs the claim with the cited tests or generated results.
- **bounded**: the claim holds only within stated limits (seeds, runs, the pinned tools, a
  synthetic sample); the evidence states the bounds.
- **partial**: part of the claim is backed; the evidence says what is not.
- **not-covered**: the claim is a statement of a limit or of something deliberately not done.

Evidence paths are files, directories, or `path::name` for one test in a file. A claim is only as
strong as its evidence; several claims are bounded or partial on purpose, and the limits are in
[the limitations](limitations.md), [the threat model](threat-model.md) and
[the sandbox](sandbox.md).

| Area | Claim | Evidence | Status |
|---|---|---|---|
| verdict-meaning | `VERIFIED_WITHIN_BOUNDS` means every required oracle passed and no variant was found within the recorded bounds; it is not a proof of absence. | `docs/limitations.md`, `src/assay/cli/verify.py::LIMITS`, `docs/oracles.md` | bounded |
| forbidden-vocabulary | Output and docs never call a result secure, safe, proven, guaranteed or unhackable except to deny it. | `tools/docs_check.py::FORBIDDEN`, `tests/unit/test_docs_check.py` | met |
| oracle-integrity | The IntegrityOracle refuses an out-of-scope, protected-path, vacuous, special-cased or environment-sniffing patch before anything runs. | `src/assay/oracles/integrity/oracle.py`, `tests/unit/test_oracle_integrity.py`, `tests/unit/test_integrity_environment_attacks.py` | partial |
| oracle-exploit | The exploit oracle counts a reproduction only from a harness event the test contract emitted, never console output; a timeout is never a pass. | `tests/unit/test_oracle_exploit.py::test_a_timeout_is_never_a_pass`, `tests/security/test_oracle_forgery.py` | met |
| oracle-variant | A variant counts only after a generated test reproduced it three times; a passing search is a bounded statement about the inputs tried. | `src/assay/oracles/variant/oracle.py`, `tests/unit/test_oracle_variant.py`, `docs/variant-power.md` | bounded |
| oracle-behavior | The benign tests pass with the same recorded results on both revisions; a patched timeout is never a pass. | `tests/unit/test_oracle_behavior.py::test_a_patched_timeout_is_never_a_pass`, `tests/unit/test_oracle_behavior.py` | met |
| oracle-regression | A breaking change to storage layout, ABI or events rejects the patch. | `src/assay/oracles/regression/interface.py`, `tests/unit/test_oracle_regression.py` | met |
| ledger-promotion | A claim becomes trusted or refuted only through an oracle run with a matching verdict, enforced by SQLite triggers and checked invariants. | `src/assay/ledger/invariants.py`, `tests/unit/test_ledger_invariants.py`, `tests/unit/test_ledger_lifecycle.py` | met |
| ledger-audit | The audit log is append-only and hash-chained; an edited, rehashed, reordered or deleted row is detected. | `src/assay/ledger/audit.py`, `tests/unit/test_ledger_audit.py` | met |
| bundle-tamper | Replay rehashes every file against the manifest and re-runs the oracles; a changed file, or a manifest that claims another verdict, is caught. | `src/assay/report/replay.py`, `tests/unit/test_bundle_replay.py::test_a_tampered_bundle_exits_5_and_runs_nothing`, `tests/unit/test_bundle_replay.py::test_a_manifest_that_claims_another_verdict_does_not_match` | bounded |
| determinism | The same inputs and image give byte-identical verify manifests, scan JSON, HTML report and benchmark reports. | `tests/integration/test_determinism.py`, `tests/unit/test_bundle_replay.py::test_two_verifications_give_byte_identical_manifests_apart_from_timing` | met |
| benchmark | With the `standard` profile the full configuration's verdicts equal the labels for 32 of 32 development and 32 of 32 held-out patches; held-out cases were written after the oracle freeze by the same author. | `docs/results.md`, `docs/results.json`, `bench/PROTOCOL.md` | bounded |
| matrix | `assay verify` matches the label of all 32 development patches with the `standard` profile. | `docs/classification-matrix.md`, `tests/integration/test_matrix.py` | bounded |
| variant-power | The variant search found a variant for all 8 overfit patches and none for the 8 good patches in the recorded run. | `docs/variant-power.md`, `tests/integration/test_variant.py` | bounded |
| static-coverage | Slither and Aderyn together map a finding to the class for 6 of 8 fixtures; findings are candidate hints at evidence level E0. | `docs/static-coverage.md`, `tests/integration/test_analyzers.py` | bounded |
| symbolic | For three fixtures the overfit patch got a confirmed counterexample and no good patch did within loop bound 3; for rounding every run was out of memory and inconclusive. | `docs/symbolic.md`, `tests/integration/test_symbolic.py` | partial |
| model-untrusted | A model only proposes; its output is validated, a generated PoC passes a default-deny checker before it runs, and nothing it says changes a status. | `tests/security/test_injection.py`, `tests/security/test_fix_injection.py`, `tests/unit/test_poc_checker.py` | met |
| redaction | Code goes to a model endpoint only with `--allow-llm`, after allowlist filtering and pattern-based redaction of keys, paths and user names; the key lives only in the environment. | `tests/unit/test_llm_redact.py`, `src/assay/llm/redact.py` | partial |
| report-safety | The HTML report escapes project, patch and model text, has no JavaScript and a `default-src 'none'` content security policy. | `tests/unit/test_report_html.py` | met |
| ci-safety | `assay ci verify` uses no model and no secret, refuses unsafe diffs, and the workflows use no `pull_request_target` and pin Actions to full commit SHAs. | `tests/unit/test_github_actions.py`, `tests/unit/test_ci_diff.py`, `tests/unit/test_ci_summary.py` | met |
| sandbox-config | A hostile `foundry.toml`, analyzer or Halmos configuration has no effect; inline configuration is rejected at ingest before Docker is called. | `tests/security/test_s1_project_config.py`, `tests/security/test_s1_analyzer_config.py`, `tests/security/test_s1_halmos_config.py`, `tests/security/test_s2_compiler.py` | met |
| sandbox-isolation | The container has no network beyond loopback, a read-only root, no capabilities, uid 10001, no host environment, and resource limits that contain output, timeouts and fork bombs. | `tests/security/test_s3_s6_container_policy.py`, `tests/security/test_s7_read_only_root.py` | met |
| sandbox-ingest | Symlinks out of the tree, path traversal, special files, oversized trees and unsafe patch paths are rejected at ingest with exit code 5, and an argv outside the allowlist is refused before Docker. | `tests/security/test_s8_ingest_and_argv.py`, `tests/security/test_s8_patches.py`, `tests/unit/test_sandbox_allowlist.py` | met |
| supply-chain | Every tool and dependency is pinned by version and sha256; `pip-audit` found no known vulnerability, and the image scan found none in the Python layers. | `docker/runner/versions.lock`, `docs/audit.md`, `THIRD_PARTY_NOTICES.md` | bounded |
| no-live-chain | Assay runs an offline, in-process EVM only: no mainnet fork, no RPC, no transaction signing or broadcasting. | `docs/limitations.md`, `SECURITY.md` | not-covered |
| environment-variants | The variant search does not randomize the block environment, so a patch that is safe only at the default timestamp, block number, base fee, randomness, coinbase, gas or chain id can still pass. | `docs/limitations.md`, `docs/audit.md` | not-covered |
| no-independent-audit | The audit is a self-audit, not an independent one, and no benchmark uses code from another author. | `docs/audit.md`, `docs/limitations.md` | not-covered |
