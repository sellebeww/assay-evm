# Roadmap

Assay is delivered in eleven phases. Each phase lists its tasks and the condition under which it
is done. A phase is done only when every item in its "Done when" list holds.

## Delivery decisions

These decisions are final and recorded in [ADR 0007](adr/0007-phased-delivery-decisions.md):

1. The VariantOracle is split. The basic version (fuzzing the PoC parameters through Foundry)
   ships in Phase 2. The full version (call sequences, an alternative attacker contract, optional
   Medusa, profiles, invariants) ships in Phase 4.
2. The evidence bundle and `assay replay` ship in Phase 2, not in Phase 7.
3. No server mode, network API or dashboard is built. Phase 10 is the final audit.
4. Names: PyPI distribution `assay-evm`, Python import `assay`, CLI command `assay`.

## Phase 0: Foundations

- [x] ADRs 0001 to 0007 in `docs/adr/`
- [x] Fixture specification (`docs/fixture-spec.md`)
- [x] Roadmap (`docs/roadmap.md`)
- [x] README with "What Assay does not claim"
- [x] Python skeleton: `pyproject.toml`, `src/assay/` with `py.typed`, single-source version
- [x] Typer app with a version command
- [x] `Makefile` with `install`, `lint`, `typecheck`, `test`, `check`, `fmt`, `clean`
- [x] `.gitignore`
- [x] `LICENSE` (MIT, 2026), `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`
- [x] CI workflow (`.github/workflows/ci.yml`) running `make check`, actions pinned to commit SHAs
      (checked with actionlint; first run happens once the repository is on GitHub)
- [x] Dependabot configuration (`uv` and `github-actions`, weekly)

Done when:

- `make check` is green on the skeleton.
- The roadmap and ADRs 0001 to 0007 exist.
- Every public file is self-contained: no references to untracked files, no tool attribution
  footers, no co-author trailers.

## Phase 1: Sandbox and Foundry core

- [x] solc version selected and recorded in `docs/fixture-spec.md` and `versions.lock`
- [x] Runner image `docker/runner/` with pinned versions and `versions.lock`
- [x] `make image` and `make image-check` (smoke project in `tests/data/smoke/`)
- [x] ADR 0008: runner platform (native arm64 or amd64 emulation)
- [x] `SandboxRunner` with argv allowlist and result model
- [x] Ingest: snapshot, `tree_sha256`, `foundry.toml` rewrite, symlink and traversal rejection,
      size and file-count limits
- [x] ADR 0009: inline Foundry configuration is rejected at ingest
- [x] Foundry adapter (build and test through the runner, `forge test --json` parser)
- [x] `assay dev forge-test`
- [ ] Security suite S1 to S8 in `tests/security/` (S1, S2, S7 and S8 done; S3 and S4 are
      covered by integration tests; S5 and S6 open)
- [x] Determinism test on the smoke project
- [x] `make test-integration`
- [x] `make test-security`
- [x] Integration job in CI
- [x] `docs/sandbox.md`, including what the sandbox does not cover

Done when:

- All of S1 to S8 pass against the real runner.
- The smoke project gives byte-identical normalized output across three runs.
- `make check` needs no Docker.

## Phase 2: Ledger and oracles

Status: done. Every item of the "Done when" list below holds; the result of the matrix is in
[`docs/classification-matrix.md`](classification-matrix.md). Two tasks remain open: the command
`assay dev ledger-audit`, and the cross-platform check of `make fixtures-check` for the fixtures
other than `reentrancy/single_function`.

- [x] Ledger: migration 1, state machine, triggers, blob store, hash-chained audit log
- [x] `assay dev ledger-demo`, `ledger-verify`
- [ ] `assay dev ledger-audit`
- [x] Property tests for ledger invariants
- [x] Shared harness `solidity/AssayExploit.sol` (predicates, `AssayPoC`, `recordBehavior`)
- [x] Fixture checker `tools/fixture_check.py` and `make fixtures-check` (plain Foundry only)
- [x] Eight fixtures with four labelled patches each: `reentrancy/single_function`,
      `access_control/missing_modifier`, `unchecked_call/ignored_return`,
      `signature_replay/missing_nonce`, `delegatecall/user_controlled_target`,
      `oracle_manipulation/spot_price`, `dos/payout_loop`, `rounding/share_inflation`
- [x] Runner allowlist extended with `forge inspect` (tested)
- [x] Integration tests of the harness (`tests/integration/test_harness.py`)
- [ ] Cross-platform check of `make fixtures-check` (linux/arm64 against linux/amd64) for all
      eight fixtures (done for `reentrancy/single_function`)
- [x] Oracle run trees as in ADR 0011; `assay verify` rejects a project with a top-level `assay/`
- [x] IntegrityOracle
- [x] ExploitOracle
- [x] VariantOracle, basic version (fixed seed, `--fuzz-runs`, sanity check on the vulnerable
      revision)
- [x] BehaviorOracle
- [x] RegressionOracle
- [x] `assay verify` with exit codes and `--bundle-out` (ADR 0012, ADR 0013)
- [x] Evidence bundle with deterministic `manifest.json`
- [x] `assay replay`
- [x] Classification matrix generator, `make matrix`, `docs/classification-matrix.md`
- [x] `matrix.yml` workflow (manual trigger)
- [x] `docs/oracles.md`

Done when:

- `make fixtures-check` shows 40 rows that all match the ground-truth pattern.
- The matrix reports `MATRIX RESULT: 32/32 match`. Any mismatch is investigated and explained,
  never tuned away.
- Replay works on an intact bundle and rejects a tampered one.
- Two verifications of the same input give byte-identical manifests.

## Phase 3: Static analysis

- [x] Slither and Aderyn in the runner image (ADR 0015: Python from python-build-standalone,
      hash-pinned wheels, Aderyn offline through the svm layout of the pinned solc)
- [x] Adapters with strict parsing and size limits, and `assay dev analyze`
- [x] Ledger migration 2 (`scan`, `observation`)
- [x] Normalizer with stable ids and class mapping file
- [x] Deduplication across tools (ADR 0016)
- [x] SARIF 2.1.0 export validated against the official schema
- [x] `assay scan`
- [x] `make static-coverage` and `docs/static-coverage.md`

Done when:

- Scan is idempotent and deterministic.
- SARIF output validates against the schema.
- No `trusted` claim can come from analyzer output, and a test proves it.
- The coverage table lists the classes the analyzers do not detect.

## Phase 4: Fuzz and symbolic

- [x] Profiles `quick`, `standard`, `thorough` with deterministic seed derivation (ADR 0017)
- [x] Counterexample confirmation (three replays) and generated `variant_poc.t.sol`
- [x] Invariant mode (`AssayInvariant`) for the reentrancy, rounding and dos fixtures
- [x] `make variant-power` and `docs/variant-power.md`
- [x] Halmos and its solver in a symbolic runner image, linux/amd64 only (ADR 0018)
- [x] `solidity/AssayCheck.sol`
- [x] SymbolicOracle (`--symbolic`), with counterexamples confirmed by three Foundry replays
- [x] Bounded equivalence as evidence for the BehaviorOracle (an annotation; it never changes a
      verdict)
- [x] `make symbolic-report` and `docs/symbolic.md`, including unsupported fixtures and why

Optional items, not part of the done condition and left open: an alternative attacker contract,
and Medusa as a second engine. The held-out seed family for final decisions belongs to the fix
loop and is delivered in Phase 6.

Done when:

- `good` patches stay `VERIFIED_WITHIN_BOUNDS` and `overfit` patches stay `REJECTED` under the
  full oracle.
- The bounds statement matches what actually ran.
- Timeouts and solver "unknown" results never become PASS.
- The matrix is re-run with the `standard` profile.

## Phase 5: LLM layer

- [x] OpenAI-compatible client (httpx, temperature 0, timeout, bounded retries)
- [x] Budgets for calls and tokens
- [x] Cassettes: `replay`, `record`, `live`
- [x] Redaction, `--allow-llm` consent, `--llm-dry-run`
- [x] Ledger migration 3 (`model_run`)
- [x] Hypothesizer
- [x] PoC writer with the default-deny static PoC checker
- [x] `assay prove`
- [x] `assay dev llm-ask`
- [x] Injection corpus (`tests/data/injection/`) and oracle-attack tests with an obedient synthetic
      cassette
- [x] `docs/llm.md`

Done when:

- Scan to prove reaches `REPRODUCED` from synthetic cassettes, with no real model.
- Hostile content cannot cause a prohibited action: no execution on the host, no write outside
  `poc/`, no status change without an oracle.
- No code path lets model output raise a status.

## Phase 6: Auto-fix loop

- [x] Patcher (diffs applied only through the sandboxed patch path, within scope and size limits)
- [x] Verification loop with sanitized, truncated, quoted feedback
- [x] Anti-cheating rules: no seeds in prompts, held-out seed family for the final decision,
      special-casing detection
- [x] `assay fix` and `assay run`
- [x] Final bundle with attempt history
- [x] `docs/fix-loop.md`

Done when:

- The two-attempt scenario (overfit rejected, then good accepted) works from cassettes.
- A destructive patch ends `REJECTED` after attempts run out.
- Dangerous diffs are rejected before anything runs.
- Replay of a fix bundle needs no model.

The fix loop is decided by [ADR 0019](adr/0019-fix-loop-ledger-and-held-out-decision.md). It has
been exercised with synthetic cassettes only, in which the fixtures' own patches play the model;
no live model has been evaluated, and nothing here measures how often a model finds a patch that
passes.

## Phase 7: Reports, CLI polish and docs

- [x] `assay report` (self-contained HTML, no JavaScript, CSP)
- [x] `assay doctor`
- [x] `--json` output with schemas in `docs/schemas/`
- [x] `docs/cli.md`
- [x] README rewrite
- [x] `docs/design.md`, `docs/threat-model.md`, `docs/limitations.md`
- [x] `make demo`, `make demo-overfit` and `docs/demo.md`
- [x] Packaging with `uv build`
- [x] `make docs-check` (relative links, vocabulary)

Done when:

- Reports are byte-deterministic and the XSS tests pass.
- Demos run offline from a clean clone after `make image`.
- Every README claim is backed by something in the repository.

## Phase 8: GitHub Action

- [x] `assay ci verify`
- [x] Markdown summary renderer
- [x] Composite `action.yml`
- [x] `examples/demo-project` and `action-demo.yml` (local Action)
- [x] ADR for image preparation and caching in CI
- [x] `make lint-actions` (pinned actionlint)
- [x] `docs/github-action.md`, including a warning against `pull_request_target`

This phase is written and tested on a local machine; no GitHub account or remote repository is
needed to finish it.

Done when:

- `assay ci verify` prints `no changes in scope` with exit 0 on the demo project.
- Diff handling rejects binaries, symlinks, renames out of scope and path traversal.
- Markdown injection tests pass.
- actionlint passes.
- No workflow uses `pull_request_target` or secrets.

## Phase 9: Benchmark and research

- [x] `bench/PROTOCOL.md`, written before any held-out result exists
- [x] Benchmark runner (`assay bench run`, `assay bench report`)
- [x] Ablations V0 to V3 with Wilson intervals and a per-class breakdown (V4, with the symbolic
      oracle, is supported by the runner and was not part of the runs)
- [x] Dev-split results
- [x] Oracle freeze (`make bench-freeze`, `bench/FROZEN_HASH`)
- [x] Eight held-out fixtures with different code shapes (`bench/heldout/`)
- [x] Held-out run: 32 of 32 verdicts equal the labels, with the oracle hash equal to the frozen
      hash (result version `v1`)
- [x] `docs/results.md` and `docs/results.json` with a findings section (no mismatch in `v1`)

Done when:

- The report marks held-out results as held-out only if the oracle hash equals the frozen hash.
- Every threat to validity is stated.
- The numbers are reproduced exactly by the commands listed in the report.

## Phase 10: Final audit

- [x] Self-audit in sections A to G: sandbox claims, environment sniffing, evidence forgery, supply
      chain and licenses, secrets, claims table with evidence, audit summary (`docs/audit.md`)
- [x] `pip-audit` and an image scan (Trivy); results in `docs/audit.md`
- [x] `THIRD_PARTY_NOTICES.md` and `make third-party-notices`
- [x] `docs/claims.md` and `make claims-check` (part of `make check`)
- [x] `docs/audit.md`
- [x] Updated `SECURITY.md`
- [x] Security-suite tests for S3 to S6 (and S9) against the real image
- [ ] v2 result version addressing finding B1 (variant search randomizes the block environment),
      with a re-run benchmark

Done when:

- Every claim in the README and in `docs/` has an evidence path.
- Every audit finding is decided one by one: fixed, documented as a limitation, or the claim is
  softened.
- The working tree and the full history contain no secrets, no references to untracked files and
  no tool attribution.
- The copyright holder in `LICENSE` and the contact in `CODE_OF_CONDUCT.md` and `SECURITY.md` are
  filled in.

## Release criteria

Publication is a separate decision taken after Phase 10. It requires:

- Every phase's "Done when" list holds.
- Every claim in the README and `docs/` is listed with evidence in `docs/claims.md`, and
  `make claims-check` passes.
- `docs/limitations.md` states what Assay cannot do, which classes are not covered, and its
  assumptions.
- The self-audit is described as a self-audit, not an independent one. Findings that let a wrong
  patch pass, forge evidence or break the sandbox are fixed before publication.
- Third-party licenses are summarized in `THIRD_PARTY_NOTICES.md`. The Dockerfile may be
  distributed; a built image is not.
- `make check`, `make test-integration`, `make test-security` and `make lint-actions` pass, and
  `uv build` produces clean artifacts.
