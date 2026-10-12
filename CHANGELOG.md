# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Version numbers
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html), written in the PEP 440 form used
by Python packaging.

## [Unreleased]

### Added

- A self-audit (`docs/audit.md`) and a claims table (`docs/claims.md`) with `make claims-check`
  (`tools/claims_check.py`), which is part of `make check`: every claim in the README and the
  docs cites an evidence path that must exist, and every claim area the README marks must have a
  row. `THIRD_PARTY_NOTICES.md` records the license of every bundled tool and dependency, read
  from their own license files, and `make third-party-notices` regenerates the Python list from
  the images.
- Security-suite tests for the claims S3 to S6 and a new claim S9 against the real runner image
  (`tests/security/test_s3_s6_container_policy.py`): output capping, timeout and removal, the pids
  limit, no network beyond loopback, and the empty host environment, non-root user and dropped
  capabilities.
- A benchmark of the oracles (`bench/PROTOCOL.md`): `assay bench run`, `assay bench freeze` and
  `assay bench report` (hidden commands) and the targets `make bench-oracles`, `make bench-freeze`
  and `make bench-report`. The runner stores per-oracle results, the ablations V0 to V4 are
  computed from them with Wilson intervals, and `docs/results.md` and `docs/results.json` are
  rendered from the result folders. Held-out results are marked held-out only if the hash of
  `src/assay/oracles`, `solidity/` and `versions.lock` equals `bench/FROZEN_HASH`.
- Eight held-out fixtures in `bench/heldout/`, one per class, with code shapes that differ from the
  development fixtures; `make fixtures-check` checks the labels of both splits (16 fixtures, 80
  rows).
- `assay ci verify`: verifies the Solidity diff of a pull request against the PoCs of a project,
  without a model and without secrets. It computes the diff between two revisions with git
  (limited to a scope, text only; binary files, symlinks, submodules, renames across the scope
  boundary and unsafe paths are refused with exit code 5), runs the verification for every PoC,
  writes one evidence bundle per PoC, `summary.md` and `result.json`, and exits by `--fail-on`
  (`rejected`, `inconclusive` or `never`). The Markdown summary quotes every string of the pull
  request as code. Documented in `docs/cli.md`.
- A composite GitHub Action (`action.yml`): installs Assay from its own code, builds the sandbox
  image with Docker Buildx and the Actions cache ([ADR 0021](docs/adr/0021-sandbox-image-in-github-actions.md)),
  writes the job summary, uploads the bundles, optionally keeps one pull request comment up to
  date (same-repository pull requests only) and uploads SARIF. `docs/github-action.md` explains
  its use, its behavior for forks and why `pull_request_target` must not be used with it.
- `examples/demo-project` and the workflow `action-demo.yml`, which runs the local Action on pull
  requests that change `examples/**`.
- `make lint-actions`: a pinned, checksum-verified actionlint over the workflows and the steps of
  `action.yml`; part of the CI workflow.
- `make demo` and `make demo-overfit` (documented in `docs/demo.md`): an offline, deterministic
  demo on the reentrancy fixture. `make demo-overfit` verifies the overfit patch and shows the
  patch passing the earlier checks and being rejected with `variant_found`, with the generated
  `variant_poc.t.sol`. `make demo` runs `assay run` from four synthetic cassettes in
  `demo/cassettes/` (a hypothesis, the PoC, an overfit patch, the good patch) to
  `VERIFIED_WITHIN_BOUNDS`, and writes the bundle and the HTML report to `demo-out/`.
  `make demo-cassettes` records them again; an integration test fails when they are out of date.
- A new README (the problem, demo, install, how it works, verdicts and evidence levels, measured
  results with their weaknesses, security summary, limits) and the public documents
  `docs/design.md`, `docs/threat-model.md` and `docs/limitations.md`.
- `make docs-check`, part of `make check`: relative links and heading anchors in `README.md` and
  `docs/`, and the words the project never uses for a result, allowed only in a sentence that
  denies them.
- Packaging: the wheel carries the shared Solidity harness and `versions.lock`, so an installed
  `assay` finds them outside a checkout; the sdist lists the Dockerfile directory, the demo, the
  Makefile and the project documents; more classifiers.
- `assay report BUNDLE --out FILE.html`: a self-contained HTML report of an evidence bundle, with
  inline CSS, no JavaScript, no external resource and a `Content-Security-Policy` meta tag
  (`default-src 'none'; style-src 'unsafe-inline'; img-src data:`). It shows the verdict, what the
  result does and does not mean, the oracle table, the PoC and `variant_poc`, the patch with a
  hand-written diff renderer, the attempt history, the manifest hash and how to replay. The same
  bundle gives the same bytes. Text from projects, patches, PoCs and models is escaped for its
  context; the tests parse the page and check that hostile payloads stay inert. A bundle that
  does not match its manifest is refused (exit code 5).
- `assay doctor`: Docker command and daemon, runner image and the tool versions its labels
  declare against `versions.lock`, image platform and native or emulated mode, free disk space,
  and the `ASSAY_LLM_*` variables as SET or NOT SET. Exit code 0 or 4, with a one-line fix per
  problem (ADR 0020).
- `--json` on `assay prove` and `assay scan` (the latter as an alias of `--format json`); every
  `--json` document is validated against a Pydantic model, and the JSON Schemas of scan, verify,
  prove, fix, run, replay and doctor are exported to `docs/schemas/` (`make schemas`).
  `assay --version`, `--help` with an example on every command, and a command line reference in
  `docs/cli.md` with the exit codes.
- `assay fix` and `assay run`: a model-written patch for a reproduced finding, a bounded loop
  (3 attempts by default, 5 at most) that runs the IntegrityOracle first and then the whole
  verification, structured, redacted feedback quoted as data, a final verification with a held-out
  seed that decides the verdict, and the ledger moves `REPRODUCED -> PATCH_PROPOSED ->
  VERIFIED_WITHIN_BOUNDS`, `REJECTED` or `INCONCLUSIVE` on oracle runs only. The bundle of a fix
  loop adds `fix/history.json` (diff hashes, verdicts, reasons and limits; no prompt, no key) and
  replays without a model. `assay run` chains scan, prove, fix and bundle. Documentation in
  `docs/fix-loop.md` and ADR 0019. `run_verification` can record a verification under an existing
  finding, with its own patch limits and an integrity gate; no oracle changed.
- `assay prove`: a structured hypothesis (CANDIDATE to HYPOTHESIZED, evidence level E0), a
  model-written PoC that a default-deny static checker must accept before it is written or run,
  and a bounded repair loop that runs the PoC through the ExploitOracle on the unpatched project
  (`REPRODUCED`, `NOT_REPRODUCED` or `INCONCLUSIVE`, by oracle runs only). Hidden command
  `assay dev ledger-audit` checks the global ledger invariants. Synthetic cassettes, a prompt
  injection corpus with a model that obeys it, and forgery tests against the ExploitOracle and
  the IntegrityOracle. `ExploitOracle.reproduce` runs the PoC on the vulnerable revision only.
- LLM layer, first part: one OpenAI-compatible Chat Completions client built on httpx (configured
  only through `ASSAY_LLM_*`, https or localhost, temperature 0, timeout, bounded retries),
  hard call and token budgets, `replay`, `record` and `live` cassettes, redaction with a file
  allowlist, the `--allow-llm` consent and `--llm-dry-run`, strict validation of model output
  with one repair attempt, and ledger migration 3 (`model_run`). Hidden command
  `assay dev llm-ask`, and the documentation in `docs/llm.md`.
- Architecture decision records 0001 to 0008, the fixture specification, the roadmap and the
  README.
- Python package skeleton (`assay-evm`, import name `assay`) with the `assay version` command.
- Makefile targets `install`, `lint`, `typecheck`, `test`, `check`, `fmt` and `clean`.
- Runner image with pinned Foundry, solc and forge-std (`make image`), an offline smoke check
  (`make image-check`), and the sandbox documentation.
- Security policy, contributing guide, code of conduct, CI workflow and Dependabot configuration.
- Sandbox runner: runs one allowlisted `forge build` or `forge test` command per container, with
  no network, a read-only root filesystem, no capabilities, a non-root user, resource limits, a
  wall-clock timeout, capped output and out-of-memory detection.
- Ingest: project snapshots with `tree_sha256`, a rewritten `foundry.toml`, removal of
  `remappings.txt`, skip rules for repository metadata and secrets, rejection of symlinks out of
  the tree, special files and inline Foundry configuration (ADR 0009), and size limits.
- Foundry adapter with normalized, deterministic results of `forge build` and `forge test`.
- Hidden developer command `assay dev forge-test <dir>`.
- Makefile target `test-integration` for the tests that need Docker and the runner image.
- Security suite in `tests/security/` for the sandbox claims S1, S2, S7 and S8, and the Makefile
  target `test-security`.
- Determinism test: the smoke and probe projects give byte-identical normalized results across
  three runs.
- CI job `integration`, which builds the runner image and runs `make test-integration` and
  `make test-security`.
- Ledger (`assay.ledger`): SQLite schema with numbered migrations (`PRAGMA user_version`) and the
  tables `project`, `revision`, `finding`, `claim`, `oracle_run`, `patch`, `verification`,
  `artifact` and `audit_log`; the finding lifecycle with evidence levels E0 to E3; claim
  statuses that change only through `promote_claim` and an oracle run with a matching verdict;
  immutable oracle runs; an append-only, hash-chained audit log with chain verification; and a
  content-addressed, write-once blob store. Triggers enforce the claim, finding and immutability
  rules for any writer of the database, not only for the application code.
- Hidden developer commands `assay dev ledger-demo <db>` and `assay dev ledger-verify <db>`.
- Shared Solidity harness `solidity/AssayExploit.sol`: the predicates `attacker_profit`,
  `victim_loss`, `unauthorized_role_change` and `invariant_broken`, reported as events of the
  test contract and as `ASSAY_PREDICATE|<kind>|<detail>` lines; `recordBehavior` with
  `ASSAY_REC|<key>|<hex>` lines; and the PoC base contract `AssayPoC` with `test_replay` and
  `testFuzz_variants` (randomized attacker address, attacker balance and four knobs).
- First fixture, `fixtures/reentrancy/single_function`: a vault with single-function reentrancy,
  benign tests, a PoC and the patches `good`, `overfit`, `destructive` and `regressing`.
- Fixture checker `tools/fixture_check.py` and the Makefile target `fixtures-check`: runs every
  fixture variant with plain Foundry in the sandbox runner, independently of the oracles, and
  compares replay, variant search, benign tests, interface and behavior records with
  `expected.json`. Static checks cover the fixture layout, headers, pragmas, import rules,
  `foundry.toml` and `expected.json`.
- Integration tests of the harness (`tests/integration/test_harness.py`).
- ADR 0010 (mutually exclusive patch labels) and ADR 0011 (run trees for the shared harness and
  the PoC).
- Patch application in ingest (`assay.ingest.patch`): its own unified-diff parser, no
  `git apply`; refuses path traversal, symlinks, binary content, protected paths and paths outside
  `src/`, never follows a symlink in the tree, and writes either every file or none. The patched
  revision is snapshotted by the same ingest rules.
- Oracle framework (`assay.oracles.base`): results with verdicts, structured reasons, executions
  and evidence; every execution is recorded as an `oracle_run` with a claim promoted from its
  verdict.
- Run trees for the oracles as in ADR 0011 (`assay.oracles.runtree`).
- IntegrityOracle: scope and protected-path checks, protected-file hashes, and detection of
  vacuous patches, special-casing and environment sniffing.
- ExploitOracle: three replays of `test_replay` with a fixed seed on each revision; only
  `AssayPredicate` events of the test contract count.
- `assay verify --base DIR --patch FILE --poc DIR [--json] [--ledger FILE]`: runs the integrity and
  exploit oracles, prints a verdict table and the final verdict, records everything in the
  ledger, and reports `INCONCLUSIVE` (`missing_oracles`) while the other oracles are missing.
- Ledger: `add_verification`, `find_finding` and the `FinalVerdict` enum.
- `docs/oracles.md` and ADR 0012 (patches that cannot be applied, and when verification stops).
- Unit tests for the patch parser, every IntegrityOracle detection, the ExploitOracle and
  `assay verify`; integration tests on the reentrancy fixture; security tests for hostile patches
  (`tests/security/test_s8_patches.py`).
- VariantOracle, basic version: `testFuzz_variants` on both revisions with the fixed seed and
  `--fuzz-runs` runs (default 256); a variant on the patched revision fails as `variant_found`
  and its counterexample (attacker, balance, knobs, calldata) is stored; a search that finds
  nothing on the vulnerable revision is `INCONCLUSIVE` (`variant_search_ineffective`).
- BehaviorOracle: benign tests that pass on the vulnerable revision must pass on the patched one
  (`benign_test_failed`), and their `AssayRecord` values must stay the same per key
  (`behavior_changed`, with a diff as evidence).
- RegressionOracle: storage layout, ABI and events of every concrete contract under `src/` are
  compared through `forge inspect` (`layout_changed`, `abi_changed`, `event_changed`; additive
  changes are warnings), and the whole test suite must pass on the patched revision
  (`test_suite_failed`).
- Evidence bundles: `assay verify --bundle-out DIR` writes the inputs, the harness, sanitized
  evidence per oracle and a deterministic `manifest.json` (sha256 of every file, image id, tool
  versions, `versions.lock`, settings, verdicts, bounds statement).
- `assay replay <bundle>`: checks every file against the manifest (exit code 5 on any change,
  before anything runs), checks the runner image (exit code 4, "run make image"), re-runs every
  oracle offline and prints `REPLAY MATCH` (exit code 0) or the differences (exit code 1).
- ADR 0013 (evidence bundle contents and the replay environment) and ADR 0014 (single-threaded
  `forge test` runs).
- Unit tests for the interface comparison, the three new oracles, the final verdict rule, the
  bundle and replay, and the forbidden vocabulary in `verify` and `replay` output; integration
  tests of all four labelled patches of the reentrancy fixture against `expected.json`, of
  replay and tampering, and of byte-identical manifests.
- Four fixtures, each with benign tests, a PoC with knobs and the patches `good`, `overfit`,
  `destructive` and `regressing`: `access_control/missing_modifier` (payout functions without
  the owner check), `unchecked_call/ignored_return` (a refused payment still clears the wage),
  `signature_replay/missing_nonce` (a signed voucher pays again; the overfit patch leaves the
  high-`s` twin of a signature open) and `delegatecall/user_controlled_target` (a caller-chosen
  module overwrites the owner). Their regressing patches change the storage layout, the ABI,
  the events and the storage layout respectively.
- Unit tests that validate the `expected.json` of every fixture against the schema and the
  consistency rules, and that the development split has one fixture per class.
- The last three fixtures, so that every class has its development fixture:
  `oracle_manipulation/spot_price` (a lender values collateral at the spot price of a small pool;
  the overfit patch caps the size of one swap, which several smaller swaps get around),
  `dos/payout_loop` (one refused refund stops the refund loop for every contributor; the overfit
  patch isolates reverting contributors but still forwards all gas, so a gas-burning one blocks
  the loop) and `rounding/share_inflation` (a first depositor inflates the price of a vault share;
  the overfit patch requires a minimum first deposit, which a larger donation defeats). Their
  regressing patches change the events, the ABI and the storage layout respectively.
- Classification matrix: `tests/integration/test_matrix.py` (marker `matrix`) runs
  `assay verify` on all 32 patches and compares each final verdict and reason with
  `expected.json`; it also verifies three patches a second time and requires the same verdict and
  a byte-identical bundle manifest. `tools/matrix_report.py` prints the matrix, ending with
  `MATRIX RESULT: <matching>/<total> match`, and renders `docs/classification-matrix.md` from the
  results. Makefile target `matrix`.
- Workflow `matrix.yml`, started by hand only (`workflow_dispatch`): builds the runner image,
  runs `make matrix` and uploads the matrix page as a workflow artifact.
- Slither 0.11.6 and Aderyn v0.6.8 in the runner image (ADR 0015): Python 3.12 from
  python-build-standalone, Slither and its dependencies from a hash-pinned requirements file
  (wheels only, installed at build time), a `solc_select` stand-in that refuses downloads, and
  Aderyn finding the pinned solc as svm-rs's one installed version, so neither tool uses the
  network. `make image-check` checks both versions against `versions.lock`.
- Analyzer adapters (`assay.analysis`): the tools run through the sandbox runner; their JSON
  output is parsed as untrusted input with limits on size, depth, string length and values,
  strict models, and project-relative paths only; malformed output is a structured error.
- Ledger migration 2: tables `scan` and `observation`, with triggers that keep scans immutable
  and let an observation change only by being linked to a finding once; `Ledger.record_scan`,
  `get_scan` and `scan_observations`. Recording analyzer output creates no claim and changes no
  status, which a test checks on the code and on random scan sequences.
- Hidden developer command `assay dev analyze <slither|aderyn> <dir>`: stores the raw report as a
  blob, records the scan and prints the number of results, the duration and the blob hash.
- Recorded analyzer output in `tests/data/analyzers/`, unit tests for hostile output, an
  integration test of both tools on the reentrancy fixture, and the security test
  `tests/security/test_s1_analyzer_config.py`.
- Normalizer (`assay.analysis.normalize`): analyzer results become candidate findings with a
  class from the mapping file `src/assay/analysis/class_map.toml` (the eight fixture classes or
  `other`), the severity, rule and message exactly as reported, the state `CANDIDATE` at
  evidence level E0, and a stable id (sha256 of class, relative path, line range and snippet
  hash). The enclosing function of a location comes from a bounded token scan of the snapshot
  (`assay.analysis.source_map`).
- Deduplication across tools: results of one class in the same function, or outside functions
  with overlapping lines, merge into one finding that lists every source (ADR 0016).
- SARIF 2.1.0 export (`assay.analysis.sarif`): one run, the rules that occur, results with
  `partialFingerprints` and the properties `assayEvidenceLevel` and `assayStatus`; tests validate
  it against a copy of the official OASIS schema in `tests/data/sarif/`.
- `assay scan <dir> [--format table|json|sarif] [--out FILE] [--fail-on SEVERITY]`: runs both
  analyzers, records the project, findings, scans and linked observations in the ledger, and
  prints the findings as candidate (unverified). A repeated scan of the same input adds nothing
  to the ledger and prints byte-identical JSON. Exit code 0 when the scan finished, 1 when
  `--fail-on` is met, 3 when an analyzer gave no usable result (ADR 0016). Tool text in the
  output has forbidden words replaced by `[term withheld]`. Documented in `docs/scan.md`.
- Ledger: `find_project`, `find_scans` and `link_observation` (an observation is linked to one
  finding of its own project, once; a link creates no claim and changes no status).
- `tools/static_coverage.py` and the Makefile target `static-coverage`: `assay scan` on every
  fixture, rendered into `docs/static-coverage.md` with the findings per analyzer, the class hits
  and the classes no analyzer detects.
- `jsonschema` in the development dependencies, to validate the SARIF export in the tests.
- Campaign profiles of the VariantOracle (`quick`, `standard`, `thorough`) in
  `src/assay/oracles/variant/profiles.toml`: seeds, fuzz runs per seed, invariant runs and depth,
  and a time limit per campaign. Every seed is derived from one recorded base seed. New options
  `assay verify --profile` (default `standard`) and `--seed` (default `0x1`) (ADR 0017).
- Invariant mode of the variant search: `solidity/AssayInvariant.sol` (handler-driven
  `invariant_assay`), fixture invariants for `reentrancy/single_function` (`vault_solvent`),
  `rounding/share_inflation` (`deposit_mints_shares`) and `dos/payout_loop`
  (`refunds_complete`), and invariant runs and depth in the Foundry configuration of the run
  trees.
- Counterexample confirmation: a reported variant is saved as `counterexample.json`, replayed
  three times through a concrete test `variant_poc.t.sol` generated from a template (numbers
  only, from strictly validated input), and fails a patch only when all three replays reproduce
  it; otherwise `flaky_counterexample` or `counterexample_rejected`. The test and the replay
  results are in the bundle's `evidence/variant/`. `AssayPoC.assayReplayVariant` replays one
  fuzz input.
- Bounds and timing: the report and the manifest record the profile, base seed, derived seeds,
  runs per seed, invariant runs and depth, the seeds that ran and where a variant was found
  (`bounds.variant`), and the measured durations apart from them (`timing`); the bounds statement
  is built from the numbers that ran.
- `tools/variant_power.py` and the Makefile target `variant-power` (variable `PROFILES`): the
  variant search on every overfit and good patch per profile, rendered into
  `docs/variant-power.md`.
- `make matrix` takes the variable `PROFILE` (default `standard`); the matrix results and page
  record the profile and its bounds.
- The fixture checker runs fixture invariants with fixed runs and depth (`--invariant-runs`,
  `--invariant-depth`), shows them in an `invariant` column, and requires that they break on the
  vulnerable revision and hold under the `good` patch; `poc/` may hold at most one
  `AssayInvariant` contract.
- The forge parser reads `invariant_failures` (reason and shrunk call sequence), and
  `SandboxRunner.run` takes a per-run wall-clock limit.
- Symbolic oracle (Halmos), optional with `assay verify --symbolic`, run after the variant
  search: properties in the PoC directory's `symbolic/` subdirectory, built on the new harness
  `solidity/AssayCheck.sol` (`check_variant_*` wrappers of the PoC predicates, `check_equiv_*`
  bounded equivalence with the vulnerable revision under `baseline/`), with recorded bounds (loop
  unrolling, calldata per property, calls per property, solver time, run limits). A
  counterexample fails a patch only after a generated `variant_poc.t.sol` reproduced it three
  times with Foundry; a timeout, an out-of-memory kill or an unknown result is INCONCLUSIVE
  (`symbolic_unknown`) and never a pass. Bounded equivalence never changes a verdict.
- Symbolic runner image `assay-runner-symbolic:dev` (Dockerfile target `runner-symbolic`, linux/amd64
  only): Halmos 0.3.3 with z3 4.12.6.0, pinned in `docker/runner/halmos-requirements.txt` and
  `versions.lock` (ADR 0018). `make image` builds it and `make image-check` checks it on
  `tests/data/symbolic_smoke/`.
- Symbolic properties for four fixtures (access control, delegatecall, unchecked call, rounding),
  `tools/symbolic_report.py`, the Makefile target `symbolic-report` and the generated page
  `docs/symbolic.md`, which also lists the fixtures without properties and why.
- The verify report and the bundle manifest record the evidence level and the symbolic
  annotations; a bundle of a symbolic verification records the symbolic image, and `assay
  replay` uses it.

### Changed

- Two verifications of the same inputs give manifests that are byte-identical apart from the new
  `timing` section (ADR 0017). The manifest schema version is 2; `assay replay` refuses a
  version 1 bundle with exit code 2 and a message, instead of reporting it as tampered.
- The verify report schema version is 3; `--fuzz-runs` defaults to the profile's runs per seed.

- The fixture checker reports every entry of `fixtures/` that is not a `<class>/<name>/` fixture
  directory (a file, a symlink, an unknown class, an empty class directory) and fails, instead of
  skipping it; hidden entries are ignored. Its output ends with one summary line per fixture.

- The sandbox allowlist accepts `forge inspect <contract> <field>` for the fields `abi`,
  `events`, `methodIdentifiers` and `storageLayout`, with `--json` and `--force`.
- `make typecheck` also checks `tools/`.
- The Foundry adapter keeps the raw logs of every test as `events`, accepts `--fuzz-seed` and
  `--fuzz-runs`, and runs `forge inspect` (`inspect()`).
- The ledger accepts a patch with an empty diff (a patch that changes nothing).
- `make image-check` also passes `--pull never`, `--memory-swap` and `--log-driver none`, as the
  sandbox runner does.
- `assay verify` runs all five oracles in the order integrity, exploit, variant, behavior,
  regression, and no longer reports `missing_oracles`. Only an integrity violation or a patch
  that was not applied stops verification early. New options: `--fuzz-runs` and `--bundle-out`.
- The verify report (schema version 2) records the harness hash, the fuzz runs, the target
  contracts of the interface comparison and the warnings of every oracle; the text output adds a
  limits line and a warnings section.
- The forge output parser keeps the counterexample of a failing fuzz or invariant test (calldata,
  arguments, the index of the failing run), and the captured probe output in
  `tests/data/forge/` keeps its counterexample.
- `SandboxRunner.image_labels()` reads the labels of the runner image.
- Every `forge test` that Assay or the fixture checker runs passes `--threads 1`, and the sandbox
  allowlist accepts `--threads 1` for `forge test` (ADR 0014). With several threads, forge split a
  fuzz campaign over parallel workers and reported run counts and gas figures that depended on
  scheduling, so two verifications of the same patch could give different manifests.
- Oracle results and executions carry warnings that never change a verdict.
- CI runs `make fixtures-check` in a job of its own, in parallel with the integration job, so
  that eight fixtures do not lengthen the pull-request run.
- Ingest leaves the project's `slither.config.json` and `aderyn.toml` out of the snapshot (in
  any letter case) and keeps them as evidence, as it does with `foundry.toml`.
- The sandbox allowlist accepts `slither` and `aderyn` with a target inside the project and a
  fixed set of options (ADR 0015).
- Ingest leaves a project's `halmos.toml` out of the snapshot (in any letter case) and keeps it
  as evidence; the sandbox allowlist accepts `halmos` with fixed directories and a fixed set of
  options, without `--ffi` or `--config`.
- The PoC trees of the oracles and of the fixture checker leave the PoC directory's `symbolic/`
  subdirectory out.
- pip in the image build waits up to 120 s per read and retries ten times, so that a slow
  connection (an emulated build) does not fail the build; every wheel is still checked against
  its sha256.

### Fixed

- Ingest matches the project's `foundry.toml` and `remappings.txt` in any letter case. On a
  case-insensitive filesystem, forge read a `Remappings.txt` left in the snapshot, so a project
  could replace forge-std with its own code.
