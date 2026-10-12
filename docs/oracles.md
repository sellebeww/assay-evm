# Oracles and `assay verify`

An oracle is a deterministic check of a candidate patch. It returns `PASS`, `FAIL` or
`INCONCLUSIVE`, with structured reasons, and every execution is recorded in the ledger. Only
oracle results change the status of a claim ([ADR 0005](adr/0005-only-deterministic-oracles-promote-claims.md)).

`assay verify` runs five oracles: integrity, exploit, variant, behavior and regression, and, with
`--symbolic`, the symbolic oracle (Halmos) after the variant search. The only positive final
verdict, `VERIFIED_WITHIN_BOUNDS`, needs a `PASS` from all five, and from the symbolic oracle
when it ran. It means that none of the checks below found a problem within the bounds that ran;
it is not a proof of absence, and each oracle section states what its `PASS` does not show.

## `assay verify`

```sh
assay verify --base <project dir> --patch <file.diff> --poc <poc dir>
             [--profile quick|standard|thorough] [--seed 0x...] [--fuzz-runs N]
             [--symbolic] [--bundle-out DIR] [--json] [--ledger FILE]
```

- `--base`: the vulnerable Foundry project. Its `src/` is the code under test and its `test/`
  holds the benign tests; it must not have a top-level `assay/` directory, which is reserved for
  the shared harness ([ADR 0011](adr/0011-run-trees-for-harness-and-poc.md)).
- `--patch`: the candidate patch, a unified diff (format below), at most 1 MiB.
- `--poc`: the directory with the PoC, a contract deriving from `AssayPoC`
  ([fixture specification](fixture-spec.md), section 10). When it lies inside the base project,
  it is a protected path as well.
- `--profile`: the campaign profile of the variant search, `standard` by default (see
  [Campaign profiles](#campaign-profiles)).
- `--seed`: the base seed, `0x1` by default (`0x` and 1 to 16 hex digits). It is the fuzz seed of
  the exploit replays and of the project's own fuzz tests, and every seed of the variant search
  is derived from it.
- `--fuzz-runs`: the number of runs of every fuzz campaign Assay starts (the variant search and
  the fuzz tests among the project's own tests), 1 to 1,000,000; by default the profile's runs per
  seed. Every `forge test` runs on one thread, so that a campaign is the same on every machine and
  its results are repeatable ([ADR 0014](adr/0014-single-threaded-forge-test-runs.md)).
- `--symbolic`: also run the [SymbolicOracle](#symbolicoracle) on the properties in the PoC
  directory's `symbolic/` subdirectory, after the VariantOracle. Off by default. It needs the
  symbolic runner image (`make image` builds it).
- `--bundle-out`: write an evidence bundle into this directory, which must be empty or absent
  (see [Evidence bundle](#evidence-bundle)).
- `--ledger`: the ledger database, by default `.assay/ledger.db` in the current directory, with
  its blobs in `.assay/blobs/`.
- `--json`: print the report as JSON. The report holds tree and patch hashes, the result of each
  oracle with its reasons and warnings, the final verdict, the bounds that ran, the evidence
  level and the symbolic annotations, and, apart from them, the measured durations (`timing`);
  it holds no timestamps, host paths or ledger ids, so the same inputs give the same report
  except for `timing`.

The base project and the PoC directory go through ingest first (snapshot, rewritten
`foundry.toml`, rejection of symlinks out of the tree and other dangerous entries; see
[the sandbox documentation](sandbox.md)). The patch is applied to a copy of the base snapshot,
and the result becomes the patched revision through the same ingest rules. Every forge command
runs in the sandbox, without network.

Oracle order: integrity, exploit, variant, symbolic (with `--symbolic` only), behavior,
regression. The output lists every oracle with its verdict and reason codes, then the final
verdict, its reasons, the bounds that ran, the evidence level, the symbolic annotations (with
`--symbolic`), the measured time and the limits, warnings, and the details:

```
oracle      verdict  reason
integrity   PASS     -
exploit     PASS     -
variant     FAIL     variant_found
behavior    PASS     -
regression  PASS     -

final verdict: REJECTED
reason: variant_found
bounds: integrity: static checks of the patch and the patched sources; exploit: ...
evidence level: E1
time: 26.7 s in total, variant search 10.1 s, 3 campaigns, 3.2 s, counterexample replays 3.3 s
limits: a verdict covers only the checks and bounds listed here; ...
```

Final verdict:

- `REJECTED` when any oracle failed; the reasons are the failure reasons of every failed oracle.
- `INCONCLUSIVE` when no oracle failed but one was inconclusive or did not run.
- `VERIFIED_WITHIN_BOUNDS` only when all five oracles ran and passed, and the symbolic oracle,
  when it ran, passed too.

Evidence level (`evidence_level` in the report and the manifest): `E3` for
`VERIFIED_WITHIN_BOUNDS`; `E2` when the integrity, exploit, behavior and regression oracles
passed and nothing failed (the variant search did not decide); `E1` when the PoC reproduced on
the vulnerable revision; `E0` otherwise. A symbolic result never creates a level of its own: it
is an annotation (`annotations`) that states what Halmos ran, for example `symbolic: no
counterexample within loop bound 3 for check_variant_payOut (calldata 4+32*2 bytes), ...` or
`symbolic: unknown (timeout 900 s)`, and the bounded-equivalence result next to it.

Warnings (for example a function added to the interface) appear in the report and never change a
verdict.

Verification stops after the IntegrityOracle, and nothing from the patch runs in the sandbox,
when the patch was not applied or when the IntegrityOracle found an integrity violation
([ADR 0012](adr/0012-patches-that-cannot-be-applied.md)). The remaining oracles are reported
as skipped. Any other failure does not stop verification: the remaining oracles run, so that the
report is complete.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | `VERIFIED_WITHIN_BOUNDS` |
| 1 | `REJECTED` (other than an integrity violation) |
| 2 | usage error: bad options, a PoC directory that contains the base project, a base project without `src/`, a patch larger than 1 MiB, a bundle directory that is not empty |
| 3 | `INCONCLUSIVE` |
| 4 | infrastructure problem: Docker or the runner image missing, the harness, the ledger or `versions.lock` unusable, out of memory |
| 5 | integrity violation (see the IntegrityOracle), or the base project or the PoC directory rejected at ingest |

## Patch format

Unified diffs of text files with `a/` and `b/` path prefixes, as `git diff` writes them, with or
without `diff --git` headers. Text before the first file section is ignored. Files may be
created (`--- /dev/null`) and deleted (`+++ /dev/null`). Not accepted: renames, copies, mode
changes, quoted paths, binary hunks, a file changed twice, and a path that is both a file and a
directory. A hunk may apply at an offset from its stated line, nearest first, but its context
must match exactly. Either every file applies or nothing is written. An empty patch is valid and
changes nothing.

The patch may change files only under the scope, `src/`. Protected paths are refused even inside
the scope; they are compared case-insensitively, because a case-insensitive filesystem opens
`Test/A.sol` for `test/A.sol`: `test/`, `poc/`, `solidity/`, `assay/`, `foundry.toml`,
`remappings.txt`, `expected.json`, and the PoC directory when it lies inside the base project.

Default limits: 1 MiB per patch, 100 files, 20,000 changed lines, 16 MiB per patched file.

## Common contract

An oracle result has a verdict, reasons, warnings and executions. A reason has a code, a detail,
and optionally a path and a line. Details may quote text from the project (file names,
identifiers, revert reasons); output escapes control characters.

An execution is one check of one revision. Each execution is recorded as one immutable
`oracle_run` with the argv, the runner image digest, the seed, the exit code, the verdict, a
reason and a trace blob, together with a claim that the run decides: `PASS` makes the claim
`trusted`, `FAIL` `refuted`, `INCONCLUSIVE` `inconclusive`, through `promote_claim`. The trace
is canonical JSON without durations or host paths; further evidence (for example the normalized
forge results of every run, a counterexample, a behavior diff) is stored as blobs and listed in
the trace by sha256. The verification row holds the final verdict, its reasons, the bounds and,
with `--bundle-out`, the sha256 of the bundle manifest. The ledger accepts
`VERIFIED_WITHIN_BOUNDS` only with a `PASS` of all five oracles on the patched revision and no
`FAIL`.

The oracles that run forge (all but the IntegrityOracle) treat a timeout, unusable output or a
failing compilation of the vulnerable revision as `INCONCLUSIVE`, never as `PASS`. An
out-of-memory kill is an infrastructure problem (exit code 4).

The finding that a verification creates stays `CANDIDATE`: the lifecycle steps before a
reproduction need a recorded hypothesis and a checked PoC, which `assay verify` does not have.

## IntegrityOracle

Protects the evidence and the rules of the game. It runs nothing in the sandbox; its
`oracle_run` records an empty argv, no seed and no exit code, and the digest of the runner image
that the verification uses. It runs on the patched revision, or on the vulnerable revision when the
patch was not applied.

| Reason | Integrity violation | Cause |
|---|---|---|
| `path_traversal` | yes | an absolute path, a `..` component, a backslash, a control character or an empty component in a path of the patch |
| `symlink` | yes | a symbolic link mode (`120000`) in the patch, or a symlink on the way to a target |
| `binary_file` | yes | a binary hunk, a NUL byte, a patch that is not UTF-8 text, or a binary target file |
| `protected_path_modified` | yes | the patch touches a protected path, or a protected file differs between the revisions (compared by sha256) |
| `out_of_scope` | yes | the patch touches a path outside `src/` |
| `ingest_rejected` | yes | the patched tree breaks an ingest rule, for example inline Foundry configuration |
| `malformed_patch` | no | not a diff in the accepted format |
| `patch_too_large` | no | a patch limit is exceeded |
| `patch_does_not_apply` | no | the context does not match the vulnerable sources |
| `vacuous_patch` | no | see below |
| `special_casing` | no | see below |
| `environment_sniffing` | no | see below |

The content checks read Solidity source as data (comments and string contents masked, brackets
matched); they look for patterns and never refer to a fixture, a file name, a function name or a
particular PoC.

`vacuous_patch`, for each contract of the vulnerable revision under `src/`:

- an external or public function (or `receive`, `fallback`) is removed, or becomes internal or
  private;
- such a function starts to revert unconditionally: a top-level `revert`, `require(false)`,
  `assert(false)` or a comparison of two number literals that is false, before any top-level
  `return`;
- a function that is neither `view` nor `pure` loses every statement other than `return`;
- a function gets a modifier, or uses a changed modifier, that blocks every call: no `_;`, an
  unconditional revert, or a requirement that the caller is `address(0)`;
- the contract no longer makes any low-level call (`call`, `delegatecall`) or value transfer
  (`transfer`, `send`) while the vulnerable revision made at least one.

`special_casing`, on the lines the patch adds (comments excluded):

- a value that the PoC uses and the vulnerable sources do not: an address literal, a four-byte
  literal such as a selector, or a number of at least 256 (units such as `ether` and notations
  such as `1e18` or `1_000` are compared by value);
- a comparison of an address, or of `msg.sig`, with a hard-coded value that the vulnerable
  sources do not use.

`environment_sniffing`, on every Solidity file under `src/` of the patched revision: the local
chain id 31337; the addresses of Foundry's cheatcode contract, console contract, default sender
or test contract; the text `hevm cheat code`; an import from `forge-std/`, `ds-test/` or of a
file named like a console library.

These checks are heuristics with known limits: they can miss a disguised change, and a
legitimate patch can trigger them. A failure names the file and line so that a person can
review it.

What a `PASS` does not show: the checks are textual heuristics over Solidity source. They do not
prove that a patch is free of special-casing or environment sniffing; a disguised change (for
example a value computed at run time) can pass them.

## ExploitOracle

Runs the PoC on both revisions in PoC trees (ADR 0011) that differ only in `src/`. On each
revision it compiles the tree (`forge build --json`), reads the topic of the harness event
`AssayPredicate` (`forge inspect assay/AssayExploit.sol:AssayExploit events --json`, once), and
runs `forge test --json -vv --threads 1 --match-test '^test_replay[(][)]$' --fuzz-seed 0x1` three
times.
Forge matches `--match-test` against the signature, so the filter names `test_replay()`.

A replay reproduces the exploit only when `test_replay` passes and the raw logs contain a
well-formed `AssayPredicate` event emitted by the test contract itself (address
`0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496`). Console lines and events from any other address
never count.

| Revision | Observation in every replay | Verdict | Reason |
|---|---|---|---|
| vulnerable | reproduces | `PASS` | |
| vulnerable | finishes without a predicate (`AssayNoPredicate`), or passes without the event | `INCONCLUSIVE` | `vacuous_poc` |
| vulnerable | reverts for another reason | `FAIL` | `poc_not_reproduced` |
| patched | reproduces | `FAIL` | `exploit_still_reproducible` |
| patched | does not reproduce | `PASS` | |

Further `INCONCLUSIVE` reasons on either revision: `flaky_poc` (replays disagree),
`timeout` (a timeout is never a pass), `unusable_output`, `poc_build_failed` or
`patched_build_failed` (compilation failed), `poc_setup_failed`, `poc_not_found`,
`poc_ambiguous`, `poc_skipped`, `harness_unreadable`, `run_tree_rejected` and
`run_tree_mismatch`. An out-of-memory kill is an infrastructure problem (exit code 4).

`assay prove` uses the vulnerable side alone (`ExploitOracle.reproduce`), before any patch
exists; see [the LLM layer](llm.md#assay-prove).

The patched revision runs only after the vulnerable revision passed. Each revision is one
`oracle_run`. The oracle's verdict is the patched revision's verdict, or `INCONCLUSIVE` when the
vulnerable revision did not pass: a PoC that does not reproduce says nothing about a patch.

What a `PASS` does not show: that the hole is closed. It shows only that the original PoC, with
its original values, no longer records a predicate on the patched revision. Close variants are
the VariantOracle's task.

## VariantOracle

Looks for a close relative of the original exploit that the patch still allows, within the
bounds of a campaign profile. Both revisions run in PoC trees whose Foundry configuration carries
the profile's invariant runs and depth.

### Search modes

- Fuzz: the PoC's `testFuzz_variants`, one campaign per seed:
  `forge test --json -vv --threads 1 --match-test '^testFuzz_variants[(]' --fuzz-seed <seed>
  --fuzz-runs <runs per seed>`. The harness draws the attacker address, the attacker's starting
  balance and the four knobs of the PoC from the ranges the PoC declares. A variant counts only
  when `testFuzz_variants` fails with
  `ASSAY_VARIANT_FOUND|attacker=<address>|balance=<wei>|knobs=<k0>,<k1>,<k2>,<k3>`, forge reports
  the failing input, and the test contract itself emitted an `AssayPredicate` event.
- Invariant: when the PoC directory holds a fixture invariant (a contract deriving from
  `AssayInvariant`, see the [fixture specification](fixture-spec.md)), its `invariant_assay`
  test, one campaign per seed: `forge test ... --match-test '^invariant_assay[(]' --fuzz-seed
  <seed>`, with the profile's sequences and calls per sequence. Foundry calls the fixture's
  handler with random sequences and checks the invariant after every call, so variants made of
  several calls are reachable. A variant counts when the invariant breaks with
  `ASSAY_INVARIANT_BROKEN|<name>` and forge reports the call sequence, which it shrinks. A PoC
  directory without an invariant has no invariant mode, and the bounds statement says so.

In each mode the seeds run in order, and the search stops at the first seed that finds something;
a search that finds nothing runs every seed. On the patched revision the invariant mode does not
run once a fuzz variant is confirmed.

### Campaign profiles

The profiles live in `src/assay/oracles/variant/profiles.toml`, the only place where their values
are kept:

| Profile | Seeds | Fuzz runs per seed | Invariant sequences per seed | Calls per sequence | Limit per campaign |
|---|---|---|---|---|---|
| `quick` | 1 | 64 | 32 | 15 | 180 s |
| `standard` (default) | 3 | 256 | 64 | 25 | 300 s |
| `thorough` | 8 | 1024 | 256 | 50 | 900 s |

Seed `i` is the first 16 hex digits of sha256(`assay-variant-seed-v1`, `search`, base seed, `i`),
so the same base seed gives the same seeds on every machine and a campaign repeats exactly. The
limit covers one campaign, compilation included; a campaign that reaches it is `INCONCLUSIVE`
(`timeout`), never a pass. `quick` is meant for a first look and can miss variants that the
larger profiles find; how often it does on the fixtures is measured in
[variant search power](variant-power.md).

### Sanity check

Each mode must find the exploit on the vulnerable revision. A mode that finds nothing there says
nothing about the patched revision: its result does not count towards a pass, and a warning
(`fuzz_search_ineffective` or `invariant_search_ineffective`) says so. When no mode finds the
exploit, the verdict is `INCONCLUSIVE` with `variant_search_ineffective`.

### Counterexample flow

When a campaign reports a variant on the patched revision:

1. The reported input is saved as `counterexample.json`: the fuzzer's raw arguments and the
   attacker, balance and knobs they select, or the shrunk call sequence (sender, target, calldata
   of each call), together with the profile, the base seed, the seed and its position.
2. A concrete test `variant_poc.t.sol` is written from a template. It derives from the PoC (or the
   fixture invariant) and replays the input with fixed values: `assayReplayVariant` with the six
   fuzzer arguments, or one `assayReplayCall` per call of the sequence followed by
   `assayCheckInvariant`. Only numbers enter the source: each value is printed as a 64-digit hex
   literal from strictly validated hex, besides the base contract's name and file, which must be a
   plain identifier and a plain path. A counterexample that does not fit (calldata that is not a
   selector and whole words, a time or block shift in a sequence, a suspicious name) is refused,
   never written: `INCONCLUSIVE` with `counterexample_rejected`.
3. The test runs three times in the sandbox on the patched revision. Only when all three runs pass
   with the predicate from the test contract is the variant confirmed: `FAIL` with
   `variant_found`. Runs that disagree, or a test that reaches no predicate, give `INCONCLUSIVE`
   with `flaky_counterexample`; a test that does not compile gives `variant_poc_build_failed`.
   The counterexample, the test and the results of each replay are kept either way, in the
   bundle under `evidence/variant/`.

A confirmed `variant_found` stands on its own: it fails even when the sanity check did not pass.
The witness found on the vulnerable revision is stored as `sanity-counterexample.json`.

### Verdicts

| Observation | Verdict | Reason |
|---|---|---|
| a variant on the patched revision, confirmed by three replays of three | `FAIL` | `variant_found` |
| a reported variant whose replays disagree or miss | `INCONCLUSIVE` | `flaky_counterexample` |
| a reported variant that cannot be written into a test | `INCONCLUSIVE` | `counterexample_rejected` |
| no mode finds the exploit on the vulnerable revision, no variant on the patched one | `INCONCLUSIVE` | `variant_search_ineffective` |
| the exploit found on the vulnerable revision, no variant on the patched one in any seed | `PASS` | |

Further `INCONCLUSIVE` reasons: `variant_search_incomplete`, `variant_unconfirmed`,
`variant_search_failed`, `poc_setup_failed`, `poc_not_found`, `poc_ambiguous`, `poc_skipped`,
their invariant counterparts (`invariant_search_incomplete`, `invariant_unconfirmed`,
`invariant_search_failed`, `invariant_setup_failed`, `invariant_not_found`,
`invariant_ambiguous`, `invariant_skipped`), `poc_build_failed`, `patched_build_failed`,
`variant_poc_build_failed`, `variant_poc_rejected`, `harness_unreadable`, `timeout`,
`unusable_output`, `run_tree_rejected` and `run_tree_mismatch`.

### Bounds and time

The bounds statement is built from the numbers of what ran on the patched revision: the profile,
the base seed and every derived seed, then per mode the seeds that ran out of how many, the runs
or sequences and calls that forge reported, and how the mode ended. For example:

```
profile standard, base seed 0x1, seeds 0x67cf8d5c98c791f4, ...; on the patched revision:
fuzz: 3 of 3 seeds of 256 runs (768 runs), no variant found; invariant: 3 of 3 seeds of 64
sequences of up to 25 calls (192 sequences, 4800 calls), no variant found; no variant found
within these runs; this is not a proof of absence
```

A mode that found nothing on the vulnerable revision is marked "not counted"; a mode that did not
run is marked "not run". The same numbers are recorded in the report and the bundle manifest
(`bounds.variant`), and a replay must reproduce them. The measured durations of every campaign and
replay are reported apart from the bounds (`timing`, and the `time:` line of the text output),
since they differ between runs ([ADR 0017](adr/0017-campaign-profiles-and-confirmed-variants.md)).

What a `PASS` does not show: that no variant exists. The search tries the seeds and runs of one
profile, inside the ranges the PoC declares, with the attacker contract the PoC uses and the call
sequence of `exploit()`, and, where a fixture has one, the sequences its invariant handler can
make. Variants outside those are outside this search.

## BehaviorOracle

Checks that the patch keeps the legitimate behavior of the project.

Both revisions run in benign trees: `src/` of the revision, the project's `test/` directory and
the harness. On each revision the oracle compiles the tree and runs every test
(`forge test --json -vv --threads 1 --fuzz-seed 0x1 --fuzz-runs N`).

- The vulnerable revision sets the baseline: which tests pass, and what each passing test
  records with `recordBehavior(key, data)`. Only `AssayRecord` events emitted by the test
  contract itself count; console lines never do. Tests that fail on the vulnerable revision are
  not compared.
- Every test that passes on the vulnerable revision must pass on the patched revision; otherwise
  `FAIL` `benign_test_failed`. Tests that no longer compile against the patched sources fail as
  well.
- For every test that passes on both revisions, the recorded values are compared key by key, in
  order. A key whose values differ, or that only one revision records, is `FAIL`
  `behavior_changed`; the differences are stored as `behavior-diff.json`.

| Observation | Verdict | Reason |
|---|---|---|
| a benign test that passed no longer passes | `FAIL` | `benign_test_failed` |
| a recorded value changed for the same key | `FAIL` | `behavior_changed` |
| the same tests pass with the same records | `PASS` | |
| no `test/` directory, or no test passes on the vulnerable revision | `INCONCLUSIVE` | `no_benign_tests` |

Further `INCONCLUSIVE` reasons: `benign_build_failed` (the vulnerable revision does not compile
with its tests), `harness_unreadable`, `timeout`, `unusable_output`, `run_tree_rejected`,
`run_tree_mismatch`.

What a `PASS` does not show: that behavior is unchanged in general. Only the behavior the benign
tests exercise and record is compared; code paths without a test, and values a test does not
record, are not covered.

## RegressionOracle

Checks that the patch does not break the interface of the contracts and that the project's test
suite still passes.

The target contracts are every concrete contract (not abstract, not an interface, not a library)
declared in a Solidity file under `src/` of the vulnerable revision
([ADR 0013](adr/0013-evidence-bundle-and-replay.md)). For each target the oracle reads
`forge inspect <path>:<Name> storageLayout --json` and `... abi --json` on both revisions, in
benign trees, and compares them:

| Kind | Breaking: `FAIL` | Additive: warning only |
|---|---|---|
| storage layout | any difference of a variable of the vulnerable revision (name, slot, offset, type, size, order), including a new variable placed before or between existing ones or packed into the free bytes of the last used slot: `layout_changed` | a new variable that starts in a slot after the last slot used by the vulnerable revision: `storage_appended` |
| ABI functions (with constructor, `receive`, `fallback`) | a function removed, its parameter types changed, or its return types or state mutability changed: `abi_changed` | a new function: `function_added` |
| events | an event removed, or its parameter types, indexed parameters or anonymity changed: `event_changed` | a new event: `event_added` |
| contracts | a target that is no longer a concrete contract: `abi_changed` | a new concrete contract: `contract_added` |

Types are compared by their full description (struct members, mapping key and value, array
base), not by forge's type identifiers, which contain AST ids. Parameter names and custom errors
are not compared.

On the patched revision the oracle also runs the project's whole test suite
(`forge test --json -vv --threads 1 --fuzz-seed 0x1 --fuzz-runs N` on the benign tree). Every test
and every
`setUp()` must pass, also tests that already failed on the vulnerable revision; otherwise `FAIL`
`test_suite_failed`. A patched revision that does not compile with its tests fails the same way.
Skipped tests give the warning `tests_skipped`.

Further `INCONCLUSIVE` reasons: `no_tests`, `no_target_contracts`, `target_not_inspectable`,
`vulnerable_build_failed`, `timeout`, `unusable_output`, `run_tree_rejected`,
`run_tree_mismatch`. A breaking change found before a later step timed out still fails; the step
that did not finish is listed in the trace.

What a `PASS` does not show: that the patch is compatible with every caller or every deployed
state. The comparison covers the storage layout, functions and events reported by the compiler
for contracts under `src/`; it does not compare custom errors, bytecode, gas, storage written
through assembly or `delegatecall`, or contracts outside `src/`. The test suite is only as good
as the project's tests.

## SymbolicOracle

Runs Halmos on symbolic properties, within recorded bounds, after the VariantOracle. Optional:
only with `--symbolic`. Halmos runs in the symbolic runner image, which is built for linux/amd64
only and runs under emulation on an arm64 host
([ADR 0018](adr/0018-halmos-in-a-linux-amd64-image.md)); everything else, including the replays
of a counterexample, runs in the regular runner image.

### Properties

Properties are Solidity contracts in the `symbolic/` subdirectory of the PoC directory that
derive from `AssayCheck` (`solidity/AssayCheck.sol`, imported as `assay/AssayCheck.sol`). The
other oracles and the fixture checker leave `symbolic/` out of their run trees. A property is a
public function whose parameters Halmos treats as symbolic; only static types are allowed
(`address`, `bool`, `uintN`, `intN`, `bytesN`), and parameter names contain no `_`. Two kinds,
told apart by the name:

- `check_variant_<name>`: the exploit, generalized. It calls the target through
  `assayCall(caller, target, value, data)` and ends with one or more of `assertNoAttackerProfit`,
  `assertNoVictimLoss`, `assertNoUnauthorizedRoleChange` and `assertInvariantHolds`, which
  assert that the PoC predicate of the same name does not hold.
- `check_equiv_<name>`: bounded equivalence. It runs the same calls on the revision under test
  (`src/`) and on the vulnerable revision, which the oracle places under `baseline/` (imported
  as `../../baseline/<file>.sol`), with the exploit condition excluded through `vm.assume`, and
  asserts with `assertSameCall` and `assertSame` that success, return or revert data and the
  observable state agree.

A property makes at most `ASSAY_MAX_CALLS` (4) calls through `assayCall`; further calls revert,
so paths beyond the limit end without a counterexample.

### Runs

Two Halmos runs per verification, each in its own symbolic tree (`src/` of the revision, the
whole PoC directory under `test/`, `src/` of the vulnerable revision under `baseline/`, the
harness under `assay/`):

```
halmos --root /work/project --forge-build-out /work/scratch/out --function <prefix>
       --loop 3 --solver z3 --solver-timeout-assertion 60s --solver-threads 1
       --json-output /work/scratch/halmos.json --no-status
```

with the prefix `check_variant_` on the vulnerable revision and `check_` (variant and
equivalence properties) on the patched revision. Limits per run: 900 s wall clock, 4096 MiB of
memory, a 256 MiB `/tmp`. The JSON report is untrusted input: it is read without following a
symlink, bounded in size, depth and values before parsing, and validated by strict models that
keep only the contract, signature, result code, path counts, the number of loops cut at the
bound and the counterexample values. A property signature with a non-static parameter type
makes the report unusable. Sources that contain a Halmos option annotation (`custom:halmos`)
are refused before Halmos runs: Assay sets the bounds itself.

Halmos's result per property: 0 no counterexample on any explored path; 1 a counterexample;
2 a solver timeout (`unknown`); 3 a path that could not be explored; 4 every path reverted;
5 an error. Only 0 can lead to a pass; 2 to 5 are unknown.

### Sanity check and counterexample flow

A variant property counts only when Halmos reports a counterexample with a valid model for it on
the vulnerable revision; a property that finds nothing there says nothing about the patched
revision and gets the warning `symbolic_check_ineffective`.

A counterexample on the patched revision goes through the same flow as a variant of the
VariantOracle: the parameter names come from the property's ABI (`forge inspect ... abi`), the
model's values are written as 64-digit hex words into a generated `variant_poc.t.sol` that calls
`assayReplayCheck` with the property's selector and those words (nothing else from the report
enters Solidity source), and the test runs three times with Foundry on the patched revision. In
that replay the `assertNo*` wrappers record the PoC predicate instead of asserting; only three
replays of three that reach the predicate confirm the variant. The counterexample is stored as
`counterexample.json` and the test as `variant_poc.t.sol` in the bundle's `evidence/symbolic/`.

### Verdicts

| Observation | Verdict | Reason |
|---|---|---|
| a counterexample on the patched revision, confirmed by three replays of three | `FAIL` | `variant_found` |
| a counterexample whose replays disagree or reach no predicate | `INCONCLUSIVE` | `flaky_counterexample` |
| a wall-clock timeout, an out-of-memory kill, or an unknown result (codes 2 to 5) of a counted property | `INCONCLUSIVE` | `symbolic_unknown` |
| no variant property has a counterexample on the vulnerable revision | `INCONCLUSIVE` | `symbolic_check_ineffective` |
| every counted property without a counterexample on the patched revision | `PASS` | |

Further `INCONCLUSIVE` reasons: `no_symbolic_properties` (the PoC directory has no `symbolic/`),
`inline_halmos_config`, `symbolic_build_failed`, `symbolic_output_unusable`,
`counterexample_rejected`, `variant_poc_build_failed`, `variant_poc_rejected`,
`symbolic_abi_unreadable`, `harness_unreadable` and `run_tree_rejected`. A timeout or an unknown
result is never a pass.

### Bounded equivalence

The equivalence properties run on the patched revision only. Their outcome is one of: no
difference within the bounds, a difference (a counterexample, not replayed), unknown, or no
equivalence properties. It adds to the BehaviorOracle's evidence only when it shows no
difference: the bounds statement then carries `bounded equivalence: no difference from the
vulnerable revision within loop bound 3 for ...`. A difference or an unknown result changes no
verdict; it is a warning (`equivalence_not_shown`) and a note in the report.

### Bounds

The bounds statement names the loop bound, each counted property with its calldata size, the
number of loops cut at the bound, the call limit, the solver and its time per query, and the run
limits, for example:

```
symbolic: no counterexample within loop bound 3 for check_variant_payOut (calldata 4+32*2
bytes), check_variant_payOutAll (calldata 4+32*1 bytes); Halmos 0.3.3, solver z3 with 60 s
per query, at most 4 calls of the target per property, run limit 900 s and 4096 MiB; this is not
a proof of absence
```

or `symbolic: unknown (timeout 900 s); ...`. The same values are in the report and the manifest
(`bounds.symbolic`).

What a `PASS` does not show: that no variant exists. Halmos explores the paths of the properties
as written, from the state their `setUp()` builds, with loops cut at the bound and at most the
stated number of calls; other states, callers, call sequences and longer paths are not covered,
and a property covers only the attack it was written for. Results per fixture:
[symbolic checks](symbolic.md).

## Evidence bundle

`assay verify ... --bundle-out DIR` writes a bundle of the verification
([ADR 0013](adr/0013-evidence-bundle-and-replay.md)). `DIR` must be empty or absent; a file, a
non-empty directory, a symlink, or a directory inside the base project or the PoC directory is
refused before anything runs (exit code 2). A bundle is also written when verification stops
early.

```
DIR/
├── manifest.json
├── base/          the vulnerable project as ingested (no .git, .assay, out, cache)
├── poc/           the PoC directory as ingested
├── harness/       the shared harness that ran
├── patch.diff     the candidate patch, byte for byte
├── evidence/      per oracle: result.json and the artifacts of its executions
└── fix/           only in the bundle of `assay fix` and `assay run`: history.json, the attempt
                   history (see [the fix loop](fix-loop.md))
```

`manifest.json` holds:

- the sha256 and size of every other file of the bundle;
- the Assay version, the runner image id, the tool versions from the image labels, and the full
  content of `versions.lock` with its sha256; with `--symbolic`, the same for the symbolic
  runner image (`symbolic_environment`);
- the settings (campaign profile, base seed, fuzz runs when given, replays of the PoC, whether
  the symbolic oracle ran) and the patch policy;
- the tree hashes of the inputs, the verdict, reasons and warnings of every oracle, the final
  verdict and its reasons, the bounds (with the variant campaigns: profile, base seed, derived
  seeds, runs per seed, invariant runs and depth, the seeds that ran, where a variant was found,
  the confirmation replays; with `--symbolic`, the Halmos bounds and the result of every
  property) and the bounds statement, the evidence level and the symbolic annotations;
- `timing`: the measured duration of the verification, of every oracle and of every variant
  campaign and replay, in seconds.

It holds no timestamps, absolute host paths or user names: evidence and manifest pass through a
sanitizer that replaces known host paths with placeholders such as `<work>` and `<home>`. Two
verifications of the same inputs with the same runner image give manifests that are byte-identical
apart from `timing`, which holds durations only
([ADR 0017](adr/0017-campaign-profiles-and-confirmed-variants.md)).

A bundle is tamper-evident, not a signature: whoever can rewrite both the files and the manifest
can forge it.

## `assay replay`

```sh
assay replay <bundle dir> [--json]
```

1. Every file of the bundle is hashed and compared with `manifest.json`. A changed, missing or
   unexpected file, a symlink or a special file stops the replay with exit code 5; nothing runs.
2. The runner image recorded in the manifest is used when it exists locally. Otherwise
   `assay-runner:dev` is used when its tool versions and the current `versions.lock` match the
   manifest, and the output says so. Otherwise the replay stops with exit code 4: run
   `make image`. A bundle of a verification with `--symbolic` needs the symbolic runner image
   as well, chosen the same way (`assay-runner-symbolic:dev`).
3. Every oracle runs again in the sandbox, without network, on `base/`, `patch.diff` and `poc/`,
   with the bundle's harness, settings (including the campaign profile and base seed) and patch
   policy, into a temporary ledger.
4. The inputs, the status, verdict, reason codes and warning codes of every oracle, the final
   verdict and its reasons, and the bounds (including where each variant campaign found
   something) are compared with the manifest; durations are not. When they are equal the output
   is `REPLAY MATCH`; otherwise `REPLAY MISMATCH` with one line per difference.

Exit codes: 0 `REPLAY MATCH`; 1 the replay differs; 2 usage error, or a bundle of another format
version (bundles written before campaign profiles existed are version 1 and must be produced
again); 4 Docker or the runner image missing; 5 the bundle does not match its manifest.
