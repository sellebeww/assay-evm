# Fixture specification

Fixtures are small, synthetic, intentionally vulnerable Solidity projects. Each fixture comes with
a PoC exploit, benign tests and four labelled patches. They serve as ground truth for the oracles
and as the development split of the benchmark.

Fixtures are test material. They MUST NOT be deployed anywhere.

## 1. Directory layout

Development fixtures live in `fixtures/<class>/<name>/`. Held-out fixtures (section 9) use the
same layout under `bench/heldout/<class>/<name>/`.

```
fixtures/<class>/<name>/
├── src/            vulnerable contract(s) and small mocks
├── test/           benign tests
├── poc/            PoC exploit deriving from AssayPoC, and an optional invariant
│   └── symbolic/   optional Halmos properties deriving from AssayCheck
├── patches/
│   ├── good.diff
│   ├── overfit.diff
│   ├── destructive.diff
│   └── regressing.diff
├── foundry.toml
├── expected.json
└── README.md
```

| Path | Content and rules |
|---|---|
| `src/` | The vulnerable contract, at most about 120 lines, plus optional small mocks in separate files (a minimal token, a tiny AMM). Original code only. Every `.sol` file carries the mandatory header (section 5). |
| `test/` | Benign tests: deposits, normal withdrawals and a few ordinary uses of the contract. They call `recordBehavior(key, data)` so that observable results can be compared between revisions. |
| `poc/` | One PoC contract deriving from `AssayPoC` (from the shared harness in `solidity/`), plus any helper contracts the attack deploys (for example a contract that re-enters the target). The PoC implements only `setUpTarget()` and `exploit()`. `exploit()` consumes the numeric knobs that `testFuzz_variants` randomizes, so that variants of the attack are reachable by fuzzing. Optionally one fixture invariant deriving from `AssayInvariant`, with its handler (section 10), for variants made of several calls. |
| `poc/symbolic/` | Optional symbolic properties for the SymbolicOracle: contracts deriving from `AssayCheck` with `check_variant_*` and `check_equiv_*` functions (section 10). Only the symbolic oracle compiles them; the PoC trees of the other oracles and of the checker leave this directory out. |
| `patches/` | Four unified diffs against the fixture root, one per label (section 2). |
| `foundry.toml` | Minimal configuration for plain Foundry: the pinned solc version, `ffi = false`, no `fs_permissions`, no RPC endpoints, no remappings outside the fixture. |
| `expected.json` | The expected result for the vulnerable revision and each patch (section 4). |
| `README.md` | Plain-language explanation (section 6). |

Fixtures do not vendor forge-std, the shared harness or any other library. Those are provided by
the runner environment. The runner environment places the harness under `assay/` at the root of
every run tree and runs the PoC in a tree of its own, in which `poc/` takes the place of `test/`
([ADR 0011](adr/0011-run-trees-for-harness-and-poc.md)). Hence:

| Files under | May import |
|---|---|
| `src/` | only other files under `src/`, by relative path (never forge-std or the harness) |
| `test/` | `forge-std/...`, `assay/AssayExploit.sol`, `assay/AssayInvariant.sol`, and files under `src/` or `test/` by relative path |
| `poc/` | `forge-std/...`, `assay/AssayExploit.sol`, `assay/AssayInvariant.sol`, and files under `src/` or `poc/` by relative path |
| `poc/symbolic/` | the same, `assay/AssayCheck.sol`, and the vulnerable revision's sources under `baseline/` by relative path (`../../baseline/<file>.sol`), which the symbolic run tree provides |

A fixture must not contain an `assay/` directory, and its top level holds exactly the entries
shown above.

Protected paths: `test/`, `poc/`, `foundry.toml`, `expected.json` and the shared harness in
`solidity/`. Patches may modify files under `src/` only.

## 2. Patch labels

The labels are mutually exclusive ([ADR 0010](adr/0010-mutually-exclusive-patch-labels.md)).
Every patch MUST block the original PoC. A patch that does not block it fits no label and must be
rewritten. Beyond that, each label is defined by three observations: whether the variant search
still finds an exploit, whether the benign tests pass, and whether the interface (storage layout,
ABI, events) changed in a breaking way.

| Label | Original PoC | Variant search | Benign tests | Interface |
|---|---|---|---|---|
| `good` | BLOCKED | BLOCKED | pass | same |
| `overfit` | BLOCKED | EXPLOITED | pass | same |
| `destructive` | BLOCKED | BLOCKED | FAIL | same or changed |
| `regressing` | BLOCKED | BLOCKED | pass | changed |

These definitions are mutually exclusive. A patch whose observations match no row is invalid.

### `good`

Closes the root cause. Benign behavior, storage layout, ABI and events stay the same. Examples:
checks-effects-interactions for reentrancy; a time-weighted price for oracle manipulation;
isolating one recipient's failure without changing the interface for a payout loop; virtual
shares or an offset for a vault.

### `overfit`

Closes only the path used by the original PoC, so a close variant still works. It MUST look like a
plausible half-fix a developer could write. It MUST NOT insert PoC-specific addresses, selectors or
numbers. Examples: only one of two similar functions gets the permission check; a return value is
checked on one path but not on another; a nonce is added but malleable signatures (high `s`) still
replay, or `chainId` is missing from the signed message; an allowlist at only one entry point; a
per-swap size cap that several small swaps get around; a minimum first deposit that a larger
donation still defeats.

Every `overfit` patch in the development split MUST be defeatable by `testFuzz_variants` alone,
that is, by randomizing the attacker address, the attacker balance and the PoC knobs. Variants
that need a different call sequence belong to held-out fixtures or to the invariant mode.

### `destructive`

Closes the hole by disabling or removing legitimate functionality, so at least one benign test
fails. Examples: an unconditional revert, a function body emptied of its effect, a modifier that
no caller can satisfy.

### `regressing`

Closes the hole and keeps the benign tests passing, but changes the storage layout, the ABI or
the events in a breaking way.

### Interface comparison

The interface of the target contract is compared with `forge inspect` output (`storageLayout`
and `abi`) between the vulnerable and the patched revision.

- Breaking (status `changed`): a storage slot, offset, type or order changes; a function is
  removed or its signature changes; an event is removed or changed.
- Additive (status stays `same`): a storage variable appended after the last existing slot, a new
  function, a new event. Additive changes appear as warnings in reports and do not affect the
  label.

In detail:

| Kind | Compared | Breaking | Additive |
|---|---|---|---|
| `layout` | Every variable of the vulnerable revision: name, slot, offset, type and size, in order. | Any difference, including a new variable placed before or between existing ones, or packed into the free bytes of the last used slot. | New variables after the existing ones that start in a slot after the last slot used by the vulnerable revision. |
| `abi` | Functions, including the constructor, `receive` and `fallback`, identified by name and parameter types (tuples in canonical form). | A function removed, or its return types or state mutability changed. | A new function. |
| `events` | Events identified by name and parameter types. | An event removed, or its indexed parameters or anonymity changed. | A new event. |

Custom errors are not compared.

### Compilation

Every variant (the vulnerable revision and each patched revision) MUST compile together with the
fixture's benign tests and PoC. A compilation failure is not an observation; it is a broken
fixture. Consequently, a `destructive` patch disables behavior while keeping the symbols that the
tests and the PoC reference.

## 3. Vulnerability classes

Each class has exactly one development fixture and one held-out fixture with a different code
shape (`bench/heldout/`, listed in `bench/splits/heldout.json`).

| # | Class id | What goes wrong | Development fixture |
|---|---|---|---|
| 1 | `reentrancy` | An external call happens before the state is updated, so the callee re-enters. | `fixtures/reentrancy/single_function` |
| 2 | `access_control` | A privileged function lacks a permission check. | `fixtures/access_control/missing_modifier` |
| 3 | `unchecked_call` | The result of a low-level call is ignored, so accounting diverges when the receiver refuses. | `fixtures/unchecked_call/ignored_return` |
| 4 | `signature_replay` | A signed claim can be reused because there is no nonce or domain separation. | `fixtures/signature_replay/missing_nonce` |
| 5 | `delegatecall` | `delegatecall` to an attacker-chosen target overwrites storage such as the owner. | `fixtures/delegatecall/user_controlled_target` |
| 6 | `oracle_manipulation` | A lending contract values collateral at the spot price of a tiny AMM pool inside the fixture, which one large swap can move. | `fixtures/oracle_manipulation/spot_price` |
| 7 | `dos` | One payout loop over many recipients, so one always-reverting recipient blocks everyone. | `fixtures/dos/payout_loop` |
| 8 | `rounding` | An ERC4626-style vault where the first depositor inflates the price per share, so later deposits round to zero shares. | `fixtures/rounding/share_inflation` |

The class id is also the first path segment of the fixture and the value of `class` in
`expected.json`.

## 4. `expected.json`

`expected.json` records the expected observations for the vulnerable revision and the four patches,
and the expected final verdict for each patch. A unit test validates every file against this
schema. Unknown fields are rejected.

### Top-level fields

| Field | Type | Rule |
|---|---|---|
| `schema_version` | integer | `1` |
| `fixture` | string | Path relative to the split root, `<class>/<name>`; must match the directory. |
| `class` | string | One of the eight class ids; must equal the first segment of `fixture`. |
| `solc` | string | Exact solc version `MAJOR.MINOR.PATCH`; must equal the pinned version (section 7). |
| `contract` | string | Target contract for the interface comparison, as `<path under src>:<ContractName>`. |
| `variants` | object | Exactly the keys `vulnerable`, `good`, `overfit`, `destructive`, `regressing`. |

### Variant fields

| Field | Type | Rule |
|---|---|---|
| `applies` | boolean | Whether the patch applies cleanly to the vulnerable tree. `true` for `vulnerable` (no patch) and required to be `true` for every patch of a valid fixture. |
| `replay` | string | `EXPLOITED` or `BLOCKED`: result of the PoC's `test_replay`. |
| `fuzz_variants` | string | `EXPLOITED` or `BLOCKED`: result of the PoC's `testFuzz_variants`. |
| `benign` | string | `pass` or `FAIL`: result of the benign tests. |
| `interface` | object | `{"status": ..., "kinds": [...]}`. `status` is `baseline` (only for `vulnerable`), `same` or `changed`. `kinds` is empty unless `status` is `changed`, in which case it lists one or more of `layout`, `abi`, `events`. |
| `verdict` | string | Patches only. `VERIFIED_WITHIN_BOUNDS` or `REJECTED`. |
| `reason` | string or null | Patches only. The reason that must appear among the failure reasons reported by the oracles; `null` for `good`. |

### Outcome definitions

- `replay` is `EXPLOITED` when `test_replay` passes and the test contract emitted its predicate
  (an `AssayPredicate` event, section 10); otherwise `BLOCKED`.
- `fuzz_variants` is `EXPLOITED` when Foundry finds an input for which the predicate is reached,
  using the checker's fixed seed and run count; `BLOCKED` when no such input is found within those
  bounds. `BLOCKED` is a bounded statement, not a proof of absence. Concretely, `EXPLOITED` means
  that `testFuzz_variants` failed with a reason that starts with `ASSAY_VARIANT_FOUND|`, reported
  a counterexample, and the test contract emitted an `AssayPredicate` event; `BLOCKED` means that
  `testFuzz_variants` passed after the full run count.
- `benign` is `pass` when every benign test passes; `FAIL` when at least one fails.
- Anything else is not an observation but a broken fixture: a compilation failure, a failing
  `setUp()`, a `test_replay` that passes without the event, or a `testFuzz_variants` that fails
  for another reason or stops before the full run count.

### Consistency rules

| Variant | `replay` | `fuzz_variants` | `benign` | `interface.status` | `verdict` | `reason` |
|---|---|---|---|---|---|---|
| `vulnerable` | EXPLOITED | EXPLOITED | pass | baseline | (absent) | (absent) |
| `good` | BLOCKED | BLOCKED | pass | same | VERIFIED_WITHIN_BOUNDS | `null` |
| `overfit` | BLOCKED | EXPLOITED | pass | same | REJECTED | `variant_found` |
| `destructive` | BLOCKED | BLOCKED | FAIL | same or changed | REJECTED | `benign_test_failed` or an integrity reason such as `vacuous_patch` |
| `regressing` | BLOCKED | BLOCKED | pass | changed | REJECTED | `layout_changed`, `abi_changed` or `event_changed`, matching one of `interface.kinds` |

The classification matrix counts a patch as a match when the final verdict equals `verdict` and
`reason` (if not `null`) appears among the reported failure reasons.

### Example

The contract name below is illustrative.

```json
{
  "schema_version": 1,
  "fixture": "reentrancy/single_function",
  "class": "reentrancy",
  "solc": "0.8.36",
  "contract": "Bank.sol:Bank",
  "variants": {
    "vulnerable": {
      "applies": true,
      "replay": "EXPLOITED",
      "fuzz_variants": "EXPLOITED",
      "benign": "pass",
      "interface": {"status": "baseline", "kinds": []}
    },
    "good": {
      "applies": true,
      "replay": "BLOCKED",
      "fuzz_variants": "BLOCKED",
      "benign": "pass",
      "interface": {"status": "same", "kinds": []},
      "verdict": "VERIFIED_WITHIN_BOUNDS",
      "reason": null
    },
    "overfit": {
      "applies": true,
      "replay": "BLOCKED",
      "fuzz_variants": "EXPLOITED",
      "benign": "pass",
      "interface": {"status": "same", "kinds": []},
      "verdict": "REJECTED",
      "reason": "variant_found"
    },
    "destructive": {
      "applies": true,
      "replay": "BLOCKED",
      "fuzz_variants": "BLOCKED",
      "benign": "FAIL",
      "interface": {"status": "same", "kinds": []},
      "verdict": "REJECTED",
      "reason": "benign_test_failed"
    },
    "regressing": {
      "applies": true,
      "replay": "BLOCKED",
      "fuzz_variants": "BLOCKED",
      "benign": "pass",
      "interface": {"status": "changed", "kinds": ["layout"]},
      "verdict": "REJECTED",
      "reason": "layout_changed"
    }
  }
}
```

## 5. Mandatory header

Every `.sol` file under a fixture's `src/` starts with this exact first line:

```solidity
// INTENTIONALLY VULNERABLE: test fixture, do not deploy
```

The SPDX license identifier and the `pragma` follow on the next lines. Patches MUST NOT remove or
alter the header. The fixture `README.md` also opens with a notice that the code is intentionally
vulnerable.

## 6. Fixture README

Each fixture `README.md` contains, in this order:

1. A notice that the code is intentionally vulnerable and must not be deployed.
2. The hole: what goes wrong, in plain language.
3. The attack: what the PoC does and which predicate it records.
4. The variants: which knobs the PoC exposes and what a variant looks like.
5. The four patches: what each changes and why it has its label.

## 7. solc version

- One solc version is used for every fixture, development and held-out alike.
- Selection rule: the newest version supported at the same time by Foundry, Slither, Halmos and
  the fixtures, with official builds for both runner platforms (ADR 0008).
- Pinned version: **0.8.36** (`v0.8.36+commit.8a079791`), also recorded in
  `docker/runner/versions.lock`. Reasons:
  - Foundry v1.8.4 supports it, and official static builds exist for linux/amd64 and linux/arm64.
  - The latest Slither release (0.11.6) added parsing support for the language features of 0.8.35.
    Version 0.8.36 adds no language features, only EVM and compiler changes, so its syntax is
    covered by that release.
  - The newer 0.8.37 adds a language feature (`block.slotnum`) and was released after Slither
    0.11.6, so Slither support for it is not established.
  - Halmos is not verified yet. Its latest release (v0.3.3) predates every 0.8.3x release from
    0.8.31 on. Compatibility is checked when Halmos is added (Phase 4); an incompatibility leads to
    an ADR that changes the version or documents the gap.
- Known compiler bugs of 0.8.36 and how fixtures avoid them:
  - `MisorderedNamedParametersInRequireWithCustomErrors` and
    `SpillSlotCollisionAcrossMutualRecursion` occur only with the via-IR pipeline. Fixtures compile
    with the legacy pipeline (`via_ir` is never enabled).
  - `MemoryByteArrayElementDeleteClearsWholeWord` affects `delete` applied to an element of a
    `bytes memory` array. Fixtures do not use this construct.
- Every `.sol` file uses the exact pragma `pragma solidity 0.8.36;`. No ranges, no caret, no `>=`.
- The fixture `foundry.toml` and `expected.json` declare the same version. A unit test checks both
  against `versions.lock`.
- solc is baked into the runner image. Nothing is downloaded at run time.
- Changing the version requires an ADR, updating every fixture, and re-running
  `make fixtures-check` and the classification matrix.

## 8. Ground truth and label changes

- Labels are established by plain Foundry through `make fixtures-check` (`tools/fixture_check.py`).
  The checker MUST NOT import or call any Assay oracle code. It runs every forge command through
  the sandbox runner, uses ingest's snapshot step for the fixed Foundry configuration, and reads
  forge's JSON output itself. Because fixtures are trusted, the checker may use `git apply` on its
  own copies.
- Before running anything, the checker checks the files of every fixture and of the harness
  against this specification: the top-level entries, header and pragma, the import rules of
  section 1, one `AssayPoC` contract and at most one `AssayInvariant` contract under `poc/`,
  none of either under `test/`, benign tests that call `recordBehavior`,
  `foundry.toml`, and `expected.json` (schema, consistency rules, no duplicate keys). A unit test
  runs the same checks without Docker.
- For each variant, the checker copies `src/`, `test/` and `poc/` (without `poc/symbolic/`, whose
  properties are Halmos input, not ground truth) and applies the patch with
  `git apply` under a fixed environment, so that no system or user git configuration changes the
  result. The patch must touch only text files under `src/`, and the patched sources must still
  follow the header, pragma and import rules. The checker then builds two run trees, both with
  the harness under `assay/`: the benign tree (`src/` and `test/`) and the PoC tree (`src/`, with
  `poc/` in the place of `test/`). In the benign tree it runs `forge build`, `forge test` and
  `forge inspect` (`storageLayout`, `abi`); in the PoC tree `forge build` and `forge test`. The
  PoC tree's configuration adds the invariant runs and depth, so that a fixture invariant runs
  with fixed bounds.
- Fuzz bounds: seed `0x1` and 256 runs by default, changeable with `--fuzz-seed` and
  `--fuzz-runs`, on one thread ([ADR 0014](adr/0014-single-threaded-forge-test-runs.md)).
  Invariant bounds: 64 runs of depth 25 by default, changeable with `--invariant-runs` and
  `--invariant-depth`, with the same seed. The same fixtures and settings give the same output.
- The checker discovers the fixtures itself: every directory `fixtures/<class>/<name>/` is a
  fixture, so a new fixture needs no registration; `--only <class>/<name>` restricts a run.
  Every other visible entry at those two levels (a file, a symlink, a directory that is not named
  after a class id, a class directory without a fixture) is reported as a problem of the fixtures
  root and fails the check; nothing there is skipped silently. Hidden entries (names starting
  with `.`) are ignored.
- The checker produces one row per variant: eight fixtures times five variants gives 40 rows, 80
  with the held-out split. Every row must match `expected.json`. The columns are `variant`,
  `applies`, `replay`, `fuzz_variants`, `benign`, `invariant`, `interface` and `records`,
  followed by the result. `invariant` is `BROKEN` when the fixture invariant broke, `holds` when
  it held for every run and `-` when the fixture has none; it must be `BROKEN` on the vulnerable
  revision and `holds` under the `good` patch, and is informational for the other labels. It is
  not part of `expected.json`. `records` compares the `AssayRecord` events of the passing benign tests with the
  vulnerable revision (`same` or `changed`); a patch whose expected verdict is
  `VERIFIED_WITHIN_BOUNDS` must keep them `same`, for the other labels the column is
  informational. On the vulnerable revision, every benign test must record at least one value. `--verbose` explains every observation, for example the revert reason of a
  blocked replay or the values of a variant. After the tables, a summary gives one line per
  fixture with its matching rows, and a last line the number of fixtures and of matching rows.
- Exit status: 0 when every row matches; 1 when a row does not match, a fixture is broken or the
  fixtures root holds a foreign entry; 2 when the sandbox cannot be used or the arguments are
  invalid.
- Oracles are tested against the labels only after the checker confirms them.
- If a patch does not match its label (for instance an `overfit` patch that really closes the
  hole), the patch is fixed. The label is not changed to fit the patch.
- Labels and the expected observations in `expected.json` change only through human review. The
  change must state what was wrong, include the `make fixtures-check` output before and after, and
  update the fixture README. No tool and no model output may edit a label.
- Oracles MUST NOT special-case fixture names, function names, file names or PoC contents.

## 9. Authoring rules

- Original code only: no copies of real contracts or past exploits, no real protocol names, no new
  dependencies. Tiny mocks inside the fixture are allowed.
- Benign tests exercise ordinary use and record observable results with `recordBehavior`.
- The PoC uses only the predicate helpers from the shared harness (`attacker_profit`,
  `victim_loss`, `unauthorized_role_change`, `invariant_broken`). A PoC that finishes without a
  predicate is a failure, not a success.
- Predicate arguments are values measured in the test, for example balances read before and
  after the attack, never constants. The PoC never emits the harness events itself and never
  changes the harness state directly.
- Held-out fixtures in `bench/heldout/` are written after the oracle freeze, with code shapes that
  differ from the development fixtures (for example cross-function reentrancy, access control
  through an initializer, cross-chain signature replay, fee rounding). They are written without
  running `assay verify` on them; only `make fixtures-check` is allowed before the held-out run.

## 10. Shared harness

`solidity/AssayExploit.sol` holds two abstract contracts, `solidity/AssayInvariant.sol` a third.
They are protected paths, and fixtures import them rather than copy them (section 1).

### `AssayExploit`

`AssayExploit` inherits `Test` from forge-std. Benign tests derive from it to use
`recordBehavior`; `AssayPoC` derives from it for the predicates.

| Predicate | Holds when | Detail |
|---|---|---|
| `attacker_profit(asset, balanceBefore, balanceAfter)` | `balanceAfter > balanceBefore` | `<asset>:<before>-><after>` |
| `victim_loss(asset, balanceBefore, balanceAfter)` | `balanceAfter < balanceBefore` | `<asset>:<before>-><after>` |
| `unauthorized_role_change(role, expectedHolder, actualHolder)` | the two addresses differ | `<role>:<expected>-><actual>` |
| `invariant_broken(name, invariantHolds)` | `invariantHolds` is false | `<name>` |

A predicate returns whether it held. When it holds, the test contract emits
`AssayPredicate(string kind, string detail)` and prints `ASSAY_PREDICATE|<kind>|<detail>`, where
`<kind>` is the predicate's name. `asset`, `role` and `name` are 1 to 32 characters from letters,
digits, `_`, `.` and `-`; anything else reverts, so every marker line splits into exactly three
fields.

`recordBehavior(bytes32 key, bytes data)` emits `AssayRecord(bytes32 indexed key, bytes data)` and
prints `ASSAY_REC|<key>|<hex>`, where `<hex>` is `data` in lowercase `0x` hex. The key is
left-aligned text of 1 to 32 characters (letters, digits, `_`, `.`, `-`, `:`) padded with zero
bytes; a string literal converts to it implicitly.

Tools rely on the events, and only on those emitted by the test contract itself. The console
lines are for people; text printed by the target or by the PoC never counts.

### `AssayPoC`

A PoC derives from `AssayPoC` and implements only two functions:

- `setUpTarget()` deploys and funds the target and declares the knobs and the attacker balance;
- `exploit()` runs the attack as `attacker` (for example through `vm.startPrank(attacker)`) and
  ends with one or more predicates.

Declarations are allowed only inside `setUpTarget()`:

- `declareKnob(index, name, replayValue, min, max)` for the knobs 0 to 3. Undeclared knobs are 0
  in both modes.
- `declareAttackerBalance(replayValue, min, max)` in wei. Without a declaration the replay
  balance is 0 and variants draw it from 0 to 100 ether.

`exploit()` reads `attacker`, `attackerKey` (the attacker's private key, for exploits that need a
signature) and `knob(index)`. The attacker's balance is set before `exploit()` runs.

The harness defines `setUp()` and the two test modes; a PoC cannot override them.

- `test_replay` runs `exploit()` with the original values: the replay attacker, the replay
  balance and the replay value of every knob. It reverts with `AssayNoPredicate()` when no
  predicate held, so a PoC that finishes without a predicate fails.
- `testFuzz_variants(attackerSeed, balanceSeed, knob0Seed, knob1Seed, knob2Seed, knob3Seed)`
  derives the attacker's key from a hash of `attackerSeed`, so the fuzzer cannot steer the
  attacker onto an address that already exists in the test, and bounds the balance and the knobs
  to their declared ranges. It runs `exploit()` in a sub-call (`assayAttempt`, callable only by
  the test contract). When a predicate holds, the test fails with the reason
  `ASSAY_VARIANT_FOUND|attacker=<address>|balance=<wei>|knobs=<k0>,<k1>,<k2>,<k3>`. When the
  exploit reverts or reaches no predicate, that input passes. A passing `testFuzz_variants`
  therefore means that no variant was found in the runs that were made.

Every attempt starts without a prank left over from an earlier attempt that reverted: forge
refuses a new `vm.startPrank` while an unused one is active, which would otherwise make every
later attempt in the same test revert and count as blocked.

`assayReplayVariant(attackerSeed, balanceSeed, knobSeeds)` replays one input of
`testFuzz_variants` as a concrete attempt: the same seeds select the same attacker, balance and
knobs. The VariantOracle uses it in the tests it generates to confirm a variant
([Oracles](oracles.md#counterexample-flow)).

### `AssayInvariant`

A fixture invariant is a property of the target that every sequence of calls through a handler
must keep. Foundry's invariant mode calls the handler with random sequences and checks the
property after every call; the runs and the calls per sequence come from the campaign profile of
the VariantOracle, or from the fixture checker's settings. A fixture invariant derives from
`AssayInvariant` and implements three functions:

- `setUpInvariant()` deploys and funds the target, deploys the handler and registers it with
  `targetContract(address(handler))`, so that only the handler is called;
- `invariantName()` returns a label (1 to 32 letters, digits, `_`, `.`, `-`);
- `invariantHolds()` reads the state and returns whether the property holds.

The harness defines `setUp()` and `invariant_assay()`, which fails with the reason
`ASSAY_INVARIANT_BROKEN|<name>` when the property does not hold. Every call of a campaign comes
from one fixed sender (`INVARIANT_SENDER`), so that the reported sequences repeat exactly for a
seed; handler functions must therefore not depend on `msg.sender`, and act through their own
accounts (for example with `vm.prank`).
`assayReplayCall(sender, target, data)` and `assayCheckInvariant()` replay a sequence in a
generated test and record `invariant_broken` from the test contract.

Rules for a fixture invariant:

- It states the defect of the fixture's class in terms of state, not of the PoC: it must break
  on the vulnerable revision and hold under the `good` patch (checked by `make fixtures-check`).
- The handler drives the attack through ordinary calls with bounded arguments and can interleave
  honest actors, so that a campaign can find variants of several calls. Bounds keep honest
  behavior within what the `good` patch supports (for example a gas limit that fits the number
  of honest accounts).
- It lives in `poc/` next to the PoC, a protected path; a patch cannot change it.

Three development fixtures have an invariant:

| Fixture | Invariant | Property |
|---|---|---|
| `reentrancy/single_function` | `vault_solvent` | the vault holds at least the ether it credits to its depositors |
| `rounding/share_inflation` | `deposit_mints_shares` | a deposit of a positive amount never mints zero shares |
| `dos/payout_loop` | `refunds_complete` | after a refund run, every honest contributor has its contribution back |

### `AssayCheck`

`solidity/AssayCheck.sol` is the base of symbolic properties, run by Halmos through the
SymbolicOracle ([oracles](oracles.md#symbolicoracle)). A property is a public function whose
parameters Halmos treats as symbolic:

- `check_variant_<name>(...)` generalizes the exploit: it calls the target through
  `assayCall(caller, target, value, data)` (at most `ASSAY_MAX_CALLS`, 4, calls per property) and
  ends with `assertNoAttackerProfit`, `assertNoVictimLoss`, `assertNoUnauthorizedRoleChange` or
  `assertInvariantHolds`, which assert that the PoC predicate of the same name does not hold.
  In a Foundry replay of a counterexample (`assayReplayCheck`) the same wrappers record the
  predicate as the PoC would.
- `check_equiv_<name>(...)` compares the revision under test (`src/`) with the vulnerable one
  (`baseline/`), outside the exploit condition (excluded with `vm.assume`), with `assertSameCall`
  and `assertSame`.

Rules: parameters of static types only; parameter names without `_`; fixed accounts as
constants (`address(uint160(0xA11CE0))`), not `makeAddr`, which Halmos treats as symbolic; no
`@custom:halmos` annotations (the oracle refuses them). Four development fixtures have
properties: `access_control/missing_modifier`, `delegatecall/user_controlled_target`,
`unchecked_call/ignored_return` and `rounding/share_inflation`; the others and the reasons are
listed in [symbolic checks](symbolic.md).

The harness itself is tested by `tests/integration/test_harness.py` with the contracts in
`tests/data/harness/`.
