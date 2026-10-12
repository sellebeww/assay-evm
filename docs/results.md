# Benchmark results

`assay bench report` writes this page from stored result folders, with the findings of
`bench/findings.json` and the threats of `bench/PROTOCOL.md`. It is not edited by hand.

## What these results mean

This is a self-validation of the oracles on synthetic fixtures, not an independent benchmark and not
a measurement of detection quality on real contracts. The development fixtures were used to build
the oracles. The held-out fixtures were written after the oracles were frozen and without running
the oracles on them, but by the same party that wrote the oracles. Each verdict covers only the
checks and bounds that ran; `VERIFIED_WITHIN_BOUNDS` means that nothing was found within them and is
not a proof of absence ([Oracles](oracles.md)).

## Runs

| Split | Status | Cases | Profile | Oracle tree hash | Result folder |
|---|---|---|---|---|---|
| `dev` | development split; not held-out by definition | 32 | `standard` | `47dfd491563ccff2` | `bench/results/dev-standard-47dfd49156-45825f0775` |
| `heldout` | HELD-OUT: the oracle hash of the run equals bench/FROZEN_HASH | 32 | `standard` | `47dfd491563ccff2` | `bench/results/heldout-standard-47dfd49156-e1439c5fbc` |

## Split `dev`

Status: **development split; not held-out by definition**.

Verdicts equal to the label: 32/32 (100.0 %, 95 % CI 89.2 to 100.0 %).

| Patch label | Expected verdict | Expected reason | Matching |
|---|---|---|---|
| `good` | `VERIFIED_WITHIN_BOUNDS` | none | 8/8 |
| `overfit` | `REJECTED` | `variant_found` | 8/8 |
| `destructive` | `REJECTED` | `benign_test_failed` or an integrity reason | 8/8 |
| `regressing` | `REJECTED` | `layout_changed`, `abi_changed` or `event_changed` | 8/8 |

### Ablations on `dev`

Each cell is the number of wrong decisions over the number of cases the configuration could judge,
with the Wilson 95 % interval. For bad patches a wrong decision is an acceptance (false accept); for
good patches it is a rejection (false reject). Percentages are rounded away from the favorable
direction.

| Config | Accepts a case when | Overfit accepted | Destructive accepted | Regressing accepted | All bad accepted | Good rejected |
|---|---|---|---|---|---|---|
| V0 | tests only | 8/8 (100.0 %, 95 % CI 67.5 to 100.0 %) | 0/8 (0.0 %, 95 % CI 0.0 to 32.5 %) | 8/8 (100.0 %, 95 % CI 67.5 to 100.0 %) | 16/24 (66.7 %, 95 % CI 46.7 to 82.1 %) | 0/8 (0.0 %, 95 % CI 0.0 to 32.5 %) |
| V1 | V0 and the original PoC is blocked | 8/8 (100.0 %, 95 % CI 67.5 to 100.0 %) | 0/8 (0.0 %, 95 % CI 0.0 to 32.5 %) | 8/8 (100.0 %, 95 % CI 67.5 to 100.0 %) | 16/24 (66.7 %, 95 % CI 46.7 to 82.1 %) | 0/8 (0.0 %, 95 % CI 0.0 to 32.5 %) |
| V2 | V1 and no variant is found | 0/8 (0.0 %, 95 % CI 0.0 to 32.5 %) | 0/8 (0.0 %, 95 % CI 0.0 to 32.5 %) | 8/8 (100.0 %, 95 % CI 67.5 to 100.0 %) | 8/24 (33.4 %, 95 % CI 17.9 to 53.3 %) | 0/8 (0.0 %, 95 % CI 0.0 to 32.5 %) |
| V3 | all non-symbolic oracles (full configuration) | 0/8 (0.0 %, 95 % CI 0.0 to 32.5 %) | 0/8 (0.0 %, 95 % CI 0.0 to 32.5 %) | 0/8 (0.0 %, 95 % CI 0.0 to 32.5 %) | 0/24 (0.0 %, 95 % CI 0.0 to 13.8 %) | 0/8 (0.0 %, 95 % CI 0.0 to 32.5 %) |

V4 (symbolic oracle) is not part of this run.

### Per class on `dev`

Each cell: bad patches accepted out of the bad patches of the class, and good patches rejected out of the good patches of the class.

| Class | V0 | V1 | V2 | V3 |
|---|---|---|---|---|
| `reentrancy` | 2/3 bad, 0/1 good | 2/3 bad, 0/1 good | 1/3 bad, 0/1 good | 0/3 bad, 0/1 good |
| `access_control` | 2/3 bad, 0/1 good | 2/3 bad, 0/1 good | 1/3 bad, 0/1 good | 0/3 bad, 0/1 good |
| `unchecked_call` | 2/3 bad, 0/1 good | 2/3 bad, 0/1 good | 1/3 bad, 0/1 good | 0/3 bad, 0/1 good |
| `signature_replay` | 2/3 bad, 0/1 good | 2/3 bad, 0/1 good | 1/3 bad, 0/1 good | 0/3 bad, 0/1 good |
| `delegatecall` | 2/3 bad, 0/1 good | 2/3 bad, 0/1 good | 1/3 bad, 0/1 good | 0/3 bad, 0/1 good |
| `oracle_manipulation` | 2/3 bad, 0/1 good | 2/3 bad, 0/1 good | 1/3 bad, 0/1 good | 0/3 bad, 0/1 good |
| `dos` | 2/3 bad, 0/1 good | 2/3 bad, 0/1 good | 1/3 bad, 0/1 good | 0/3 bad, 0/1 good |
| `rounding` | 2/3 bad, 0/1 good | 2/3 bad, 0/1 good | 1/3 bad, 0/1 good | 0/3 bad, 0/1 good |

### Cases on `dev`

| Class | Fixture | Patch | Expected | Actual | Result |
|---|---|---|---|---|---|
| `reentrancy` | `single_function` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | match |
| `reentrancy` | `single_function` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | match |
| `reentrancy` | `single_function` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (vacuous_patch, benign_test_failed, test_suite_failed)` | match |
| `reentrancy` | `single_function` | `regressing` | `REJECTED (layout_changed)` | `REJECTED (layout_changed)` | match |
| `access_control` | `missing_modifier` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | match |
| `access_control` | `missing_modifier` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | match |
| `access_control` | `missing_modifier` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (benign_test_failed, test_suite_failed)` | match |
| `access_control` | `missing_modifier` | `regressing` | `REJECTED (layout_changed)` | `REJECTED (layout_changed)` | match |
| `unchecked_call` | `ignored_return` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | match |
| `unchecked_call` | `ignored_return` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | match |
| `unchecked_call` | `ignored_return` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (benign_test_failed, test_suite_failed)` | match |
| `unchecked_call` | `ignored_return` | `regressing` | `REJECTED (abi_changed)` | `REJECTED (abi_changed)` | match |
| `signature_replay` | `missing_nonce` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | match |
| `signature_replay` | `missing_nonce` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | match |
| `signature_replay` | `missing_nonce` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (benign_test_failed, test_suite_failed)` | match |
| `signature_replay` | `missing_nonce` | `regressing` | `REJECTED (event_changed)` | `REJECTED (event_changed)` | match |
| `delegatecall` | `user_controlled_target` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | match |
| `delegatecall` | `user_controlled_target` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | match |
| `delegatecall` | `user_controlled_target` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (benign_test_failed, test_suite_failed)` | match |
| `delegatecall` | `user_controlled_target` | `regressing` | `REJECTED (layout_changed)` | `REJECTED (layout_changed)` | match |
| `oracle_manipulation` | `spot_price` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | match |
| `oracle_manipulation` | `spot_price` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | match |
| `oracle_manipulation` | `spot_price` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (benign_test_failed, test_suite_failed)` | match |
| `oracle_manipulation` | `spot_price` | `regressing` | `REJECTED (event_changed)` | `REJECTED (event_changed)` | match |
| `dos` | `payout_loop` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | match |
| `dos` | `payout_loop` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | match |
| `dos` | `payout_loop` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (benign_test_failed, test_suite_failed)` | match |
| `dos` | `payout_loop` | `regressing` | `REJECTED (abi_changed)` | `REJECTED (abi_changed)` | match |
| `rounding` | `share_inflation` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | match |
| `rounding` | `share_inflation` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | match |
| `rounding` | `share_inflation` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (benign_test_failed, test_suite_failed)` | match |
| `rounding` | `share_inflation` | `regressing` | `REJECTED (layout_changed)` | `REJECTED (layout_changed)` | match |

## Split `heldout`

Status: **HELD-OUT: the oracle hash of the run equals bench/FROZEN_HASH**.

Verdicts equal to the label: 32/32 (100.0 %, 95 % CI 89.2 to 100.0 %).

| Patch label | Expected verdict | Expected reason | Matching |
|---|---|---|---|
| `good` | `VERIFIED_WITHIN_BOUNDS` | none | 8/8 |
| `overfit` | `REJECTED` | `variant_found` | 8/8 |
| `destructive` | `REJECTED` | `benign_test_failed` or an integrity reason | 8/8 |
| `regressing` | `REJECTED` | `layout_changed`, `abi_changed` or `event_changed` | 8/8 |

### Ablations on `heldout`

Each cell is the number of wrong decisions over the number of cases the configuration could judge,
with the Wilson 95 % interval. For bad patches a wrong decision is an acceptance (false accept); for
good patches it is a rejection (false reject). Percentages are rounded away from the favorable
direction.

| Config | Accepts a case when | Overfit accepted | Destructive accepted | Regressing accepted | All bad accepted | Good rejected |
|---|---|---|---|---|---|---|
| V0 | tests only | 8/8 (100.0 %, 95 % CI 67.5 to 100.0 %) | 0/8 (0.0 %, 95 % CI 0.0 to 32.5 %) | 8/8 (100.0 %, 95 % CI 67.5 to 100.0 %) | 16/24 (66.7 %, 95 % CI 46.7 to 82.1 %) | 0/8 (0.0 %, 95 % CI 0.0 to 32.5 %) |
| V1 | V0 and the original PoC is blocked | 8/8 (100.0 %, 95 % CI 67.5 to 100.0 %) | 0/8 (0.0 %, 95 % CI 0.0 to 32.5 %) | 8/8 (100.0 %, 95 % CI 67.5 to 100.0 %) | 16/24 (66.7 %, 95 % CI 46.7 to 82.1 %) | 0/8 (0.0 %, 95 % CI 0.0 to 32.5 %) |
| V2 | V1 and no variant is found | 0/8 (0.0 %, 95 % CI 0.0 to 32.5 %) | 0/8 (0.0 %, 95 % CI 0.0 to 32.5 %) | 8/8 (100.0 %, 95 % CI 67.5 to 100.0 %) | 8/24 (33.4 %, 95 % CI 17.9 to 53.3 %) | 0/8 (0.0 %, 95 % CI 0.0 to 32.5 %) |
| V3 | all non-symbolic oracles (full configuration) | 0/8 (0.0 %, 95 % CI 0.0 to 32.5 %) | 0/8 (0.0 %, 95 % CI 0.0 to 32.5 %) | 0/8 (0.0 %, 95 % CI 0.0 to 32.5 %) | 0/24 (0.0 %, 95 % CI 0.0 to 13.8 %) | 0/8 (0.0 %, 95 % CI 0.0 to 32.5 %) |

V4 (symbolic oracle) is not part of this run.

### Per class on `heldout`

Each cell: bad patches accepted out of the bad patches of the class, and good patches rejected out of the good patches of the class.

| Class | V0 | V1 | V2 | V3 |
|---|---|---|---|---|
| `reentrancy` | 2/3 bad, 0/1 good | 2/3 bad, 0/1 good | 1/3 bad, 0/1 good | 0/3 bad, 0/1 good |
| `access_control` | 2/3 bad, 0/1 good | 2/3 bad, 0/1 good | 1/3 bad, 0/1 good | 0/3 bad, 0/1 good |
| `unchecked_call` | 2/3 bad, 0/1 good | 2/3 bad, 0/1 good | 1/3 bad, 0/1 good | 0/3 bad, 0/1 good |
| `signature_replay` | 2/3 bad, 0/1 good | 2/3 bad, 0/1 good | 1/3 bad, 0/1 good | 0/3 bad, 0/1 good |
| `delegatecall` | 2/3 bad, 0/1 good | 2/3 bad, 0/1 good | 1/3 bad, 0/1 good | 0/3 bad, 0/1 good |
| `oracle_manipulation` | 2/3 bad, 0/1 good | 2/3 bad, 0/1 good | 1/3 bad, 0/1 good | 0/3 bad, 0/1 good |
| `dos` | 2/3 bad, 0/1 good | 2/3 bad, 0/1 good | 1/3 bad, 0/1 good | 0/3 bad, 0/1 good |
| `rounding` | 2/3 bad, 0/1 good | 2/3 bad, 0/1 good | 1/3 bad, 0/1 good | 0/3 bad, 0/1 good |

### Cases on `heldout`

| Class | Fixture | Patch | Expected | Actual | Result |
|---|---|---|---|---|---|
| `reentrancy` | `cross_function` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | match |
| `reentrancy` | `cross_function` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | match |
| `reentrancy` | `cross_function` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (vacuous_patch, benign_test_failed, test_suite_failed)` | match |
| `reentrancy` | `cross_function` | `regressing` | `REJECTED (layout_changed)` | `REJECTED (layout_changed)` | match |
| `access_control` | `reinitializable` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | match |
| `access_control` | `reinitializable` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | match |
| `access_control` | `reinitializable` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (vacuous_patch, benign_test_failed, test_suite_failed)` | match |
| `access_control` | `reinitializable` | `regressing` | `REJECTED (layout_changed)` | `REJECTED (layout_changed)` | match |
| `unchecked_call` | `token_return` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | match |
| `unchecked_call` | `token_return` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | match |
| `unchecked_call` | `token_return` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (vacuous_patch, benign_test_failed, test_suite_failed)` | match |
| `unchecked_call` | `token_return` | `regressing` | `REJECTED (abi_changed)` | `REJECTED (abi_changed)` | match |
| `signature_replay` | `cross_chain` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | match |
| `signature_replay` | `cross_chain` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | match |
| `signature_replay` | `cross_chain` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (vacuous_patch, benign_test_failed, test_suite_failed)` | match |
| `signature_replay` | `cross_chain` | `regressing` | `REJECTED (event_changed)` | `REJECTED (event_changed)` | match |
| `delegatecall` | `strategy_registry` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | match |
| `delegatecall` | `strategy_registry` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | match |
| `delegatecall` | `strategy_registry` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (vacuous_patch, benign_test_failed, test_suite_failed)` | match |
| `delegatecall` | `strategy_registry` | `regressing` | `REJECTED (layout_changed)` | `REJECTED (layout_changed)` | match |
| `oracle_manipulation` | `donation_price` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | match |
| `oracle_manipulation` | `donation_price` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | match |
| `oracle_manipulation` | `donation_price` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (vacuous_patch, benign_test_failed, test_suite_failed)` | match |
| `oracle_manipulation` | `donation_price` | `regressing` | `REJECTED (abi_changed)` | `REJECTED (abi_changed)` | match |
| `dos` | `forced_ether` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | match |
| `dos` | `forced_ether` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | match |
| `dos` | `forced_ether` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (vacuous_patch, benign_test_failed, test_suite_failed)` | match |
| `dos` | `forced_ether` | `regressing` | `REJECTED (layout_changed)` | `REJECTED (layout_changed)` | match |
| `rounding` | `fee_floor` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | match |
| `rounding` | `fee_floor` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | match |
| `rounding` | `fee_floor` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (vacuous_patch, benign_test_failed, test_suite_failed)` | match |
| `rounding` | `fee_floor` | `regressing` | `REJECTED (abi_changed)` | `REJECTED (abi_changed)` | match |

## Findings

Result version: `v1`. Every mismatch between a verdict and a label is listed with its cause. The causes are read from `bench/findings.json`; a mismatch without a recorded cause is shown as unexplained.

Mismatches between a verdict and a label: none.

## Threats to validity

1. The fixtures are written by the same party as the oracles. The held-out cases are written after
   the freeze and without running the oracles on them, but by the same author, who knows what the
   oracles check. The freeze limits only the oracle side. A truly independent set would need other
   authors.
2. The samples are small, so the intervals are wide. Eight cases of a kind cannot separate rates
   that differ by a few tens of percentage points.
3. The ablation on synthetic fixtures is partly tautological, because the fixtures are designed so
   that overfit and regressing patches pass the old tests.
4. Labels may be wrong. They are established with plain Foundry under the same bounds as the
   oracles use (fixed seed, fixed number of runs), so a label that holds only within those bounds
   is a label within them.
5. Model non-determinism. The oracle benchmark uses no model. A model pipeline would need
   repeated runs or recorded answers.
6. Results are tied to the pinned tool versions and to the runner image of the run, and to the
   machine architecture.
7. Synthetic code is not real-world contract code. Fixtures are small, single-purpose and
   readable.
8. The freeze hash does not cover the Python code outside the oracle package (section 5).
9. The variant search is bounded by its campaign profile. A label `overfit` is a statement that a
   variant exists within the fixture checker's bounds, and a `good` verdict is a statement that
   none was found within the profile's bounds; neither is a proof.
10. The classes are the eight classes of the fixture specification. Results say nothing about
    other classes.

## Run details

### `dev`

| Item | Value |
|---|---|
| Assay version | `0.1.0.dev0` |
| Git commit | - |
| Runner image (local image id) | `sha256:a2209e37ccdf894aa1d7c6b76b9d06a7806a035517a03f0cb4023a61d4ec8bf7` |
| Tools in the image | aderyn v0.6.8, forge-std v1.17.0, foundry v1.8.4, python 3.12.15, slither 0.11.6, solc 0.8.36 |
| `versions.lock` sha256 | `33ce0a91c77fc73f95bb8b9c5ee92e2dc43caf7b2837a76b44b2756bd6b71d60` |
| Oracle tree sha256 | `47dfd491563ccff2ea2e8d13c1bf721b6aecc715fff76d035f0661aacb17f4e0` |
| Fixtures tree sha256 | `45825f07753841cf3c409fe056995bd2da1bc2bb7677079b99f3ccdb763771d9` |
| Split file sha256 | `727616ac39e45cdbf87020f409cf4b1d288088b7d1956a1bd6c4daa8acc3f376` |
| Machine architecture | `arm64` |
| Campaign profile | `standard` |
| Base seed | `0x1` |
| Seeds per search mode | 3 |
| Fuzz runs per campaign | 256 |
| Invariant runs and depth | 64 sequences of up to 25 calls |
| Replays of the PoC per revision | 3 |
| Symbolic oracle | no |
| Total time | 1 h 03 min for 32 verifications, one after the other |

### `heldout`

| Item | Value |
|---|---|
| Assay version | `0.1.0.dev0` |
| Git commit | - |
| Runner image (local image id) | `sha256:a2209e37ccdf894aa1d7c6b76b9d06a7806a035517a03f0cb4023a61d4ec8bf7` |
| Tools in the image | aderyn v0.6.8, forge-std v1.17.0, foundry v1.8.4, python 3.12.15, slither 0.11.6, solc 0.8.36 |
| `versions.lock` sha256 | `33ce0a91c77fc73f95bb8b9c5ee92e2dc43caf7b2837a76b44b2756bd6b71d60` |
| Oracle tree sha256 | `47dfd491563ccff2ea2e8d13c1bf721b6aecc715fff76d035f0661aacb17f4e0` |
| Fixtures tree sha256 | `e1439c5fbc01af45738acb40543fbe787d71b94906d24e1034b4ee7332466e9a` |
| Split file sha256 | `cbb82f53c6fa313bce75886ec50db13aff8d87d2abc0d0ad046461507d1b8c74` |
| Machine architecture | `arm64` |
| Campaign profile | `standard` |
| Base seed | `0x1` |
| Seeds per search mode | 3 |
| Fuzz runs per campaign | 256 |
| Invariant runs and depth | 64 sequences of up to 25 calls |
| Replays of the PoC per revision | 3 |
| Symbolic oracle | no |
| Total time | 17 min 07 s for 32 verifications, one after the other |

The image id identifies a local build of the runner image; images built on another machine or
platform have other ids ([ADR 0008](adr/0008-runner-platform.md)). Times depend on the machine and
are given for orientation only.

## Reproduce

```sh
make image
make bench-oracles SPLIT=dev PROFILE=standard
# bench/FROZEN_HASH was created by `make bench-freeze` before the next line
make bench-oracles SPLIT=heldout PROFILE=standard
make bench-report RESULTS="bench/results/dev-standard-47dfd49156-45825f0775 bench/results/heldout-standard-47dfd49156-e1439c5fbc"
```

The runs take between ten minutes and about two hours per split, depending on the machine. The
report is a function of the result folders, `bench/findings.json` and `bench/PROTOCOL.md`: the same
inputs give the same files.
