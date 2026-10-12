# Variant search power

`make variant-power` writes this page from one run of the variant search over the development
fixtures, with `tools/variant_power.py`. It is not edited by hand.

This page shows what the variant search of `assay verify` finds with each campaign profile on the
patches of the development fixtures. An `overfit` patch blocks the original PoC but leaves a close
variant open; a `good` patch closes the hole. For each patch and profile the VariantOracle ran on
the vulnerable and the patched revision, with the seeds derived from the base seed below. A variant
counts as found only when the generated test `variant_poc.t.sol` reproduced it in three replays out
of three (FAIL `variant_found`).

## What these numbers mean

These numbers describe the reach of the search, not a guarantee. A profile can miss a variant that
exists: the `quick` profile runs fewer seeds, runs and sequences, and can pass a patch that
`standard` or `thorough` reject. A search that finds nothing states only that nothing was found
within the runs it made; it is not a proof of absence. The fixtures, their patches and the oracles
were written by the same author, so the numbers say nothing about other code.

No good patch may get a variant: a variant for a good patch would mean that the patch, its label or
the search is wrong, and is investigated rather than accepted.

## Result

`VARIANT POWER: quick: 8/8 overfit patches with a variant, 0/8 good patches with a variant; standard: 8/8 overfit patches with a variant, 0/8 good patches with a variant`

| Profile | Overfit patches with a variant | Good patches with a variant | Time |
|---|---|---|---|
| `quick` | 8/8 | 0/8 | 2 min 19 s |
| `standard` | 8/8 | 0/8 | 2 min 49 s |

## Overfit patches without a variant

Every profile found the variant of every overfit patch in this run. That holds for these fixtures,
these seeds and this run only: with other seeds or other code, a smaller profile can miss a variant
that a larger one finds.

## Searches

| Class | Fixture | Patch | Profile | Verdict | Variant found | Mode | Seed | Time |
|---|---|---|---|---|---|---|---|---|
| `reentrancy` | `single_function` | `overfit` | `quick` | FAIL | yes | fuzz | 1 of 1 | 11 s |
| `reentrancy` | `single_function` | `overfit` | `standard` | FAIL | yes | fuzz | 1 of 3 | 11 s |
| `reentrancy` | `single_function` | `good` | `quick` | PASS | no | - | none of 1 | 8 s |
| `reentrancy` | `single_function` | `good` | `standard` | PASS | no | - | none of 3 | 11 s |
| `access_control` | `missing_modifier` | `overfit` | `quick` | FAIL | yes | fuzz | 1 of 1 | 9 s |
| `access_control` | `missing_modifier` | `overfit` | `standard` | FAIL | yes | fuzz | 1 of 3 | 12 s |
| `access_control` | `missing_modifier` | `good` | `quick` | PASS | no | - | none of 1 | 6 s |
| `access_control` | `missing_modifier` | `good` | `standard` | PASS | no | - | none of 3 | 7 s |
| `unchecked_call` | `ignored_return` | `overfit` | `quick` | FAIL | yes | fuzz | 1 of 1 | 9 s |
| `unchecked_call` | `ignored_return` | `overfit` | `standard` | FAIL | yes | fuzz | 1 of 3 | 14 s |
| `unchecked_call` | `ignored_return` | `good` | `quick` | PASS | no | - | none of 1 | 6 s |
| `unchecked_call` | `ignored_return` | `good` | `standard` | PASS | no | - | none of 3 | 8 s |
| `signature_replay` | `missing_nonce` | `overfit` | `quick` | FAIL | yes | fuzz | 1 of 1 | 10 s |
| `signature_replay` | `missing_nonce` | `overfit` | `standard` | FAIL | yes | fuzz | 1 of 3 | 10 s |
| `signature_replay` | `missing_nonce` | `good` | `quick` | PASS | no | - | none of 1 | 6 s |
| `signature_replay` | `missing_nonce` | `good` | `standard` | PASS | no | - | none of 3 | 7 s |
| `delegatecall` | `user_controlled_target` | `overfit` | `quick` | FAIL | yes | fuzz | 1 of 1 | 9 s |
| `delegatecall` | `user_controlled_target` | `overfit` | `standard` | FAIL | yes | fuzz | 1 of 3 | 9 s |
| `delegatecall` | `user_controlled_target` | `good` | `quick` | PASS | no | - | none of 1 | 6 s |
| `delegatecall` | `user_controlled_target` | `good` | `standard` | PASS | no | - | none of 3 | 9 s |
| `oracle_manipulation` | `spot_price` | `overfit` | `quick` | FAIL | yes | fuzz | 1 of 1 | 10 s |
| `oracle_manipulation` | `spot_price` | `overfit` | `standard` | FAIL | yes | fuzz | 1 of 3 | 10 s |
| `oracle_manipulation` | `spot_price` | `good` | `quick` | PASS | no | - | none of 1 | 6 s |
| `oracle_manipulation` | `spot_price` | `good` | `standard` | PASS | no | - | none of 3 | 8 s |
| `dos` | `payout_loop` | `overfit` | `quick` | FAIL | yes | fuzz | 1 of 1 | 12 s |
| `dos` | `payout_loop` | `overfit` | `standard` | FAIL | yes | fuzz | 1 of 3 | 12 s |
| `dos` | `payout_loop` | `good` | `quick` | PASS | no | - | none of 1 | 9 s |
| `dos` | `payout_loop` | `good` | `standard` | PASS | no | - | none of 3 | 12 s |
| `rounding` | `share_inflation` | `overfit` | `quick` | FAIL | yes | fuzz | 1 of 1 | 12 s |
| `rounding` | `share_inflation` | `overfit` | `standard` | FAIL | yes | fuzz | 1 of 3 | 15 s |
| `rounding` | `share_inflation` | `good` | `quick` | PASS | no | - | none of 1 | 9 s |
| `rounding` | `share_inflation` | `good` | `standard` | PASS | no | - | none of 3 | 13 s |

## Run

| Profile | Seeds | Fuzz runs per seed | Invariant sequences per seed | Calls per sequence | Limit per campaign |
|---|---|---|---|---|---|
| `quick` | 1 | 64 | 32 | 15 | 180 s |
| `standard` | 3 | 256 | 64 | 25 | 300 s |

| Item | Value |
|---|---|
| Assay version | `0.1.0.dev0` |
| Tools in the image | aderyn v0.6.8, forge-std v1.17.0, foundry v1.8.4, python 3.12.15, slither 0.11.6, solc 0.8.36 |
| `versions.lock` sha256 | `9417ef73bae09372ae624eb8e766d87b150c8c105f21fc54f3d57b64ee720d20` |
| Base seed | `0x1` |
| Total time | 5 min 9 s, one search after the other |

Times depend on the machine and are given for orientation only; every other number repeats exactly
for the same base seed, profile and runner image.

## Reproduce

```sh
make image
make variant-power PROFILES="quick standard"
```
