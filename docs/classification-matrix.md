# Classification matrix

`make matrix` writes this page from the results of one run, with `tools/matrix_report.py`. It is not
edited by hand.

The matrix runs `assay verify` on each of the four labelled patches of the 8 development fixtures
under `fixtures/`, and compares the final verdict and its reasons with the verdict and reason that
the fixture's `expected.json` gives for the patch label. A patch matches when the final verdict is
the expected one and the expected reason, if there is one, is among the reported reasons. The labels
themselves are established with plain Foundry by `make fixtures-check`, which uses no oracle code
([fixture specification](fixture-spec.md), section 8).

## What this result means

This is a self-validation on synthetic fixtures, not an independent benchmark. The fixtures, their
patches and their labels were written by the same author as the oracles, and they were designed so
that the overfit and regressing patches pass the existing tests while the oracles have something to
find. A full match shows that the oracles reproduce these labels within the bounds below. The
numbers must not be read as a detection rate on real code, or as a statement about patches,
contracts or vulnerability shapes outside these fixtures. Each verdict covers only the checks and
bounds that ran; `VERIFIED_WITHIN_BOUNDS` means that nothing was found within them and is not a
proof of absence ([Oracles and `assay verify`](oracles.md)).

## Result

`MATRIX RESULT: 32/32 match`

Campaign profile of the variant search: `standard`.

| Patch label | Expected verdict | Expected reason | Matching |
|---|---|---|---|
| `good` | `VERIFIED_WITHIN_BOUNDS` | none | 8/8 |
| `overfit` | `REJECTED` | `variant_found` | 8/8 |
| `destructive` | `REJECTED` | `benign_test_failed` or an integrity reason | 8/8 |
| `regressing` | `REJECTED` | `layout_changed`, `abi_changed` or `event_changed` | 8/8 |

## Patches

| Class | Fixture | Patch | Expected | Actual | Time | Result |
|---|---|---|---|---|---|---|
| `reentrancy` | `single_function` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | 21 s | match |
| `reentrancy` | `single_function` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | 20 s | match |
| `reentrancy` | `single_function` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (vacuous_patch, benign_test_failed, test_suite_failed)` | 21 s | match |
| `reentrancy` | `single_function` | `regressing` | `REJECTED (layout_changed)` | `REJECTED (layout_changed)` | 20 s | match |
| `access_control` | `missing_modifier` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | 17 s | match |
| `access_control` | `missing_modifier` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | 21 s | match |
| `access_control` | `missing_modifier` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (benign_test_failed, test_suite_failed)` | 21 s | match |
| `access_control` | `missing_modifier` | `regressing` | `REJECTED (layout_changed)` | `REJECTED (layout_changed)` | 18 s | match |
| `unchecked_call` | `ignored_return` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | 18 s | match |
| `unchecked_call` | `ignored_return` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | 18 s | match |
| `unchecked_call` | `ignored_return` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (benign_test_failed, test_suite_failed)` | 17 s | match |
| `unchecked_call` | `ignored_return` | `regressing` | `REJECTED (abi_changed)` | `REJECTED (abi_changed)` | 18 s | match |
| `signature_replay` | `missing_nonce` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | 20 s | match |
| `signature_replay` | `missing_nonce` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | 20 s | match |
| `signature_replay` | `missing_nonce` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (benign_test_failed, test_suite_failed)` | 18 s | match |
| `signature_replay` | `missing_nonce` | `regressing` | `REJECTED (event_changed)` | `REJECTED (event_changed)` | 18 s | match |
| `delegatecall` | `user_controlled_target` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | 19 s | match |
| `delegatecall` | `user_controlled_target` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | 20 s | match |
| `delegatecall` | `user_controlled_target` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (benign_test_failed, test_suite_failed)` | 20 s | match |
| `delegatecall` | `user_controlled_target` | `regressing` | `REJECTED (layout_changed)` | `REJECTED (layout_changed)` | 20 s | match |
| `oracle_manipulation` | `spot_price` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | 22 s | match |
| `oracle_manipulation` | `spot_price` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | 22 s | match |
| `oracle_manipulation` | `spot_price` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (benign_test_failed, test_suite_failed)` | 21 s | match |
| `oracle_manipulation` | `spot_price` | `regressing` | `REJECTED (event_changed)` | `REJECTED (event_changed)` | 23 s | match |
| `dos` | `payout_loop` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | 23 s | match |
| `dos` | `payout_loop` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | 23 s | match |
| `dos` | `payout_loop` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (benign_test_failed, test_suite_failed)` | 22 s | match |
| `dos` | `payout_loop` | `regressing` | `REJECTED (abi_changed)` | `REJECTED (abi_changed)` | 24 s | match |
| `rounding` | `share_inflation` | `good` | `VERIFIED_WITHIN_BOUNDS` | `VERIFIED_WITHIN_BOUNDS` | 24 s | match |
| `rounding` | `share_inflation` | `overfit` | `REJECTED (variant_found)` | `REJECTED (variant_found)` | 25 s | match |
| `rounding` | `share_inflation` | `destructive` | `REJECTED (benign_test_failed)` | `REJECTED (benign_test_failed, test_suite_failed)` | 27 s | match |
| `rounding` | `share_inflation` | `regressing` | `REJECTED (layout_changed)` | `REJECTED (layout_changed)` | 27 s | match |

## Run

| Item | Value |
|---|---|
| Assay version | `0.1.0.dev0` |
| Runner image (local image id) | `sha256:a2209e37ccdf894aa1d7c6b76b9d06a7806a035517a03f0cb4023a61d4ec8bf7` |
| Tools in the image | aderyn v0.6.8, forge-std v1.17.0, foundry v1.8.4, python 3.12.15, slither 0.11.6, solc 0.8.36 |
| `versions.lock` sha256 | `33ce0a91c77fc73f95bb8b9c5ee92e2dc43caf7b2837a76b44b2756bd6b71d60` |
| Campaign profile of the variant search | `standard` |
| Base seed | `0x1` |
| Seeds per search mode | 3 |
| Fuzz runs per campaign | 256 |
| Invariant runs and depth per campaign | 64 sequences of up to 25 calls |
| Replays of the PoC per revision | 3 |
| Total time | 11 min 06 s for 32 verifications, one after the other |

The image id identifies a local build of the runner image; images built on another machine or
platform have other ids ([ADR 0008](adr/0008-runner-platform.md)). Times depend on the machine and
are given for orientation only.

## Reproduce

```sh
make image
make matrix PROFILE=standard
```

`make matrix` needs Docker and runs the verifications one after the other, which takes from about
half an hour to two hours depending on the machine. It can also be started by hand in the GitHub
workflow `matrix.yml`, which uploads this page as a workflow artifact.
