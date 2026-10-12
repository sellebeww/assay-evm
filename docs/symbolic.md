# Symbolic checks

`make symbolic-report` writes this page from one run of the symbolic oracle over the development
fixtures, with `tools/symbolic_report.py`. It is not edited by hand. How the oracle works and how to
use it with `assay verify --symbolic`: [oracles](oracles.md#symbolicoracle); why Halmos runs in a
linux/amd64 image: [ADR 0018](adr/0018-halmos-in-a-linux-amd64-image.md).

The symbolic oracle runs Halmos on properties that a fixture's PoC directory holds in `symbolic/`. A
variant property (`check_variant_*`) is the exploit with symbolic parameters: Halmos explores every
value of every parameter at once, along every path within the loop unrolling bound, and reports a
counterexample when some input makes the PoC's predicate hold. An equivalence property
(`check_equiv_*`) runs the same calls on the patched and on the vulnerable revision, outside the
exploit condition, and asserts that results and observable state agree.

## What a result shows

A PASS states that Halmos found no counterexample on any path it explored, within the stated bounds:
the loop unrolling bound, the calldata of each property (4 bytes of selector and one 32-byte word
per parameter), at most the stated number of calls of the target per property, the solver time per
query and the run limits, starting from the state that the property's `setUp()` builds. A
counterexample counts only after a generated Foundry test (`variant_poc.t.sol`) reproduced it three
times out of three.

## What it does not show

It is not a proof that the patch is correct. Paths longer than the loop bound are cut and listed;
inputs outside a property's assumptions, other initial states, other callers and call sequences the
property does not make are not covered; a property covers only the attack it was written for. A
timeout, an out-of-memory kill or an unknown solver result is INCONCLUSIVE (`symbolic_unknown`),
never a pass. A property that finds no counterexample on the vulnerable revision is not counted.
Halmos deploys contracts at other addresses than Foundry, so a counterexample that names a deployed
contract cannot be replayed and stays INCONCLUSIVE (`flaky_counterexample`). Bounded equivalence
only adds to the BehaviorOracle's evidence when it shows no difference; a difference or an unknown
result is noted and changes no verdict.

## Bounds

The loop bound is the number of iterations Halmos explores per loop; a path that would iterate
further is cut, and the number of cut loops is reported. The calldata of a property is fixed by its
parameters, which are static types only. The call limit (`ASSAY_MAX_CALLS` in
`solidity/AssayCheck.sol`) caps the calls a property makes through `assayCall`; paths beyond it end
without a counterexample.

| Bound | Value |
|---|---|
| Loop unrolling bound | 3 |
| Calls of the target per property | at most 4 |
| Calldata per property | 4 + 32 * (number of parameters) bytes |
| Solver time per query | 60 s |
| Limit per Halmos run | 900 s, 4096 MiB |

## Result

`SYMBOLIC REPORT: 4 fixtures with properties, 4 without; overfit FAIL 3/4; good PASS 3/4; INCONCLUSIVE 4; contradictions 0`

| Class | Fixture | Patch | Verdict | Variant properties (patched) | Equivalence | Time |
|---|---|---|---|---|---|---|
| `access_control` | `missing_modifier` | `good` | PASS | `check_variant_payOut` no counterexample; `check_variant_payOutAll` no counterexample | no difference | 11 s |
| `access_control` | `missing_modifier` | `overfit` | FAIL (variant_found) | `check_variant_payOut` counterexample; `check_variant_payOutAll` no counterexample | no difference | 14 s |
| `access_control` | `missing_modifier` | `destructive` | PASS | `check_variant_payOut` no counterexample; `check_variant_payOutAll` no counterexample | difference | 10 s |
| `access_control` | `missing_modifier` | `regressing` | PASS | `check_variant_payOut` no counterexample; `check_variant_payOutAll` no counterexample | no difference | 10 s |
| `unchecked_call` | `ignored_return` | `good` | PASS | `check_variant_pay` no counterexample; `check_variant_payMany` no counterexample | no difference | 11 s |
| `unchecked_call` | `ignored_return` | `overfit` | FAIL (variant_found) | `check_variant_pay` no counterexample; `check_variant_payMany` counterexample | no difference | 14 s |
| `unchecked_call` | `ignored_return` | `destructive` | PASS | `check_variant_pay` no counterexample; `check_variant_payMany` no counterexample | difference | 11 s |
| `unchecked_call` | `ignored_return` | `regressing` | PASS | `check_variant_pay` no counterexample; `check_variant_payMany` no counterexample | difference | 11 s |
| `delegatecall` | `user_controlled_target` | `good` | PASS | `check_variant_runUpkeep` no counterexample; `check_variant_runUpkeepBatch` no counterexample | no difference | 10 s |
| `delegatecall` | `user_controlled_target` | `overfit` | FAIL (variant_found) | `check_variant_runUpkeep` no counterexample; `check_variant_runUpkeepBatch` counterexample | no difference | 15 s |
| `delegatecall` | `user_controlled_target` | `destructive` | PASS | `check_variant_runUpkeep` no counterexample; `check_variant_runUpkeepBatch` no counterexample | difference | 11 s |
| `delegatecall` | `user_controlled_target` | `regressing` | PASS | `check_variant_runUpkeep` no counterexample; `check_variant_runUpkeepBatch` no counterexample | no difference | 11 s |
| `rounding` | `share_inflation` | `good` | INCONCLUSIVE (symbolic_unknown) | - | none | 52 s |
| `rounding` | `share_inflation` | `overfit` | INCONCLUSIVE (symbolic_unknown) | - | none | 59 s |
| `rounding` | `share_inflation` | `destructive` | INCONCLUSIVE (symbolic_unknown) | `check_variant_inflation` no counterexample | none | 35 s |
| `rounding` | `share_inflation` | `regressing` | INCONCLUSIVE (symbolic_unknown) | - | none | 49 s |

Bounds statements, as `assay verify --symbolic` reports them:

- `access_control/missing_modifier` `good`: symbolic: no counterexample within loop bound 3 for check_variant_payOut (calldata 4+32*2 bytes), check_variant_payOutAll (calldata 4+32*1 bytes); Halmos 0.3.3, solver z3 with 60 s per query, at most 4 calls of the target per property, run limit 900 s and 4096 MiB; this is not a proof of absence
  bounded equivalence: no difference from the vulnerable revision within loop bound 3 for check_equiv_ownerPayOut (calldata 4+32*1 bytes), check_equiv_ownerPayOutAll (calldata 4+32*0 bytes), check_equiv_setOwner (calldata 4+32*1 bytes), outside the exploit condition; this is not a proof of equivalence
- `access_control/missing_modifier` `overfit`: symbolic: counterexample of check_variant_payOut within loop bound 3, confirmed by 3 of 3 replays; Halmos 0.3.3, solver z3 with 60 s per query, at most 4 calls of the target per property, run limit 900 s and 4096 MiB
  bounded equivalence: no difference from the vulnerable revision within loop bound 3 for check_equiv_ownerPayOut (calldata 4+32*1 bytes), check_equiv_ownerPayOutAll (calldata 4+32*0 bytes), check_equiv_setOwner (calldata 4+32*1 bytes), outside the exploit condition; this is not a proof of equivalence
- `access_control/missing_modifier` `destructive`: symbolic: no counterexample within loop bound 3 for check_variant_payOut (calldata 4+32*2 bytes), check_variant_payOutAll (calldata 4+32*1 bytes); Halmos 0.3.3, solver z3 with 60 s per query, at most 4 calls of the target per property, run limit 900 s and 4096 MiB; this is not a proof of absence
  bounded equivalence: Halmos reported a difference for check_equiv_ownerPayOut (calldata 4+32*1 bytes), check_equiv_ownerPayOutAll (calldata 4+32*0 bytes) (not replayed); the verdict is unchanged
- `access_control/missing_modifier` `regressing`: symbolic: no counterexample within loop bound 3 for check_variant_payOut (calldata 4+32*2 bytes), check_variant_payOutAll (calldata 4+32*1 bytes); Halmos 0.3.3, solver z3 with 60 s per query, at most 4 calls of the target per property, run limit 900 s and 4096 MiB; this is not a proof of absence
  bounded equivalence: no difference from the vulnerable revision within loop bound 3 for check_equiv_ownerPayOut (calldata 4+32*1 bytes), check_equiv_ownerPayOutAll (calldata 4+32*0 bytes), check_equiv_setOwner (calldata 4+32*1 bytes), outside the exploit condition; this is not a proof of equivalence
- `unchecked_call/ignored_return` `good`: symbolic: no counterexample within loop bound 3 for check_variant_pay (calldata 4+32*2 bytes), check_variant_payMany (calldata 4+32*3 bytes); Halmos 0.3.3, solver z3 with 60 s per query, at most 4 calls of the target per property, run limit 900 s and 4096 MiB; this is not a proof of absence
  bounded equivalence: no difference from the vulnerable revision within loop bound 3 for check_equiv_book (calldata 4+32*1 bytes), check_equiv_payAccepted (calldata 4+32*2 bytes), outside the exploit condition; this is not a proof of equivalence
- `unchecked_call/ignored_return` `overfit`: symbolic: counterexample of check_variant_payMany within loop bound 3, confirmed by 3 of 3 replays; Halmos 0.3.3, solver z3 with 60 s per query, at most 4 calls of the target per property, run limit 900 s and 4096 MiB
  bounded equivalence: no difference from the vulnerable revision within loop bound 3 for check_equiv_book (calldata 4+32*1 bytes), check_equiv_payAccepted (calldata 4+32*2 bytes), outside the exploit condition; this is not a proof of equivalence
- `unchecked_call/ignored_return` `destructive`: symbolic: no counterexample within loop bound 3 for check_variant_pay (calldata 4+32*2 bytes), check_variant_payMany (calldata 4+32*3 bytes); Halmos 0.3.3, solver z3 with 60 s per query, at most 4 calls of the target per property, run limit 900 s and 4096 MiB; this is not a proof of absence
  bounded equivalence: Halmos reported a difference for check_equiv_payAccepted (calldata 4+32*2 bytes) (not replayed); the verdict is unchanged
- `unchecked_call/ignored_return` `regressing`: symbolic: no counterexample within loop bound 3 for check_variant_pay (calldata 4+32*2 bytes), check_variant_payMany (calldata 4+32*3 bytes); Halmos 0.3.3, solver z3 with 60 s per query, at most 4 calls of the target per property, run limit 900 s and 4096 MiB; this is not a proof of absence
  bounded equivalence: Halmos reported a difference for check_equiv_payAccepted (calldata 4+32*2 bytes) (not replayed); the verdict is unchanged
- `delegatecall/user_controlled_target` `good`: symbolic: no counterexample within loop bound 3 for check_variant_runUpkeep (calldata 4+32*2 bytes), check_variant_runUpkeepBatch (calldata 4+32*3 bytes); Halmos 0.3.3, solver z3 with 60 s per query, at most 4 calls of the target per property, run limit 900 s and 4096 MiB; this is not a proof of absence
  bounded equivalence: no difference from the vulnerable revision within loop bound 3 for check_equiv_approvedUpkeep (calldata 4+32*1 bytes), check_equiv_ownerWithdraw (calldata 4+32*1 bytes), outside the exploit condition; this is not a proof of equivalence
- `delegatecall/user_controlled_target` `overfit`: symbolic: counterexample of check_variant_runUpkeepBatch within loop bound 3, confirmed by 3 of 3 replays; Halmos 0.3.3, solver z3 with 60 s per query, at most 4 calls of the target per property, run limit 900 s and 4096 MiB
  bounded equivalence: no difference from the vulnerable revision within loop bound 3 for check_equiv_approvedUpkeep (calldata 4+32*1 bytes), check_equiv_ownerWithdraw (calldata 4+32*1 bytes), outside the exploit condition; this is not a proof of equivalence
- `delegatecall/user_controlled_target` `destructive`: symbolic: no counterexample within loop bound 3 for check_variant_runUpkeep (calldata 4+32*2 bytes), check_variant_runUpkeepBatch (calldata 4+32*3 bytes); Halmos 0.3.3, solver z3 with 60 s per query, at most 4 calls of the target per property, run limit 900 s and 4096 MiB; this is not a proof of absence
  bounded equivalence: Halmos reported a difference for check_equiv_approvedUpkeep (calldata 4+32*1 bytes) (not replayed); the verdict is unchanged
- `delegatecall/user_controlled_target` `regressing`: symbolic: no counterexample within loop bound 3 for check_variant_runUpkeep (calldata 4+32*2 bytes), check_variant_runUpkeepBatch (calldata 4+32*3 bytes); Halmos 0.3.3, solver z3 with 60 s per query, at most 4 calls of the target per property, run limit 900 s and 4096 MiB; this is not a proof of absence
  bounded equivalence: no difference from the vulnerable revision within loop bound 3 for check_equiv_approvedUpkeep (calldata 4+32*1 bytes), check_equiv_ownerWithdraw (calldata 4+32*1 bytes), outside the exploit condition; this is not a proof of equivalence
- `rounding/share_inflation` `good`: symbolic: unknown (out of memory, limit 4096 MiB); loop bound 3; Halmos 0.3.3, solver z3 with 60 s per query, at most 4 calls of the target per property, run limit 900 s and 4096 MiB
- `rounding/share_inflation` `overfit`: symbolic: unknown (out of memory, limit 4096 MiB); loop bound 3; Halmos 0.3.3, solver z3 with 60 s per query, at most 4 calls of the target per property, run limit 900 s and 4096 MiB
- `rounding/share_inflation` `destructive`: symbolic: unknown on the vulnerable revision (out of memory, limit 4096 MiB), so the patched revision's result is not counted; loop bound 3; Halmos 0.3.3, solver z3 with 60 s per query, at most 4 calls of the target per property, run limit 900 s and 4096 MiB
- `rounding/share_inflation` `regressing`: symbolic: unknown (out of memory, limit 4096 MiB); loop bound 3; Halmos 0.3.3, solver z3 with 60 s per query, at most 4 calls of the target per property, run limit 900 s and 4096 MiB

## Findings

No patch that closes the hole got a confirmed counterexample in this run. INCONCLUSIVE rows are what
they say: the oracle could not decide within the bounds, and they count as neither pass nor fail.

## Fixtures without symbolic properties

These fixtures have no `symbolic/` properties. With `--symbolic`, `assay verify` reports the
symbolic oracle as INCONCLUSIVE (`no_symbolic_properties`) for them.

| Class | Fixture | Reason |
|---|---|---|
| `reentrancy` | `single_function` | callback recursion: the attack re-enters the vault from the attacker contract's `receive` function, so every path nests calls through code that the property would have to model as an unknown callee, and the depth of the nesting is the attack |
| `signature_replay` | `missing_nonce` | `ecrecover`: the attack replays a signed claim, and Halmos treats `ecrecover` as an uninterpreted function, so a counterexample over signatures and signers would not correspond to a real signature that a replay could reproduce |
| `oracle_manipulation` | `spot_price` | AMM arithmetic: the collateral value is a product and quotient of pool reserves after a symbolic swap, non-linear 256-bit arithmetic in several steps that the solver cannot settle within useful bounds |
| `dos` | `payout_loop` | a payout loop over a list of recipients whose length is the attack: a property would have to fix the list length to the loop unrolling bound, so the bound, not the patch, would decide the result |

## Run

| Item | Value |
|---|---|
| Assay version | `0.1.0.dev0` |
| Tools in the runner image | aderyn v0.6.8, forge-std v1.17.0, foundry v1.8.4, python 3.12.15, slither 0.11.6, solc 0.8.36 |
| Tools in the symbolic image | foundry v1.8.4, halmos 0.3.3, solc 0.8.36, z3 4.12.6.0 |
| `versions.lock` sha256 | `33ce0a91c77fc73f95bb8b9c5ee92e2dc43caf7b2837a76b44b2756bd6b71d60` |
| Total time | 5 min 35 s, one patch after the other |

On an arm64 host the symbolic image runs under emulation, which makes every Halmos run slower; the
times are for orientation only. Verdicts and bounds repeat for the same inputs and images.

## Reproduce

```sh
make image
make symbolic-report
```
