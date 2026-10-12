# Fixture: unchecked_call / token_return (held-out)

> **Intentionally vulnerable.** The code in this directory is test material with a known hole.
> It must never be deployed or used to hold real funds.

This fixture belongs to the held-out split. Its code shape differs from the development fixture
of the same class: the ignored result is the return value of a token call, not of a low-level
call that sends ether.

## The hole

`DepositPool` takes deposits of one token, credits them, and pays them out again. `SoftToken`
reports a transfer it cannot make by returning `false`; it does not revert, as some real tokens
do. `deposit` and `depositMany` call `transferFrom` and ignore the answer. A "deposit" from an
account that holds no tokens, or has not approved the pool, moves nothing, and the pool credits it
all the same. `withdraw` pays out of the tokens that other depositors really paid in.

## The attack

The PoC (`poc/UnpaidDeposit.t.sol`) sets up a pool that holds 1000 tokens from two depositors.
The attacker owns no tokens and approves nothing. It calls `deposit` with the whole balance of the
pool, which the token refuses silently and the pool credits, and then calls `withdraw` for the
same amount. The attacker ends with the pool's 1000 tokens. The PoC records the predicate
`attacker_profit` for the asset `tok`.

## The variants

The PoC exposes two knobs, which `testFuzz_variants` draws at random together with the attacker
address and the attacker's starting balance:

| Knob | Meaning | Replay value | Range searched |
|---|---|---|---|
| 0 `route` | how the attacker "deposits": 0 `deposit`, 1 `depositMany` with two entries | 0 | 0 to 1 |
| 1 `take_bps` | the part of the pool's tokens that the attacker claims, in basis points | 10000 | 1 to 10000 |

A variant is the same attack through the batch function, or for a part of the pool.

## The four patches

| Patch | Change | Label and why |
|---|---|---|
| `good` | `deposit` and `depositMany` revert when `transferFrom` returns `false`. | Closes the root cause: credit is given only for tokens that moved. Behavior, storage layout and ABI stay the same. |
| `overfit` | `deposit` reverts when `transferFrom` returns `false`; `depositMany` is unchanged. | Checks the result on the path the PoC uses and not on the other path, which does the same call. The route 1 variant still works. |
| `destructive` | `withdraw` reverts unconditionally. | The attacker can still get credit but cannot take tokens out, so the original PoC is blocked. Honest depositors cannot withdraw either, and the benign tests that withdraw fail. |
| `regressing` | The `good` change, and `deposit` returns the credited amount. | Closes the hole and keeps the benign tests passing, but changes the return types of `deposit`, a breaking ABI change. |
