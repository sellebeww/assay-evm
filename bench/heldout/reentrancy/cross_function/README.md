# Fixture: reentrancy / cross_function (held-out)

> **Intentionally vulnerable.** The code in this directory is test material with a known hole.
> It must never be deployed or used to hold real funds.

This fixture belongs to the held-out split. Its code shape differs from the development fixture
of the same class: the function that sends the ether and the function that the attack re-enters
are two different functions.

## The hole

`CreditVault` keeps ether as credit per account. `deposit()` adds credit, `moveCredit` and
`moveAllCredit` hand credit to another account, and `cashOut()` pays the sender all of its credit.

`cashOut` sends the ether first and clears the credit afterwards. Sending ether to a contract
runs that contract's code, and while it runs the vault still shows the full credit. The contract
can call a different function of the vault, one that moves the credit to another account. The
credit is paid out once by `cashOut` and, after the call returns, still exists on the account it
was moved to. A second `cashOut` pays it again.

This is cross-function reentrancy: no function calls itself, so a guard on `cashOut` alone
would not matter; what matters is every function that reads or moves the credit while a payout
is in progress.

## The attack

The PoC (`poc/CrossFunctionReentrancy.t.sol`) sets up a vault that holds 20 ether of credit for
two depositors. The attacker starts with 1 ether and deploys a contract that:

1. deposits the ether;
2. calls `cashOut`;
3. in the payout (`receive`), moves the credit that is still shown to the attacker's own account;
4. forwards the payout to the attacker.

The attacker then calls `cashOut` from its own account and receives the moved credit. Two ether
leave the vault for one ether deposited. The PoC records the predicate `attacker_profit` for the
asset `eth`.

## The variants

The PoC exposes two knobs, which `testFuzz_variants` draws at random together with the attacker
address and the attacker's starting balance (0.01 to 10 ether):

| Knob | Meaning | Replay value | Range searched |
|---|---|---|---|
| 0 `route` | the function the payout calls: 0 `moveCredit`, 1 `moveAllCredit` | 0 | 0 to 1 |
| 1 `moved_bps` | with route 0, the part of the credit that is moved, in basis points | 10000 | 1 to 10000 |

A variant is the same attack through the other credit-moving function, or with a part of the
credit.

## The four patches

| Patch | Change | Label and why |
|---|---|---|
| `good` | `cashOut` clears the credit and the total before it sends the ether. | Closes the root cause: during the payout the vault shows no credit, so no function can move it. Behavior, storage layout and ABI stay the same. |
| `overfit` | A flag is set while `cashOut` pays, and `moveCredit` reverts while it is set. | Blocks the original PoC, which re-enters `moveCredit`. `moveAllCredit` moves the same credit and has no check, so the route 1 variant still works. The flag is a new variable after the last used slot, which is an additive layout change. |
| `destructive` | `cashOut` reverts unconditionally. | Blocks the exploit by disabling the payout. Benign tests that cash out fail. |
| `regressing` | The `good` change, and `totalCredit` is declared before `creditOf`. | Closes the hole and keeps the benign tests passing, but swaps two storage slots, a breaking layout change. |
