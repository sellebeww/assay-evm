# Fixture: reentrancy / single_function

> **Intentionally vulnerable.** The code in this directory is test material with a known hole.
> It must never be deployed or used to hold real funds.

## The hole

`Vault` keeps ether for its depositors. `deposit()` credits the ether sent with the call, and
`withdraw(amount)` sends part of that credit back.

`withdraw` does its work in the wrong order. It reads the caller's credit, sends the ether, and
only then writes the reduced credit back. Sending ether to a contract runs that contract's code.
While that code runs, the vault still shows the old, untouched credit. The receiving contract can
therefore call `withdraw` again, and again, and every nested call passes the balance check. When
the calls unwind, each of them writes the same reduced credit, computed from the stale value, so
the vault forgets all but one of the payouts. The ether that leaves the vault belongs to the
other depositors.

This is single-function reentrancy: the attack re-enters the same function that is still
running.

## The attack

The PoC (`poc/VaultReentrancy.t.sol`) sets up a vault in which two depositors hold 10 ether in
total. The attacker starts with 1 ether and deploys a small contract that:

1. deposits the attacker's ether;
2. withdraws a chunk of it;
3. on every payout, re-enters `withdraw` with the same chunk while the vault still has ether,
   up to a fixed number of times;
4. withdraws whatever credit the vault still shows and sends everything to the attacker.

With the original values (one chunk equal to the whole deposit, five re-entries) the attacker
ends with 6 ether. The PoC records the predicate `attacker_profit` for the asset `eth`.

## The variants

The PoC exposes two knobs, which `testFuzz_variants` draws at random together with the attacker
address and the attacker's starting balance (0.01 to 10 ether):

| Knob | Meaning | Replay value | Range searched |
|---|---|---|---|
| 0 `chunk_bps` | size of each withdrawal, in basis points of the deposit | 10000 (the whole deposit) | 1 to 10000 |
| 1 `reentries` | how many times the attack contract re-enters `withdraw` | 5 | 1 to 10 |

A variant is the same attack with other values, for example withdrawing a tenth of the deposit
per call, re-entering three times, from a different address with a different balance.

## The invariant

`poc/VaultSolvency.t.sol` holds the fixture invariant `vault_solvent`: the vault always holds at
least the ether it credits to its depositors. Its handler lets honest depositors deposit and
withdraw and lets an attacker contract deposit in one call and withdraw with re-entries in a
later one, in any order. Single-function reentrancy breaks the invariant, because a withdrawal
that re-enters is paid more than once while the credit drops only once. It holds under the
`good` patch; under the `overfit` patch a withdrawal of half the credit or less still breaks it.

## The four patches

| Patch | Change | Label and why |
|---|---|---|
| `good.diff` | Writes the reduced credit and the new total before sending the ether (checks, effects, interactions). | `good`: a nested call sees the reduced credit, so it can only take what is really left. No variant pays out more than was deposited, benign behavior is unchanged, and the storage layout, ABI and events are the same. |
| `overfit.diff` | After sending the ether, checks again that the current credit still covers the amount; the stale write stays. | `overfit`: the original attack withdraws the whole deposit per call, so the second check fails once a nested call has written a credit of zero. An attack that withdraws half of the deposit or less per call passes every second check and still drains the vault. The variant search finds such values. |
| `destructive.diff` | Removes the ether transfer from `withdraw`. | `destructive`: without the transfer there is nothing to re-enter, but withdrawals no longer return any ether, so the benign withdrawal tests fail. |
| `regressing.diff` | Adds a reentrancy lock, declared as a new storage variable at the top of the contract. | `regressing`: the lock blocks every nested call and the benign tests pass, but the new variable moves `balanceOf` and `totalDeposits` to other storage slots. A deployed vault upgraded with this code would read its old data from the wrong slots. |
