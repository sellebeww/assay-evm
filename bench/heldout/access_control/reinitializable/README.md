# Fixture: access_control / reinitializable (held-out)

> **Intentionally vulnerable.** The code in this directory is test material with a known hole.
> It must never be deployed or used to hold real funds.

This fixture belongs to the held-out split. Its code shape differs from the development fixture
of the same class: the missing check is not on a privileged function but on the initializers that
create the privileged account.

## The hole

`Treasury` has no constructor, as if it were the logic of a proxy. An administrator sets it up
after deployment with an initializer, `initialize(owner)` or `initializeWithFee(owner, feeBps)`.
Both initializers write the owner. Neither checks that the treasury has not been set up already,
so anyone can call either of them again at any time, make themselves the owner and sweep the
treasury.

## The attack

The PoC (`poc/TreasuryTakeover.t.sol`) sets up a treasury that its administrator initialized and
that holds 10 ether. The attacker, an account without any role, calls `initialize` with its own
address, and then calls `sweep` as the new owner. All ten ether move to the attacker. The PoC
records the predicate `attacker_profit` for the asset `eth`.

## The variants

The PoC exposes two knobs, which `testFuzz_variants` draws at random together with the attacker
address and the attacker's starting balance (0 to 1 ether):

| Knob | Meaning | Replay value | Range searched |
|---|---|---|---|
| 0 `initializer` | the initializer the attacker calls: 0 `initialize`, 1 `initializeWithFee` | 0 | 0 to 1 |
| 1 `sweep_bps` | the part of the treasury that is swept, in basis points | 10000 | 1 to 10000 |

A variant is the same takeover through the other initializer, or with a part of the funds.

## The four patches

| Patch | Change | Label and why |
|---|---|---|
| `good` | Both initializers revert when an owner is already set. | Closes the root cause: once set up, the treasury cannot be set up again. Behavior, storage layout and ABI stay the same. |
| `overfit` | Only `initialize` reverts when an owner is already set. | Blocks the original PoC, which calls `initialize`. `initializeWithFee` writes the owner too and has no check, so the variant with `initializer` 1 still works. |
| `destructive` | `sweep` reverts unconditionally. | The attacker can still become the owner, but cannot take the ether, so the original PoC is blocked. The owner cannot sweep either, and the benign tests that sweep fail. |
| `regressing` | The `good` change, and `feeBps` is declared before `owner`. | Closes the hole and keeps the benign tests passing, but changes the position of both variables in storage, a breaking layout change. |
