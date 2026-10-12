# Fixture: delegatecall / strategy_registry (held-out)

> **Intentionally vulnerable.** The code in this directory is test material with a known hole.
> It must never be deployed or used to hold real funds.

This fixture belongs to the held-out split. Its code shape differs from the development fixture
of the same class: the target of the `delegatecall` is not passed in the call that runs it. It is
registered first, by the account that will run it, and run later by a second call.

## The hole

`StrategyHub` lets every account register a strategy with `setStrategy` and run it with
`harvest`. The hub runs a strategy with `delegatecall`, so that a strategy can credit rewards in the
hub's own storage. A strategy therefore has the hub's storage and can write any slot, including
`owner`.

The owner keeps a list of approved strategies, but `setStrategy` does not consult it: any account
can register any contract. A contract that writes the first storage slot makes its creator the
owner of the hub as soon as the hub runs it.

## The attack

The PoC (`poc/StrategyTakeover.t.sol`) sets up a hub that holds 10 ether. The attacker has no role.
It deploys a strategy whose `harvest` sets the first slot to the attacker's address, registers it
with `setStrategy`, calls `harvest`, and then sweeps the hub as its new owner. The PoC records the
predicate `attacker_profit` for the asset `eth`.

## The variants

The PoC exposes two knobs, which `testFuzz_variants` draws at random together with the attacker
address and the attacker's starting balance (0 to 1 ether):

| Knob | Meaning | Replay value | Range searched |
|---|---|---|---|
| 0 `marked` | 0: the attacker's strategy has no `isStrategy` marker; 1: it has one | 0 | 0 to 1 |
| 1 `sweep_bps` | the part of the hub that is swept, in basis points | 10000 | 1 to 10000 |

A variant is the same takeover with a strategy that answers the marker, or sweeping a part of the
hub.

## The four patches

| Patch | Change | Label and why |
|---|---|---|
| `good` | `setStrategy` reverts for a strategy that the owner has not approved. | Closes the root cause: only strategies on the owner's list are ever run with the hub's storage. Behavior, storage layout and ABI stay the same, because the list and its setter existed already. |
| `overfit` | `setStrategy` reverts unless the strategy answers `isStrategy()` with `true`. | A plausible sanity check that blocks the original PoC, whose strategy has no such function. Any contract can answer the marker, so the variant with `marked` 1 still works. |
| `destructive` | `harvest` reverts unconditionally. | Blocks the takeover by disabling the delegated call. The benign tests that harvest fail. |
| `regressing` | The `good` change, and `harvests` is declared before `strategyOf`. | Closes the hole and keeps the benign tests passing, but swaps two storage slots, a breaking layout change. The slot that strategies write is unchanged. |
