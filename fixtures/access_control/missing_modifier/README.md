# Fixture: access_control / missing_modifier

> **Intentionally vulnerable.** The code in this directory is test material with a known hole.
> It must never be deployed or used to hold real funds.

## The hole

`FeeCollector` collects fees in ether. Its owner pays them out, for example to suppliers, and can
hand ownership to someone else.

The contract has an `onlyOwner` modifier, and `setOwner` uses it. The two payout functions,
`payOut(to, amount)` and `payOutAll(to)`, are documented as "owner only", but neither of them
carries the modifier and neither checks the caller in any other way. Anyone can call them and
send the collected fees to any address, including their own.

## The attack

The PoC (`poc/FeeCollectorDrain.t.sol`) sets up a collector that holds 20 ether of fees paid by
a customer. The attacker, an account with no role at all, calls `payOutAll` with its own address
and receives everything. The PoC records the predicate `attacker_profit` for the asset `eth`.

## The variants

The PoC exposes two knobs, which `testFuzz_variants` draws at random together with the attacker
address and the attacker's starting balance (0 to 1 ether):

| Knob | Meaning | Replay value | Range searched |
|---|---|---|---|
| 0 `route` | which payout function the attacker calls: 0 `payOutAll`, 1 `payOut` | 0 | 0 to 1 |
| 1 `share_bps` | for `payOut`, the share of the collected fees taken, in basis points | 10000 (everything) | 1 to 10000 |

A variant is the same theft through the other payout function, for example taking 37 percent
of the fees through `payOut` from a different address.

## The four patches

| Patch | Change | Label and why |
|---|---|---|
| `good.diff` | Adds `onlyOwner` to both payout functions. | `good`: only the owner can move fees, whichever function is used. The owner's payouts work as before, and the storage layout, ABI and events are the same. |
| `overfit.diff` | Adds `onlyOwner` to `payOutAll` only, the function the original attack used. | `overfit`: the original attack is blocked, but `payOut` still checks nothing, so the same theft works through the sibling function. The variant search finds it as soon as it tries route 1. |
| `destructive.diff` | Lets the payout functions send fees to the owner only. | `destructive`: an outsider can no longer send the fees to itself, but the owner can no longer pay a supplier or a separate treasury either, so the benign payout tests fail. |
| `regressing.diff` | Moves ownership into a small `Owned` base contract and adds `onlyOwner` to both payout functions. | `regressing`: every payout is owner-only and the benign tests pass, but the base contract's `owner` now comes first in storage. `owner`, `totalCollected` and `totalPaidOut` all move to other slots, so a deployed collector upgraded with this code would read its old data from the wrong slots. |
