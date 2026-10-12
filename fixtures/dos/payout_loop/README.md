# Fixture: dos / payout_loop

> **Intentionally vulnerable.** The code in this directory is test material with a known hole.
> It must never be deployed or used to hold real funds.

## The hole

`Crowdfund` collects ether for a project. Anyone may contribute. Once the goal is reached, the
organizer takes the funds; if the organizer cancels the campaign instead, anyone may call
`refundAll()`, which walks through the list of contributors and sends each one its contribution
back.

The loop treats every refund as all or nothing. When one transfer fails, `refundAll()` reverts,
and the refunds already sent in the same call are undone with it. A contributor that is a
contract decides for itself whether it accepts ether. One contributor that always refuses its
refund therefore blocks the refunds of everybody, on every call, and the ether of all honest
contributors stays locked in the campaign for good. The attacker pays for this with its own
contribution, which is locked as well.

## The attack

The PoC (`poc/CrowdfundRefundBlock.t.sol`) opens a campaign with a goal of 100 ether, to which
three honest contributors give 1, 2 and 3 ether. The attacker contributes 0.01 ether through a
small contract whose `receive` function reverts. The organizer then cancels the campaign, and a
keeper calls `refundAll()` with a gas limit of 500,000, an ordinary limit for one transaction.
The call reverts on the attacker's refund, so nobody gets anything back. The PoC records the
predicate `invariant_broken` with the name `refunds_complete`: after the refund run, the honest
contributors do not hold their balances plus their contributions.

## The variants

The PoC exposes two knobs, which `testFuzz_variants` draws at random together with the attacker
address and the attacker's contribution (0.001 to 1 ether):

| Knob | Meaning | Replay value | Range searched |
|---|---|---|---|
| 0 `burn_gas` | how the attacker's contract refuses a refund: 0 reverts, 1 runs an endless loop that burns all the gas the refund call gives it | 0 | 0 to 1 |
| 1 `late_joiners` | honest contributors who join after the attacker, so that their refunds come after the attacker's in the loop | 0 | 0 to 3 |

A call forwards all but one 64th of the remaining gas, so a contract that burns everything it
receives leaves the loop with almost nothing to continue. A variant is the same blockade by a
gas-burning contributor that is followed by at least one honest contributor in the loop.

## The invariant

`poc/RefundsComplete.t.sol` holds the fixture invariant `refunds_complete`: after a refund run,
every honest contributor has its contribution back. Its handler lets five honest accounts
contribute, lets the attacker add up to two contributor contracts that refuse refunds (by
reverting or by burning gas), and lets the organizer cancel and a keeper run `refundAll` with a
gas limit of 500,000, in any order. A refusing contributor that stops the loop breaks the
invariant. It holds under the `good` patch; under the `overfit` patch a gas-burning contributor
still breaks it.

## The four patches

| Patch | Change | Label and why |
|---|---|---|
| `good.diff` | Sends each refund with a fixed allowance of 50,000 gas. When a refund fails, the contribution stays owed, a `RefundFailed` event records it and the loop goes on; a later call of `refundAll()` retries it. | `good`: one contributor can neither revert the whole call nor use up the gas meant for the others, so every honest contributor is refunded in the same call, whichever way the attacker refuses. Ordinary refunds, including those to contract wallets, work as before. The storage layout and the ABI are the same; the new event is an addition. |
| `overfit.diff` | Keeps a failed refund owed and goes on with the loop, but still forwards all the gas to every contributor. | `overfit`: a contributor that reverts no longer blocks anybody, so the original attack fails. A contributor that burns all the gas it receives still does: the loop runs out of gas at the next refund, and the whole call reverts. The variant search finds it with `burn_gas = 1` and at least one late joiner. |
| `destructive.diff` | Skips every contributor that is a contract. | `destructive`: the attacker's contract is skipped and the honest people are refunded, but so is every legitimate contract wallet, whose ether stays locked. The benign test that refunds a contract wallet fails. |
| `regressing.diff` | The isolated refunds of `good.diff`, and `refundAll()` now returns the number of failed refunds. | `regressing`: the blockade is lifted and the benign tests pass, but `refundAll()` gained a return value. Its ABI changed, so callers and interfaces built against the old definition no longer match it. |

The refunds still go through one loop over every contributor. A campaign with very many
contributors needs more gas than one transaction can have, whatever the patch; that limit is a
different shape of denial of service, which this PoC does not exercise.
