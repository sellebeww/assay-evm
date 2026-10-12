# Fixture: dos / forced_ether (held-out)

> **Intentionally vulnerable.** The code in this directory is test material with a known hole.
> It must never be deployed or used to hold real funds.

This fixture belongs to the held-out split. Its code shape differs from the development fixture
of the same class: there is no loop over recipients and no recipient that refuses a payment. The
function that is blocked depends on a strict equality that anyone can break.

## The hole

`Presale` collects pledges. When they reach the target, anyone may call `finalize`, which sends
everything to the beneficiary. As a sanity check, `finalize` requires that the balance of the
contract equals the sum of the pledges. A contract can receive ether without any code of its own
running, for example from a contract that destroys itself and names it as the recipient. A single
wei sent that way makes the balance differ from the pledges for good, and `finalize` reverts every
time. Once the target is reached, pledges cannot be withdrawn, so the pledged ether is stuck.

## The attack

The PoC (`poc/ForcedEther.t.sol`) deploys two presales with the same beneficiary, target and
pledges, both at the target. The attacker forces 1 wei into one of them with a contract that
destroys itself in its constructor. A keeper then calls `finalize` on both. The presale that was
not touched is the control and is finalized; the other one reverts. The PoC records the predicate
`invariant_broken` for the property `finalize_possible`, which breaks when the control can be
finalized and the attacked presale cannot.

## The variants

The PoC exposes one knob, which `testFuzz_variants` draws at random together with the attacker
address and the attacker's starting balance (1000 wei to 1 ether):

| Knob | Meaning | Replay value | Range searched |
|---|---|---|---|
| 0 `forced_wei` | the ether that the attacker forces into the presale, in wei | 1 | 1 to 1000 |

A variant is the same attack with more ether.

## The four patches

| Patch | Change | Label and why |
|---|---|---|
| `good` | `finalize` requires the balance to be at least the pledges, instead of equal to them. | Closes the root cause: ether that was forced in no longer matters, and the pledges are still covered. Behavior, storage layout and ABI stay the same. |
| `overfit` | `finalize` tolerates a balance up to 10 wei above the pledges. | A plausible allowance for dust that blocks the original PoC, which forces 1 wei. A larger amount still breaks the equality, so the variant still works. |
| `destructive` | `finalize` reverts unconditionally. | A presale that cannot be finalized is not forced into it by anyone, so the original PoC is blocked, but the presale never pays the beneficiary, and the benign tests that finalize fail. |
| `regressing` | The `good` change, and `finalized` is declared before `totalPledged`. | Closes the hole and keeps the benign tests passing, but changes the position of both variables in storage, a breaking layout change. |
