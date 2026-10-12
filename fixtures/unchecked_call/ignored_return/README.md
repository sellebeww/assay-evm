# Fixture: unchecked_call / ignored_return

> **Intentionally vulnerable.** The code in this directory is test material with a known hole.
> It must never be deployed or used to hold real funds.

## The hole

`Payroll` holds ether for a team. The employer books a wage for each payee, and anyone may then
push a booked wage to its payee, with `pay(payee)` for one payee or `payMany(payees)` for several
at once. Letting anyone push payments is convenient: a keeper can run payday for everybody.

Both functions clear the payee's wage first and then send the ether with a low-level call. The
call reports whether the payee accepted the ether, but the payroll never looks at the answer.
When the payee is a contract that refuses ether at that moment, the call fails quietly: the ether
stays in the payroll, while the books say the wage was paid. The payee's money is no longer owed
to anyone.

## The attack

The PoC (`poc/PayrollLockedWallet.t.sol`) sets up a payroll with 20 ether. One payee is a
smart-contract wallet that its holder has locked, so that it refuses ether for a while; it is owed
5 ether. Three colleagues are owed 1 ether each. The attacker, an account with no role, calls
`pay` for the locked wallet. The payment fails, the wage is cleared anyway, and the wallet's
5 ether are gone from the books. The PoC records the predicate `victim_loss` for the asset `eth`,
measured as the wallet's booked wage plus its balance, before and after.

## The variants

The PoC exposes two knobs, which `testFuzz_variants` draws at random together with the attacker
address and the attacker's starting balance (0 to 1 ether):

| Knob | Meaning | Replay value | Range searched |
|---|---|---|---|
| 0 `route` | how the attacker pushes the wage: 0 `pay`, 1 `payMany` | 0 | 0 to 1 |
| 1 `batch_size` | for `payMany`, the number of payees in the batch; the locked wallet comes last, after colleagues who are paid normally | 1 | 1 to 4 |

A variant is the same griefing through the batch function, for example a payday for two
colleagues with the locked wallet slipped in at the end.

## The four patches

| Patch | Change | Label and why |
|---|---|---|
| `good.diff` | Checks the result of the call in both payment functions and reverts when the payee refuses the ether. | `good`: a refused payment undoes the whole call, so the wage stays booked until the payee can accept it. Ordinary payments work as before, and the storage layout, ABI and events are the same (the new error is not part of the compared interface). |
| `overfit.diff` | Checks the result of the call in `pay` only, the function the original attack used. | `overfit`: the original attack is blocked, but `payMany` has its own copy of the payment code and still ignores the result, so the same loss happens through a batch. The variant search finds it as soon as it tries route 1. |
| `destructive.diff` | Lets only the payee itself trigger its payment, in both functions. | `destructive`: an outsider can no longer push a payment to a locked wallet, but keepers can no longer run payday either, so the benign tests in which a keeper pays one or several payees fail. |
| `regressing.diff` | When the payee refuses the ether, keeps the wage booked instead of clearing it; `pay` now returns whether it paid. | `regressing`: no wage is lost and the benign tests pass, but `pay` gained a return value. Its ABI changed, so callers and interfaces built against the old definition no longer match it. |
