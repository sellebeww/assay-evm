# Fixture: oracle_manipulation / spot_price

> **Intentionally vulnerable.** The code in this directory is test material with a known hole.
> It must never be deployed or used to hold real funds.

## The hole

`MiniPool` is a tiny constant-product market for two tokens: a base token and a quote token. Its
`spotPrice()` reads the price of the base token from the two reserves at this very moment.
`Lender` lends the quote token against the base token as collateral, up to 75 percent of the
collateral's value, and it values the collateral with that spot price.

The spot price of a small pool is cheap to move. Whoever buys a large amount of base tokens
empties the base reserve and fills the quote reserve, so the price shoots up for as long as nobody
trades back. Within the same transaction, the lender believes the new price. An attacker can buy
base tokens at a rising price, deposit them as collateral at the inflated price and borrow more
quote tokens than the purchase cost. The loan is never repaid; the lender is left with collateral
that is worth far less than the debt.

## The attack

The PoC (`poc/SpotPriceBorrow.t.sol`) opens the pool with 1,000 base and 1,000 quote tokens (a
price of one) and gives the lender 5,000 quote tokens to lend. The market then runs for a day.
The attacker starts with 2,000 quote tokens, as it could from a flash loan, and:

1. buys base tokens with all 2,000 quote tokens in one swap, which lifts the price to almost nine;
2. deposits the base tokens it bought as collateral;
3. borrows as much as the lender allows at the inflated price, capped at what the lender holds.

It ends with about 4,486 quote tokens for the 2,000 it spent. The PoC records the predicate
`attacker_profit` for the asset `quote`, measured as the attacker's quote balance before and
after.

## The variants

The PoC exposes two knobs, which `testFuzz_variants` draws at random together with the attacker
address:

| Knob | Meaning | Replay value | Range searched |
|---|---|---|---|
| 0 `pump` | quote tokens spent on base tokens, in whole tokens | 2000 | 1 to 3000 |
| 1 `swaps` | the number of equal swaps the purchase is split into | 1 | 1 to 40 |

A variant is the same manipulation with another budget, or split into several smaller swaps, for
example 1,200 quote tokens spent in 15 swaps of 80. A purchase of less than about a third of the
quote reserve does not lift the price enough to pay for itself.

## The four patches

| Patch | Change | Label and why |
|---|---|---|
| `good.diff` | The pool keeps a cumulative price, the sum of each price times the seconds it was in force, brought up to date before every change of the reserves. The lender values collateral at the average of that price over a window of at least 30 minutes, and at the last completed average while the current window is shorter. | `good`: a trade can only change the price from the next second on, so swaps in the current transaction leave the average untouched, however many there are. Collateral bought at a rising price is valued at the old price, and the attacker can borrow at most 75 percent of what it paid. Ordinary lending works as before, because without trades the average equals the spot price. The new state variables are appended after the existing ones, the ABI only gains functions and the events are the same. |
| `overfit.diff` | Caps every swap at a tenth of the reserve it sells into. | `overfit`: the single swap of the original attack is refused. The same purchase split into enough smaller swaps passes the cap and moves the price just as far, because the curve does not care how a purchase is split. The variant search finds such a split. |
| `destructive.diff` | Sets the loan-to-value ratio to zero. | `destructive`: nothing can be borrowed against the manipulated price, but nothing can be borrowed at all, so the benign tests of ordinary loans fail. |
| `regressing.diff` | The time-weighted price of `good.diff`, and the `Borrowed` event gains the price used. | `regressing`: the manipulation is blocked and the benign tests pass, but `Borrowed(address,uint256)` became `Borrowed(address,uint256,uint256)`, a different event. Anything that watches for the old event stops seeing loans. |
