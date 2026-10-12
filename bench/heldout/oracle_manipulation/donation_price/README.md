# Fixture: oracle_manipulation / donation_price (held-out)

> **Intentionally vulnerable.** The code in this directory is test material with a known hole.
> It must never be deployed or used to hold real funds.

This fixture belongs to the held-out split. Its code shape differs from the development fixture
of the same class: the pool does not trade, so no swap moves the price. The price follows the
token balances of the pool, which anyone can change without a trade.

## The hole

`ReferencePool` publishes a reference price, the quote tokens held per base token, and takes
deposits. It computes the price from `balanceOf` of the two tokens. `LoanDesk` lends the quote
token against the base token and values the collateral at that price, up to 75 percent.

Quote tokens that are sent to the pool, either with a plain token transfer or with a deposit of
quote tokens alone, raise the price at once. A borrower can raise it, lock collateral that is now
valued far above its worth, and borrow against the inflated value.

## The attack

The PoC (`poc/DonationPrice.t.sol`) sets up a pool of 1000 base and 1000 quote tokens (price 1)
and a desk that holds 50000 quote tokens to lend. The attacker holds 10000 base and 2000 quote
tokens. It transfers its quote tokens to the pool, which raises the price to 3, locks all its
base tokens, and borrows the largest loan the desk allows, 22500 quote tokens. It never repays.

The attacker's tokens are valued at the price of 1 that the pool had before the attack: 12000
before, 22500 after. The PoC records the predicate `attacker_profit` for the asset `usd_value`.

## The variants

The PoC exposes two knobs, which `testFuzz_variants` draws at random together with the attacker
address and the attacker's starting balance:

| Knob | Meaning | Replay value | Range searched |
|---|---|---|---|
| 0 `route` | how the attacker raises the price: 0 a plain transfer to the pool, 1 `deposit(0, amount)` | 0 | 0 to 1 |
| 1 `donation_bps` | the part of the attacker's quote tokens that moves the price, in basis points | 10000 | 1 to 10000 |

A variant is the same attack through a one-sided deposit, or with a smaller part of the tokens
that still moves the price enough to pay.

## The four patches

| Patch | Change | Label and why |
|---|---|---|
| `good` | The pool keeps its own reserves, changed only by `deposit`, and computes the price from them; a deposit must keep the ratio of the reserves. | Closes the root cause: neither a plain transfer nor a one-sided deposit moves the price. The benign tests deposit in proportion, so behavior stays the same. The reserves are new variables after the last used slot, an additive layout change. |
| `overfit` | The pool keeps its own reserves and computes the price from them, but `deposit` accepts any ratio. | Ignores tokens that are transferred in, which is what the original PoC does. A one-sided deposit still changes the reserves, so the route 1 variant still works. |
| `destructive` | `borrow` reverts unconditionally. | The attacker can raise the price but cannot borrow, so the original PoC is blocked. Honest borrowers cannot borrow either, and the benign tests that borrow fail. |
| `regressing` | The `good` change, and `deposit` returns the price. | Closes the hole and keeps the benign tests passing, but changes the return types of `deposit`, a breaking ABI change. |
