# Fixture: rounding / share_inflation

> **Intentionally vulnerable.** The code in this directory is test material with a known hole.
> It must never be deployed or used to hold real funds.

## The hole

`ShareVault` pools one token for its depositors, in the style of ERC4626. A deposit mints shares
in proportion to what the vault already holds: `assets * totalSupply / totalAssets`, rounded down.
`totalAssets` is simply the vault's token balance, so tokens paid into the vault directly, as a
strategy pays yield, raise the value of every share.

The first depositor of an empty vault sets the price of a share. An attacker can open the vault
with a deposit of 1 wei, which mints 1 share, and then pay a large amount into the vault directly.
That one share is now worth the whole balance. A later deposit smaller than that balance mints
`assets * 1 / (balance)` shares, which rounds down to zero: the depositor's tokens join the vault,
and the attacker, who owns every share, redeems them together with its own.

## The attack

The PoC (`poc/ShareInflation.t.sol`) has a victim with a pending deposit of 5 tokens. Before it
lands, the attacker deposits 1 wei and pays 10 tokens into the vault directly. The victim's 5
tokens mint no shares. The attacker then redeems its single share for all 15 tokens and 1 wei in
the vault, 5 tokens more than it put in. The PoC records the predicate `attacker_profit` for the
asset `asset`, measured as the attacker's token balance before and after.

## The variants

The PoC exposes two knobs, which `testFuzz_variants` draws at random together with the attacker
address:

| Knob | Meaning | Replay value | Range searched |
|---|---|---|---|
| 0 `seed` | the attacker's first deposit, in wei | 1 | 1 to 1,000,000 |
| 1 `donation` | tokens paid into the vault directly, in wei | 10 tokens | 1 wei to 10,000 tokens |

A variant opens the vault with a larger first deposit and makes a larger donation. The price of
a share is then lower, but a share can still be worth a sizeable part of the victim's deposit,
which rounds down by up to one share; the attacker, holding almost every share, collects most of
that rounding. With a first deposit of 1,000 wei, a donation of about 5,000 tokens makes the
victim's 5 tokens round down to zero shares again.

## The invariant

`poc/ShareMinting.t.sol` holds the fixture invariant `deposit_mints_shares`: a deposit of a
positive amount never mints zero shares. Its handler lets two victims and an attacker deposit and
redeem, and lets the attacker pay tokens into the vault directly, in any order. Once a donation
makes one share worth more than a deposit, that deposit rounds down to zero shares and the
invariant breaks. It holds under the `good` patch, which refuses a deposit that would mint no
shares; under the `overfit` patch a larger donation still breaks it.

## The four patches

| Patch | Change | Label and why |
|---|---|---|
| `good.diff` | One virtual share and one virtual asset take part in every conversion: shares are `assets * (totalSupply + 1) / (totalAssets + 1)`, assets `shares * (totalAssets + 1) / (totalSupply + 1)`. A deposit that would mint no shares reverts. | `good`: the virtual share owns part of every donation, so the attacker gives up at least as much of its donation as it can take from the victim's rounding, whatever the first deposit and the donation. The attacker never ends with more than it put in. A victim can still lose part of a deposit to rounding when an attacker pays for it, but no longer to the attacker's profit. With a vault that holds as many assets as shares, deposits and redemptions give the same amounts as before, and so does the yield scenario of the benign tests. The storage layout, ABI and events are the same. |
| `overfit.diff` | Requires the first deposit of an empty vault to be at least 1,000 wei. | `overfit`: the 1-wei opening of the original attack is refused. A first deposit above the minimum together with a larger donation still lifts the price of a share far enough, and the victim's deposit still rounds down to the attacker's profit. The variant search finds such a pair, for example a first deposit of about 288,000 wei and a donation of about 8,970 tokens, after which the victim's 5 tokens buy 160 shares worth about 4.985 tokens. |
| `destructive.diff` | Mints one share per asset and pays one asset per share, whatever the vault holds. | `destructive`: a donation no longer changes the price of a share, so the attack fails, but yield no longer reaches the shareholders either. The benign test in which yield raises the value of shares fails. |
| `regressing.diff` | The virtual share and asset of `good.diff`, kept in a new state variable `virtualOffset` declared at the top of the contract. | `regressing`: the attack is blocked and the benign tests pass, but the new variable takes storage slot 0. `totalSupply` and `balanceOf` move to other slots, so a vault upgraded in place would read its old data from the wrong slots. |
