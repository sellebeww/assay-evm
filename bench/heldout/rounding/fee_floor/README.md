# Fixture: rounding / fee_floor (held-out)

> **Intentionally vulnerable.** The code in this directory is test material with a known hole.
> It must never be deployed or used to hold real funds.

This fixture belongs to the held-out split. Its code shape differs from the development fixture
of the same class: there are no shares and no price per share. The rounding is in the fee that a
withdrawal pays.

## The hole

`FeePool` keeps ether for depositors. A withdrawal of `amount` wei pays a fee of 30 basis points,
computed as `amount * 30 / 10000` with integer division, which rounds down. For any amount below
334 wei the fee rounds down to zero. The fee is charged on each withdrawal separately, so a
depositor who withdraws in many small pieces pays no fee at all, where one large withdrawal of the
same amount pays 0.30 percent. Even above that size, every piece loses the fraction that the
division drops.

## The attack

The PoC (`poc/FeeFloor.t.sol`) sets up a pool with 5 ether of deposits. The attacker deposits
9990 wei and withdraws it in 30 withdrawals of 333 wei. Each fee rounds down to zero, so the pool
accrues no fee, where the fee on 9990 wei is 30 wei when rounded up. The PoC records the predicate
`victim_loss` for the asset `fees`: the fees the pool was owed against the fees it accrued.

## The variants

The PoC exposes two knobs, which `testFuzz_variants` draws at random together with the attacker
address and the attacker's starting balance (1 to 10 ether):

| Knob | Meaning | Replay value | Range searched |
|---|---|---|---|
| 0 `chunk` | the amount of each withdrawal, in wei | 333 | 1 to 5000 |
| 1 `chunks` | the number of withdrawals | 30 | 1 to 40 |

A variant is the same attack with another piece size, for example pieces above a minimum size,
where each fee loses only the fraction that the division drops.

## The four patches

| Patch | Change | Label and why |
|---|---|---|
| `good` | `feeOn` rounds up. | Closes the root cause: the pool never gets less than the exact fee, however a withdrawal is split. The benign tests withdraw round amounts, whose fee is exact, so behavior stays the same. Storage layout and ABI stay the same. |
| `overfit` | `withdraw` reverts for amounts below 1000 wei. | A plausible half-fix that blocks the original PoC, whose pieces are 333 wei. Pieces of 1000 wei and more still lose the dropped fraction of their fee, so the variant with a larger `chunk` still works. |
| `destructive` | `withdraw` reverts unconditionally. | Nobody can split a withdrawal when nobody can withdraw, so the original PoC is blocked. The benign tests that withdraw fail. |
| `regressing` | The `good` change, and `withdraw` returns the amount paid out. | Closes the hole and keeps the benign tests passing, but changes the return types of `withdraw`, a breaking ABI change. |
