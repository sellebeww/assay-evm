# Fixture: delegatecall / user_controlled_target

> **Intentionally vulnerable.** The code in this directory is test material with a known hole.
> It must never be deployed or used to hold real funds.

## The hole

`ModuleVault` holds ether for its owner. Routine upkeep, such as moving surplus ether to cold
storage, lives in separate module contracts. The vault runs a module with `delegatecall`: the
module's code runs as if it were the vault's own code, with the vault's storage and the vault's
ether. That is only acceptable for code the owner trusts, so the owner keeps a list of approved
modules. Anyone may run upkeep, so that a keeper can do it.

The vault never consults that list. `runUpkeep(module, data)` and `runUpkeepBatch(modules, data)`
run whatever module the caller names. A module written by an attacker can then write anything
into the vault's storage. The vault keeps its owner in its first storage slot, so a module whose
first variable sits in the same slot can make anyone the owner.

`src/SweepModule.sol` is the legitimate module that the benign tests and the PoC use; it has no
hole of its own.

## The attack

The PoC (`poc/ModuleVaultTakeover.t.sol`) sets up a vault with 15 ether and an approved sweep
module that keeps a 5 ether reserve. The attacker deploys `TakeoverModule`, whose only variable
lines up with the vault's owner slot, and runs it through `runUpkeep` with its own address. The
attacker is now the owner and withdraws all the ether. The PoC records two predicates:
`unauthorized_role_change` for the role `owner`, and `attacker_profit` for the asset `eth`.

## The variants

The PoC exposes three knobs, which `testFuzz_variants` draws at random together with the attacker
address and the attacker's starting balance (0 to 1 ether):

| Knob | Meaning | Replay value | Range searched |
|---|---|---|---|
| 0 `entry` | which entry point runs the attack module: 0 `runUpkeep`, 1 `runUpkeepBatch` | 0 | 0 to 1 |
| 1 `cover_runs` | for `runUpkeepBatch`, ordinary sweeps placed before the attack module in the batch | 0 | 0 to 3 |
| 2 `drain_bps` | share of the vault's ether withdrawn after the takeover, in basis points | 10000 (everything) | 1 to 10000 |

A variant is the same takeover through the batch entry point, for example hidden behind two
ordinary sweeps, followed by a partial withdrawal.

## The four patches

| Patch | Change | Label and why |
|---|---|---|
| `good.diff` | Checks the approval list in the private function that both entry points use, before the `delegatecall`. | `good`: only approved modules run, whichever entry point is used, so no foreign code touches the vault's storage. Keepers' upkeep works as before, and the storage layout, ABI and events are the same. |
| `overfit.diff` | Checks the approval list in `runUpkeep` only, the entry point the original attack used. | `overfit`: the original attack is blocked, but `runUpkeepBatch` still runs any module, so the same takeover works through a batch. The variant search finds it as soon as it tries entry 1. |
| `destructive.diff` | Runs modules with a plain `call` instead of `delegatecall`. | `destructive`: a module now runs in its own context and cannot touch the vault's storage, but it cannot move the vault's ether either. The sweep module no longer sweeps anything, so the benign upkeep tests fail. |
| `regressing.diff` | Checks the approval list like `good.diff`, and also makes `owner` an immutable value. | `regressing`: the takeover is blocked and the benign tests pass, but an immutable is kept in the contract's code, not in storage. `approvedModule` and `upkeepRuns` move up one slot, so a vault upgraded in place, or any module written for the old layout, would read and write the wrong slots. |
