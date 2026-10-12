# Static analysis coverage

`make static-coverage` writes this page from one run of `assay scan` over the development fixtures,
with `tools/static_coverage.py`. It is not edited by hand.

The development split has one fixture per vulnerability class. This page shows what the two static
analyzers report on the unpatched code of each fixture, after Assay normalized and deduplicated
their results. A finding counts for an analyzer when one of its sources comes from that analyzer; a
finding of both analyzers counts for both and once in the column after deduplication.

## What this result means

A class hit means only that at least one finding in the fixture maps to the fixture's class through
`src/assay/analysis/class_map.toml`. It does not mean that the finding points at the defect the
fixture contains, and it is not a reproduction: every finding is a candidate (unverified) at
evidence level E0. A class without a hit says nothing about the code either; the analyzers simply
reported nothing of that class.

The detector mapping was written from the detector documentation of the pinned tool versions before
any coverage run. Neither the mapping nor the fixtures are changed to improve these numbers.

## Result

`STATIC COVERAGE: 6/8 fixture classes with at least one finding mapped to the class`

| Class | Fixture | Slither findings | Slither class hit | Aderyn findings | Aderyn class hit | Findings after deduplication | Class hit by any analyzer |
|---|---|---|---|---|---|---|---|
| `reentrancy` | `single_function` | 2 | yes | 2 | yes | 3 | yes |
| `access_control` | `missing_modifier` | 4 | yes | 2 | no | 6 | yes |
| `unchecked_call` | `ignored_return` | 10 | yes | 7 | yes | 10 | yes |
| `signature_replay` | `missing_nonce` | 2 | no | 1 | yes | 3 | yes |
| `delegatecall` | `user_controlled_target` | 9 | yes | 9 | yes | 16 | yes |
| `oracle_manipulation` | `spot_price` | 12 | no | 16 | no | 18 | no |
| `dos` | `payout_loop` | 5 | yes | 4 | yes | 6 | yes |
| `rounding` | `share_inflation` | 6 | no | 4 | no | 7 | no |

## Classes the analyzers did not detect

No finding of either analyzer maps to the class of 2 of the 8 fixtures:

- `oracle_manipulation` (`oracle_manipulation/spot_price`): the analyzers reported `aderyn/large-numeric-literal`, `aderyn/reentrancy-state-change`, `aderyn/unchecked-return`, `aderyn/unsafe-erc20-operation`, `aderyn/unused-public-function`, `slither/reentrancy-benign`, `slither/reentrancy-events`, `slither/reentrancy-no-eth`, `slither/unchecked-transfer`.
- `rounding` (`rounding/share_inflation`): the analyzers reported `aderyn/reentrancy-state-change`, `aderyn/unchecked-return`, `aderyn/unsafe-erc20-operation`, `slither/incorrect-equality`, `slither/reentrancy-benign`, `slither/reentrancy-events`, `slither/reentrancy-no-eth`, `slither/unchecked-transfer`.

Detected by one analyzer only (the other reported nothing of the class):

- `access_control` (`access_control/missing_modifier`): nothing from Aderyn.
- `signature_replay` (`signature_replay/missing_nonce`): nothing from Slither.

These gaps are expected and are the reason Assay does not stop at static analysis. A hypothesis can
be turned into a PoC and checked by the oracles whether or not an analyzer flagged it, and a patch
is judged by the oracles, never by analyzer output.

## Findings mapped to the fixture's class

- `reentrancy/single_function`:
  - `slither/reentrancy-benign`, `slither/reentrancy-eth`, `slither/reentrancy-events`, `aderyn/reentrancy-state-change` at `src/Vault.sol:29-40` (`Vault.withdraw`)
- `access_control/missing_modifier`:
  - `slither/arbitrary-send-eth` at `src/FeeCollector.sol:63-71` (`FeeCollector._send`)
- `unchecked_call/ignored_return`:
  - `slither/unchecked-lowlevel`, `aderyn/unchecked-low-level-call` at `src/Payroll.sol:49-56` (`Payroll.pay`)
  - `slither/unchecked-lowlevel`, `aderyn/unchecked-low-level-call` at `src/Payroll.sol:60-70` (`Payroll.payMany`)
- `signature_replay/missing_nonce`:
  - `aderyn/ecrecover` at `src/VoucherRedeemer.sol:43-43` (`VoucherRedeemer.redeem`)
- `delegatecall/user_controlled_target`:
  - `aderyn/delegate-call-unchecked-address` at `src/ModuleVault.sol:47-47` (`ModuleVault.runUpkeep`)
  - `aderyn/delegate-call-unchecked-address`, `aderyn/delegatecall-in-loop` at `src/ModuleVault.sol:52-54` (`ModuleVault.runUpkeepBatch`)
  - `slither/controlled-delegatecall` at `src/ModuleVault.sol:69-75` (`ModuleVault._run`)
- `dos/payout_loop`:
  - `slither/calls-loop`, `aderyn/require-revert-in-loop` at `src/Crowdfund.sol:67-80` (`Crowdfund.refundAll`)

## All findings per fixture

### `reentrancy/single_function`

Input tree sha256 `858288a69ceda063acf4e414a16ca4dc47c61e79bd157fe0608525c950637313`.

| Class | Reported by | Location |
|---|---|---|
| `access_control` | `aderyn/eth-send-unchecked-address` | `src/Vault.sol:29-29` (`Vault.withdraw`) |
| `other` | `slither/low-level-calls` | `src/Vault.sol:29-40` (`Vault.withdraw`) |
| `reentrancy` | `slither/reentrancy-benign`, `slither/reentrancy-eth`, `slither/reentrancy-events`, `aderyn/reentrancy-state-change` | `src/Vault.sol:29-40` (`Vault.withdraw`) |

### `access_control/missing_modifier`

Input tree sha256 `f4150473969d6274e140e2409854c4c9df64dca8a91bbd92ae2062b178b33867`.

| Class | Reported by | Location |
|---|---|---|
| `other` | `aderyn/modifier-used-only-once` | `src/FeeCollector.sol:25-25` (`FeeCollector.onlyOwner`) |
| `other` | `aderyn/centralization-risk` | `src/FeeCollector.sol:44-44` (`FeeCollector.setOwner`) |
| `other` | `slither/incorrect-equality` | `src/FeeCollector.sol:57-61` (`FeeCollector.payOutAll`) |
| `access_control` | `slither/arbitrary-send-eth` | `src/FeeCollector.sol:63-71` (`FeeCollector._send`) |
| `other` | `slither/low-level-calls` | `src/FeeCollector.sol:63-71` (`FeeCollector._send`) |
| `reentrancy` | `slither/reentrancy-events` | `src/FeeCollector.sol:63-71` (`FeeCollector._send`) |

### `unchecked_call/ignored_return`

Input tree sha256 `b4614006f8dbc2298166ab114735ded106273d92241b7a191197a81abd4141d9`.

| Class | Reported by | Location |
|---|---|---|
| `other` | `slither/immutable-states`, `aderyn/state-variable-could-be-immutable` | `src/Payroll.sol:10-10` |
| `access_control` | `slither/arbitrary-send-eth`, `aderyn/eth-send-unchecked-address` | `src/Payroll.sol:49-56` (`Payroll.pay`) |
| `other` | `slither/low-level-calls`, `slither/missing-zero-check` | `src/Payroll.sol:49-56` (`Payroll.pay`) |
| `reentrancy` | `slither/reentrancy-events` | `src/Payroll.sol:49-56` (`Payroll.pay`) |
| `unchecked_call` | `slither/unchecked-lowlevel`, `aderyn/unchecked-low-level-call` | `src/Payroll.sol:49-56` (`Payroll.pay`) |
| `access_control` | `slither/arbitrary-send-eth`, `aderyn/eth-send-unchecked-address` | `src/Payroll.sol:60-70` (`Payroll.payMany`) |
| `dos` | `slither/calls-loop` | `src/Payroll.sol:60-70` (`Payroll.payMany`) |
| `other` | `slither/costly-loop`, `slither/low-level-calls`, `slither/missing-zero-check`, `aderyn/costly-loop` | `src/Payroll.sol:60-70` (`Payroll.payMany`) |
| `reentrancy` | `slither/reentrancy-eth`, `slither/reentrancy-events`, `aderyn/reentrancy-state-change` | `src/Payroll.sol:60-70` (`Payroll.payMany`) |
| `unchecked_call` | `slither/unchecked-lowlevel`, `aderyn/unchecked-low-level-call` | `src/Payroll.sol:60-70` (`Payroll.payMany`) |

### `signature_replay/missing_nonce`

Input tree sha256 `f8fb71aa48f16fe016450fc96cca3bee5be7d93728e64fc051d79895bfd7ddc4`.

| Class | Reported by | Location |
|---|---|---|
| `other` | `slither/low-level-calls` | `src/VoucherRedeemer.sol:40-52` (`VoucherRedeemer.redeem`) |
| `reentrancy` | `slither/reentrancy-events` | `src/VoucherRedeemer.sol:40-52` (`VoucherRedeemer.redeem`) |
| `signature_replay` | `aderyn/ecrecover` | `src/VoucherRedeemer.sol:43-43` (`VoucherRedeemer.redeem`) |

### `delegatecall/user_controlled_target`

Input tree sha256 `7bfd7667779240d4b4d3911b07c2e46dcf2c49728198d40a4c1993ca00196510`.

| Class | Reported by | Location |
|---|---|---|
| `other` | `slither/immutable-states`, `aderyn/state-variable-could-be-immutable` | `src/ModuleVault.sol:12-12` |
| `other` | `aderyn/centralization-risk` | `src/ModuleVault.sol:41-41` (`ModuleVault.setModuleApproval`) |
| `delegatecall` | `aderyn/delegate-call-unchecked-address` | `src/ModuleVault.sol:47-47` (`ModuleVault.runUpkeep`) |
| `delegatecall` | `aderyn/delegate-call-unchecked-address`, `aderyn/delegatecall-in-loop` | `src/ModuleVault.sol:52-54` (`ModuleVault.runUpkeepBatch`) |
| `dos` | `aderyn/require-revert-in-loop` | `src/ModuleVault.sol:54-54` (`ModuleVault.runUpkeepBatch`) |
| `other` | `aderyn/costly-loop` | `src/ModuleVault.sol:54-54` (`ModuleVault.runUpkeepBatch`) |
| `unchecked_call` | `aderyn/unchecked-return` | `src/ModuleVault.sol:55-55` (`ModuleVault.runUpkeepBatch`) |
| `other` | `slither/low-level-calls`, `slither/missing-zero-check`, `aderyn/centralization-risk` | `src/ModuleVault.sol:60-67` (`ModuleVault.withdraw`) |
| `reentrancy` | `slither/reentrancy-events` | `src/ModuleVault.sol:60-67` (`ModuleVault.withdraw`) |
| `delegatecall` | `slither/controlled-delegatecall` | `src/ModuleVault.sol:69-75` (`ModuleVault._run`) |
| `dos` | `slither/calls-loop` | `src/ModuleVault.sol:69-75` (`ModuleVault._run`) |
| `other` | `slither/costly-loop`, `slither/low-level-calls` | `src/ModuleVault.sol:69-75` (`ModuleVault._run`) |
| `reentrancy` | `slither/reentrancy-benign`, `slither/reentrancy-events` | `src/ModuleVault.sol:69-75` (`ModuleVault._run`) |
| `other` | `slither/missing-zero-check` | `src/SweepModule.sol:17-17` (`SweepModule.constructor`) |
| `access_control` | `aderyn/eth-send-unchecked-address` | `src/SweepModule.sol:24-24` (`SweepModule.sweep`) |
| `other` | `slither/low-level-calls` | `src/SweepModule.sol:24-29` (`SweepModule.sweep`) |

### `oracle_manipulation/spot_price`

Input tree sha256 `f4215a195703e636697e193411e76cbb1cb0bb71e5503214e7816805ed640bbd`.

| Class | Reported by | Location |
|---|---|---|
| `other` | `aderyn/large-numeric-literal` | `src/Lender.sol:12-12` |
| `reentrancy` | `aderyn/reentrancy-state-change` | `src/Lender.sol:41-41` (`Lender.constructor`) |
| `reentrancy` | `slither/reentrancy-benign`, `slither/reentrancy-events`, `aderyn/reentrancy-state-change` | `src/Lender.sol:60-65` (`Lender.depositCollateral`) |
| `unchecked_call` | `slither/unchecked-transfer`, `aderyn/unchecked-return` | `src/Lender.sol:60-65` (`Lender.depositCollateral`) |
| `reentrancy` | `slither/reentrancy-events` | `src/Lender.sol:67-75` (`Lender.withdrawCollateral`) |
| `unchecked_call` | `slither/unchecked-transfer`, `aderyn/unchecked-return` | `src/Lender.sol:67-75` (`Lender.withdrawCollateral`) |
| `other` | `aderyn/unsafe-erc20-operation` | `src/Lender.sol:73-73` (`Lender.withdrawCollateral`) |
| `reentrancy` | `slither/reentrancy-events` | `src/Lender.sol:77-84` (`Lender.borrow`) |
| `unchecked_call` | `slither/unchecked-transfer`, `aderyn/unchecked-return` | `src/Lender.sol:77-84` (`Lender.borrow`) |
| `other` | `aderyn/unsafe-erc20-operation` | `src/Lender.sol:82-82` (`Lender.borrow`) |
| `reentrancy` | `slither/reentrancy-events`, `slither/reentrancy-no-eth`, `aderyn/reentrancy-state-change` | `src/Lender.sol:86-93` (`Lender.repay`) |
| `unchecked_call` | `slither/unchecked-transfer`, `aderyn/unchecked-return` | `src/Lender.sol:86-93` (`Lender.repay`) |
| `reentrancy` | `slither/reentrancy-events`, `slither/reentrancy-no-eth`, `aderyn/reentrancy-state-change` | `src/MiniPool.sol:38-48` (`MiniPool.addLiquidity`) |
| `unchecked_call` | `slither/unchecked-transfer`, `aderyn/unchecked-return` | `src/MiniPool.sol:38-48` (`MiniPool.addLiquidity`) |
| `reentrancy` | `slither/reentrancy-events`, `slither/reentrancy-no-eth`, `aderyn/reentrancy-state-change` | `src/MiniPool.sol:52-70` (`MiniPool.swap`) |
| `unchecked_call` | `slither/unchecked-transfer`, `aderyn/unchecked-return` | `src/MiniPool.sol:52-70` (`MiniPool.swap`) |
| `other` | `aderyn/unsafe-erc20-operation` | `src/MiniPool.sol:61-61` (`MiniPool.swap`) |
| `other` | `aderyn/unused-public-function` | `src/MiniPool.sol:80-80` (`MiniPool.spotPrice`) |

### `dos/payout_loop`

Input tree sha256 `b86e7bb8fcc1c3b65e7b7ea302affc6b72554cc23549b30a85d5f2016fa27449`.

| Class | Reported by | Location |
|---|---|---|
| `access_control` | `aderyn/eth-send-unchecked-address` | `src/Crowdfund.sol:67-67` (`Crowdfund.refundAll`) |
| `dos` | `slither/calls-loop`, `aderyn/require-revert-in-loop` | `src/Crowdfund.sol:67-80` (`Crowdfund.refundAll`) |
| `other` | `slither/costly-loop`, `slither/low-level-calls`, `aderyn/costly-loop` | `src/Crowdfund.sol:67-80` (`Crowdfund.refundAll`) |
| `reentrancy` | `slither/reentrancy-eth`, `slither/reentrancy-events`, `aderyn/reentrancy-state-change` | `src/Crowdfund.sol:67-80` (`Crowdfund.refundAll`) |
| `other` | `slither/low-level-calls` | `src/Crowdfund.sol:83-93` (`Crowdfund.claim`) |
| `reentrancy` | `slither/reentrancy-events` | `src/Crowdfund.sol:83-93` (`Crowdfund.claim`) |

### `rounding/share_inflation`

Input tree sha256 `7daed46870e99f2f5945df78a40876d30576adf7728c22d194acc4f795e983ee`.

| Class | Reported by | Location |
|---|---|---|
| `other` | `slither/incorrect-equality` | `src/ShareVault.sol:35-38` (`ShareVault.convertToShares`) |
| `other` | `slither/incorrect-equality` | `src/ShareVault.sol:41-44` (`ShareVault.convertToAssets`) |
| `reentrancy` | `slither/reentrancy-benign`, `slither/reentrancy-events`, `slither/reentrancy-no-eth`, `aderyn/reentrancy-state-change` | `src/ShareVault.sol:47-54` (`ShareVault.deposit`) |
| `unchecked_call` | `slither/unchecked-transfer`, `aderyn/unchecked-return` | `src/ShareVault.sol:47-54` (`ShareVault.deposit`) |
| `reentrancy` | `slither/reentrancy-events` | `src/ShareVault.sol:57-66` (`ShareVault.redeem`) |
| `unchecked_call` | `slither/unchecked-transfer`, `aderyn/unchecked-return` | `src/ShareVault.sol:57-66` (`ShareVault.redeem`) |
| `other` | `aderyn/unsafe-erc20-operation` | `src/ShareVault.sol:64-64` (`ShareVault.redeem`) |

## Run

| Item | Value |
|---|---|
| Assay version | `0.1.0.dev0` |
| Analyzers in the image | aderyn v0.6.8, slither 0.11.6 |
| `versions.lock` sha256 | `9417ef73bae09372ae624eb8e766d87b150c8c105f21fc54f3d57b64ee720d20` |

## Reproduce

```
make image
make static-coverage
```
