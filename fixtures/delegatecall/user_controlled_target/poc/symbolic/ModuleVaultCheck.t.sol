// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayCheck} from "assay/AssayCheck.sol";
import {ModuleVault} from "../../src/ModuleVault.sol";
import {SweepModule} from "../../src/SweepModule.sol";

/// @notice A module whose first storage variable lines up with the vault's owner slot.
contract SlotZeroWriter {
    address private slot0;

    function write(address value) external {
        slot0 = value;
    }
}

/// @notice Symbolic variant properties of the caller-chosen delegatecall target: any caller other
///         than the owner, any new owner value, through either entry point, with or without an
///         ordinary sweep before it in a batch. The state is the PoC's: an owner, 15 ether, and
///         one approved sweep module.
contract ModuleVaultCheck is AssayCheck {
    ModuleVault internal vault;
    SweepModule internal sweeper;
    SlotZeroWriter internal writer;
    address internal owner;

    function setUp() public {
        owner = address(uint160(0xA11CE0));
        vm.deal(owner, 20 ether);
        vm.startPrank(owner);
        vault = new ModuleVault();
        (bool sent,) = address(vault).call{value: 15 ether}("");
        require(sent, "deposit failed");
        sweeper = new SweepModule(address(uint160(0xC01D50)), 5 ether);
        vault.setModuleApproval(address(sweeper), true);
        vm.stopPrank();
        writer = new SlotZeroWriter();
    }

    /// @notice `runUpkeep` with an unapproved module does not change the owner.
    function check_variant_runUpkeep(address caller, address newOwner) public {
        vm.assume(caller != owner);
        bytes memory data = abi.encodeCall(SlotZeroWriter.write, (newOwner));
        assayCall(caller, address(vault), 0, abi.encodeCall(ModuleVault.runUpkeep, (address(writer), data)));
        assertNoUnauthorizedRoleChange("owner", owner, vault.owner());
    }

    /// @notice `runUpkeepBatch` with an unapproved module, alone or after one sweep, does not
    ///         change the owner.
    function check_variant_runUpkeepBatch(address caller, address newOwner, bool cover) public {
        vm.assume(caller != owner);
        uint256 size = cover ? 2 : 1;
        address[] memory modules = new address[](size);
        bytes[] memory data = new bytes[](size);
        if (cover) {
            modules[0] = address(sweeper);
            data[0] = abi.encodeCall(SweepModule.sweep, ());
        }
        modules[size - 1] = address(writer);
        data[size - 1] = abi.encodeCall(SlotZeroWriter.write, (newOwner));
        assayCall(caller, address(vault), 0, abi.encodeCall(ModuleVault.runUpkeepBatch, (modules, data)));
        assertNoUnauthorizedRoleChange("owner", owner, vault.owner());
    }
}
