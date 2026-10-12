// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayExploit} from "assay/AssayExploit.sol";
import {ModuleVault} from "../src/ModuleVault.sol";
import {SweepModule} from "../src/SweepModule.sol";

/// @notice Ordinary use of the vault and its sweep module. Every test records what an outside
///         observer can see.
contract ModuleVaultBenignTest is AssayExploit {
    ModuleVault internal vault;
    SweepModule internal sweeper;
    address internal owner = makeAddr("owner");
    address internal keeper = makeAddr("keeper");
    address internal coldStorage = makeAddr("cold_storage");

    function setUp() public {
        vm.deal(owner, 20 ether);
        vm.startPrank(owner);
        vault = new ModuleVault();
        (bool sent,) = address(vault).call{value: 10 ether}("");
        require(sent, "deposit failed");
        sweeper = new SweepModule(coldStorage, 4 ether);
        vault.setModuleApproval(address(sweeper), true);
        vm.stopPrank();
    }

    function test_ether_is_held() public {
        vm.prank(owner);
        (bool sent,) = address(vault).call{value: 2 ether}("");
        assertTrue(sent);

        assertEq(address(vault).balance, 12 ether);
        recordBehavior("deposit", abi.encode(address(vault).balance, vault.owner()));
    }

    function test_owner_approves_and_revokes_modules() public {
        address other = makeAddr("other_module");
        vm.startPrank(owner);
        vault.setModuleApproval(other, true);
        vault.setModuleApproval(other, false);
        vm.stopPrank();

        assertTrue(vault.approvedModule(address(sweeper)));
        assertFalse(vault.approvedModule(other));
        recordBehavior("approval", abi.encode(vault.approvedModule(address(sweeper)), vault.approvedModule(other)));
    }

    function test_keeper_runs_an_approved_sweep() public {
        vm.expectEmit(address(vault));
        emit ModuleVault.UpkeepRun(address(sweeper), keeper);
        vm.prank(keeper);
        vault.runUpkeep(address(sweeper), abi.encodeCall(SweepModule.sweep, ()));

        assertEq(coldStorage.balance, 6 ether);
        assertEq(address(vault).balance, 4 ether);
        assertEq(vault.upkeepRuns(), 1);
        recordBehavior("sweep", abi.encode(coldStorage.balance, address(vault).balance, vault.upkeepRuns()));
    }

    function test_keeper_runs_a_batch() public {
        address[] memory modules = new address[](2);
        bytes[] memory data = new bytes[](2);
        for (uint256 i = 0; i < 2; i++) {
            modules[i] = address(sweeper);
            data[i] = abi.encodeCall(SweepModule.sweep, ());
        }
        vm.prank(keeper);
        vault.runUpkeepBatch(modules, data);

        assertEq(coldStorage.balance, 6 ether);
        assertEq(vault.upkeepRuns(), 2);
        recordBehavior("batch", abi.encode(coldStorage.balance, address(vault).balance, vault.upkeepRuns()));
    }

    function test_owner_withdraws() public {
        address payable recipient = payable(makeAddr("recipient"));
        vm.prank(owner);
        vault.withdraw(recipient, 3 ether);

        assertEq(recipient.balance, 3 ether);
        assertEq(address(vault).balance, 7 ether);
        recordBehavior("withdraw", abi.encode(recipient.balance, address(vault).balance));
    }

    function test_only_the_owner_approves_and_withdraws() public {
        vm.expectRevert(abi.encodeWithSelector(ModuleVault.NotOwner.selector, keeper));
        vm.prank(keeper);
        vault.setModuleApproval(keeper, true);

        vm.expectRevert(abi.encodeWithSelector(ModuleVault.NotOwner.selector, keeper));
        vm.prank(keeper);
        vault.withdraw(payable(keeper), 1 ether);
        recordBehavior("not_owner", abi.encode(vault.owner(), address(vault).balance));
    }

    function test_batch_lengths_must_match() public {
        address[] memory modules = new address[](2);
        bytes[] memory data = new bytes[](1);
        vm.expectRevert(ModuleVault.LengthMismatch.selector);
        vm.prank(keeper);
        vault.runUpkeepBatch(modules, data);
        recordBehavior("length_mismatch", abi.encode(vault.upkeepRuns()));
    }
}
