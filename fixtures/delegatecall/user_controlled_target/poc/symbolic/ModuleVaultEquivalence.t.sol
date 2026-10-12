// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayCheck} from "assay/AssayCheck.sol";
import {ModuleVault} from "../../src/ModuleVault.sol";
import {ModuleVault as BaselineModuleVault} from "../../baseline/ModuleVault.sol";
import {SweepModule} from "../../src/SweepModule.sol";

/// @notice Bounded equivalence with the vulnerable revision outside the exploit condition: with
///         the approved module only, upkeep behaves as in the vulnerable revision, whoever calls;
///         the owner's withdrawals behave the same for every amount.
contract ModuleVaultEquivalence is AssayCheck {
    ModuleVault internal underTest;
    BaselineModuleVault internal baseline;
    SweepModule internal sweeper;
    address internal owner;

    function setUp() public {
        owner = address(uint160(0xA11CE0));
        sweeper = new SweepModule(address(uint160(0xC01D50)), 5 ether);
        vm.startPrank(owner);
        underTest = new ModuleVault();
        baseline = new BaselineModuleVault();
        underTest.setModuleApproval(address(sweeper), true);
        baseline.setModuleApproval(address(sweeper), true);
        vm.stopPrank();
        vm.deal(address(underTest), 15 ether);
        vm.deal(address(baseline), 15 ether);
    }

    function _sameState() internal view {
        assertSame(underTest.owner(), baseline.owner());
        assertSame(underTest.upkeepRuns(), baseline.upkeepRuns());
        assertSame(underTest.approvedModule(address(sweeper)), baseline.approvedModule(address(sweeper)));
        assertSame(address(underTest).balance, address(baseline).balance);
    }

    /// @notice Upkeep with the approved sweep module, by any keeper.
    function check_equiv_approvedUpkeep(address keeper) public {
        bytes memory data = abi.encodeCall(SweepModule.sweep, ());
        assertSameCall(keeper, address(underTest), address(baseline), abi.encodeCall(ModuleVault.runUpkeep, (address(sweeper), data)));
        _sameState();
    }

    /// @notice The owner's withdrawal of any amount.
    function check_equiv_ownerWithdraw(uint256 amount) public {
        address payable to = payable(address(uint160(0xAEC10)));
        assertSameCall(owner, address(underTest), address(baseline), abi.encodeCall(ModuleVault.withdraw, (to, amount)));
        _sameState();
    }
}
