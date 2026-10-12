// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayCheck} from "assay/AssayCheck.sol";
import {FeeCollector} from "../../src/FeeCollector.sol";
import {FeeCollector as BaselineFeeCollector} from "../../baseline/FeeCollector.sol";

/// @notice Bounded equivalence with the vulnerable revision outside the exploit condition: when
///         the owner calls, the revision under test behaves as the vulnerable one for every
///         amount; and fee collection is the same for every payer.
contract FeeCollectorEquivalence is AssayCheck {
    FeeCollector internal underTest;
    BaselineFeeCollector internal baseline;
    address internal owner;
    address internal payee;

    function setUp() public {
        owner = address(uint160(0xA11CE0));
        payee = address(uint160(0xBEEF0));
        underTest = new FeeCollector(owner);
        baseline = new BaselineFeeCollector(owner);
        vm.deal(address(underTest), 20 ether);
        vm.deal(address(baseline), 20 ether);
    }

    function _sameState() internal view {
        assertSame(underTest.owner(), baseline.owner());
        assertSame(underTest.totalCollected(), baseline.totalCollected());
        assertSame(underTest.totalPaidOut(), baseline.totalPaidOut());
        assertSame(address(underTest).balance, address(baseline).balance);
    }

    /// @notice The owner's `payOut`: same success, return data and state, for every amount.
    function check_equiv_ownerPayOut(uint256 amount) public {
        assertSameCall(owner, address(underTest), address(baseline), abi.encodeCall(FeeCollector.payOut, (payable(payee), amount)));
        _sameState();
    }

    /// @notice The owner's `payOutAll`: same success, return data and state.
    function check_equiv_ownerPayOutAll() public {
        assertSameCall(owner, address(underTest), address(baseline), abi.encodeCall(FeeCollector.payOutAll, (payable(payee))));
        _sameState();
    }

    /// @notice The owner's `setOwner`: same success, return data and state, for every new owner.
    function check_equiv_setOwner(address newOwner) public {
        assertSameCall(owner, address(underTest), address(baseline), abi.encodeCall(FeeCollector.setOwner, (newOwner)));
        _sameState();
    }
}
