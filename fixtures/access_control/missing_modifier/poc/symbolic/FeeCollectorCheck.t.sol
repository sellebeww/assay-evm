// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayCheck} from "assay/AssayCheck.sol";
import {FeeCollector} from "../../src/FeeCollector.sol";

/// @notice Symbolic variant properties of the missing permission check: any caller other than the
///         owner, any amount, paid to an account the caller names. The state is the PoC's: an
///         owner and 20 ether of collected fees.
contract FeeCollectorCheck is AssayCheck {
    FeeCollector internal collector;
    address internal owner;
    address internal payee;

    function setUp() public {
        owner = address(uint160(0xA11CE0));
        payee = address(uint160(0xBEEF0));
        collector = new FeeCollector(owner);
        address payer = address(uint160(0xBA7E50));
        vm.deal(payer, 20 ether);
        vm.prank(payer);
        collector.collect{value: 20 ether}();
    }

    /// @notice `payOut` by anyone but the owner pays nothing to the payee.
    function check_variant_payOut(address caller, uint256 amount) public {
        vm.assume(caller != owner);
        uint256 before = payee.balance;
        assayCall(caller, address(collector), 0, abi.encodeCall(FeeCollector.payOut, (payable(payee), amount)));
        assertNoAttackerProfit("eth", before, payee.balance);
    }

    /// @notice `payOutAll` by anyone but the owner pays nothing to the payee.
    function check_variant_payOutAll(address caller) public {
        vm.assume(caller != owner);
        uint256 before = payee.balance;
        assayCall(caller, address(collector), 0, abi.encodeCall(FeeCollector.payOutAll, (payable(payee))));
        assertNoAttackerProfit("eth", before, payee.balance);
    }
}
