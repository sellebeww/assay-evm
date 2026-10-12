// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayCheck} from "assay/AssayCheck.sol";
import {Payroll} from "../../src/Payroll.sol";

/// @notice A payee wallet that refuses ether.
contract RefusingWallet {
    receive() external payable {
        revert("locked");
    }
}

/// @notice Symbolic variant properties of the ignored return value: any caller pushes the wage of
///         a payee that refuses ether, through `pay` or through `payMany` after a colleague, for
///         any booked amount; the caller is anyone but the payee itself. The value the payee holds (its booked wage plus its balance) must
///         not shrink.
contract PayrollCheck is AssayCheck {
    Payroll internal payroll;
    RefusingWallet internal victim;
    address internal employer;
    address internal colleague;

    function setUp() public {
        employer = address(uint160(0xE3B10));
        colleague = address(uint160(0xC011E0));
        victim = new RefusingWallet();
        vm.deal(employer, 20 ether);
        vm.startPrank(employer);
        payroll = new Payroll();
        payroll.fund{value: 20 ether}();
        payroll.book(colleague, 1 ether);
        vm.stopPrank();
    }

    /// @dev The attacker is anyone but the victim: a wallet that pushes its own wage while it
    ///      refuses ether only harms itself.
    function _book(address caller, uint256 wage) internal {
        vm.assume(caller != address(victim));
        vm.assume(wage > 0 && wage <= 10 ether);
        vm.prank(employer);
        payroll.book(address(victim), wage);
    }

    function _held() internal view returns (uint256) {
        return payroll.owed(address(victim)) + address(victim).balance;
    }

    /// @notice `pay` to a refusing payee does not clear its wage.
    function check_variant_pay(address caller, uint256 wage) public {
        _book(caller, wage);
        uint256 before = _held();
        assayCall(caller, address(payroll), 0, abi.encodeCall(Payroll.pay, (address(victim))));
        assertNoVictimLoss("eth", before, _held());
    }

    /// @notice `payMany` with the refusing payee, alone or after a colleague, does not clear its
    ///         wage.
    function check_variant_payMany(address caller, uint256 wage, bool withColleague) public {
        _book(caller, wage);
        uint256 before = _held();
        address[] memory payees = new address[](withColleague ? 2 : 1);
        if (withColleague) payees[0] = colleague;
        payees[payees.length - 1] = address(victim);
        assayCall(caller, address(payroll), 0, abi.encodeCall(Payroll.payMany, (payees)));
        assertNoVictimLoss("eth", before, _held());
    }
}
