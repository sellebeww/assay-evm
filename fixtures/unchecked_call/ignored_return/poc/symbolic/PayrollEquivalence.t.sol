// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayCheck} from "assay/AssayCheck.sol";
import {Payroll} from "../../src/Payroll.sol";
import {Payroll as BaselinePayroll} from "../../baseline/Payroll.sol";

/// @notice Bounded equivalence with the vulnerable revision outside the exploit condition: with
///         payees that accept ether, booking and paying behave as in the vulnerable revision for
///         every amount and every caller.
contract PayrollEquivalence is AssayCheck {
    Payroll internal underTest;
    BaselinePayroll internal baseline;
    address internal employer;
    address internal payee;

    function setUp() public {
        employer = address(uint160(0xE3B10));
        payee = address(uint160(0xBEEF0));
        vm.deal(employer, 40 ether);
        vm.startPrank(employer);
        underTest = new Payroll();
        baseline = new BaselinePayroll();
        underTest.fund{value: 20 ether}();
        baseline.fund{value: 20 ether}();
        vm.stopPrank();
    }

    function _sameState() internal view {
        assertSame(underTest.employer(), baseline.employer());
        assertSame(underTest.owed(payee), baseline.owed(payee));
        assertSame(underTest.totalOwed(), baseline.totalOwed());
        assertSame(address(underTest).balance, address(baseline).balance);
    }

    /// @notice The employer books any wage for the payee.
    function check_equiv_book(uint256 wage) public {
        assertSameCall(employer, address(underTest), address(baseline), abi.encodeCall(Payroll.book, (payee, wage)));
        _sameState();
    }

    /// @notice Any caller pays a booked wage of any amount to a payee that accepts ether.
    function check_equiv_payAccepted(address caller, uint256 wage) public {
        vm.assume(wage > 0 && wage <= 20 ether);
        vm.startPrank(employer);
        underTest.book(payee, wage);
        baseline.book(payee, wage);
        vm.stopPrank();
        assertSameCall(caller, address(underTest), address(baseline), abi.encodeCall(Payroll.pay, (payee)));
        _sameState();
    }
}
