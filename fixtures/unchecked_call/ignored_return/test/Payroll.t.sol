// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayExploit} from "assay/AssayExploit.sol";
import {Payroll} from "../src/Payroll.sol";

/// @notice A payee that is a contract, like a smart-contract wallet that accepts ether.
contract PayeeWallet {
    receive() external payable {}
}

/// @notice Ordinary use of the payroll. Every test records what an outside observer can see.
contract PayrollBenignTest is AssayExploit {
    Payroll internal payroll;
    address internal employer = makeAddr("employer");
    address internal keeper = makeAddr("keeper");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");

    function setUp() public {
        vm.deal(employer, 20 ether);
        vm.startPrank(employer);
        payroll = new Payroll();
        payroll.fund{value: 10 ether}();
        vm.stopPrank();
    }

    function test_funding_is_held() public {
        vm.expectEmit(address(payroll));
        emit Payroll.Funded(employer, 2 ether);
        vm.prank(employer);
        payroll.fund{value: 2 ether}();

        assertEq(address(payroll).balance, 12 ether);
        recordBehavior("fund", abi.encode(address(payroll).balance, payroll.totalOwed()));
    }

    function test_employer_books_a_wage() public {
        vm.prank(employer);
        payroll.book(alice, 2 ether);

        assertEq(payroll.owed(alice), 2 ether);
        assertEq(payroll.totalOwed(), 2 ether);
        recordBehavior("book", abi.encode(payroll.owed(alice), payroll.totalOwed()));
    }

    function test_keeper_pays_a_payee() public {
        vm.prank(employer);
        payroll.book(alice, 2 ether);

        vm.expectEmit(address(payroll));
        emit Payroll.Paid(alice, 2 ether);
        vm.prank(keeper);
        payroll.pay(alice);

        assertEq(alice.balance, 2 ether);
        assertEq(payroll.owed(alice), 0);
        assertEq(payroll.totalOwed(), 0);
        assertEq(address(payroll).balance, 8 ether);
        recordBehavior("pay", abi.encode(alice.balance, payroll.totalOwed(), address(payroll).balance));
    }

    function test_payday_for_several_payees() public {
        vm.startPrank(employer);
        payroll.book(alice, 1 ether);
        payroll.book(bob, 2 ether);
        vm.stopPrank();

        address[] memory payees = new address[](3);
        payees[0] = alice;
        payees[1] = bob;
        payees[2] = carol;
        vm.prank(keeper);
        payroll.payMany(payees);

        assertEq(alice.balance, 1 ether);
        assertEq(bob.balance, 2 ether);
        assertEq(carol.balance, 0);
        assertEq(payroll.totalOwed(), 0);
        recordBehavior("pay_many", abi.encode(alice.balance, bob.balance, carol.balance, payroll.totalOwed()));
    }

    function test_contract_payee_is_paid() public {
        PayeeWallet wallet = new PayeeWallet();
        vm.prank(employer);
        payroll.book(address(wallet), 1.5 ether);

        vm.prank(keeper);
        payroll.pay(address(wallet));

        assertEq(address(wallet).balance, 1.5 ether);
        assertEq(payroll.owed(address(wallet)), 0);
        recordBehavior("contract_payee", abi.encode(address(wallet).balance, payroll.totalOwed()));
    }

    function test_booking_beyond_the_funds_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(Payroll.Underfunded.selector, 11 ether, 10 ether));
        vm.prank(employer);
        payroll.book(alice, 11 ether);
        recordBehavior("underfunded", abi.encode(payroll.owed(alice), payroll.totalOwed()));
    }

    function test_only_the_employer_books() public {
        vm.expectRevert(abi.encodeWithSelector(Payroll.NotEmployer.selector, keeper));
        vm.prank(keeper);
        payroll.book(keeper, 1 ether);
        recordBehavior("not_employer", abi.encode(payroll.owed(keeper), payroll.totalOwed()));
    }

    function test_paying_without_a_wage_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(Payroll.NothingOwed.selector, bob));
        vm.prank(keeper);
        payroll.pay(bob);
        recordBehavior("nothing_owed", abi.encode(bob.balance, payroll.totalOwed()));
    }
}
