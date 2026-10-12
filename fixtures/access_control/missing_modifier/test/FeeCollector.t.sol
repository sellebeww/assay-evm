// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayExploit} from "assay/AssayExploit.sol";
import {FeeCollector} from "../src/FeeCollector.sol";

/// @notice Ordinary use of the fee collector. Every test records what an outside observer can see.
contract FeeCollectorBenignTest is AssayExploit {
    FeeCollector internal collector;
    address internal owner = makeAddr("owner");
    address internal payer = makeAddr("payer");
    address internal supplier = makeAddr("supplier");
    address internal treasury = makeAddr("treasury");

    function setUp() public {
        collector = new FeeCollector(owner);
        vm.deal(payer, 10 ether);
    }

    function test_fees_are_collected() public {
        vm.expectEmit(address(collector));
        emit FeeCollector.Collected(payer, 2 ether);
        vm.prank(payer);
        collector.collect{value: 2 ether}();

        assertEq(collector.totalCollected(), 2 ether);
        assertEq(address(collector).balance, 2 ether);
        recordBehavior("collect", abi.encode(collector.totalCollected(), address(collector).balance));
    }

    function test_owner_pays_a_supplier() public {
        vm.prank(payer);
        collector.collect{value: 5 ether}();

        vm.expectEmit(address(collector));
        emit FeeCollector.PaidOut(supplier, 2 ether);
        vm.prank(owner);
        collector.payOut(payable(supplier), 2 ether);

        assertEq(supplier.balance, 2 ether);
        assertEq(collector.totalPaidOut(), 2 ether);
        assertEq(address(collector).balance, 3 ether);
        recordBehavior("pay_supplier", abi.encode(supplier.balance, collector.totalPaidOut()));
    }

    function test_owner_pays_out_everything() public {
        vm.prank(payer);
        collector.collect{value: 4 ether}();

        vm.prank(owner);
        collector.payOutAll(payable(treasury));

        assertEq(treasury.balance, 4 ether);
        assertEq(address(collector).balance, 0);
        assertEq(collector.totalPaidOut(), 4 ether);
        recordBehavior("pay_all", abi.encode(treasury.balance, collector.totalPaidOut()));
    }

    function test_new_owner_takes_over_payouts() public {
        address successor = makeAddr("successor");
        vm.prank(payer);
        collector.collect{value: 3 ether}();

        vm.prank(owner);
        collector.setOwner(successor);
        assertEq(collector.owner(), successor);

        vm.prank(successor);
        collector.payOut(payable(supplier), 1 ether);
        assertEq(supplier.balance, 1 ether);
        recordBehavior("handover", abi.encode(collector.owner(), supplier.balance));
    }

    function test_only_the_owner_changes_the_owner() public {
        vm.expectRevert(abi.encodeWithSignature("NotOwner(address)", payer));
        vm.prank(payer);
        collector.setOwner(payer);

        assertEq(collector.owner(), owner);
        recordBehavior("owner_kept", abi.encode(collector.owner()));
    }

    function test_payout_beyond_the_balance_reverts() public {
        vm.prank(payer);
        collector.collect{value: 1 ether}();

        vm.expectRevert(abi.encodeWithSelector(FeeCollector.InsufficientFunds.selector, 2 ether, 1 ether));
        vm.prank(owner);
        collector.payOut(payable(supplier), 2 ether);
        recordBehavior("over_payout", abi.encode(address(collector).balance, collector.totalPaidOut()));
    }

    function test_zero_amounts_revert() public {
        vm.expectRevert(FeeCollector.ZeroAmount.selector);
        vm.prank(payer);
        collector.collect{value: 0}();

        vm.expectRevert(FeeCollector.ZeroAmount.selector);
        vm.prank(owner);
        collector.payOutAll(payable(treasury));
        recordBehavior("zero_amounts", abi.encode(collector.totalCollected(), collector.totalPaidOut()));
    }
}
