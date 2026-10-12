// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayExploit} from "assay/AssayExploit.sol";
import {Treasury} from "../src/Treasury.sol";

/// @notice Ordinary use of the treasury. Every test records what an outside observer can see.
contract TreasuryBenignTest is AssayExploit {
    Treasury internal treasury;
    address internal admin = makeAddr("admin");
    address internal alice = makeAddr("alice");
    address internal vendor = makeAddr("vendor");

    function setUp() public {
        treasury = new Treasury();
        vm.deal(alice, 10 ether);
    }

    function test_initialize_sets_the_owner() public {
        treasury.initialize(admin);

        assertEq(treasury.owner(), admin);
        assertEq(treasury.feeBps(), 0);
        recordBehavior("initialize", abi.encode(treasury.owner(), treasury.feeBps()));
    }

    function test_initialize_with_fee_sets_owner_and_fee() public {
        treasury.initializeWithFee(admin, 250);

        assertEq(treasury.owner(), admin);
        assertEq(treasury.feeBps(), 250);
        assertEq(treasury.feeFor(10_000), 250);
        recordBehavior("initialize_fee", abi.encode(treasury.owner(), treasury.feeBps(), treasury.feeFor(8_000)));
    }

    function test_funds_are_received_and_swept_by_the_owner() public {
        treasury.initialize(admin);
        vm.prank(alice);
        treasury.fund{value: 4 ether}();

        vm.prank(admin);
        treasury.sweep(payable(vendor), 1.5 ether);

        assertEq(vendor.balance, 1.5 ether);
        assertEq(address(treasury).balance, 2.5 ether);
        assertEq(treasury.totalReceived(), 4 ether);
        recordBehavior("sweep", abi.encode(vendor.balance, address(treasury).balance, treasury.totalReceived()));
    }

    function test_owner_changes_the_fee() public {
        treasury.initializeWithFee(admin, 100);
        vm.prank(admin);
        treasury.setFee(400);

        assertEq(treasury.feeBps(), 400);
        assertEq(treasury.feeFor(5_000), 200);
        recordBehavior("set_fee", abi.encode(treasury.feeBps(), treasury.feeFor(5_000)));
    }

    function test_only_the_owner_can_sweep_or_change_the_fee() public {
        treasury.initialize(admin);
        vm.prank(alice);
        treasury.fund{value: 1 ether}();

        vm.expectRevert(abi.encodeWithSelector(Treasury.NotOwner.selector, alice));
        vm.prank(alice);
        treasury.sweep(payable(alice), 1 ether);

        vm.expectRevert(abi.encodeWithSelector(Treasury.NotOwner.selector, alice));
        vm.prank(alice);
        treasury.setFee(10);
        recordBehavior("not_owner", abi.encode(address(treasury).balance, treasury.feeBps()));
    }

    function test_invalid_arguments_revert() public {
        vm.expectRevert(Treasury.ZeroAddress.selector);
        treasury.initialize(address(0));

        vm.expectRevert(abi.encodeWithSelector(Treasury.FeeTooHigh.selector, uint16(2_000)));
        treasury.initializeWithFee(admin, 2_000);

        treasury.initialize(admin);
        vm.prank(alice);
        treasury.fund{value: 1 ether}();
        vm.expectRevert(abi.encodeWithSelector(Treasury.InsufficientFunds.selector, 2 ether, 1 ether));
        vm.prank(admin);
        treasury.sweep(payable(vendor), 2 ether);

        vm.expectRevert(Treasury.ZeroAmount.selector);
        vm.prank(admin);
        treasury.sweep(payable(vendor), 0);
        recordBehavior("invalid", abi.encode(treasury.owner(), address(treasury).balance));
    }
}
