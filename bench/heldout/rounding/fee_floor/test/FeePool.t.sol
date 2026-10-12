// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayExploit} from "assay/AssayExploit.sol";
import {FeePool} from "../src/FeePool.sol";

/// @notice Ordinary use of the pool. Every test records what an outside observer can see.
contract FeePoolBenignTest is AssayExploit {
    FeePool internal pool;
    address internal treasury = makeAddr("treasury");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    function setUp() public {
        pool = new FeePool(treasury);
        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);
    }

    function test_deposit_credits_the_sender() public {
        vm.prank(alice);
        pool.deposit{value: 4 ether}();
        vm.prank(bob);
        pool.deposit{value: 1 ether}();

        assertEq(pool.balanceOf(alice), 4 ether);
        assertEq(pool.balanceOf(bob), 1 ether);
        assertEq(pool.totalDeposits(), 5 ether);
        recordBehavior("deposit", abi.encode(pool.balanceOf(alice), pool.balanceOf(bob), pool.totalDeposits()));
    }

    function test_withdraw_pays_the_amount_minus_the_fee() public {
        vm.prank(alice);
        pool.deposit{value: 4 ether}();
        vm.prank(alice);
        pool.withdraw(1 ether);

        assertEq(pool.feesAccrued(), 0.003 ether);
        assertEq(alice.balance, 6.997 ether);
        assertEq(pool.balanceOf(alice), 3 ether);
        assertEq(pool.totalDeposits(), 3 ether);
        recordBehavior("withdraw", abi.encode(alice.balance, pool.feesAccrued(), pool.balanceOf(alice)));
    }

    function test_the_fee_is_exact_for_round_amounts() public {
        assertEq(pool.feeOn(1 ether), 0.003 ether);
        assertEq(pool.feeOn(10_000), 30);
        assertEq(pool.feeOn(0.5 ether), 0.0015 ether);
        recordBehavior("fee_on", abi.encode(pool.feeOn(1 ether), pool.feeOn(10_000), pool.feeOn(0.5 ether)));
    }

    function test_fees_are_collected_by_anyone_for_the_treasury() public {
        vm.prank(alice);
        pool.deposit{value: 5 ether}();
        vm.startPrank(alice);
        pool.withdraw(2 ether);
        pool.withdraw(1 ether);
        vm.stopPrank();

        vm.prank(bob);
        pool.collectFees();
        assertEq(treasury.balance, 0.009 ether);
        assertEq(pool.feesAccrued(), 0);
        assertEq(address(pool).balance, 2 ether);
        recordBehavior("collect", abi.encode(treasury.balance, pool.feesAccrued(), address(pool).balance));
    }

    function test_withdrawing_everything_leaves_only_fees() public {
        vm.prank(alice);
        pool.deposit{value: 2 ether}();
        vm.prank(bob);
        pool.deposit{value: 3 ether}();
        vm.prank(alice);
        pool.withdraw(2 ether);
        vm.prank(bob);
        pool.withdraw(3 ether);

        assertEq(pool.totalDeposits(), 0);
        assertEq(address(pool).balance, pool.feesAccrued());
        recordBehavior("everything", abi.encode(alice.balance, bob.balance, pool.feesAccrued()));
    }

    function test_invalid_calls_revert() public {
        vm.expectRevert(FeePool.ZeroAmount.selector);
        vm.prank(alice);
        pool.deposit{value: 0}();

        vm.prank(alice);
        pool.deposit{value: 1 ether}();
        vm.expectRevert(abi.encodeWithSelector(FeePool.InsufficientBalance.selector, 2 ether, 1 ether));
        vm.prank(alice);
        pool.withdraw(2 ether);

        vm.expectRevert(FeePool.ZeroAmount.selector);
        vm.prank(alice);
        pool.withdraw(0);

        vm.expectRevert(FeePool.ZeroAmount.selector);
        pool.collectFees();

        recordBehavior("invalid", abi.encode(pool.balanceOf(alice), pool.totalDeposits()));
        vm.expectRevert(FeePool.ZeroAddress.selector);
        new FeePool(address(0));
    }
}
