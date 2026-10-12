// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayExploit} from "assay/AssayExploit.sol";
import {SoftToken} from "../src/SoftToken.sol";
import {DepositPool} from "../src/DepositPool.sol";

/// @notice Ordinary use of the pool. Every test records what an outside observer can see.
contract DepositPoolBenignTest is AssayExploit {
    SoftToken internal token;
    DepositPool internal pool;
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    function setUp() public {
        token = new SoftToken();
        pool = new DepositPool(token);
        token.mint(alice, 1_000e18);
        token.mint(bob, 500e18);
        vm.prank(alice);
        token.approve(address(pool), type(uint256).max);
        vm.prank(bob);
        token.approve(address(pool), 100e18);
    }

    function test_deposit_credits_the_sender() public {
        vm.prank(alice);
        pool.deposit(300e18);

        assertEq(pool.creditOf(alice), 300e18);
        assertEq(pool.totalCredit(), 300e18);
        assertEq(token.balanceOf(address(pool)), 300e18);
        assertEq(token.balanceOf(alice), 700e18);
        recordBehavior("deposit", abi.encode(pool.creditOf(alice), pool.totalCredit(), token.balanceOf(alice)));
    }

    function test_batch_deposit_credits_every_entry() public {
        uint256[] memory amounts = new uint256[](3);
        amounts[0] = 10e18;
        amounts[1] = 20e18;
        amounts[2] = 30e18;
        vm.prank(alice);
        pool.depositMany(amounts);

        assertEq(pool.creditOf(alice), 60e18);
        assertEq(token.balanceOf(address(pool)), 60e18);
        recordBehavior("deposit_many", abi.encode(pool.creditOf(alice), pool.totalCredit(), token.balanceOf(alice)));
    }

    function test_withdraw_returns_the_tokens() public {
        vm.startPrank(alice);
        pool.deposit(400e18);
        pool.withdraw(150e18);
        vm.stopPrank();

        assertEq(pool.creditOf(alice), 250e18);
        assertEq(token.balanceOf(alice), 750e18);
        assertEq(token.balanceOf(address(pool)), 250e18);
        recordBehavior("withdraw", abi.encode(pool.creditOf(alice), token.balanceOf(alice), pool.totalCredit()));
    }

    function test_two_depositors_do_not_affect_each_other() public {
        vm.prank(alice);
        pool.deposit(200e18);
        vm.prank(bob);
        pool.deposit(100e18);
        vm.prank(alice);
        pool.withdraw(200e18);

        assertEq(pool.creditOf(alice), 0);
        assertEq(pool.creditOf(bob), 100e18);
        assertEq(token.balanceOf(address(pool)), 100e18);
        recordBehavior("two_depositors", abi.encode(pool.creditOf(bob), pool.totalCredit(), token.balanceOf(address(pool))));
    }

    function test_withdraw_more_than_credit_reverts() public {
        vm.prank(alice);
        pool.deposit(50e18);

        vm.expectRevert(abi.encodeWithSelector(DepositPool.InsufficientCredit.selector, 60e18, 50e18));
        vm.prank(alice);
        pool.withdraw(60e18);

        vm.expectRevert(DepositPool.ZeroAmount.selector);
        vm.prank(alice);
        pool.withdraw(0);
        recordBehavior("over_withdraw", abi.encode(pool.creditOf(alice), pool.totalCredit()));
    }

    function test_zero_deposits_revert() public {
        vm.expectRevert(DepositPool.ZeroAmount.selector);
        vm.prank(alice);
        pool.deposit(0);

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 5e18;
        vm.expectRevert(DepositPool.ZeroAmount.selector);
        vm.prank(alice);
        pool.depositMany(amounts);
        recordBehavior("zero_deposits", abi.encode(pool.creditOf(alice), pool.totalCredit()));
    }
}
