// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayExploit} from "assay/AssayExploit.sol";
import {Lender} from "../src/Lender.sol";
import {MiniPool} from "../src/MiniPool.sol";
import {MockToken} from "../src/MockToken.sol";

/// @notice Ordinary use of the pool and the lender. Every test records what an outside observer
///         can see.
contract LenderBenignTest is AssayExploit {
    MockToken internal collateral;
    MockToken internal stable;
    MiniPool internal pool;
    Lender internal lender;
    address internal maker = makeAddr("market_maker");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    function setUp() public {
        collateral = new MockToken();
        stable = new MockToken();
        pool = new MiniPool(collateral, stable);

        // The market maker opens the pool at a price of two quote tokens per base token.
        collateral.mint(maker, 2_000 ether);
        stable.mint(maker, 4_000 ether);
        vm.startPrank(maker);
        collateral.approve(address(pool), type(uint256).max);
        stable.approve(address(pool), type(uint256).max);
        pool.addLiquidity(1_000 ether, 2_000 ether);
        vm.stopPrank();

        lender = new Lender(pool);
        stable.mint(address(lender), 10_000 ether);
        collateral.mint(alice, 100 ether);
        stable.mint(bob, 100 ether);
        vm.prank(alice);
        collateral.approve(address(lender), type(uint256).max);
        vm.prank(alice);
        stable.approve(address(lender), type(uint256).max);
        vm.prank(bob);
        stable.approve(address(pool), type(uint256).max);
        vm.prank(bob);
        collateral.approve(address(pool), type(uint256).max);
    }

    function test_collateral_is_valued_at_the_pool_price() public {
        vm.expectEmit(address(lender));
        emit Lender.CollateralDeposited(alice, 50 ether);
        vm.prank(alice);
        lender.depositCollateral(50 ether);

        assertEq(lender.collateralOf(alice), 50 ether);
        assertEq(lender.price(), 2 ether);
        assertEq(lender.collateralValue(alice), 100 ether);
        assertEq(lender.borrowLimit(alice), 75 ether);
        recordBehavior(
            "valuation",
            abi.encode(lender.collateralOf(alice), lender.price(), lender.collateralValue(alice), lender.borrowLimit(alice))
        );
    }

    function test_borrow_within_the_limit() public {
        vm.startPrank(alice);
        lender.depositCollateral(50 ether);
        lender.borrow(60 ether);
        vm.stopPrank();

        assertEq(lender.debtOf(alice), 60 ether);
        assertEq(stable.balanceOf(alice), 60 ether);
        assertEq(stable.balanceOf(address(lender)), 9_940 ether);
        recordBehavior("borrow", abi.encode(lender.debtOf(alice), stable.balanceOf(alice), lender.borrowLimit(alice)));
    }

    function test_borrow_beyond_the_limit_reverts() public {
        vm.startPrank(alice);
        lender.depositCollateral(50 ether);
        vm.expectRevert(abi.encodeWithSelector(Lender.BorrowLimitExceeded.selector, 76 ether, 75 ether));
        lender.borrow(76 ether);
        lender.borrow(75 ether);
        vm.stopPrank();

        assertEq(lender.debtOf(alice), 75 ether);
        recordBehavior("over_borrow", abi.encode(lender.debtOf(alice), stable.balanceOf(alice)));
    }

    function test_repay_and_withdraw_everything() public {
        vm.startPrank(alice);
        lender.depositCollateral(50 ether);
        lender.borrow(60 ether);
        lender.repay(60 ether);
        lender.withdrawCollateral(50 ether);
        vm.stopPrank();

        assertEq(lender.debtOf(alice), 0);
        assertEq(lender.collateralOf(alice), 0);
        assertEq(collateral.balanceOf(alice), 100 ether);
        assertEq(stable.balanceOf(alice), 0);
        assertEq(stable.balanceOf(address(lender)), 10_000 ether);
        recordBehavior(
            "repay_withdraw", abi.encode(collateral.balanceOf(alice), stable.balanceOf(address(lender)))
        );
    }

    function test_withdraw_that_uncovers_the_debt_reverts() public {
        vm.startPrank(alice);
        lender.depositCollateral(50 ether);
        lender.borrow(60 ether);
        vm.expectRevert(abi.encodeWithSelector(Lender.BorrowLimitExceeded.selector, 60 ether, 45 ether));
        lender.withdrawCollateral(20 ether);
        lender.withdrawCollateral(10 ether);
        vm.stopPrank();

        assertEq(lender.collateralOf(alice), 40 ether);
        assertEq(lender.borrowLimit(alice), 60 ether);
        recordBehavior("partial_withdraw", abi.encode(lender.collateralOf(alice), lender.borrowLimit(alice)));
    }

    function test_repay_more_than_owed_reverts() public {
        vm.startPrank(alice);
        lender.depositCollateral(10 ether);
        lender.borrow(5 ether);
        vm.expectRevert(abi.encodeWithSelector(Lender.ExceedsDebt.selector, 6 ether, 5 ether));
        lender.repay(6 ether);
        vm.stopPrank();
        recordBehavior("over_repay", abi.encode(lender.debtOf(alice)));
    }

    function test_swaps_follow_the_curve() public {
        uint256 expectedOut = pool.getAmountOut(20 ether, 2_000 ether, 1_000 ether);
        vm.expectEmit(address(pool));
        emit MiniPool.Swapped(bob, false, 20 ether, expectedOut);
        vm.prank(bob);
        uint256 bought = pool.swap(false, 20 ether, expectedOut);

        assertEq(bought, expectedOut);
        assertEq(collateral.balanceOf(bob), bought);
        assertEq(pool.quoteReserve(), 2_020 ether);
        assertEq(pool.baseReserve(), 1_000 ether - bought);
        assertGt(pool.spotPrice(), 2 ether);

        vm.prank(bob);
        uint256 sold = pool.swap(true, bought, 0);
        assertLt(sold, 20 ether);
        recordBehavior("swaps", abi.encode(bought, sold, pool.baseReserve(), pool.quoteReserve(), pool.spotPrice()));
    }

    function test_slippage_limit_is_enforced() public {
        uint256 expectedOut = pool.getAmountOut(10 ether, 2_000 ether, 1_000 ether);
        vm.expectRevert(abi.encodeWithSelector(MiniPool.Slippage.selector, expectedOut, expectedOut + 1));
        vm.prank(bob);
        pool.swap(false, 10 ether, expectedOut + 1);
        recordBehavior("slippage", abi.encode(pool.baseReserve(), pool.quoteReserve()));
    }

    function test_liquidity_is_added_at_the_current_ratio() public {
        vm.startPrank(maker);
        pool.addLiquidity(100 ether, 200 ether);
        vm.expectRevert(MiniPool.UnbalancedLiquidity.selector);
        pool.addLiquidity(100 ether, 100 ether);
        vm.stopPrank();

        assertEq(pool.baseReserve(), 1_100 ether);
        assertEq(pool.quoteReserve(), 2_200 ether);
        assertEq(pool.spotPrice(), 2 ether);
        recordBehavior("liquidity", abi.encode(pool.baseReserve(), pool.quoteReserve(), pool.spotPrice()));
    }

    function test_zero_amounts_revert() public {
        vm.startPrank(alice);
        vm.expectRevert(Lender.ZeroAmount.selector);
        lender.depositCollateral(0);
        vm.expectRevert(Lender.ZeroAmount.selector);
        lender.borrow(0);
        vm.stopPrank();
        vm.expectRevert(MiniPool.ZeroAmount.selector);
        vm.prank(bob);
        pool.swap(false, 0, 0);
        recordBehavior("zero_amounts", abi.encode(lender.collateralOf(alice), lender.debtOf(alice)));
    }
}
