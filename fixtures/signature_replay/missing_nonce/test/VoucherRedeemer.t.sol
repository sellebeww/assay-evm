// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayExploit} from "assay/AssayExploit.sol";
import {VoucherRedeemer} from "../src/VoucherRedeemer.sol";

/// @notice Ordinary use of the voucher redeemer. Every test records what an outside observer can
///         see. A voucher is always signed right before it is submitted, from the digest the
///         contract reports at that moment.
contract VoucherRedeemerBenignTest is AssayExploit {
    VoucherRedeemer internal redeemer;
    address internal issuer;
    uint256 internal issuerKey;
    address internal sponsor = makeAddr("sponsor");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    function setUp() public {
        (issuer, issuerKey) = makeAddrAndKey("issuer");
        redeemer = new VoucherRedeemer(issuer);
        vm.deal(sponsor, 20 ether);
        vm.prank(sponsor);
        redeemer.fund{value: 10 ether}();
    }

    function sign(uint256 key, address to, uint256 amount) internal view returns (uint8, bytes32, bytes32) {
        return vm.sign(key, redeemer.voucherDigest(to, amount));
    }

    function test_funding_is_held() public {
        vm.expectEmit(address(redeemer));
        emit VoucherRedeemer.Funded(sponsor, 2 ether);
        vm.prank(sponsor);
        redeemer.fund{value: 2 ether}();

        assertEq(address(redeemer).balance, 12 ether);
        recordBehavior("fund", abi.encode(address(redeemer).balance, redeemer.totalRedeemed()));
    }

    function test_recipient_redeems_a_voucher() public {
        (uint8 v, bytes32 r, bytes32 s) = sign(issuerKey, alice, 1 ether);
        vm.prank(alice);
        redeemer.redeem(alice, 1 ether, v, r, s);

        assertEq(alice.balance, 1 ether);
        assertEq(redeemer.totalRedeemed(), 1 ether);
        assertEq(address(redeemer).balance, 9 ether);
        recordBehavior("redeem", abi.encode(alice.balance, redeemer.totalRedeemed()));
    }

    function test_recipient_redeems_two_vouchers_in_turn() public {
        (uint8 v, bytes32 r, bytes32 s) = sign(issuerKey, alice, 1 ether);
        vm.prank(alice);
        redeemer.redeem(alice, 1 ether, v, r, s);

        (v, r, s) = sign(issuerKey, alice, 0.5 ether);
        vm.prank(alice);
        redeemer.redeem(alice, 0.5 ether, v, r, s);

        assertEq(alice.balance, 1.5 ether);
        assertEq(redeemer.totalRedeemed(), 1.5 ether);
        recordBehavior("two_vouchers", abi.encode(alice.balance, redeemer.totalRedeemed()));
    }

    function test_anyone_submits_and_the_recipient_is_paid() public {
        (uint8 v, bytes32 r, bytes32 s) = sign(issuerKey, alice, 2 ether);
        vm.prank(bob);
        redeemer.redeem(alice, 2 ether, v, r, s);

        assertEq(alice.balance, 2 ether);
        assertEq(bob.balance, 0);
        recordBehavior("relayed", abi.encode(alice.balance, bob.balance, redeemer.totalRedeemed()));
    }

    function test_a_changed_amount_is_rejected() public {
        (uint8 v, bytes32 r, bytes32 s) = sign(issuerKey, alice, 1 ether);
        vm.expectRevert(VoucherRedeemer.InvalidSignature.selector);
        vm.prank(alice);
        redeemer.redeem(alice, 2 ether, v, r, s);
        recordBehavior("changed_amount", abi.encode(alice.balance, redeemer.totalRedeemed()));
    }

    function test_a_voucher_signed_by_someone_else_is_rejected() public {
        (, uint256 otherKey) = makeAddrAndKey("other");
        (uint8 v, bytes32 r, bytes32 s) = sign(otherKey, bob, 1 ether);
        vm.expectRevert(VoucherRedeemer.InvalidSignature.selector);
        vm.prank(bob);
        redeemer.redeem(bob, 1 ether, v, r, s);
        recordBehavior("wrong_signer", abi.encode(bob.balance, redeemer.totalRedeemed()));
    }

    function test_a_voucher_beyond_the_funds_reverts() public {
        (uint8 v, bytes32 r, bytes32 s) = sign(issuerKey, alice, 11 ether);
        vm.expectRevert(abi.encodeWithSelector(VoucherRedeemer.InsufficientFunds.selector, 11 ether, 10 ether));
        vm.prank(alice);
        redeemer.redeem(alice, 11 ether, v, r, s);
        recordBehavior("beyond_funds", abi.encode(alice.balance, redeemer.totalRedeemed()));
    }
}
