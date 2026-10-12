// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayExploit} from "assay/AssayExploit.sol";
import {ClaimDesk} from "../src/ClaimDesk.sol";

/// @notice Ordinary use of the desk. Every test records what an outside observer can see.
contract ClaimDeskBenignTest is AssayExploit {
    uint256 internal constant ISSUER_KEY = 0x155EED;

    ClaimDesk internal desk;
    address internal issuer;
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    function setUp() public {
        issuer = vm.addr(ISSUER_KEY);
        desk = new ClaimDesk(issuer);
    }

    function _sign(address to, uint256 amount, uint256 nonce, uint256 key)
        internal
        view
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        return vm.sign(key, desk.claimDigest(to, amount, nonce));
    }

    function test_a_signed_claim_pays_the_recipient() public {
        vm.deal(address(this), 10 ether);
        desk.fund{value: 10 ether}();

        (uint8 v, bytes32 r, bytes32 s) = _sign(alice, 3 ether, 1, ISSUER_KEY);
        vm.prank(bob);
        desk.claim(alice, 3 ether, 1, v, r, s);

        assertEq(alice.balance, 3 ether);
        assertEq(desk.totalClaimed(), 3 ether);
        assertTrue(desk.used(1));
        recordBehavior("claim", abi.encode(alice.balance, desk.totalClaimed(), address(desk).balance));
    }

    function test_two_nonces_pay_twice() public {
        vm.deal(address(this), 10 ether);
        desk.fund{value: 10 ether}();

        (uint8 v1, bytes32 r1, bytes32 s1) = _sign(alice, 1 ether, 1, ISSUER_KEY);
        (uint8 v2, bytes32 r2, bytes32 s2) = _sign(alice, 1 ether, 2, ISSUER_KEY);
        desk.claim(alice, 1 ether, 1, v1, r1, s1);
        desk.claim(alice, 1 ether, 2, v2, r2, s2);

        assertEq(alice.balance, 2 ether);
        assertEq(desk.totalClaimed(), 2 ether);
        recordBehavior("two_claims", abi.encode(alice.balance, desk.totalClaimed()));
    }

    function test_a_nonce_pays_only_once() public {
        vm.deal(address(this), 10 ether);
        desk.fund{value: 10 ether}();

        (uint8 v, bytes32 r, bytes32 s) = _sign(alice, 1 ether, 5, ISSUER_KEY);
        desk.claim(alice, 1 ether, 5, v, r, s);

        vm.expectRevert(abi.encodeWithSelector(ClaimDesk.NonceUsed.selector, 5));
        desk.claim(alice, 1 ether, 5, v, r, s);
        recordBehavior("nonce_reuse", abi.encode(alice.balance, desk.totalClaimed()));
    }

    function test_a_claim_signed_by_someone_else_is_rejected() public {
        vm.deal(address(this), 10 ether);
        desk.fund{value: 10 ether}();

        (uint8 v, bytes32 r, bytes32 s) = _sign(alice, 1 ether, 1, 0xBAD);
        vm.expectRevert(ClaimDesk.InvalidSignature.selector);
        desk.claim(alice, 1 ether, 1, v, r, s);

        (v, r, s) = _sign(alice, 1 ether, 1, ISSUER_KEY);
        vm.expectRevert(ClaimDesk.InvalidSignature.selector);
        desk.claim(bob, 1 ether, 1, v, r, s);
        recordBehavior("bad_signature", abi.encode(alice.balance, desk.totalClaimed()));
    }

    function test_a_claim_larger_than_the_balance_reverts() public {
        vm.deal(address(this), 1 ether);
        desk.fund{value: 1 ether}();

        (uint8 v, bytes32 r, bytes32 s) = _sign(alice, 2 ether, 1, ISSUER_KEY);
        vm.expectRevert(abi.encodeWithSelector(ClaimDesk.InsufficientFunds.selector, 2 ether, 1 ether));
        desk.claim(alice, 2 ether, 1, v, r, s);
        recordBehavior("insufficient", abi.encode(address(desk).balance, desk.totalClaimed()));
    }

    function test_zero_arguments_revert() public {
        vm.expectRevert(ClaimDesk.ZeroAmount.selector);
        desk.fund{value: 0}();

        (uint8 v, bytes32 r, bytes32 s) = _sign(alice, 0, 1, ISSUER_KEY);
        vm.expectRevert(ClaimDesk.ZeroAmount.selector);
        desk.claim(alice, 0, 1, v, r, s);

        vm.expectRevert(ClaimDesk.ZeroAddress.selector);
        desk.claim(address(0), 1 ether, 1, v, r, s);
        recordBehavior("zero_arguments", abi.encode(desk.totalClaimed()));
    }
}
