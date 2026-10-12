// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayCheck} from "assay/AssayCheck.sol";
import {MockToken} from "../../src/MockToken.sol";
import {ShareVault} from "../../src/ShareVault.sol";

/// @notice Symbolic variant property of first-depositor share inflation: the attacker deposits
///         any first amount, donates any amount, the victim deposits 5 tokens, and the attacker
///         redeems all its shares. The ranges are the PoC's knob ranges. Products and quotients
///         of symbolic values make this property hard for the solver.
contract ShareVaultCheck is AssayCheck {
    uint256 private constant VICTIM_DEPOSIT = 5 ether;

    MockToken internal token;
    ShareVault internal vault;
    address internal attacker;
    address internal victim;

    function setUp() public {
        token = new MockToken();
        vault = new ShareVault(token);
        attacker = address(uint160(0xA77AC0));
        victim = address(uint160(0xF1C70));
        token.mint(victim, VICTIM_DEPOSIT);
        vm.prank(victim);
        token.approve(address(vault), type(uint256).max);
        vm.prank(attacker);
        token.approve(address(vault), type(uint256).max);
    }

    /// @notice The attacker ends with no more tokens than it started with.
    function check_variant_inflation(uint256 seed, uint256 donation) public {
        vm.assume(seed >= 1 && seed <= 1e6);
        vm.assume(donation >= 1 && donation <= 10_000 ether);
        token.mint(attacker, seed + donation);
        uint256 before = token.balanceOf(attacker);
        assayCall(attacker, address(vault), 0, abi.encodeCall(ShareVault.deposit, (seed, attacker)));
        assayCall(attacker, address(token), 0, abi.encodeCall(MockToken.transfer, (address(vault), donation)));
        assayCall(victim, address(vault), 0, abi.encodeCall(ShareVault.deposit, (VICTIM_DEPOSIT, victim)));
        assayCall(
            attacker, address(vault), 0, abi.encodeCall(ShareVault.redeem, (vault.balanceOf(attacker), attacker))
        );
        assertNoAttackerProfit("asset", before, token.balanceOf(attacker));
    }
}
