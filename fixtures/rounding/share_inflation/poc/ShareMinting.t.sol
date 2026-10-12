// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Test} from "forge-std/Test.sol";
import {AssayInvariant} from "assay/AssayInvariant.sol";
import {MockToken} from "../src/MockToken.sol";
import {ShareVault} from "../src/ShareVault.sol";

/// @notice Calls of the invariant campaign: deposits and redemptions of two victims and of an
///         attacker, and direct payments of the attacker into the vault, in any order. Every
///         deposit that mints no shares for a positive amount is remembered.
contract ShareVaultHandler is Test {
    uint256 private constant MAX_DEPOSIT = 10 ether;
    uint256 private constant MAX_DONATION = 10_000 ether;

    MockToken public immutable token;
    ShareVault public immutable vault;
    address private immutable attacker;
    address[2] private victims;

    /// @notice Whether a deposit of a positive amount minted zero shares.
    bool public zeroShareDeposit;

    constructor() {
        token = new MockToken();
        vault = new ShareVault(token);
        attacker = makeAddr("attacker");
        victims = [makeAddr("victim_a"), makeAddr("victim_b")];
        vm.prank(attacker);
        token.approve(address(vault), type(uint256).max);
        for (uint256 i = 0; i < victims.length; i++) {
            vm.prank(victims[i]);
            token.approve(address(vault), type(uint256).max);
        }
    }

    function attackerDeposit(uint256 amount) external {
        _deposit(attacker, bound(amount, 1, MAX_DEPOSIT));
    }

    function attackerDonate(uint256 amount) external {
        amount = bound(amount, 1, MAX_DONATION);
        token.mint(attacker, amount);
        vm.prank(attacker);
        token.transfer(address(vault), amount);
    }

    function attackerRedeem() external {
        _redeemAll(attacker);
    }

    function victimDeposit(uint256 who, uint256 amount) external {
        _deposit(victims[who % victims.length], bound(amount, 1, MAX_DEPOSIT));
    }

    function victimRedeem(uint256 who) external {
        _redeemAll(victims[who % victims.length]);
    }

    function _deposit(address account, uint256 amount) private {
        token.mint(account, amount);
        vm.prank(account);
        try vault.deposit(amount, account) returns (uint256 shares) {
            if (shares == 0) zeroShareDeposit = true;
        } catch {}
    }

    function _redeemAll(address account) private {
        uint256 shares = vault.balanceOf(account);
        if (shares == 0) return;
        vm.prank(account);
        try vault.redeem(shares, account) {} catch {}
    }
}

/// @notice Every deposit of a positive amount mints at least one share. Share inflation breaks
///         it: once a donation makes one share worth more than a deposit, the deposit rounds
///         down to zero shares and its assets go to the existing shareholders.
contract ShareMintingInvariant is AssayInvariant {
    ShareVaultHandler internal handler;

    function setUpInvariant() internal override {
        handler = new ShareVaultHandler();
        targetContract(address(handler));
    }

    function invariantName() internal pure override returns (string memory) {
        return "deposit_mints_shares";
    }

    function invariantHolds() internal view override returns (bool) {
        return !handler.zeroShareDeposit();
    }
}
