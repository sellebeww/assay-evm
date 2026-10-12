// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayExploit} from "assay/AssayExploit.sol";
import {MockToken} from "../src/MockToken.sol";
import {ShareVault} from "../src/ShareVault.sol";

/// @notice Ordinary use of the vault. Every test records what an outside observer can see.
contract ShareVaultBenignTest is AssayExploit {
    MockToken internal token;
    ShareVault internal vault;
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");

    function setUp() public {
        token = new MockToken();
        vault = new ShareVault(token);
        token.mint(alice, 200 ether);
        token.mint(bob, 200 ether);
        vm.prank(alice);
        token.approve(address(vault), type(uint256).max);
        vm.prank(bob);
        token.approve(address(vault), type(uint256).max);
    }

    function test_first_deposit_mints_one_share_per_asset() public {
        assertEq(vault.convertToShares(100 ether), 100 ether);

        vm.expectEmit(address(vault));
        emit ShareVault.Deposit(alice, alice, 100 ether, 100 ether);
        vm.prank(alice);
        uint256 shares = vault.deposit(100 ether, alice);

        assertEq(shares, 100 ether);
        assertEq(vault.balanceOf(alice), 100 ether);
        assertEq(vault.totalSupply(), 100 ether);
        assertEq(vault.totalAssets(), 100 ether);
        recordBehavior("first_deposit", abi.encode(shares, vault.totalSupply(), vault.totalAssets()));
    }

    function test_second_deposit_at_the_same_price() public {
        vm.prank(alice);
        vault.deposit(100 ether, alice);
        vm.prank(bob);
        uint256 shares = vault.deposit(50 ether, bob);

        assertEq(shares, 50 ether);
        assertEq(vault.convertToAssets(50 ether), 50 ether);
        recordBehavior("second_deposit", abi.encode(shares, vault.totalSupply(), vault.totalAssets()));
    }

    function test_deposit_for_another_receiver() public {
        vm.prank(alice);
        vault.deposit(30 ether, carol);

        assertEq(vault.balanceOf(carol), 30 ether);
        assertEq(vault.balanceOf(alice), 0);
        assertEq(token.balanceOf(alice), 170 ether);
        recordBehavior("deposit_for", abi.encode(vault.balanceOf(carol), token.balanceOf(alice)));
    }

    function test_partial_redemption_returns_assets() public {
        vm.prank(alice);
        vault.deposit(100 ether, alice);

        vm.expectEmit(address(vault));
        emit ShareVault.Withdraw(alice, alice, 40 ether, 40 ether);
        vm.prank(alice);
        uint256 assets = vault.redeem(40 ether, alice);

        assertEq(assets, 40 ether);
        assertEq(vault.balanceOf(alice), 60 ether);
        assertEq(token.balanceOf(alice), 140 ether);
        recordBehavior("partial_redeem", abi.encode(assets, vault.balanceOf(alice), vault.totalAssets()));
    }

    function test_redemption_to_another_receiver() public {
        vm.prank(alice);
        vault.deposit(100 ether, alice);
        vm.prank(alice);
        vault.redeem(100 ether, carol);

        assertEq(token.balanceOf(carol), 100 ether);
        assertEq(vault.totalSupply(), 0);
        assertEq(vault.totalAssets(), 0);
        recordBehavior("redeem_for", abi.encode(token.balanceOf(carol), vault.totalSupply()));
    }

    function test_yield_raises_the_value_of_shares() public {
        vm.prank(alice);
        vault.deposit(100 ether, alice);
        // A strategy pays 10 tokens of yield into the vault.
        token.mint(address(vault), 10 ether);

        vm.prank(bob);
        uint256 bobShares = vault.deposit(7 ether, bob);
        assertLt(bobShares, 7 ether);

        vm.prank(alice);
        uint256 aliceAssets = vault.redeem(100 ether, alice);
        assertGt(aliceAssets, 100 ether);
        assertEq(aliceAssets, 110 ether);
        recordBehavior("yield", abi.encode(bobShares, aliceAssets, vault.totalSupply()));
    }

    function test_redeeming_more_than_held_reverts() public {
        vm.prank(alice);
        vault.deposit(10 ether, alice);

        vm.expectRevert(abi.encodeWithSelector(ShareVault.InsufficientShares.selector, 11 ether, 10 ether));
        vm.prank(alice);
        vault.redeem(11 ether, alice);
        recordBehavior("over_redeem", abi.encode(vault.balanceOf(alice), vault.totalSupply()));
    }

    function test_zero_amounts_revert() public {
        vm.expectRevert(ShareVault.ZeroAmount.selector);
        vm.prank(alice);
        vault.deposit(0, alice);
        vm.expectRevert(ShareVault.ZeroAmount.selector);
        vm.prank(alice);
        vault.redeem(0, alice);
        recordBehavior("zero_amounts", abi.encode(vault.totalSupply(), vault.totalAssets()));
    }
}
