// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayExploit} from "assay/AssayExploit.sol";
import {Vault} from "../src/Vault.sol";

/// @notice A contract that holds ether in the vault for its owner, like a smart-contract wallet.
contract VaultUser {
    Vault private immutable vault;

    constructor(Vault vault_) {
        vault = vault_;
    }

    function deposit() external payable {
        vault.deposit{value: msg.value}();
    }

    function withdraw(uint256 amount) external {
        vault.withdraw(amount);
    }

    receive() external payable {}
}

/// @notice Ordinary use of the vault. Every test records what an outside observer can see.
contract VaultBenignTest is AssayExploit {
    Vault internal vault;
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    function setUp() public {
        vault = new Vault();
        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);
    }

    function test_deposit_credits_the_sender() public {
        vm.expectEmit(address(vault));
        emit Vault.Deposited(alice, 2 ether);
        vm.prank(alice);
        vault.deposit{value: 2 ether}();

        assertEq(vault.balanceOf(alice), 2 ether);
        assertEq(vault.totalDeposits(), 2 ether);
        assertEq(address(vault).balance, 2 ether);
        recordBehavior("deposit", abi.encode(vault.balanceOf(alice), vault.totalDeposits(), alice.balance));
    }

    function test_partial_withdraw_returns_ether() public {
        vm.prank(alice);
        vault.deposit{value: 3 ether}();

        vm.expectEmit(address(vault));
        emit Vault.Withdrawn(alice, 1 ether);
        vm.prank(alice);
        vault.withdraw(1 ether);

        assertEq(vault.balanceOf(alice), 2 ether);
        assertEq(vault.totalDeposits(), 2 ether);
        assertEq(alice.balance, 8 ether);
        assertEq(address(vault).balance, 2 ether);
        recordBehavior("partial_withdraw", abi.encode(vault.balanceOf(alice), vault.totalDeposits(), alice.balance));
    }

    function test_two_depositors_withdraw_everything() public {
        vm.prank(alice);
        vault.deposit{value: 4 ether}();
        vm.prank(bob);
        vault.deposit{value: 1 ether}();

        vm.prank(alice);
        vault.withdraw(4 ether);
        assertEq(vault.balanceOf(bob), 1 ether);
        vm.prank(bob);
        vault.withdraw(1 ether);

        assertEq(vault.balanceOf(alice), 0);
        assertEq(vault.balanceOf(bob), 0);
        assertEq(vault.totalDeposits(), 0);
        assertEq(address(vault).balance, 0);
        assertEq(alice.balance, 10 ether);
        assertEq(bob.balance, 10 ether);
        recordBehavior("full_withdraw", abi.encode(alice.balance, bob.balance, vault.totalDeposits()));
    }

    function test_repeated_deposits_and_withdrawals() public {
        vm.startPrank(alice);
        vault.deposit{value: 1 ether}();
        vault.deposit{value: 2 ether}();
        vault.withdraw(0.5 ether);
        vault.deposit{value: 0.25 ether}();
        vault.withdraw(1 ether);
        vm.stopPrank();

        assertEq(vault.balanceOf(alice), 1.75 ether);
        assertEq(alice.balance, 8.25 ether);
        recordBehavior("repeated", abi.encode(vault.balanceOf(alice), vault.totalDeposits(), alice.balance));
    }

    function test_contract_depositor_can_withdraw() public {
        VaultUser user = new VaultUser(vault);
        user.deposit{value: 2 ether}();
        user.withdraw(1.5 ether);

        assertEq(vault.balanceOf(address(user)), 0.5 ether);
        assertEq(address(user).balance, 1.5 ether);
        recordBehavior("contract_user", abi.encode(vault.balanceOf(address(user)), address(user).balance));
    }

    function test_withdraw_more_than_credit_reverts() public {
        vm.prank(alice);
        vault.deposit{value: 1 ether}();

        vm.expectRevert(abi.encodeWithSelector(Vault.InsufficientBalance.selector, 2 ether, 1 ether));
        vm.prank(alice);
        vault.withdraw(2 ether);

        vm.expectRevert(abi.encodeWithSelector(Vault.InsufficientBalance.selector, 1 ether, 0));
        vm.prank(bob);
        vault.withdraw(1 ether);
        recordBehavior("over_withdraw", abi.encode(vault.balanceOf(alice), vault.totalDeposits()));
    }

    function test_zero_amounts_revert() public {
        vm.expectRevert(Vault.ZeroAmount.selector);
        vm.prank(alice);
        vault.deposit{value: 0}();

        vm.prank(alice);
        vault.deposit{value: 1 ether}();
        vm.expectRevert(Vault.ZeroAmount.selector);
        vm.prank(alice);
        vault.withdraw(0);
        recordBehavior("zero_amounts", abi.encode(vault.balanceOf(alice), vault.totalDeposits()));
    }
}
