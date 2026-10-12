// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayExploit} from "assay/AssayExploit.sol";
import {CreditVault} from "../src/CreditVault.sol";

/// @notice A contract that keeps credit in the vault for its owner, like a smart-contract wallet.
contract CreditWallet {
    CreditVault private immutable vault;

    constructor(CreditVault vault_) {
        vault = vault_;
    }

    function deposit() external payable {
        vault.deposit{value: msg.value}();
    }

    function cashOut() external {
        vault.cashOut();
    }

    receive() external payable {}
}

/// @notice Ordinary use of the vault. Every test records what an outside observer can see.
contract CreditVaultBenignTest is AssayExploit {
    CreditVault internal vault;
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");

    function setUp() public {
        vault = new CreditVault();
        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);
        vm.deal(carol, 10 ether);
    }

    function test_deposit_credits_the_sender() public {
        vm.prank(alice);
        vault.deposit{value: 2 ether}();
        vm.prank(bob);
        vault.deposit{value: 3 ether}();

        assertEq(vault.creditOf(alice), 2 ether);
        assertEq(vault.creditOf(bob), 3 ether);
        assertEq(vault.totalCredit(), 5 ether);
        assertEq(address(vault).balance, 5 ether);
        recordBehavior("deposit", abi.encode(vault.creditOf(alice), vault.creditOf(bob), vault.totalCredit()));
    }

    function test_cash_out_pays_all_credit() public {
        vm.prank(alice);
        vault.deposit{value: 4 ether}();
        vm.prank(alice);
        vault.cashOut();

        assertEq(vault.creditOf(alice), 0);
        assertEq(vault.totalCredit(), 0);
        assertEq(alice.balance, 10 ether);
        recordBehavior("cash_out", abi.encode(vault.creditOf(alice), vault.totalCredit(), alice.balance));
    }

    function test_move_credit_in_part() public {
        vm.prank(alice);
        vault.deposit{value: 5 ether}();
        vm.prank(alice);
        vault.moveCredit(bob, 2 ether);

        assertEq(vault.creditOf(alice), 3 ether);
        assertEq(vault.creditOf(bob), 2 ether);
        assertEq(vault.totalCredit(), 5 ether);
        vm.prank(bob);
        vault.cashOut();
        assertEq(bob.balance, 12 ether);
        recordBehavior("move_part", abi.encode(vault.creditOf(alice), vault.creditOf(bob), bob.balance));
    }

    function test_move_all_credit() public {
        vm.prank(alice);
        vault.deposit{value: 3 ether}();
        vm.prank(alice);
        vault.moveAllCredit(carol);

        assertEq(vault.creditOf(alice), 0);
        assertEq(vault.creditOf(carol), 3 ether);
        vm.prank(carol);
        vault.cashOut();
        assertEq(carol.balance, 13 ether);
        assertEq(vault.totalCredit(), 0);
        recordBehavior("move_all", abi.encode(vault.creditOf(alice), vault.creditOf(carol), carol.balance));
    }

    function test_contract_account_can_cash_out() public {
        CreditWallet wallet = new CreditWallet(vault);
        wallet.deposit{value: 2 ether}();
        wallet.cashOut();

        assertEq(vault.creditOf(address(wallet)), 0);
        assertEq(address(wallet).balance, 2 ether);
        recordBehavior("wallet", abi.encode(vault.creditOf(address(wallet)), address(wallet).balance));
    }

    function test_cash_out_leaves_other_credit_alone() public {
        vm.prank(alice);
        vault.deposit{value: 1 ether}();
        vm.prank(bob);
        vault.deposit{value: 6 ether}();
        vm.prank(alice);
        vault.cashOut();

        assertEq(vault.creditOf(bob), 6 ether);
        assertEq(address(vault).balance, 6 ether);
        assertEq(vault.totalCredit(), 6 ether);
        recordBehavior("others_untouched", abi.encode(vault.creditOf(bob), vault.totalCredit()));
    }

    function test_invalid_calls_revert() public {
        vm.prank(alice);
        vault.deposit{value: 1 ether}();

        vm.expectRevert(CreditVault.ZeroAmount.selector);
        vm.prank(alice);
        vault.deposit{value: 0}();

        vm.expectRevert(abi.encodeWithSelector(CreditVault.InsufficientCredit.selector, 2 ether, 1 ether));
        vm.prank(alice);
        vault.moveCredit(bob, 2 ether);

        vm.expectRevert(CreditVault.ZeroAddress.selector);
        vm.prank(alice);
        vault.moveAllCredit(address(0));

        vm.expectRevert(CreditVault.ZeroAmount.selector);
        vm.prank(bob);
        vault.cashOut();
        recordBehavior("invalid", abi.encode(vault.creditOf(alice), vault.totalCredit()));
    }
}
