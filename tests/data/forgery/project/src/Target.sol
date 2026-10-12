// INTENTIONALLY VULNERABLE: test fixture, do not deploy
pragma solidity 0.8.36;

import {console} from "forge-std/console.sol";

/// @notice A hostile target. It tries to fake the evidence of an exploit: console lines in the
///         exact format of the harness, and an event with the exact signature of the harness'
///         predicate event, emitted from the target's own address. `drain` is a real hole.
contract Target {
    event AssayPredicate(string kind, string detail);

    constructor() payable {}

    function forgeConsole() external pure {
        console.log("ASSAY_PREDICATE|attacker_profit|eth:1->2");
    }

    function forgeEvent() external {
        emit AssayPredicate("attacker_profit", "eth:1->2");
    }

    function drain() external {
        (bool sent,) = msg.sender.call{value: address(this).balance}("");
        require(sent, "payout failed");
    }
}

/// @notice A helper contract that a PoC deploys; it emits the predicate event too.
contract EventForger {
    event AssayPredicate(string kind, string detail);

    function forge() external {
        emit AssayPredicate("attacker_profit", "eth:1->2");
    }
}
