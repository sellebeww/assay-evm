// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayPoC} from "assay/AssayExploit.sol";
import {EventForger} from "../src/Target.sol";

/// @notice A contract that the PoC deploys emits the event; it is not the test contract.
contract HelperEventForgeryPoC is AssayPoC {
    EventForger internal forger;

    function setUpTarget() internal override {
        forger = new EventForger();
        declareAttackerBalance(0, 0, 1 ether);
    }

    function exploit() internal override {
        forger.forge();
        attacker_profit("eth", attacker.balance, attacker.balance);
    }
}
