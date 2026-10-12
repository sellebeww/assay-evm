// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayPoC} from "assay/AssayExploit.sol";
import {Target} from "../src/Target.sol";

/// @notice The target prints the harness' console marker; no predicate helper holds.
contract ConsoleForgeryPoC is AssayPoC {
    Target internal target;

    function setUpTarget() internal override {
        target = new Target();
        declareAttackerBalance(0, 0, 1 ether);
    }

    function exploit() internal override {
        target.forgeConsole();
        attacker_profit("eth", attacker.balance, attacker.balance);
    }
}
