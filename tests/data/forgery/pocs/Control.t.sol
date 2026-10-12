// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayPoC} from "assay/AssayExploit.sol";
import {Target} from "../src/Target.sol";

/// @notice Control: a real exploit of `drain`, so that the forgery tests cannot pass because of
///         a broken setup.
contract ControlPoC is AssayPoC {
    Target internal target;

    function setUpTarget() internal override {
        target = new Target{value: 5 ether}();
        declareAttackerBalance(0, 0, 1 ether);
    }

    function exploit() internal override {
        uint256 balanceBefore = attacker.balance;
        vm.prank(attacker);
        target.drain();
        attacker_profit("eth", balanceBefore, attacker.balance);
    }
}
