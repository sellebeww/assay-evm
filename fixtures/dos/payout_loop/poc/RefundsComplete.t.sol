// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Test} from "forge-std/Test.sol";
import {AssayInvariant} from "assay/AssayInvariant.sol";
import {Crowdfund} from "../src/Crowdfund.sol";

/// @notice A contributor contract of the attacker that refuses every refund, by reverting or by
///         burning all the gas that the refund call forwards.
contract RefusingContributor {
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

/// @notice Calls of the invariant campaign: contributions of honest accounts, refusing
///         contributors of the attacker, the organizer's cancellation, and a keeper's refund run
///         with an ordinary gas limit, in any order.
contract CrowdfundHandler is Test {
    uint256 private constant KEEPER_GAS_LIMIT = 500_000;
    uint256 private constant MAX_REFUSERS = 2;

    Crowdfund public immutable campaign;
    address private immutable organizer;
    address[5] private honest;
    uint256 private refusers;

    /// @notice Whether a refund run took place after the cancellation.
    bool public refundRan;

    constructor() {
        organizer = makeAddr("organizer");
        vm.prank(organizer);
        campaign = new Crowdfund(100 ether);
        honest = [
            makeAddr("alice"),
            makeAddr("bob"),
            makeAddr("carol"),
            makeAddr("dave"),
            makeAddr("erin")
        ];
        for (uint256 i = 0; i < honest.length; i++) {
            vm.deal(honest[i], 10 ether);
        }
    }

    function contribute(uint256 who, uint256 amount) external {
        if (campaign.cancelled()) return;
        address account = honest[who % honest.length];
        amount = bound(amount, 0.1 ether, 2 ether);
        if (account.balance < amount) return;
        vm.prank(account);
        campaign.contribute{value: amount}();
    }

    function joinRefuser(uint256 burnGas, uint256 amount) external {
        if (campaign.cancelled() || refusers >= MAX_REFUSERS) return;
        amount = bound(amount, 0.001 ether, 1 ether);
        vm.deal(address(this), amount);
        new RefusingContributor{value: amount}(campaign, burnGas % 2 == 1);
        refusers += 1;
    }

    function cancel() external {
        if (campaign.cancelled()) return;
        vm.prank(organizer);
        campaign.cancel();
    }

    function refund() external {
        if (!campaign.cancelled()) return;
        vm.prank(makeAddr("keeper"));
        try campaign.refundAll{gas: KEEPER_GAS_LIMIT}() {} catch {}
        refundRan = true;
    }

    /// @notice Whether every honest account has its contribution back.
    function honestRefunded() external view returns (bool) {
        for (uint256 i = 0; i < honest.length; i++) {
            if (campaign.contributionOf(honest[i]) != 0) return false;
        }
        return true;
    }
}

/// @notice After a refund run, every honest contributor has its contribution back. A payout loop
///         that one refusing contributor can stop breaks it.
contract RefundsCompleteInvariant is AssayInvariant {
    CrowdfundHandler internal handler;

    function setUpInvariant() internal override {
        handler = new CrowdfundHandler();
        targetContract(address(handler));
    }

    function invariantName() internal pure override returns (string memory) {
        return "refunds_complete";
    }

    function invariantHolds() internal view override returns (bool) {
        return !handler.refundRan() || handler.honestRefunded();
    }
}
