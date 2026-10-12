// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayExploit} from "assay/AssayExploit.sol";
import {Crowdfund} from "../src/Crowdfund.sol";

/// @notice A contributor that is a contract, like a smart-contract wallet that accepts ether.
contract ContributorWallet {
    function contribute(Crowdfund campaign) external payable {
        campaign.contribute{value: msg.value}();
    }

    receive() external payable {}
}

/// @notice Ordinary use of the crowdfund. Every test records what an outside observer can see.
contract CrowdfundBenignTest is AssayExploit {
    Crowdfund internal campaign;
    address internal organizer = makeAddr("organizer");
    address internal keeper = makeAddr("keeper");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");

    function setUp() public {
        vm.prank(organizer);
        campaign = new Crowdfund(10 ether);
        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);
        vm.deal(carol, 10 ether);
    }

    function test_contributions_are_recorded() public {
        vm.expectEmit(address(campaign));
        emit Crowdfund.Contributed(alice, 1 ether);
        vm.prank(alice);
        campaign.contribute{value: 1 ether}();
        vm.prank(bob);
        campaign.contribute{value: 2 ether}();

        assertEq(campaign.contributionOf(alice), 1 ether);
        assertEq(campaign.contributionOf(bob), 2 ether);
        assertEq(campaign.totalRaised(), 3 ether);
        assertEq(campaign.contributorCount(), 2);
        assertEq(address(campaign).balance, 3 ether);
        recordBehavior("contribute", abi.encode(campaign.totalRaised(), campaign.contributorCount()));
    }

    function test_repeat_contributions_list_the_account_once() public {
        vm.startPrank(alice);
        campaign.contribute{value: 1 ether}();
        campaign.contribute{value: 0.5 ether}();
        vm.stopPrank();

        assertEq(campaign.contributionOf(alice), 1.5 ether);
        assertEq(campaign.contributorCount(), 1);
        assertEq(campaign.contributors(0), alice);
        recordBehavior("repeat", abi.encode(campaign.contributionOf(alice), campaign.contributorCount()));
    }

    function test_keeper_refunds_everyone_after_a_cancel() public {
        vm.prank(alice);
        campaign.contribute{value: 1 ether}();
        vm.prank(bob);
        campaign.contribute{value: 2 ether}();
        vm.prank(carol);
        campaign.contribute{value: 3 ether}();

        vm.expectEmit(address(campaign));
        emit Crowdfund.Cancelled();
        vm.prank(organizer);
        campaign.cancel();
        vm.expectEmit(address(campaign));
        emit Crowdfund.Refunded(alice, 1 ether);
        vm.prank(keeper);
        campaign.refundAll();

        assertEq(alice.balance, 10 ether);
        assertEq(bob.balance, 10 ether);
        assertEq(carol.balance, 10 ether);
        assertEq(campaign.totalRaised(), 0);
        assertEq(address(campaign).balance, 0);
        recordBehavior("refund_all", abi.encode(alice.balance, bob.balance, carol.balance, campaign.totalRaised()));
    }

    function test_contract_wallet_is_refunded() public {
        ContributorWallet wallet = new ContributorWallet();
        wallet.contribute{value: 1.5 ether}(campaign);
        vm.prank(alice);
        campaign.contribute{value: 1 ether}();

        vm.prank(organizer);
        campaign.cancel();
        vm.prank(keeper);
        campaign.refundAll();

        assertEq(address(wallet).balance, 1.5 ether);
        assertEq(campaign.contributionOf(address(wallet)), 0);
        assertEq(alice.balance, 10 ether);
        recordBehavior("contract_refund", abi.encode(address(wallet).balance, alice.balance, campaign.totalRaised()));
    }

    function test_a_second_refund_run_pays_nothing_twice() public {
        vm.prank(alice);
        campaign.contribute{value: 1 ether}();
        vm.prank(organizer);
        campaign.cancel();

        vm.startPrank(keeper);
        campaign.refundAll();
        campaign.refundAll();
        vm.stopPrank();

        assertEq(alice.balance, 10 ether);
        assertEq(address(campaign).balance, 0);
        recordBehavior("refund_twice", abi.encode(alice.balance, campaign.totalRaised()));
    }

    function test_organizer_claims_once_the_goal_is_reached() public {
        vm.prank(alice);
        campaign.contribute{value: 4 ether}();
        vm.prank(bob);
        campaign.contribute{value: 6 ether}();

        vm.expectEmit(address(campaign));
        emit Crowdfund.Claimed(10 ether);
        vm.prank(organizer);
        campaign.claim();

        assertEq(organizer.balance, 10 ether);
        assertTrue(campaign.claimed());
        assertEq(campaign.totalRaised(), 0);
        recordBehavior("claim", abi.encode(organizer.balance, campaign.totalRaised(), campaign.claimed()));
    }

    function test_claim_before_the_goal_reverts() public {
        vm.prank(alice);
        campaign.contribute{value: 4 ether}();

        vm.expectRevert(abi.encodeWithSelector(Crowdfund.GoalNotReached.selector, 4 ether, 10 ether));
        vm.prank(organizer);
        campaign.claim();
        recordBehavior("early_claim", abi.encode(campaign.totalRaised(), organizer.balance));
    }

    function test_refund_before_a_cancel_reverts() public {
        vm.prank(alice);
        campaign.contribute{value: 1 ether}();

        vm.expectRevert(Crowdfund.NotCancelled.selector);
        vm.prank(keeper);
        campaign.refundAll();
        recordBehavior("early_refund", abi.encode(campaign.contributionOf(alice), alice.balance));
    }

    function test_only_the_organizer_cancels_or_claims() public {
        vm.expectRevert(abi.encodeWithSelector(Crowdfund.NotOrganizer.selector, keeper));
        vm.prank(keeper);
        campaign.cancel();
        vm.expectRevert(abi.encodeWithSelector(Crowdfund.NotOrganizer.selector, keeper));
        vm.prank(keeper);
        campaign.claim();
        recordBehavior("not_organizer", abi.encode(campaign.cancelled(), campaign.claimed()));
    }

    function test_a_cancelled_campaign_is_closed() public {
        vm.prank(organizer);
        campaign.cancel();

        vm.expectRevert(Crowdfund.CampaignClosed.selector);
        vm.prank(alice);
        campaign.contribute{value: 1 ether}();
        vm.expectRevert(Crowdfund.CampaignClosed.selector);
        vm.prank(organizer);
        campaign.cancel();
        recordBehavior("closed", abi.encode(campaign.totalRaised(), campaign.contributorCount()));
    }

    function test_zero_contribution_reverts() public {
        vm.expectRevert(Crowdfund.ZeroAmount.selector);
        vm.prank(alice);
        campaign.contribute{value: 0}();
        recordBehavior("zero", abi.encode(campaign.totalRaised(), campaign.contributorCount()));
    }
}
