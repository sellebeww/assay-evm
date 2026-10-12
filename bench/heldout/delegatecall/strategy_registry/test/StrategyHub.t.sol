// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayExploit} from "assay/AssayExploit.sol";
import {IStrategy, StrategyHub} from "../src/StrategyHub.sol";

/// @notice A strategy that credits rewards in the hub. It runs in the hub's context, so it
///         declares the hub's storage layout up to the slot it writes.
contract RewardStrategy is IStrategy {
    address private owner;
    mapping(address account => address strategy) private strategyOf;
    uint256 private harvests;
    uint256 public rewardsAccrued;

    function isStrategy() external pure returns (bool) {
        return true;
    }

    function harvest() external {
        rewardsAccrued += 5;
    }
}

/// @notice A strategy that always fails.
contract FailingStrategy is IStrategy {
    function isStrategy() external pure returns (bool) {
        return true;
    }

    function harvest() external pure {
        revert("no rewards");
    }
}

/// @notice Ordinary use of the hub. Every test records what an outside observer can see.
contract StrategyHubBenignTest is AssayExploit {
    StrategyHub internal hub;
    RewardStrategy internal strategy;
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    function setUp() public {
        hub = new StrategyHub();
        strategy = new RewardStrategy();
        vm.deal(address(this), 10 ether);
    }

    function test_the_owner_approves_a_strategy() public {
        hub.approveStrategy(address(strategy), true);
        assertTrue(hub.approved(address(strategy)));

        hub.approveStrategy(address(strategy), false);
        assertFalse(hub.approved(address(strategy)));
        recordBehavior("approval", abi.encode(hub.approved(address(strategy)), hub.owner() == address(this)));
    }

    function test_an_account_harvests_its_strategy() public {
        hub.approveStrategy(address(strategy), true);
        vm.startPrank(alice);
        hub.setStrategy(address(strategy));
        hub.harvest();
        hub.harvest();
        vm.stopPrank();

        assertEq(hub.strategyOf(alice), address(strategy));
        assertEq(hub.rewardsAccrued(), 10);
        assertEq(hub.harvests(), 2);
        recordBehavior("harvest", abi.encode(hub.rewardsAccrued(), hub.harvests(), hub.strategyOf(alice)));
    }

    function test_two_accounts_share_the_hub_counters() public {
        hub.approveStrategy(address(strategy), true);
        vm.startPrank(alice);
        hub.setStrategy(address(strategy));
        hub.harvest();
        vm.stopPrank();
        vm.startPrank(bob);
        hub.setStrategy(address(strategy));
        hub.harvest();
        vm.stopPrank();

        assertEq(hub.rewardsAccrued(), 10);
        assertEq(hub.harvests(), 2);
        recordBehavior("two_accounts", abi.encode(hub.rewardsAccrued(), hub.harvests()));
    }

    function test_a_failing_strategy_reverts_the_harvest() public {
        FailingStrategy failing = new FailingStrategy();
        hub.approveStrategy(address(failing), true);
        vm.startPrank(alice);
        hub.setStrategy(address(failing));
        vm.expectRevert(abi.encodeWithSelector(StrategyHub.StrategyFailed.selector, address(failing)));
        hub.harvest();
        vm.stopPrank();

        assertEq(hub.harvests(), 0);
        recordBehavior("failing", abi.encode(hub.harvests(), hub.rewardsAccrued()));
    }

    function test_harvest_without_a_strategy_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(StrategyHub.NoStrategy.selector, alice));
        vm.prank(alice);
        hub.harvest();
        recordBehavior("no_strategy", abi.encode(hub.harvests()));
    }

    function test_the_owner_sweeps_and_others_cannot() public {
        (bool funded,) = address(hub).call{value: 4 ether}("");
        assertTrue(funded);

        vm.expectRevert(abi.encodeWithSelector(StrategyHub.NotOwner.selector, alice));
        vm.prank(alice);
        hub.sweep(payable(alice), 1 ether);

        hub.sweep(payable(bob), 1 ether);
        assertEq(bob.balance, 1 ether);
        assertEq(address(hub).balance, 3 ether);

        vm.expectRevert(abi.encodeWithSelector(StrategyHub.InsufficientFunds.selector, 9 ether, 3 ether));
        hub.sweep(payable(bob), 9 ether);
        recordBehavior("sweep", abi.encode(bob.balance, address(hub).balance));
    }

    receive() external payable {}
}
