// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayExploit} from "assay/AssayExploit.sol";
import {Presale} from "../src/Presale.sol";

/// @notice Ordinary use of the presale. Every test records what an outside observer can see.
contract PresaleBenignTest is AssayExploit {
    Presale internal presale;
    address internal beneficiary = makeAddr("beneficiary");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal keeper = makeAddr("keeper");

    function setUp() public {
        presale = new Presale(beneficiary, 10 ether);
        vm.deal(alice, 20 ether);
        vm.deal(bob, 20 ether);
    }

    function test_pledges_are_recorded() public {
        vm.prank(alice);
        presale.pledge{value: 3 ether}();
        vm.prank(bob);
        presale.pledge{value: 2 ether}();
        vm.prank(alice);
        presale.pledge{value: 1 ether}();

        assertEq(presale.pledgeOf(alice), 4 ether);
        assertEq(presale.pledgeOf(bob), 2 ether);
        assertEq(presale.totalPledged(), 6 ether);
        recordBehavior("pledge", abi.encode(presale.pledgeOf(alice), presale.pledgeOf(bob), presale.totalPledged()));
    }

    function test_a_pledge_can_be_withdrawn_before_the_target() public {
        vm.prank(alice);
        presale.pledge{value: 4 ether}();
        vm.prank(alice);
        presale.withdrawPledge();

        assertEq(presale.pledgeOf(alice), 0);
        assertEq(presale.totalPledged(), 0);
        assertEq(alice.balance, 20 ether);
        recordBehavior("withdraw", abi.encode(presale.pledgeOf(alice), presale.totalPledged(), alice.balance));
    }

    function test_a_pledge_cannot_be_withdrawn_after_the_target() public {
        vm.prank(alice);
        presale.pledge{value: 10 ether}();

        vm.expectRevert(Presale.TargetReached.selector);
        vm.prank(alice);
        presale.withdrawPledge();
        recordBehavior("locked", abi.encode(presale.pledgeOf(alice), presale.totalPledged()));
    }

    function test_finalize_pays_the_beneficiary() public {
        vm.prank(alice);
        presale.pledge{value: 6 ether}();
        vm.prank(bob);
        presale.pledge{value: 5 ether}();

        vm.prank(keeper);
        presale.finalize();

        assertTrue(presale.finalized());
        assertEq(beneficiary.balance, 11 ether);
        assertEq(address(presale).balance, 0);
        recordBehavior("finalize", abi.encode(presale.finalized(), beneficiary.balance, address(presale).balance));
    }

    function test_finalize_before_the_target_reverts() public {
        vm.prank(alice);
        presale.pledge{value: 9 ether}();

        vm.expectRevert(abi.encodeWithSelector(Presale.TargetNotReached.selector, 9 ether, 10 ether));
        vm.prank(keeper);
        presale.finalize();
        recordBehavior("early_finalize", abi.encode(presale.finalized(), presale.totalPledged()));
    }

    function test_a_finalized_presale_takes_no_more_pledges() public {
        vm.prank(alice);
        presale.pledge{value: 10 ether}();
        presale.finalize();

        vm.expectRevert(Presale.AlreadyFinalized.selector);
        vm.prank(bob);
        presale.pledge{value: 1 ether}();

        vm.expectRevert(Presale.AlreadyFinalized.selector);
        presale.finalize();
        recordBehavior("closed", abi.encode(presale.finalized(), presale.totalPledged(), beneficiary.balance));
    }

    function test_invalid_arguments_revert() public {
        vm.expectRevert(Presale.ZeroAmount.selector);
        vm.prank(alice);
        presale.pledge{value: 0}();

        vm.expectRevert(abi.encodeWithSelector(Presale.NothingPledged.selector, alice));
        vm.prank(alice);
        presale.withdrawPledge();

        recordBehavior("invalid", abi.encode(presale.totalPledged()));
        vm.expectRevert(Presale.ZeroAddress.selector);
        new Presale(address(0), 1 ether);
    }
}
