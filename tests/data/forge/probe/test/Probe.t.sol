// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Test, console} from "forge-std/Test.sol";

/// @notice Covers every test kind and status that the forge output parser normalizes.
contract Tally {
    uint256 public count;

    function bump() external {
        count += 1;
    }
}

contract ProbeTest is Test {
    uint256[] public fixtureAmount = [1, 5, 9];

    function test_Passes() public pure {
        console.log("probe log", uint256(7));
    }

    function test_Fails() public pure {
        assertEq(uint256(1), 2, "one is not two");
    }

    function test_Skipped() public {
        vm.skip(true, "not applicable");
    }

    function testFuzz_Passes(uint256 x) public pure {
        x;
    }

    function testFuzz_Fails(uint256 x) public pure {
        assertLt(x, 10);
    }

    function tableAmount(uint256 amount) public pure {
        assertGt(amount, 0);
    }
}

contract ProbeInvariantTest is Test {
    Tally internal tally;

    function setUp() public {
        tally = new Tally();
        targetContract(address(tally));
    }

    function invariant_CountStaysSmall() public view {
        assertLt(tally.count(), 1_000_000);
    }
}
