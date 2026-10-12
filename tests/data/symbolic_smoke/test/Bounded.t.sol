// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Test} from "forge-std/Test.sol";
import {Bounded} from "../src/Bounded.sol";

/// @notice One symbolic property that holds: no sequence of two calls passes the cap.
contract BoundedCheck is Test {
    Bounded internal bounded;

    function setUp() public {
        bounded = new Bounded();
    }

    function check_cap(uint256 first, uint256 second) public {
        try bounded.add(first) {} catch {}
        try bounded.add(second) {} catch {}
        assert(bounded.value() <= bounded.CAP());
    }
}
