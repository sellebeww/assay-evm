// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @notice A counter that never exceeds its cap.
contract Bounded {
    uint256 public constant CAP = 100;
    uint256 public value;

    function add(uint256 amount) external {
        require(amount <= CAP - value, "over cap");
        value += amount;
    }
}
