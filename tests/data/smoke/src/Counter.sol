// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @notice Minimal contract used to check that the runner image builds and tests offline.
contract Counter {
    uint256 public number;

    function increment() external {
        number += 1;
    }
}
