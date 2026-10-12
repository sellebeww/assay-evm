// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @notice Does not compile: `missing` is not declared.
contract Broken {
    function f() public pure returns (uint256) {
        return missing;
    }
}
