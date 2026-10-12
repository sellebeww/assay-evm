// INTENTIONALLY VULNERABLE: test fixture, do not deploy
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @title SweepModule
/// @notice Upkeep module for `ModuleVault`: moves the ether above a reserve to a fixed cold-storage
///         address. Its settings are immutable, so they live in the module's code and are the same
///         when the vault runs it with `delegatecall`. It reads and writes no storage.
contract SweepModule {
    /// @notice Where surplus ether goes.
    address public immutable coldStorage;
    /// @notice Ether the vault keeps, in wei.
    uint256 public immutable reserve;

    error SweepFailed();

    constructor(address coldStorage_, uint256 reserve_) {
        coldStorage = coldStorage_;
        reserve = reserve_;
    }

    /// @notice Sends everything above the reserve to cold storage; does nothing when there is no
    ///         surplus.
    function sweep() external {
        uint256 balance = address(this).balance;
        if (balance <= reserve) return;
        (bool sent,) = coldStorage.call{value: balance - reserve}("");
        if (!sent) revert SweepFailed();
    }
}
