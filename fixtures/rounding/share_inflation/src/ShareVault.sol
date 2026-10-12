// INTENTIONALLY VULNERABLE: test fixture, do not deploy
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {MockToken} from "./MockToken.sol";

/// @title ShareVault
/// @notice Pools one token for its depositors, in the style of ERC4626. A deposit mints shares in
///         proportion to the assets the vault holds, and a redemption pays out the same
///         proportion, so that yield paid into the vault raises the value of every share.
contract ShareVault {
    /// @notice The token the vault holds.
    MockToken public immutable asset;
    /// @notice Sum of all shares.
    uint256 public totalSupply;
    /// @notice Shares held by each account.
    mapping(address account => uint256 shares) public balanceOf;

    event Deposit(address indexed caller, address indexed receiver, uint256 assets, uint256 shares);
    event Withdraw(address indexed caller, address indexed receiver, uint256 assets, uint256 shares);

    error ZeroAmount();
    error InsufficientShares(uint256 requested, uint256 available);

    constructor(MockToken asset_) {
        asset = asset_;
    }

    /// @notice Assets held by the vault, including yield paid into it.
    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    /// @notice Shares that a deposit of `assets` mints, rounded down.
    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply;
        return supply == 0 ? assets : assets * supply / totalAssets();
    }

    /// @notice Assets that a redemption of `shares` pays out, rounded down.
    function convertToAssets(uint256 shares) public view returns (uint256) {
        uint256 supply = totalSupply;
        return supply == 0 ? shares : shares * totalAssets() / supply;
    }

    /// @notice Takes `assets` from the caller and mints the matching shares to `receiver`.
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        if (assets == 0) revert ZeroAmount();
        shares = convertToShares(assets);
        asset.transferFrom(msg.sender, address(this), assets);
        totalSupply += shares;
        balanceOf[receiver] += shares;
        emit Deposit(msg.sender, receiver, assets, shares);
    }

    /// @notice Burns `shares` of the caller and pays the matching assets to `receiver`.
    function redeem(uint256 shares, address receiver) external returns (uint256 assets) {
        if (shares == 0) revert ZeroAmount();
        uint256 available = balanceOf[msg.sender];
        if (shares > available) revert InsufficientShares(shares, available);
        assets = convertToAssets(shares);
        balanceOf[msg.sender] = available - shares;
        totalSupply -= shares;
        asset.transfer(receiver, assets);
        emit Withdraw(msg.sender, receiver, assets, shares);
    }
}
