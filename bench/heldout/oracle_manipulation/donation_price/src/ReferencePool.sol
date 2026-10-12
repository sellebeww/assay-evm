// INTENTIONALLY VULNERABLE: test fixture, do not deploy
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {PlainToken} from "./PlainToken.sol";

/// @title ReferencePool
/// @notice A small pool of a base token and a quote token that exists to publish a reference
///         price: the quote tokens in the pool per base token. It does not trade; it only takes
///         deposits.
contract ReferencePool {
    uint256 private constant PRICE_SCALE = 1e18;

    /// @notice The token whose price the pool publishes.
    PlainToken public immutable base;
    /// @notice The token the price is quoted in.
    PlainToken public immutable quote;

    event Deposited(address indexed provider, uint256 baseAmount, uint256 quoteAmount);

    error ZeroAmount();
    error EmptyPool();

    constructor(PlainToken base_, PlainToken quote_) {
        base = base_;
        quote = quote_;
    }

    /// @notice Adds base and quote tokens to the pool.
    function deposit(uint256 baseAmount, uint256 quoteAmount) external {
        if (baseAmount == 0 && quoteAmount == 0) revert ZeroAmount();
        if (baseAmount > 0) base.transferFrom(msg.sender, address(this), baseAmount);
        if (quoteAmount > 0) quote.transferFrom(msg.sender, address(this), quoteAmount);
        emit Deposited(msg.sender, baseAmount, quoteAmount);
    }

    /// @notice Quote tokens per base token, scaled by 1e18, from the token balances of the pool.
    function price() public view returns (uint256) {
        uint256 baseBalance = base.balanceOf(address(this));
        if (baseBalance == 0) revert EmptyPool();
        return quote.balanceOf(address(this)) * PRICE_SCALE / baseBalance;
    }
}
