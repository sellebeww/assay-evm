// INTENTIONALLY VULNERABLE: test fixture, do not deploy
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {MockToken} from "./MockToken.sol";

/// @title MiniPool
/// @notice A tiny constant-product market for two tokens with a 0.3 percent fee. The pool
///         prices the base token in quote tokens. Liquidity added to it stays in the pool.
contract MiniPool {
    uint256 private constant FEE_DENOMINATOR = 1000;
    uint256 private constant FEE_FACTOR = 997;
    uint256 private constant PRICE_SCALE = 1e18;

    /// @notice The token that is priced.
    MockToken public immutable base;
    /// @notice The token prices are expressed in.
    MockToken public immutable quote;
    /// @notice Base tokens held by the pool.
    uint256 public baseReserve;
    /// @notice Quote tokens held by the pool.
    uint256 public quoteReserve;

    event LiquidityAdded(address indexed provider, uint256 baseAmount, uint256 quoteAmount);
    event Swapped(address indexed trader, bool baseIn, uint256 amountIn, uint256 amountOut);

    error ZeroAmount();
    error EmptyPool();
    error UnbalancedLiquidity();
    error Slippage(uint256 amountOut, uint256 minimum);

    constructor(MockToken base_, MockToken quote_) {
        base = base_;
        quote = quote_;
    }

    /// @notice Adds liquidity. After the first deposit, the amounts must match the current ratio.
    function addLiquidity(uint256 baseAmount, uint256 quoteAmount) external {
        if (baseAmount == 0 || quoteAmount == 0) revert ZeroAmount();
        if (baseReserve != 0 && baseAmount * quoteReserve != quoteAmount * baseReserve) {
            revert UnbalancedLiquidity();
        }
        base.transferFrom(msg.sender, address(this), baseAmount);
        quote.transferFrom(msg.sender, address(this), quoteAmount);
        baseReserve += baseAmount;
        quoteReserve += quoteAmount;
        emit LiquidityAdded(msg.sender, baseAmount, quoteAmount);
    }

    /// @notice Sells `amountIn` of one token for the other: base for quote when `baseIn` is
    ///         true, quote for base otherwise. Reverts when the output is below `minOut`.
    function swap(bool baseIn, uint256 amountIn, uint256 minOut) external returns (uint256 amountOut) {
        if (amountIn == 0) revert ZeroAmount();
        (MockToken tokenIn, MockToken tokenOut, uint256 reserveIn, uint256 reserveOut) =
            baseIn ? (base, quote, baseReserve, quoteReserve) : (quote, base, quoteReserve, baseReserve);
        if (reserveIn == 0) revert EmptyPool();
        amountOut = getAmountOut(amountIn, reserveIn, reserveOut);
        if (amountOut < minOut) revert Slippage(amountOut, minOut);

        tokenIn.transferFrom(msg.sender, address(this), amountIn);
        tokenOut.transfer(msg.sender, amountOut);
        if (baseIn) {
            baseReserve = reserveIn + amountIn;
            quoteReserve = reserveOut - amountOut;
        } else {
            quoteReserve = reserveIn + amountIn;
            baseReserve = reserveOut - amountOut;
        }
        emit Swapped(msg.sender, baseIn, amountIn, amountOut);
    }

    /// @notice Output of a swap of `amountIn` against the given reserves, after the fee.
    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) public pure returns (uint256) {
        uint256 amountInWithFee = amountIn * FEE_FACTOR;
        return amountInWithFee * reserveOut / (reserveIn * FEE_DENOMINATOR + amountInWithFee);
    }

    /// @notice Price of one whole base token in quote tokens, scaled by 1e18, read from the
    ///         current reserves.
    function spotPrice() public view returns (uint256) {
        if (baseReserve == 0) revert EmptyPool();
        return quoteReserve * PRICE_SCALE / baseReserve;
    }
}
