// INTENTIONALLY VULNERABLE: test fixture, do not deploy
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {MiniPool} from "./MiniPool.sol";
import {MockToken} from "./MockToken.sol";

/// @title Lender
/// @notice Lends the pool's quote token against its base token as collateral. Collateral is
///         valued at the pool price, and an account may borrow up to 75 percent of its value.
contract Lender {
    uint256 private constant BPS = 10_000;
    uint256 private constant PRICE_SCALE = 1e18;
    /// @notice Share of the collateral value that may be borrowed, in basis points.
    uint256 public constant LOAN_TO_VALUE_BPS = 7_500;

    /// @notice The market whose price values the collateral.
    MiniPool public immutable pool;
    /// @notice The pool's base token, accepted as collateral.
    MockToken public immutable collateralToken;
    /// @notice The pool's quote token, lent out.
    MockToken public immutable debtToken;

    /// @notice Collateral deposited by each account.
    mapping(address account => uint256 amount) public collateralOf;
    /// @notice Debt tokens owed by each account.
    mapping(address account => uint256 amount) public debtOf;

    event CollateralDeposited(address indexed account, uint256 amount);
    event CollateralWithdrawn(address indexed account, uint256 amount);
    event Borrowed(address indexed account, uint256 amount);
    event Repaid(address indexed account, uint256 amount);

    error ZeroAmount();
    error ExceedsCollateral(uint256 requested, uint256 available);
    error ExceedsDebt(uint256 requested, uint256 debt);
    error BorrowLimitExceeded(uint256 debt, uint256 limit);

    constructor(MiniPool pool_) {
        pool = pool_;
        collateralToken = pool_.base();
        debtToken = pool_.quote();
    }

    /// @notice Price of one whole collateral token in debt tokens, scaled by 1e18.
    function price() public view returns (uint256) {
        return pool.spotPrice();
    }

    /// @notice Value of the collateral of `account`, in debt tokens.
    function collateralValue(address account) public view returns (uint256) {
        return collateralOf[account] * price() / PRICE_SCALE;
    }

    /// @notice Most that `account` may owe against its collateral, in debt tokens.
    function borrowLimit(address account) public view returns (uint256) {
        return collateralValue(account) * LOAN_TO_VALUE_BPS / BPS;
    }

    function depositCollateral(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        collateralToken.transferFrom(msg.sender, address(this), amount);
        collateralOf[msg.sender] += amount;
        emit CollateralDeposited(msg.sender, amount);
    }

    function withdrawCollateral(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        uint256 available = collateralOf[msg.sender];
        if (amount > available) revert ExceedsCollateral(amount, available);
        collateralOf[msg.sender] = available - amount;
        _checkLimit(msg.sender, debtOf[msg.sender]);
        collateralToken.transfer(msg.sender, amount);
        emit CollateralWithdrawn(msg.sender, amount);
    }

    function borrow(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        uint256 debt = debtOf[msg.sender] + amount;
        _checkLimit(msg.sender, debt);
        debtOf[msg.sender] = debt;
        debtToken.transfer(msg.sender, amount);
        emit Borrowed(msg.sender, amount);
    }

    function repay(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        uint256 debt = debtOf[msg.sender];
        if (amount > debt) revert ExceedsDebt(amount, debt);
        debtToken.transferFrom(msg.sender, address(this), amount);
        debtOf[msg.sender] = debt - amount;
        emit Repaid(msg.sender, amount);
    }

    function _checkLimit(address account, uint256 debt) private view {
        uint256 limit = borrowLimit(account);
        if (debt > limit) revert BorrowLimitExceeded(debt, limit);
    }
}
