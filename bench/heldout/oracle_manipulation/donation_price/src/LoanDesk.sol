// INTENTIONALLY VULNERABLE: test fixture, do not deploy
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {PlainToken} from "./PlainToken.sol";
import {ReferencePool} from "./ReferencePool.sol";

/// @title LoanDesk
/// @notice Lends the quote token against the base token as collateral. The collateral is valued
///         at the price of a reference pool, and a loan may be at most 75 percent of that value.
contract LoanDesk {
    uint256 private constant BPS = 10_000;
    uint256 private constant PRICE_SCALE = 1e18;
    uint256 private constant MAX_LOAN_BPS = 7_500;

    /// @notice The pool that publishes the price of the collateral.
    ReferencePool public immutable pool;
    PlainToken private immutable collateral;
    PlainToken private immutable debt;

    /// @notice Collateral each account has locked.
    mapping(address account => uint256 amount) public lockedOf;
    /// @notice Quote tokens each account owes.
    mapping(address account => uint256 amount) public owedBy;

    event Locked(address indexed account, uint256 amount);
    event Released(address indexed account, uint256 amount);
    event Borrowed(address indexed account, uint256 amount);
    event Repaid(address indexed account, uint256 amount);

    error ZeroAmount();
    error NotEnoughLocked(uint256 requested, uint256 available);
    error RepayTooMuch(uint256 requested, uint256 owed);
    error LoanTooLarge(uint256 owed, uint256 maximum);

    constructor(ReferencePool pool_) {
        pool = pool_;
        collateral = pool_.base();
        debt = pool_.quote();
    }

    /// @notice The most that `account` may owe, in quote tokens, at the current price.
    function maxLoan(address account) public view returns (uint256) {
        return lockedOf[account] * pool.price() / PRICE_SCALE * MAX_LOAN_BPS / BPS;
    }

    function lock(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        collateral.transferFrom(msg.sender, address(this), amount);
        lockedOf[msg.sender] += amount;
        emit Locked(msg.sender, amount);
    }

    function release(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        uint256 available = lockedOf[msg.sender];
        if (amount > available) revert NotEnoughLocked(amount, available);
        lockedOf[msg.sender] = available - amount;
        _requireWithinLimit(msg.sender, owedBy[msg.sender]);
        collateral.transfer(msg.sender, amount);
        emit Released(msg.sender, amount);
    }

    function borrow(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        uint256 owed = owedBy[msg.sender] + amount;
        _requireWithinLimit(msg.sender, owed);
        owedBy[msg.sender] = owed;
        debt.transfer(msg.sender, amount);
        emit Borrowed(msg.sender, amount);
    }

    function repay(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        uint256 owed = owedBy[msg.sender];
        if (amount > owed) revert RepayTooMuch(amount, owed);
        debt.transferFrom(msg.sender, address(this), amount);
        owedBy[msg.sender] = owed - amount;
        emit Repaid(msg.sender, amount);
    }

    function _requireWithinLimit(address account, uint256 owed) private view {
        uint256 maximum = maxLoan(account);
        if (owed > maximum) revert LoanTooLarge(owed, maximum);
    }
}
