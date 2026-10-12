// INTENTIONALLY VULNERABLE: test fixture, do not deploy
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {SoftToken} from "./SoftToken.sol";

/// @title DepositPool
/// @notice Takes deposits of one token and credits them to the depositor. A depositor can
///         withdraw up to its credit. Deposits can be made one at a time or in a batch.
contract DepositPool {
    /// @notice The token the pool holds.
    SoftToken public immutable token;
    /// @notice Tokens credited to each account.
    mapping(address account => uint256 amount) public creditOf;
    /// @notice Sum of all credit.
    uint256 public totalCredit;

    event Deposited(address indexed account, uint256 amount);
    event Withdrawn(address indexed account, uint256 amount);

    error ZeroAmount();
    error InsufficientCredit(uint256 requested, uint256 available);
    error TransferFailed();

    constructor(SoftToken token_) {
        token = token_;
    }

    /// @notice Pulls `amount` tokens from the sender and credits them to the sender.
    function deposit(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        token.transferFrom(msg.sender, address(this), amount);
        creditOf[msg.sender] += amount;
        totalCredit += amount;
        emit Deposited(msg.sender, amount);
    }

    /// @notice Makes one deposit per entry of `amounts`.
    function depositMany(uint256[] calldata amounts) external {
        for (uint256 i = 0; i < amounts.length; i++) {
            uint256 amount = amounts[i];
            if (amount == 0) revert ZeroAmount();
            token.transferFrom(msg.sender, address(this), amount);
            creditOf[msg.sender] += amount;
            totalCredit += amount;
            emit Deposited(msg.sender, amount);
        }
    }

    /// @notice Sends `amount` tokens of the sender's credit to the sender.
    function withdraw(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        uint256 available = creditOf[msg.sender];
        if (amount > available) revert InsufficientCredit(amount, available);
        creditOf[msg.sender] = available - amount;
        totalCredit -= amount;
        if (!token.transfer(msg.sender, amount)) revert TransferFailed();
        emit Withdrawn(msg.sender, amount);
    }
}
