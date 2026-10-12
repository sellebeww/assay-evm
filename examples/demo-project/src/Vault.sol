// INTENTIONALLY VULNERABLE: test fixture, do not deploy
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @title Vault
/// @notice Keeps ether for its depositors. Each depositor can take back what they put in.
contract Vault {
    /// @notice Ether credited to each depositor, in wei.
    mapping(address account => uint256 amount) public balanceOf;
    /// @notice Sum of all credited ether, in wei.
    uint256 public totalDeposits;

    event Deposited(address indexed account, uint256 amount);
    event Withdrawn(address indexed account, uint256 amount);

    error ZeroAmount();
    error InsufficientBalance(uint256 requested, uint256 available);
    error TransferFailed();

    /// @notice Credits the ether sent with the call to the sender.
    function deposit() external payable {
        if (msg.value == 0) revert ZeroAmount();
        balanceOf[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice Sends `amount` wei of the sender's credit back to the sender.
    function withdraw(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        uint256 available = balanceOf[msg.sender];
        if (amount > available) revert InsufficientBalance(amount, available);

        (bool sent,) = msg.sender.call{value: amount}("");
        if (!sent) revert TransferFailed();

        balanceOf[msg.sender] = available - amount;
        totalDeposits -= amount;
        emit Withdrawn(msg.sender, amount);
    }
}
