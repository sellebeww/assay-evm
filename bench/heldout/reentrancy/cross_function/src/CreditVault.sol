// INTENTIONALLY VULNERABLE: test fixture, do not deploy
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @title CreditVault
/// @notice Keeps ether as credit per account. Credit can be handed to another account, in part or
///         as a whole, and an account can cash out all of its credit.
contract CreditVault {
    /// @notice Ether credited to each account, in wei.
    mapping(address account => uint256 amount) public creditOf;
    /// @notice Sum of all credit, in wei.
    uint256 public totalCredit;

    event Deposited(address indexed account, uint256 amount);
    event CreditMoved(address indexed from, address indexed to, uint256 amount);
    event CashedOut(address indexed account, uint256 amount);

    error ZeroAmount();
    error ZeroAddress();
    error InsufficientCredit(uint256 requested, uint256 available);
    error TransferFailed();

    /// @notice Credits the ether sent with the call to the sender.
    function deposit() external payable {
        if (msg.value == 0) revert ZeroAmount();
        creditOf[msg.sender] += msg.value;
        totalCredit += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice Hands `amount` of the sender's credit to `to`.
    function moveCredit(address to, uint256 amount) external {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        uint256 available = creditOf[msg.sender];
        if (amount > available) revert InsufficientCredit(amount, available);
        creditOf[msg.sender] = available - amount;
        creditOf[to] += amount;
        emit CreditMoved(msg.sender, to, amount);
    }

    /// @notice Hands all of the sender's credit to `to`.
    function moveAllCredit(address to) external {
        if (to == address(0)) revert ZeroAddress();
        uint256 amount = creditOf[msg.sender];
        if (amount == 0) revert ZeroAmount();
        creditOf[msg.sender] = 0;
        creditOf[to] += amount;
        emit CreditMoved(msg.sender, to, amount);
    }

    /// @notice Pays the sender all of its credit in ether.
    function cashOut() external {
        uint256 amount = creditOf[msg.sender];
        if (amount == 0) revert ZeroAmount();

        (bool sent,) = msg.sender.call{value: amount}("");
        if (!sent) revert TransferFailed();

        creditOf[msg.sender] = 0;
        totalCredit -= amount;
        emit CashedOut(msg.sender, amount);
    }
}
