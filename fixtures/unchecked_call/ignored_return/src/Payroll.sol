// INTENTIONALLY VULNERABLE: test fixture, do not deploy
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @title Payroll
/// @notice Holds ether for a team. The employer books wages; anyone may then push a booked wage
///         to its payee, so that a keeper can run payday for everyone.
contract Payroll {
    /// @notice The account that books wages.
    address public employer;
    /// @notice Wages booked and not yet paid, per payee, in wei.
    mapping(address payee => uint256 amount) public owed;
    /// @notice Sum of all wages booked and not yet paid, in wei.
    uint256 public totalOwed;

    event Funded(address indexed from, uint256 amount);
    event WageBooked(address indexed payee, uint256 amount);
    event Paid(address indexed payee, uint256 amount);

    error NotEmployer(address caller);
    error ZeroAmount();
    error ZeroAddress();
    error Underfunded(uint256 needed, uint256 available);
    error NothingOwed(address payee);

    constructor() {
        employer = msg.sender;
    }

    /// @notice Adds the ether sent with the call to the payroll's funds.
    function fund() external payable {
        if (msg.value == 0) revert ZeroAmount();
        emit Funded(msg.sender, msg.value);
    }

    /// @notice Books a wage of `amount` wei for `payee`. Employer only; the funds must cover it.
    function book(address payee, uint256 amount) external {
        if (msg.sender != employer) revert NotEmployer(msg.sender);
        if (payee == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        uint256 needed = totalOwed + amount;
        if (needed > address(this).balance) revert Underfunded(needed, address(this).balance);
        owed[payee] += amount;
        totalOwed = needed;
        emit WageBooked(payee, amount);
    }

    /// @notice Pays everything booked for `payee`. Anyone may call it.
    function pay(address payee) external {
        uint256 amount = owed[payee];
        if (amount == 0) revert NothingOwed(payee);
        owed[payee] = 0;
        totalOwed -= amount;
        payable(payee).call{value: amount}("");
        emit Paid(payee, amount);
    }

    /// @notice Pays every listed payee that has a booked wage, in one transaction. Anyone may call
    ///         it; payees without a booked wage are skipped.
    function payMany(address[] calldata payees) external {
        for (uint256 i = 0; i < payees.length; i++) {
            address payee = payees[i];
            uint256 amount = owed[payee];
            if (amount == 0) continue;
            owed[payee] = 0;
            totalOwed -= amount;
            payable(payee).call{value: amount}("");
            emit Paid(payee, amount);
        }
    }
}
