// INTENTIONALLY VULNERABLE: test fixture, do not deploy
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @title FeeCollector
/// @notice Collects fees in ether. The owner pays them out, for example to suppliers.
contract FeeCollector {
    /// @notice Sum of all fees collected, in wei.
    uint256 public totalCollected;
    /// @notice Sum of all payouts, in wei.
    uint256 public totalPaidOut;
    /// @notice The account that controls payouts and ownership.
    address public owner;

    event Collected(address indexed from, uint256 amount);
    event PaidOut(address indexed to, uint256 amount);
    event OwnerChanged(address indexed previousOwner, address indexed newOwner);

    error NotOwner(address caller);
    error ZeroAmount();
    error ZeroAddress();
    error InsufficientFunds(uint256 requested, uint256 available);
    error TransferFailed();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        _;
    }

    constructor(address owner_) {
        if (owner_ == address(0)) revert ZeroAddress();
        owner = owner_;
        emit OwnerChanged(address(0), owner_);
    }

    /// @notice Collects the ether sent with the call as a fee.
    function collect() external payable {
        if (msg.value == 0) revert ZeroAmount();
        totalCollected += msg.value;
        emit Collected(msg.sender, msg.value);
    }

    /// @notice Hands control to `newOwner`. Owner only.
    function setOwner(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnerChanged(owner, newOwner);
        owner = newOwner;
    }

    /// @notice Pays `amount` wei of the collected fees to `to`. Owner only.
    function payOut(address payable to, uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        _send(to, amount);
    }

    /// @notice Pays everything the contract holds to `to`. Owner only.
    function payOutAll(address payable to) external {
        uint256 amount = address(this).balance;
        if (amount == 0) revert ZeroAmount();
        _send(to, amount);
    }

    function _send(address payable to, uint256 amount) private {
        if (to == address(0)) revert ZeroAddress();
        uint256 available = address(this).balance;
        if (amount > available) revert InsufficientFunds(amount, available);
        totalPaidOut += amount;
        (bool sent,) = to.call{value: amount}("");
        if (!sent) revert TransferFailed();
        emit PaidOut(to, amount);
    }
}
