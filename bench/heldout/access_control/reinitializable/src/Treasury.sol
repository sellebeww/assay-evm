// INTENTIONALLY VULNERABLE: test fixture, do not deploy
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @title Treasury
/// @notice Holds ether for an owner. The contract has no constructor, as if it were the logic of a
///         proxy: it is set up by an initializer after deployment. There are two initializers, the
///         plain one and one that also sets a handling fee.
contract Treasury {
    /// @notice The account that may sweep the treasury and change the fee.
    address public owner;
    /// @notice Handling fee in basis points, quoted by `feeFor`.
    uint16 public feeBps;
    /// @notice Sum of all ether received through `fund`, in wei.
    uint256 public totalReceived;

    event Initialized(address indexed owner, uint16 feeBps);
    event Funded(address indexed from, uint256 amount);
    event FeeChanged(uint16 previousFeeBps, uint16 newFeeBps);
    event Swept(address indexed to, uint256 amount);

    error NotOwner(address caller);
    error ZeroAddress();
    error ZeroAmount();
    error FeeTooHigh(uint16 feeBps);
    error InsufficientFunds(uint256 requested, uint256 available);
    error TransferFailed();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        _;
    }

    /// @notice Sets the owner. The fee stays as it is.
    function initialize(address owner_) external {
        if (owner_ == address(0)) revert ZeroAddress();
        owner = owner_;
        emit Initialized(owner_, feeBps);
    }

    /// @notice Sets the owner and the handling fee.
    function initializeWithFee(address owner_, uint16 feeBps_) external {
        if (owner_ == address(0)) revert ZeroAddress();
        if (feeBps_ > 1_000) revert FeeTooHigh(feeBps_);
        owner = owner_;
        feeBps = feeBps_;
        emit Initialized(owner_, feeBps_);
    }

    /// @notice Receives ether.
    function fund() external payable {
        if (msg.value == 0) revert ZeroAmount();
        totalReceived += msg.value;
        emit Funded(msg.sender, msg.value);
    }

    /// @notice The handling fee for an amount, rounded down.
    function feeFor(uint256 amount) external view returns (uint256) {
        return amount * feeBps / 10_000;
    }

    /// @notice Changes the handling fee.
    function setFee(uint16 newFeeBps) external onlyOwner {
        if (newFeeBps > 1_000) revert FeeTooHigh(newFeeBps);
        emit FeeChanged(feeBps, newFeeBps);
        feeBps = newFeeBps;
    }

    /// @notice Sends `amount` wei of the treasury to `to`.
    function sweep(address payable to, uint256 amount) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        uint256 available = address(this).balance;
        if (amount > available) revert InsufficientFunds(amount, available);
        (bool sent,) = to.call{value: amount}("");
        if (!sent) revert TransferFailed();
        emit Swept(to, amount);
    }
}
