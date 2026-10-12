// INTENTIONALLY VULNERABLE: test fixture, do not deploy
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @title FeePool
/// @notice Keeps ether for depositors. A withdrawal pays a fee of 0.30 percent of the amount,
///         which stays in the pool and can be sent to the treasury.
contract FeePool {
    uint256 private constant BPS = 10_000;

    /// @notice The fee on a withdrawal, in basis points.
    uint256 public constant FEE_BPS = 30;
    /// @notice The account that receives the collected fees.
    address public immutable treasury;
    /// @notice Ether each account has deposited and not withdrawn, in wei.
    mapping(address account => uint256 amount) public balanceOf;
    /// @notice Sum of all deposits that were not withdrawn, in wei.
    uint256 public totalDeposits;
    /// @notice Fees that were charged and not yet collected, in wei.
    uint256 public feesAccrued;

    event Deposited(address indexed account, uint256 amount);
    event Withdrawn(address indexed account, uint256 amount, uint256 fee);
    event FeesCollected(address indexed treasury, uint256 amount);

    error ZeroAmount();
    error ZeroAddress();
    error InsufficientBalance(uint256 requested, uint256 available);
    error TransferFailed();

    constructor(address treasury_) {
        if (treasury_ == address(0)) revert ZeroAddress();
        treasury = treasury_;
    }

    /// @notice Credits the ether sent with the call to the sender.
    function deposit() external payable {
        if (msg.value == 0) revert ZeroAmount();
        balanceOf[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice The fee charged on a withdrawal of `amount` wei.
    function feeOn(uint256 amount) public pure returns (uint256) {
        return amount * FEE_BPS / BPS;
    }

    /// @notice Pays `amount` wei of the sender's balance to the sender, minus the fee.
    function withdraw(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        uint256 available = balanceOf[msg.sender];
        if (amount > available) revert InsufficientBalance(amount, available);

        uint256 fee = feeOn(amount);
        balanceOf[msg.sender] = available - amount;
        totalDeposits -= amount;
        feesAccrued += fee;
        (bool sent,) = msg.sender.call{value: amount - fee}("");
        if (!sent) revert TransferFailed();
        emit Withdrawn(msg.sender, amount, fee);
    }

    /// @notice Sends the fees that were charged to the treasury.
    function collectFees() external {
        uint256 amount = feesAccrued;
        if (amount == 0) revert ZeroAmount();
        feesAccrued = 0;
        (bool sent,) = treasury.call{value: amount}("");
        if (!sent) revert TransferFailed();
        emit FeesCollected(treasury, amount);
    }
}
