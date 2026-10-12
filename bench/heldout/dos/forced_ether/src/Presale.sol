// INTENTIONALLY VULNERABLE: test fixture, do not deploy
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @title Presale
/// @notice Collects pledges of ether. Once the pledges reach the target, anyone may finalize the
///         presale, which sends everything that was pledged to the beneficiary. Until the target
///         is reached, a pledger can take its pledge back.
contract Presale {
    /// @notice The account that receives the pledges when the presale is finalized.
    address public immutable beneficiary;
    /// @notice Ether the pledges must reach before the presale can be finalized, in wei.
    uint256 public immutable target;
    /// @notice Sum of all pledges, in wei.
    uint256 public totalPledged;
    /// @notice Whether the presale has been finalized.
    bool public finalized;
    /// @notice Ether each account has pledged, in wei.
    mapping(address account => uint256 amount) public pledgeOf;

    event Pledged(address indexed account, uint256 amount);
    event PledgeWithdrawn(address indexed account, uint256 amount);
    event Finalized(address indexed beneficiary, uint256 amount);

    error ZeroAmount();
    error ZeroAddress();
    error AlreadyFinalized();
    error TargetNotReached(uint256 pledged, uint256 target);
    error TargetReached();
    error BalanceMismatch(uint256 balance, uint256 pledged);
    error NothingPledged(address account);
    error TransferFailed();

    constructor(address beneficiary_, uint256 target_) {
        if (beneficiary_ == address(0)) revert ZeroAddress();
        if (target_ == 0) revert ZeroAmount();
        beneficiary = beneficiary_;
        target = target_;
    }

    /// @notice Adds the ether sent with the call to the sender's pledge.
    function pledge() external payable {
        if (finalized) revert AlreadyFinalized();
        if (msg.value == 0) revert ZeroAmount();
        pledgeOf[msg.sender] += msg.value;
        totalPledged += msg.value;
        emit Pledged(msg.sender, msg.value);
    }

    /// @notice Takes the sender's whole pledge back. Possible only while the target is not
    ///         reached.
    function withdrawPledge() external {
        if (finalized) revert AlreadyFinalized();
        if (totalPledged >= target) revert TargetReached();
        uint256 amount = pledgeOf[msg.sender];
        if (amount == 0) revert NothingPledged(msg.sender);
        pledgeOf[msg.sender] = 0;
        totalPledged -= amount;
        (bool sent,) = msg.sender.call{value: amount}("");
        if (!sent) revert TransferFailed();
        emit PledgeWithdrawn(msg.sender, amount);
    }

    /// @notice Sends all pledges to the beneficiary once the target is reached.
    function finalize() external {
        if (finalized) revert AlreadyFinalized();
        if (totalPledged < target) revert TargetNotReached(totalPledged, target);
        // The presale must hold exactly what was pledged: any difference means that the
        // accounting is wrong, and nothing is sent.
        if (address(this).balance != totalPledged) {
            revert BalanceMismatch(address(this).balance, totalPledged);
        }
        finalized = true;
        (bool sent,) = beneficiary.call{value: totalPledged}("");
        if (!sent) revert TransferFailed();
        emit Finalized(beneficiary, totalPledged);
    }
}
