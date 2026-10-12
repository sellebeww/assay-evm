// INTENTIONALLY VULNERABLE: test fixture, do not deploy
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @title Crowdfund
/// @notice Collects ether for a project. Once the goal is reached, the organizer takes the funds.
///         If the organizer cancels the campaign instead, anyone may trigger the refund of every
///         contributor in one call.
contract Crowdfund {
    /// @notice The account that runs the campaign.
    address public immutable organizer;
    /// @notice Ether the campaign must raise before the organizer may take it, in wei.
    uint256 public immutable goal;
    /// @notice Whether the organizer cancelled the campaign.
    bool public cancelled;
    /// @notice Whether the organizer took the funds.
    bool public claimed;
    /// @notice Sum of all contributions that are neither refunded nor claimed, in wei.
    uint256 public totalRaised;
    /// @notice Ether contributed by each account and not yet refunded, in wei.
    mapping(address account => uint256 amount) public contributionOf;
    /// @notice Every account that contributed, in the order of its first contribution.
    address[] public contributors;

    event Contributed(address indexed account, uint256 amount);
    event Cancelled();
    event Refunded(address indexed account, uint256 amount);
    event Claimed(uint256 amount);

    error ZeroAmount();
    error NotOrganizer(address caller);
    error CampaignClosed();
    error NotCancelled();
    error GoalNotReached(uint256 raised, uint256 goal);
    error TransferFailed(address to);

    constructor(uint256 goal_) {
        organizer = msg.sender;
        goal = goal_;
    }

    /// @notice Number of accounts that contributed.
    function contributorCount() external view returns (uint256) {
        return contributors.length;
    }

    /// @notice Adds the ether sent with the call to the sender's contribution.
    function contribute() external payable {
        if (cancelled || claimed) revert CampaignClosed();
        if (msg.value == 0) revert ZeroAmount();
        if (contributionOf[msg.sender] == 0) contributors.push(msg.sender);
        contributionOf[msg.sender] += msg.value;
        totalRaised += msg.value;
        emit Contributed(msg.sender, msg.value);
    }

    /// @notice Cancels the campaign, so that every contribution can be refunded. Organizer only.
    function cancel() external {
        if (msg.sender != organizer) revert NotOrganizer(msg.sender);
        if (cancelled || claimed) revert CampaignClosed();
        cancelled = true;
        emit Cancelled();
    }

    /// @notice Sends every contributor its contribution back. Anyone may call it once the
    ///         campaign is cancelled.
    function refundAll() external {
        if (!cancelled) revert NotCancelled();
        uint256 count = contributors.length;
        for (uint256 i = 0; i < count; i++) {
            address account = contributors[i];
            uint256 amount = contributionOf[account];
            if (amount == 0) continue;
            contributionOf[account] = 0;
            totalRaised -= amount;
            (bool sent,) = payable(account).call{value: amount}("");
            if (!sent) revert TransferFailed(account);
            emit Refunded(account, amount);
        }
    }

    /// @notice Pays the raised ether to the organizer once the goal is reached. Organizer only.
    function claim() external {
        if (msg.sender != organizer) revert NotOrganizer(msg.sender);
        if (cancelled || claimed) revert CampaignClosed();
        uint256 raised = totalRaised;
        if (raised < goal) revert GoalNotReached(raised, goal);
        claimed = true;
        totalRaised = 0;
        (bool sent,) = payable(msg.sender).call{value: raised}("");
        if (!sent) revert TransferFailed(msg.sender);
        emit Claimed(raised);
    }
}
