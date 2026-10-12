// INTENTIONALLY VULNERABLE: test fixture, do not deploy
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @notice What a strategy offers. A strategy is meant to be a small piece of logic that the hub
///         runs for an account.
interface IStrategy {
    /// @notice Marker that a contract is meant to be used as a strategy.
    function isStrategy() external pure returns (bool);

    /// @notice The logic that runs when an account harvests.
    function harvest() external;
}

/// @title StrategyHub
/// @notice Every account registers a strategy and harvests it. Strategies are run with
///         `delegatecall`, so that they can credit rewards in the hub's own storage. The owner
///         keeps a list of approved strategies.
contract StrategyHub {
    /// @notice The account that may approve strategies and sweep the hub.
    address public owner;
    /// @notice The strategy each account has registered.
    mapping(address account => address strategy) public strategyOf;
    /// @notice Number of harvests, over all accounts.
    uint256 public harvests;
    /// @notice Rewards that strategies have credited, in units of the hub.
    uint256 public rewardsAccrued;
    /// @notice Strategies that the owner has approved.
    mapping(address strategy => bool approvedStrategy) public approved;

    event StrategyApproval(address indexed strategy, bool approved);
    event StrategySet(address indexed account, address indexed strategy);
    event Harvested(address indexed account, address indexed strategy);
    event Swept(address indexed to, uint256 amount);

    error NotOwner(address caller);
    error NoStrategy(address account);
    error StrategyFailed(address strategy);
    error ZeroAmount();
    error InsufficientFunds(uint256 requested, uint256 available);
    error TransferFailed();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {}

    /// @notice Approves or withdraws the approval of a strategy.
    function approveStrategy(address strategy, bool isApproved) external onlyOwner {
        approved[strategy] = isApproved;
        emit StrategyApproval(strategy, isApproved);
    }

    /// @notice Registers `strategy` for the sender.
    function setStrategy(address strategy) external {
        strategyOf[msg.sender] = strategy;
        emit StrategySet(msg.sender, strategy);
    }

    /// @notice Runs the sender's strategy in the context of the hub.
    function harvest() external {
        address strategy = strategyOf[msg.sender];
        if (strategy == address(0)) revert NoStrategy(msg.sender);
        (bool ok,) = strategy.delegatecall(abi.encodeCall(IStrategy.harvest, ()));
        if (!ok) revert StrategyFailed(strategy);
        harvests += 1;
        emit Harvested(msg.sender, strategy);
    }

    /// @notice Sends `amount` wei of the hub to `to`.
    function sweep(address payable to, uint256 amount) external onlyOwner {
        if (amount == 0) revert ZeroAmount();
        uint256 available = address(this).balance;
        if (amount > available) revert InsufficientFunds(amount, available);
        (bool sent,) = to.call{value: amount}("");
        if (!sent) revert TransferFailed();
        emit Swept(to, amount);
    }
}
