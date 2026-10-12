// INTENTIONALLY VULNERABLE: test fixture, do not deploy
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @title ModuleVault
/// @notice Holds ether for its owner. Routine upkeep (for example sweeping surplus ether to cold
///         storage) lives in separate module contracts that the vault runs with `delegatecall`, in
///         its own context. The owner approves modules; anyone may run upkeep, so that a keeper
///         can do it.
contract ModuleVault {
    /// @notice The account that approves modules and withdraws ether.
    address public owner;
    /// @notice Modules the owner approved for upkeep.
    mapping(address module => bool approved) public approvedModule;
    /// @notice Number of upkeep runs so far.
    uint256 public upkeepRuns;

    event ModuleApproval(address indexed module, bool approved);
    event UpkeepRun(address indexed module, address indexed keeper);
    event Withdrawn(address indexed to, uint256 amount);

    error NotOwner(address caller);
    error ZeroAmount();
    error LengthMismatch();
    error ModuleFailed(address module);
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

    /// @notice Approves or revokes `module` for upkeep. Owner only.
    function setModuleApproval(address module, bool approved) external onlyOwner {
        approvedModule[module] = approved;
        emit ModuleApproval(module, approved);
    }

    /// @notice Runs `data` on the approved upkeep module `module`, in the vault's context.
    function runUpkeep(address module, bytes calldata data) external returns (bytes memory) {
        return _run(module, data);
    }

    /// @notice Runs several upkeep calls in one transaction, in order.
    function runUpkeepBatch(address[] calldata modules, bytes[] calldata data) external {
        if (modules.length != data.length) revert LengthMismatch();
        for (uint256 i = 0; i < modules.length; i++) {
            _run(modules[i], data[i]);
        }
    }

    /// @notice Sends `amount` wei to `to`. Owner only.
    function withdraw(address payable to, uint256 amount) external onlyOwner {
        if (amount == 0) revert ZeroAmount();
        uint256 available = address(this).balance;
        if (amount > available) revert InsufficientFunds(amount, available);
        (bool sent,) = to.call{value: amount}("");
        if (!sent) revert TransferFailed();
        emit Withdrawn(to, amount);
    }

    function _run(address module, bytes calldata data) private returns (bytes memory result) {
        bool ok;
        (ok, result) = module.delegatecall(data);
        if (!ok) revert ModuleFailed(module);
        upkeepRuns += 1;
        emit UpkeepRun(module, msg.sender);
    }
}
