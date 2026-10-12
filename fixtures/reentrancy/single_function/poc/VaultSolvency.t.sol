// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Test} from "forge-std/Test.sol";
import {AssayInvariant} from "assay/AssayInvariant.sol";
import {Vault} from "../src/Vault.sol";

/// @notice An honest depositor that the handler funds and drives.
contract Depositor {
    Vault private immutable vault;
    address private immutable handler;

    constructor(Vault vault_) {
        vault = vault_;
        handler = msg.sender;
    }

    function deposit() external payable {
        vault.deposit{value: msg.value}();
    }

    function withdraw(uint256 amount) external {
        vault.withdraw(amount);
        (bool sent,) = handler.call{value: address(this).balance}("");
        require(sent, "forward failed");
    }

    receive() external payable {}
}

/// @notice The attacker's account: deposits in one call, and withdraws in a later one while
///         re-entering `withdraw` from `receive`.
contract Reenterer {
    Vault private immutable vault;
    address private immutable handler;
    uint256 private chunk;
    uint256 private reentriesLeft;

    constructor(Vault vault_) {
        vault = vault_;
        handler = msg.sender;
    }

    function deposit() external payable {
        vault.deposit{value: msg.value}();
    }

    function withdraw(uint256 chunk_, uint256 reentries) external {
        chunk = chunk_;
        reentriesLeft = reentries;
        vault.withdraw(chunk_);
        reentriesLeft = 0;
        (bool sent,) = handler.call{value: address(this).balance}("");
        require(sent, "forward failed");
    }

    receive() external payable {
        if (reentriesLeft > 0 && msg.sender == address(vault) && address(vault).balance >= chunk) {
            reentriesLeft -= 1;
            vault.withdraw(chunk);
        }
    }
}

/// @notice Calls of the invariant campaign: honest deposits and withdrawals, and an attacker that
///         deposits and later withdraws with re-entries, in any order.
contract VaultHandler is Test {
    uint256 private constant BPS = 10_000;
    uint256 private constant MAX_DEPOSIT = 5 ether;

    Vault private immutable vault;
    Reenterer private immutable reenterer;
    Depositor[] private depositors;

    constructor(Vault vault_) {
        vault = vault_;
        reenterer = new Reenterer(vault_);
        for (uint256 i = 0; i < 3; i++) {
            depositors.push(new Depositor(vault_));
        }
    }

    function deposit(uint256 who, uint256 amount) external {
        amount = bound(amount, 1, MAX_DEPOSIT);
        if (amount > address(this).balance) return;
        depositors[who % depositors.length].deposit{value: amount}();
    }

    function withdraw(uint256 who, uint256 amount) external {
        Depositor depositor = depositors[who % depositors.length];
        uint256 credited = vault.balanceOf(address(depositor));
        if (credited == 0) return;
        depositor.withdraw(bound(amount, 1, credited));
    }

    function attackerDeposit(uint256 amount) external {
        amount = bound(amount, 1, MAX_DEPOSIT);
        if (amount > address(this).balance) return;
        reenterer.deposit{value: amount}();
    }

    function attackerWithdraw(uint256 chunkBps, uint256 reentries) external {
        uint256 credited = vault.balanceOf(address(reenterer));
        uint256 chunk = credited * bound(chunkBps, 1, BPS) / BPS;
        if (chunk == 0) return;
        reenterer.withdraw(chunk, bound(reentries, 0, 5));
    }

    /// @notice Every account that can hold credit in the vault.
    function accounts() external view returns (address[] memory list) {
        list = new address[](depositors.length + 1);
        for (uint256 i = 0; i < depositors.length; i++) {
            list[i] = address(depositors[i]);
        }
        list[depositors.length] = address(reenterer);
    }

    receive() external payable {}
}

/// @notice Solvency: the vault always holds at least the ether it credits to its depositors.
///         Single-function reentrancy breaks it, because a withdrawal that re-enters is paid
///         more than once while the credit drops only once.
contract VaultSolvencyInvariant is AssayInvariant {
    Vault internal vault;
    VaultHandler internal handler;

    function setUpInvariant() internal override {
        vault = new Vault();
        handler = new VaultHandler(vault);
        vm.deal(address(handler), 100 ether);
        targetContract(address(handler));
    }

    function invariantName() internal pure override returns (string memory) {
        return "vault_solvent";
    }

    function invariantHolds() internal view override returns (bool) {
        address[] memory list = handler.accounts();
        uint256 credited = 0;
        for (uint256 i = 0; i < list.length; i++) {
            credited += vault.balanceOf(list[i]);
        }
        return address(vault).balance >= credited;
    }
}
