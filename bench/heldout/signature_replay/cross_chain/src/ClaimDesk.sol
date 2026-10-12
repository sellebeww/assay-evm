// INTENTIONALLY VULNERABLE: test fixture, do not deploy
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @title ClaimDesk
/// @notice Pays ether against claims that an issuer signed. Every claim has a nonce, and a nonce
///         pays once. The same desk is deployed on several chains, with the same issuer.
contract ClaimDesk {
    /// @notice The account whose signature authorizes a claim.
    address public immutable issuer;
    /// @notice Whether a nonce has been claimed on this desk.
    mapping(uint256 nonce => bool claimed) public used;
    /// @notice Sum of all claimed ether, in wei.
    uint256 public totalClaimed;

    event Funded(address indexed from, uint256 amount);
    event Claimed(address indexed to, uint256 amount);

    error ZeroAmount();
    error ZeroAddress();
    error InvalidSignature();
    error NonceUsed(uint256 nonce);
    error InsufficientFunds(uint256 requested, uint256 available);
    error TransferFailed();

    constructor(address issuer_) {
        if (issuer_ == address(0)) revert ZeroAddress();
        issuer = issuer_;
    }

    /// @notice Adds ether to the desk.
    function fund() external payable {
        if (msg.value == 0) revert ZeroAmount();
        emit Funded(msg.sender, msg.value);
    }

    /// @notice The digest that the issuer signs for a claim.
    function claimDigest(address to, uint256 amount, uint256 nonce) public view returns (bytes32) {
        return keccak256(abi.encode(issuer, to, amount, nonce));
    }

    /// @notice Pays `amount` wei to `to` against the issuer's signature on the claim.
    function claim(address to, uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        address signer = ecrecover(claimDigest(to, amount, nonce), v, r, s);
        if (signer == address(0) || signer != issuer) revert InvalidSignature();
        if (used[nonce]) revert NonceUsed(nonce);
        uint256 available = address(this).balance;
        if (amount > available) revert InsufficientFunds(amount, available);

        used[nonce] = true;
        totalClaimed += amount;
        (bool sent,) = payable(to).call{value: amount}("");
        if (!sent) revert TransferFailed();
        emit Claimed(to, amount);
    }
}
