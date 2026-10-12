// INTENTIONALLY VULNERABLE: test fixture, do not deploy
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @title VoucherRedeemer
/// @notice Pays out vouchers in ether. The issuer signs a voucher off-chain for a recipient and an
///         amount; anyone may submit it, and the ether goes to the named recipient.
contract VoucherRedeemer {
    /// @notice The account whose signature makes a voucher valid.
    address public immutable issuer;
    /// @notice Sum of all vouchers paid out, in wei.
    uint256 public totalRedeemed;

    event Funded(address indexed from, uint256 amount);
    event Redeemed(address indexed to, uint256 amount);

    error ZeroAmount();
    error ZeroAddress();
    error InvalidSignature();
    error InsufficientFunds(uint256 requested, uint256 available);
    error TransferFailed();

    constructor(address issuer_) {
        if (issuer_ == address(0)) revert ZeroAddress();
        issuer = issuer_;
    }

    /// @notice Adds the ether sent with the call to the funds that pay vouchers.
    function fund() external payable {
        if (msg.value == 0) revert ZeroAmount();
        emit Funded(msg.sender, msg.value);
    }

    /// @notice The digest the issuer signs for a voucher of `amount` wei payable to `to`.
    function voucherDigest(address to, uint256 amount) public view returns (bytes32) {
        return keccak256(abi.encode(issuer, to, amount));
    }

    /// @notice Pays the voucher signed by the issuer (`v`, `r`, `s`) for `amount` wei to `to`.
    function redeem(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        address signer = ecrecover(voucherDigest(to, amount), v, r, s);
        if (signer == address(0) || signer != issuer) revert InvalidSignature();
        uint256 available = address(this).balance;
        if (amount > available) revert InsufficientFunds(amount, available);

        totalRedeemed += amount;
        (bool sent,) = payable(to).call{value: amount}("");
        if (!sent) revert TransferFailed();
        emit Redeemed(to, amount);
    }
}
