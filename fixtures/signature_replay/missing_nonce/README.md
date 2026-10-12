# Fixture: signature_replay / missing_nonce

> **Intentionally vulnerable.** The code in this directory is test material with a known hole.
> It must never be deployed or used to hold real funds.

## The hole

`VoucherRedeemer` pays out vouchers in ether. An issuer signs a voucher off-chain: "pay `amount`
to `to`". Anyone may submit the signed voucher with `redeem`, and the ether goes to the named
recipient. The contract checks with `ecrecover` that the issuer signed exactly that recipient and
amount.

What the signature covers is the problem. It names the issuer, the recipient and the amount, and
nothing else: no counter that changes after each use (a nonce), no contract address and no chain
id. The contract also keeps no record of the vouchers it has paid. A voucher that was redeemed
once is therefore just as valid the second time, and the tenth time.

## The attack

The PoC (`poc/VoucherReplay.t.sol`) sets up a redeemer holding 20 ether. The issuer gives the
attacker one voucher of 1 ether, a legitimate one. The attacker redeems it, then submits the
same signature again, three more times, and receives 4 ether for a 1 ether voucher. The PoC
records the predicate `attacker_profit` for the asset `eth`, measured against the attacker's
starting balance plus the one payment the voucher is worth.

## The variants

The PoC exposes three knobs, which `testFuzz_variants` draws at random together with the attacker
address and the attacker's starting balance (0 to 1 ether):

| Knob | Meaning | Replay value | Range searched |
|---|---|---|---|
| 0 `twin` | 1 makes every other replay use the signature's twin (see below) instead of the identical bytes | 0 | 0 to 1 |
| 1 `amount` | the voucher's face value, in wei | 1 ether | 0.01 to 2 ether |
| 2 `replays` | how many times the voucher is submitted again after the first redemption | 3 | 1 to 5 |

The twin: an ECDSA signature `(v, r, s)` has a second form, `(v', r, n - s)`, where `n` is the
order of the curve and `v'` is the other recovery value. `ecrecover` accepts both and recovers the
same signer, although the bytes differ. A variant is a replay that alternates the two forms, for
example a 0.4 ether voucher replayed once with its twin.

## The four patches

| Patch | Change | Label and why |
|---|---|---|
| `good.diff` | Adds a nonce per recipient. The digest now covers the chain id, the contract address and the recipient's current nonce, and a redemption increments the nonce. | `good`: after a redemption the old voucher no longer matches the digest, in either of its two forms, so it cannot pay again. Each new voucher is signed for the next nonce, so ordinary use works as before. The storage layout keeps every existing variable in place (the nonces are appended), the ABI only gains the `nonces` getter and the events are the same. |
| `overfit.diff` | Records the hash of every redeemed signature's bytes and refuses a signature it has seen. | `overfit`: replaying the identical bytes is refused, so the original attack is blocked. The twin has different bytes and the same signer, so it pays once more. The variant search finds it as soon as it tries `twin = 1`. |
| `destructive.diff` | Lets every recipient redeem one voucher, ever. | `destructive`: no voucher can pay twice, but neither can a second, different voucher for the same recipient, so the benign test with two vouchers fails. |
| `regressing.diff` | The same nonce as in `good.diff`, and the `Redeemed` event gains a `nonce` field. | `regressing`: replays are refused and the benign tests pass, but `Redeemed(address,uint256)` became `Redeemed(address,uint256,uint256)`, a different event. Anything that watches for the old event stops seeing redemptions. |
