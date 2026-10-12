# Fixture: signature_replay / cross_chain (held-out)

> **Intentionally vulnerable.** The code in this directory is test material with a known hole.
> It must never be deployed or used to hold real funds.

This fixture belongs to the held-out split. Its code shape differs from the development fixture
of the same class: the claim has a nonce, so a signature cannot be reused on the same desk. What is
missing is the domain, which says where the signature is valid.

## The hole

`ClaimDesk` pays ether against claims that an issuer signed. A claim names the recipient, the
amount and a nonce, and each nonce pays once on a desk. The same desk is deployed on several
chains with the same issuer, and the digest that the issuer signs contains neither the chain id nor
the address of the desk. A signature that is valid for one desk is therefore valid for every desk
with the same issuer. Each desk tracks its nonces on its own, so a nonce that was paid on one
chain is still unused on the others.

## The attack

The PoC (`poc/CrossChainReplay.t.sol`) deploys two desks with the same issuer, one for chain 1 and
one for chain 10, and funds each with 10 ether. The attacker holds one claim of 1 ether that the
issuer signed for the desk on chain 1. It cashes the claim in there, as intended. It then presents
the same signature to the desk on chain 10, which pays it again. The PoC records the predicate
`attacker_profit` for the asset `eth`, measured on the second payment.

## The variants

The PoC exposes two knobs, which `testFuzz_variants` draws at random together with the attacker
address and the attacker's starting balance:

| Knob | Meaning | Replay value | Range searched |
|---|---|---|---|
| 0 `other_chain` | the chain id of the second desk | 10 | 1 to 16 |
| 1 `amount` | the amount of the claim, in wei | 1 ether | 1 wei to 5 ether |

A variant is the same replay with another amount, or onto a second desk that runs on the same
chain id as the first one, for example a second deployment on one chain.

## The four patches

| Patch | Change | Label and why |
|---|---|---|
| `good` | The digest contains `block.chainid` and the address of the desk. | Closes the root cause: a signature is valid for one desk on one chain. Behavior, storage layout and ABI stay the same. |
| `overfit` | The digest contains `block.chainid`. | Blocks the original PoC, whose second desk is on another chain. The digest still does not name the desk, so a second desk on the same chain id accepts the signature; knob 0 set to 1 reaches it. |
| `destructive` | `claim` reverts unconditionally. | Blocks the replay by disabling every claim. The benign tests that claim fail. |
| `regressing` | The `good` change, and the event `Claimed` gains the nonce as a third argument. | Closes the hole and keeps the benign tests passing, but changes an event that integrations read, a breaking events change. |
