# Demo project for the GitHub Action

> **Intentionally vulnerable.** The code in this directory is test material with a known hole.
> It must never be deployed or used to hold real funds.

This directory is a small Foundry project that the workflow
[`action-demo.yml`](../../.github/workflows/action-demo.yml) uses to try the Assay GitHub Action
(see [docs/github-action.md](../../docs/github-action.md)). It is a copy of the fixture
`fixtures/reentrancy/single_function` without its candidate patches and without its expected
results, so that a pull request can bring the patch.

| Path | Content |
|---|---|
| `src/Vault.sol` | A vault with a single-function reentrancy hole in `withdraw`. |
| `test/Vault.t.sol` | Benign tests of the vault's normal behavior. |
| `poc/` | The exploit (`VaultReentrancy.t.sol`) and a solvency invariant (`VaultSolvency.t.sol`). |
| `foundry.toml` | Plain Foundry configuration; Assay replaces it with its own when it runs. |

`forge-std` and the shared exploit harness are not vendored: the sandbox image provides both.

## Trying it

A pull request that changes `src/Vault.sol` is verified against the PoCs in `poc/`:

- moving the balance update in `withdraw` in front of the ether transfer closes the hole, and the
  verdict is `VERIFIED_WITHIN_BOUNDS` (which is not a proof of absence);
- a check after the transfer that keeps the stale write passes the original exploit but not the
  variant search, and the verdict is `REJECTED`;
- a pull request that changes nothing under `src/` gives "no changes in scope".

The four candidate patches and their labels are in the fixture's `patches/` directory.
