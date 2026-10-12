# ADR 0011: Run trees for the shared harness and the PoC

- Status: Accepted
- Date: 2026-10-03

## Context

A PoC derives from `AssayPoC` and benign tests call `recordBehavior`; both come from the shared
harness `solidity/AssayExploit.sol`. Fixtures do not vendor the harness. The PoC lives in `poc/`,
next to the benign tests in `test/`.

The snapshot configuration written by ingest compiles only `src/`, `test/` and `script/`, has no
remappings other than forge-std, and the sandbox allowlist has no option to change the test
directory. Measured with the pinned Foundry v1.8.4: files under `poc/` are not compiled and
`forge test --match-path 'poc/*'` finds no tests.

Options considered:

1. Bake the harness into the runner image and add a remapping for it. The harness could not be
   changed by a project, but every harness change would need an image rebuild, and a stale image
   would silently run an old harness unless a separate staleness check existed.
2. Add a Foundry profile whose test directory is `poc/` and allow `--profile` in the sandbox.
   This extends the rewritten configuration and the allowlist, and every security setting would
   have to be repeated and tested for the second profile.
3. Build separate run trees in which Assay places the harness and the PoC itself.

## Decision

Option 3.

- Every run tree contains `src/` of the revision under test and a copy of the repository's
  `solidity/*.sol` under `assay/`. Test and PoC files import the harness as
  `assay/AssayExploit.sol`; with no remapping for that prefix, solc resolves it to the copy at
  the root of the tree.
- The benign tree contains the project's `test/`. The PoC tree contains the PoC directory in the
  place of `test/`, and no benign tests.
- Both trees go through the ingest snapshot step, so they run under the same rewritten
  configuration as any project.
- A project or fixture must not contain a top-level `assay/` directory.

## Consequences

- The harness that runs is always the one in the repository, without an image rebuild. The
  benchmark freeze, which hashes `solidity/`, covers it.
- The PoC and the benign tests never compile or run together. A benign test cannot import the
  PoC, and a PoC can import only `src/`, its own directory, forge-std and the harness.
  `make fixtures-check` enforces these import rules for fixtures.
- The relative path between a PoC and `src/` is the same in the fixture and in the PoC tree, so
  `../src/...` imports work unchanged.
- The oracles must build their run trees the same way, so that their observations are
  comparable with the fixture checker's. Ingest or the oracles must reject a project with its own
  top-level `assay/` directory instead of letting it shadow the harness.
