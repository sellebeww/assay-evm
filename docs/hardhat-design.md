# Hardhat support: design

Status: **design only**. Assay verifies Foundry projects. This page says what Hardhat support
would need, which part of the code is already a seam, and why no adapter is implemented yet.

## Why it is not a small change

Every oracle runs `forge` inside the sandbox image. The PoC is a Foundry test deriving from
`AssayPoC`; the variant search generates Foundry fuzz and invariant tests; the behavior oracle
compares `forge test --json` results; the regression oracle reads `forge inspect` layouts, ABIs
and events. Ingest rewrites `foundry.toml` and rejects inline configuration (ADR 0009). The
runner image has Foundry, solc, Slither, Aderyn and Halmos, and no Node.js toolchain.

## Approach

A Hardhat project is not run with Hardhat's JavaScript test runner. Assay would **compile it with
Hardhat's own configuration read as data, then run the oracles on a generated Foundry project**:

1. Ingest reads `hardhat.config.*` statically (a text parse of the solc version, optimizer
   settings, remappings and source paths is not possible for arbitrary JavaScript, so the first
   version would accept only a JSON export, `npx hardhat flatten`-style input produced by the user,
   or a small declarative file `assay.toml`). It never executes the project's JavaScript on the
   host.
2. The sources and `node_modules` dependencies that the contracts import are copied into a Foundry
   layout (`src/`, `lib/`) with a generated `foundry.toml` and remappings.
3. From there the existing oracles run unchanged. PoCs for Hardhat projects are Foundry tests,
   as today.

This keeps one execution model and one sandbox policy. It does not run Hardhat plugins, tasks or
network forks.

## The seam

The code that knows the project layout is ingest (`assay.ingest`) and the Foundry adapter
(`assay.analyzers.foundry`). A `ProjectLayout` interface would sit in front of ingest with two
implementations: `FoundryLayout` (today's behavior) and `HardhatLayout`
(the conversion above). Its contract: take an untrusted directory, return a normalized snapshot
tree with a Foundry `src/`, `test/` and generated configuration, or refuse with the existing
ingest errors (symlinks, traversal, inline config). The snapshot hash, bundle format and replay
then stay identical.

Open questions that need an owner's decision: whether a JSON export is acceptable as the input
format, how to pin dependencies from `node_modules` without network, and whether to add Node.js to
the runner image (a larger image and a larger attack surface) or require the user to vendor
dependencies.

## What is not planned

Running Hardhat tests, Hardhat plugins, TypeScript tests, forked-network tests and any host-side
execution of project JavaScript.
