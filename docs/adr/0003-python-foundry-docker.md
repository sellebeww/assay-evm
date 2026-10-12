# ADR 0003: Python, Foundry and Docker

- Status: Accepted
- Date: 2026-10-02

## Context

Assay must orchestrate Solidity tooling, parse untrusted tool output strictly, and execute
untrusted code (target projects, PoCs, patches, analyzer binaries) without exposing the host.
The main analyzers (Slither, Halmos) are Python tools, and Foundry is the common Solidity
toolchain for testing and fuzzing.

## Decision

- Language: Python 3.12, `src/` layout, typed throughout.
- Tooling: uv for environments with a committed `uv.lock`, hatchling as build backend, Typer for
  the CLI (Rich only on a TTY and without `NO_COLOR`), Pydantic v2 strict models for every
  untrusted input, ruff for lint and format, mypy in strict mode, pytest with pytest-cov and
  hypothesis.
- Runtime dependencies are limited to typer, pydantic, rich and httpx. Anything else needs a stated
  reason.
- EVM tooling: Foundry (`forge build`, `forge test`, `forge inspect`, fuzz and invariant testing).
  No mainnet fork and no RPC endpoint.
- Execution: one Docker runner image (`assay-runner:dev`) with Foundry, a baked-in solc and pinned
  forge-std, later Slither, Aderyn and Halmos. Every run uses `--network none`, a read-only root
  filesystem, `--cap-drop ALL`, `no-new-privileges`, a non-root user, pids, memory and CPU limits,
  a wall-clock limit and capped output. Commands are passed as an argument vector checked against
  an allowlist; no shell is involved.
- Every executed component is pinned in `docker/runner/versions.lock` (base image digest, tool
  versions, download checksums). "latest" is never used.

## Consequences

- Integration and security tests need Docker; `make check` (lint, types, unit tests) does not.
- On macOS, Docker Desktop is required. Whether the image runs natively on arm64 or under amd64
  emulation is decided in ADR 0008.
- The sandbox does not cover kernel vulnerabilities, flaws in the Docker Desktop virtual machine or
  hardware side channels; the documentation states this.
- Nothing can be downloaded at run time, so every tool and library must be present in the image at
  build time.
