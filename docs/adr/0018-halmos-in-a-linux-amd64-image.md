# ADR 0018: Halmos in a linux/amd64 image

- Status: Accepted
- Date: 2026-10-05

## Context

Phase 4 adds an optional symbolic oracle: Halmos runs properties with symbolic parameters
(`solidity/AssayCheck.sol`) and reports, per property, that it found no counterexample within
its bounds, a counterexample, or an unknown result. Like every program that reads a target
project, Halmos must run in the sandbox runner (ADR 0003), pinned in
`docker/runner/versions.lock`, verified by sha256 at build time and offline at run time.

Halmos is a Python package. The pinned release, 0.3.3 (the latest at the time of this decision),
declares exact or narrow pins of its two solver dependencies:

- `z3-solver==4.12.6.0`: the Python binding with which Halmos builds every query, loaded in the
  Halmos process. PyPI has a `manylinux2014_x86_64` wheel of this version and no linux/arm64
  wheel; arm64 wheels exist only from 4.15.0.0 on.
- `yices-solver>=2.6.4,<2.6.5`: the `yices-smt2` binary that answers the queries (Halmos's
  default solver). PyPI has a `manylinux_2_28_x86_64` wheel of 2.6.4.post23 and no linux/arm64
  wheel. Halmos's own solver download list has no linux/arm64 build of Yices either.

ADR 0008 builds the runner natively for the host and asks for a new decision when a component
is missing for one platform: emulate only that tool, or move the whole image to amd64, with the
measured cost.

Options considered:

1. Build z3 4.12.6.0 and Yices from source for arm64 in a build stage. That needs a C++
   toolchain from the system package manager, which no runner build stage uses (ADR 0015), and
   tens of minutes of compilation per build.
2. Install a newer z3-solver that has arm64 wheels, overriding Halmos's exact pin. Halmos's
   behavior with another z3 is untested by its authors; a result would no longer be a result of
   the pinned release.
3. Move the whole runner image to linux/amd64. Every forge run, every fuzz campaign and the
   classification matrix would run under emulation on Apple Silicon, 1.4 to 2.3 times slower
   (ADR 0008), to benefit a check that is off by default.
4. Keep the runner native and build a second image, for linux/amd64 only, that adds Halmos.

## Decision

Option 4.

- The Dockerfile has two targets. `runner` is the existing image, built for the native platform
  as before (ADR 0008). `runner-symbolic` is `runner` plus Halmos and its solvers, and is always
  built for linux/amd64. `make image` builds both: `assay-runner:dev` natively and
  `assay-runner-symbolic:dev` for linux/amd64. On an amd64 host both are native; on an arm64
  host the symbolic image runs under emulation.
- Halmos is installed like Slither (ADR 0015): a virtual environment `/opt/assay/halmos` of the
  pinned Python, created in a build stage by pip with `--require-hashes --no-deps
  --only-binary :all:` from `docker/runner/halmos-requirements.txt` (every distribution pinned
  by sha256; the build checks the file's own sha256 against `versions.lock`). pip does not reach
  the image. The stage refuses to build for any platform other than linux/amd64.
- The solver is z3 4.12.6.0 from the pinned `z3-solver` wheel, which carries both the binding
  and a `z3` binary; Halmos runs with `--solver z3` on every platform. Yices, Halmos's default,
  is not installed (`yices-solver` is left out of the requirements; pip runs with `--no-deps`):
  under the emulation of Docker Desktop on Apple Silicon, `yices-smt2` from the pinned wheel
  stopped with SIGILL on its first query, so every property ended as an error. One solver for
  all hosts keeps results comparable between an emulated and a native run. Halmos never
  downloads a solver: the binary is present, and the container has no network.
- `versions.lock` records `HALMOS_VERSION`, `HALMOS_REQUIREMENTS_SHA256` and
  `Z3_SOLVER_VERSION`. The image labels `assay.halmos.version` and `assay.z3.version` name them,
  so that a bundle records them. `make image-check` checks the Halmos and z3 versions against
  `versions.lock` and runs Halmos on a smoke project (`tests/data/symbolic_smoke/`), offline,
  under the same container policy.
- The configuration of the symbolic run trees switches Foundry's dynamic test linking off
  (`dynamic_test_linking = false`): with it, forge 1.8.4 rewrites `new C()` in tests into a
  `deployCode` cheat code, which Halmos 0.3.3 does not support, and every `setUp()` failed.
- The sandbox allowlist gets one command, `halmos`, with a fixed root and build-output
  directory, a JSON report in the scratch mount, a property prefix, a loop bound, the solver
  `z3`, an assertion timeout and a thread count. `--ffi`, `--config`, `--solver-command` and
  the query dumps are not on the list. Ingest leaves a project's `halmos.toml` out, and the
  symbolic oracle refuses sources with Halmos's NatSpec options (`custom:halmos`), as ingest
  refuses inline Foundry configuration (ADR 0009).
- The symbolic oracle uses the symbolic image only for Halmos. Compiling and replaying a
  counterexample (`variant_poc.t.sol`, three replays) uses the regular runner image, natively,
  so that a confirmed variant is a Foundry result on the same image as every other oracle.
- Halmos is licensed under the AGPL-3.0. It runs as a separate program inside the image and is
  not linked into Assay; the license is recorded for the third-party notices.

## Consequences

- On an arm64 host the symbolic oracle runs under emulation and is slower; the rest of Assay
  stays native. Measured cost, Apple M1, Docker Desktop: see "Measurements" below.
- Building the symbolic image on an arm64 host downloads and installs the amd64 Python packages
  under emulation, which is slow and sensitive to the network. pip runs with a 120 s timeout and
  10 retries; a truncated download fails its sha256 and the build stops.
- Halmos treats `vm.addr` (and so forge-std's `makeAddr`) as an uninterpreted function: an
  account made that way is symbolic and may coincide with a deployed contract. Properties
  therefore write fixed accounts as constants (`solidity/AssayCheck.sol` says so).
- Halmos deploys contracts at its own addresses, not Foundry's. A counterexample whose values
  include such an address cannot be replayed with Foundry and ends INCONCLUSIVE
  (`flaky_counterexample`), never FAIL.
- Two images per host to build and keep; a bundle of a verification with `--symbolic` records
  both environments, and `assay replay` needs both (the symbolic one chosen like the runner,
  ADR 0013).
- The runner image is unchanged on both platforms; existing bundles and the matrix are not
  affected.
- When Halmos releases a version whose solver pins have arm64 wheels, a new ADR can move the
  symbolic image to the native platform.

## Measurements

Apple M1, Docker Desktop, `assay-runner-symbolic:dev` under emulation: the symbolic oracle on one
patch of the access-control, delegatecall and unchecked-call fixtures took 12 to 40 s, including
two Halmos runs (each with its own `forge build`) and, for a counterexample, three native Foundry
replays. The rounding fixture's property ran out of the 4096 MiB memory limit within about a
minute. Per-patch durations of the last run are in `docs/symbolic.md`; the regular runner and the
classification matrix are unaffected.
