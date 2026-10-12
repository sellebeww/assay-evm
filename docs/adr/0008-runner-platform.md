# ADR 0008: Runner platform

- Status: Accepted
- Date: 2026-10-03

## Context

The runner image (ADR 0003) executes all untrusted code. The primary development machine is a Mac
with Apple Silicon (linux/arm64 under Docker Desktop). Hosted CI runners are typically
linux/amd64. Running an amd64 image on arm64 works through emulation, which is slower and adds an
emulation layer underneath every sandboxed run.

Availability of the pinned components at the time of this decision:

| Component | linux/amd64 | linux/arm64 |
|---|---|---|
| Base image `debian:trixie-slim` (multi-platform index) | yes | yes |
| Foundry v1.8.4 (official release archives with checksums) | yes | yes |
| solc 0.8.36 (official static builds, binaries.soliditylang.org) | yes | yes, published from 0.8.31 onward |
| forge-std v1.17.0 (Solidity source) | platform independent | platform independent |

Components of later phases: Aderyn publishes `aarch64-unknown-linux-gnu` builds. Slither and
Halmos are Python packages; the availability of their native dependencies (in particular the
solver used by Halmos) on arm64 is verified in their own phases.

## Decision

- One Dockerfile builds the image for both platforms. The download stage is selected through
  `TARGETARCH`, and `docker/runner/versions.lock` records one checksum per platform for every
  binary.
- The image is built natively for the host: linux/arm64 on Apple Silicon, linux/amd64 on x86-64
  machines and in CI. No emulation is used by default.
- `make image RUNNER_PLATFORM=linux/amd64 RUNNER_IMAGE=assay-runner:dev-amd64` builds the amd64
  variant on an arm64 host, and `make image-check` with the same two variables runs its smoke
  check under emulation. This is for cross-checks only.
- If a component of a later phase is unavailable for one platform, a new ADR decides between
  emulating only that tool and moving the whole image to amd64, and records the measured cost.

## Consequences

- Sandboxed runs on the development machine are native, and no emulator sits inside the trust
  boundary.
- Every binary has two checksums to maintain, one per platform.
- Image IDs differ between platforms and, because layer timestamps are not yet normalized,
  between builds. A recorded image digest therefore identifies a local build, not a portable
  artifact. Before the evidence bundle format is fixed (Phase 2), replay needs a rule for
  comparing environments across machines, for example the content of `versions.lock` plus the
  reported tool versions.
- Verification status: both variants build from the same Dockerfile and pass `make image-check`
  on an Apple M1 host, linux/arm64 natively and linux/amd64 under emulation.
- Measured cost of emulation for the smoke project, over repeated runs: solc compilation took
  1.2 to 4.2 seconds under emulation against 0.45 to 1.4 seconds natively, and in back-to-back
  pairs the emulated run took 1.4 to 2.3 times as long. Timings vary with host load. Fuzzing and
  symbolic runs are expected to slow down by a similar factor, which is why emulation is not the
  default.
- For the smoke project, the arm64 and amd64 images produce identical bytecode, deployed bytecode
  and metadata. A determinism check across both platforms on the fixtures is a follow-up task
  for Phase 2.
- `assay doctor` (Phase 7) reports the platform of the image and whether it runs under emulation.
