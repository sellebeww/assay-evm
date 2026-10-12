# ADR 0015: Static analyzers in the runner image

- Status: Accepted
- Date: 2026-10-04

## Context

Phase 3 adds two static analyzers, Slither and Aderyn. Their output is an unverified hint
(evidence level E0) and never changes a status; only oracle runs do (ADR 0005). Like every other
program that reads a target project, they run in the sandbox runner (ADR 0003), in the same
image as forge, pinned in `docker/runner/versions.lock`, with every download verified by
sha256 at build time and no network at run time.

Until now the runtime image contained no shell, no interpreter and no package manager, and no
package manager ran during the build (`docs/sandbox.md`). The two analyzers do not fit that
shape unchanged:

- Slither is a Python program with 46 Python packages in its dependency closure. It compiles a
  Foundry project through crytic-compile, which runs `forge build --build-info`. crytic-compile
  imports `solc_select` when it is loaded; solc-select downloads compilers.
- Aderyn is a Rust binary with official release archives and checksums for both
  `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` (version 0.6.8). It finds the
  compiler through svm-rs, which fetches a list of solc releases from the network before it
  uses a compiler, unless the required version is already installed in svm's data directory.
  It ignores the `solc` path in `foundry.toml`.

ADR 0008 asks for a new decision if a component is missing for one platform. Both analyzers
exist for linux/amd64 and linux/arm64, so the image stays native on both platforms and no
emulation is needed.

## Decision

- **Aderyn** v0.6.8 is installed from the official release archive for the target platform,
  verified with `ADD --checksum` against the sha256 in `versions.lock` (equal to the release's
  own `.sha256` files). The archive is unpacked with Python's `tarfile` in a build stage,
  because the base image has no `xz` program.
- **Python** is CPython 3.12.15 from python-build-standalone (release 20261001), a relocatable
  build that needs only glibc from the pinned Debian base. The archive is verified with
  `ADD --checksum` (one sha256 per platform, from the release's `SHA256SUMS`). Neither Debian's
  `python3` (which would need the system package manager) nor the official Python image (a
  second, different glibc) is used.
- **Slither** 0.11.6 and its dependencies are listed in `docker/runner/slither-requirements.txt`,
  every distribution pinned by sha256, generated once with `uv pip compile --universal
  --generate-hashes`. `versions.lock` records the sha256 of that file, and the build checks it.
  pip installs the list in a build stage, into a virtual environment at `/opt/assay/slither`,
  with `--require-hashes --no-deps --only-binary :all:`: no dependency resolution, no source
  build, no code from a setup script. pip, `ensurepip`, IDLE, Tkinter and the test suite of the
  standard library are removed afterwards, and byte code is compiled at build time because the
  runtime filesystem is read-only.
- **solc-select** is not installed. A stand-in module, `docker/runner/solc_select/`, provides the
  three functions crytic-compile imports: it reports no installed compiler and refuses every
  installation. On a Foundry project crytic-compile never calls them; if any code path did, it
  would fail instead of downloading.
- **svm layout for Aderyn.** The pinned solc is registered as the one installed svm version,
  `/opt/assay/share/svm/0.8.36/solc-0.8.36` (a symlink to `/opt/assay/bin/solc`), and the image
  sets `XDG_DATA_HOME=/opt/assay/share`. With `HOME=/tmp` (the empty tmpfs), svm-rs looks there,
  finds the installed version and fetches nothing.
- **Python settings** in the image: `PYTHONSAFEPATH=1` (neither the working directory, which is
  the project, nor the script directory is on the module path), `PYTHONNOUSERSITE=1`,
  `PYTHONDONTWRITEBYTECODE=1`, and `PYTHONHASHSEED=0` so that Slither's output order repeats.
- **Analyzer configuration from the project** is treated like `foundry.toml`: ingest leaves
  `slither.config.json` and `aderyn.toml` at the project root out of the snapshot (in any letter
  case) and keeps them as evidence. Otherwise a project could switch detectors off, filter its
  own files out of the results, force another compilation framework, or set environment
  variables for Aderyn.
- The runner allowlist accepts `slither <target> [--json -] [--fail-none] [--disable-color]`
  and `aderyn <target> [--output /work/scratch/<name>.json]`, where
  `<target>` is `.` or a relative path inside the project. Slither's report goes to standard
  output only; Aderyn's to a plain file in the scratch mount, which the host reads without
  following symlinks and with a size limit.
- The image labels record `assay.python.version`, `assay.slither.version` and
  `assay.aderyn.version`, so evidence bundles record the analyzer versions with the others.

## Consequences

- The runtime image now contains one interpreter, the Python that runs Slither. It still has no
  shell and no package manager. An interpreter in the image makes some attacks easier for code
  that already runs inside the container; the container policy (no network, read-only root,
  no capabilities, non-root user, limits) is unchanged and applies to the analyzers as to forge.
- pip runs during the build, in a stage whose result is copied into the runtime image. The
  documented build-time property changes from "no package manager runs during the build" to
  "no system package manager runs during the build; pip installs hash-pinned wheels in one
  build stage".
- The image grows from about 0.17 GB to about 0.45 GB.
- A new Slither version means regenerating `slither-requirements.txt`, updating its sha256 and
  `SLITHER_VERSION` in `versions.lock`, recording the golden files in `tests/data/analyzers/`
  again, and an ADR, as for every pinned tool.
- Aderyn and Slither compile with the single pinned solc. A project whose pragma excludes 0.8.36
  cannot be analyzed; Aderyn then fails instead of downloading another compiler.
- Evidence bundles written before this change record fewer tool versions than a bundle written
  with the new image; `assay replay` compares tool versions and `versions.lock`, which both
  changed, so such a bundle replays only with an image built from the older `versions.lock`.
