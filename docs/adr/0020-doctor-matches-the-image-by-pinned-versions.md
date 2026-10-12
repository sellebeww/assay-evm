# ADR 0020: `assay doctor` matches the runner image to `versions.lock` by pinned versions

- Status: Accepted
- Date: 2026-10-12

## Context

`assay doctor` has to say whether the local runner image is the one that `docker/runner/versions.lock`
describes, and which tool versions it holds. Two obvious ways do not work.

1. Comparing the image digest with `versions.lock`. The file pins the inputs of the build (base
   image, release archives, checksums), not its result. The id of the built image differs between
   builds of the same file and between platforms, because layer timestamps are not normalized
   (ADR 0008, ADR 0013). No digest of the image can be written into the file ahead of time.
2. Running `forge --version`, `slither --version` and the other tools inside the image from
   `assay doctor`. Every program that runs in the sandbox must be on the argv allowlist, and the
   allowlist rejects `--version` for the tools on purpose; tests (including a security test) assert
   it. Widening it only for a diagnostic command would change a security boundary for a
   convenience.

## Decision

- `assay doctor` compares the tool versions that the image declares in its labels
  (`assay.<tool>.version`, which the Dockerfile writes from the build arguments taken from
  `versions.lock`) with the values in `versions.lock`. A missing label or a different value is a
  problem, with the fix "run make image". The image id is shown for information only.
- The binaries are checked by `make image-check`, which runs each tool and compares its output
  with `versions.lock`. `assay doctor` says so in its documentation and does not claim more than
  the labels show.
- The symbolic image is optional. A missing one is reported as information with a fix, not as a
  problem, so that exit code 4 means that the default flow cannot run.
- The platform check compares the architecture of the image with the architecture of the Docker
  daemon; a difference is reported as emulated, as in ADR 0008 and ADR 0018, and is not a problem.

## Consequences

- An image whose labels were edited by hand would pass the version check. The labels are
  metadata, not a measurement; the evidence bundle and `assay replay` rely on the same labels
  (ADR 0013), and `make image-check` is the check that runs the tools.
- `assay doctor` needs `docker/runner/versions.lock` from a source checkout. Without it the
  version check is reported as a problem, never as a pass.
- No allowlist entry was added.
