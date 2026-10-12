# ADR 0009: Reject inline Foundry configuration at ingest

- Status: Accepted
- Date: 2026-10-03

## Context

Ingest replaces a project's `foundry.toml` with a fixed configuration: `ffi = false`, empty
`fs_permissions`, the image's solc, no RPC endpoints, and Assay's own fuzz settings. The project's
file is kept only as evidence.

Foundry also reads configuration from Solidity comments. A NatSpec comment such as
`/// forge-config: default.fs_permissions = [{ access = "read", path = "/" }]` on a test function
or contract applies that setting to the test, on top of `foundry.toml`. With the pinned
Foundry v1.8.4 in the runner image, under the rewritten configuration:

- an inline `fs_permissions` setting made `vm.readFile("/etc/passwd")` succeed;
- an inline `ffi = true` had no effect (`vm.ffi` stayed disabled);
- an inline `fuzz.runs` setting was applied.

Inside the sandbox, file access reaches only the image, the read-only snapshot and the scratch
directory. Still, an inline setting could let a test write into the scratch directory, which is
a host directory whose content later stages read, and it could change the fuzz and invariant
bounds that oracles record. Both undermine the evidence, independent of the container's limits.

Foundry offers no switch that disables inline configuration.

## Decision

- Ingest rejects a project when any file whose name ends in `.sol` (any letter case) contains the
  text `forge-config`, in any letter case, anywhere in the file. The rejection uses the error code
  `inline_config`; commands map it to exit code 5 like every other ingest rejection.
- There is no allowlist of inline keys. Settings that affect a run (fuzz runs, seeds, depth) come
  only from Assay's configuration and command-line options, so that the recorded bounds are the
  bounds that ran.

## Consequences

- Projects that use inline configuration, for example per-test fuzz runs, are rejected until the
  comments are removed. The error names the file.
- A Solidity file that merely mentions the text (in an ordinary comment or a string) is rejected
  too. This false positive is accepted in exchange for a check that does not depend on how
  Foundry parses comments.
- If a later phase needs per-test settings, Assay passes them itself and records them in the
  bounds; such a change needs a new ADR.
- The security test for a hostile configuration (S1) covers the inline form as well as
  `foundry.toml`.
