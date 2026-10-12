# ADR 0012: Patches that cannot be applied, and when verification stops

- Status: Accepted
- Date: 2026-10-03

## Context

`assay verify` applies a candidate patch to a snapshot of the vulnerable project and runs the
oracles on both revisions. The patch is untrusted input. Ingest applies it with its own parser,
never with `git apply`, and refuses paths that leave the tree, symlinks, binary content,
protected paths (tests, PoC, harness, configuration) and paths outside the allowed scope
(`src/` by default).

The IntegrityOracle runs first. Its design lists the failure reasons `protected_path_modified`,
`out_of_scope`, `path_traversal`, `symlink`, `binary_file`, `vacuous_patch`, `special_casing` and
`environment_sniffing` (the same list the fixture checker accepts as integrity reasons). It
stops verification early only for traversal, symlinks and binary files; in every other case the
remaining oracles run, so that the report is complete.

Three cases were not covered:

1. A patch with a protected or out-of-scope path is refused by the patch application itself, so
   no patched revision exists that the remaining oracles could run on.
2. A patch can fail for reasons that are not in the list: it does not parse as a diff, it
   exceeds a size limit, its context does not match the vulnerable sources, or the patched tree
   breaks an ingest rule (for example inline Foundry configuration, ADR 0009).
3. An empty patch is a meaningful input: it is the baseline "change nothing", and verifying it
   must show that the exploit still reproduces. The ledger, however, refused a patch row with an
   empty diff.

## Decision

- Verification stops after the IntegrityOracle, and nothing from the patch runs, when the patch
  was not applied or when the IntegrityOracle reports an integrity violation. Integrity
  violations are `path_traversal`, `symlink`, `binary_file`, `protected_path_modified`,
  `out_of_scope` and `ingest_rejected`; they end with exit code 5. The oracles that did not run
  are reported as skipped.
- Four reasons are added for patches that are not accepted: `malformed_patch`,
  `patch_too_large`, `patch_does_not_apply` and `ingest_rejected`. The first three are not
  integrity violations: the final verdict is `REJECTED` with exit code 1.
- A protected file that differs between the two revisions, detected by hashing after the patch
  was applied, is reported as `protected_path_modified` and is an integrity violation as well.
- `vacuous_patch`, `special_casing` and `environment_sniffing` do not stop verification: the
  remaining oracles run, the final verdict is `REJECTED`, and the exit code is 1.
- A patch with no bytes, or only whitespace, is valid and changes nothing. The ledger accepts an
  empty diff for a patch row.
- Accepted patch format: unified diffs of text files with `a/` and `b/` path prefixes, as
  `git diff` writes them, with or without `diff --git` headers. File creation and deletion are
  supported; renames, copies, mode changes, quoted paths and binary hunks are not. A hunk may
  apply at an offset from its stated line, but its context must match exactly (no fuzz).

## Consequences

- An exit code of 5 from `assay verify` always means that no container ran anything from the
  patch.
- A patch that only fails to apply is reported as `REJECTED`, not as an integrity violation, so a
  stale diff is not mistaken for a hostile one.
- Diffs produced with renames (`git diff -M`) must be produced again without rename detection.
- The classification matrix compares reasons by name; the four new reasons can appear among the
  reported failure reasons of a patch.
