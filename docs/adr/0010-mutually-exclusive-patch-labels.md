# ADR 0010: Mutually exclusive patch labels

- Status: Accepted
- Date: 2026-10-03

## Context

Every fixture patch carries one of four labels: `good`, `overfit`, `destructive` or
`regressing`. The labels are the ground truth of the classification matrix, so a patch must fit
exactly one of them.

Two looser definitions of the last two labels were considered:

- `destructive` as "a function is missing or changed". A patch that removes a function also
  changes the ABI, which is the defining observation of `regressing`.
- `regressing` as "the interface changed, benign tests pass or fail". A patch that changes the
  interface and breaks a benign test would then fit both `regressing` and `destructive`.

With overlapping labels, the expected verdict and reason of a patch depend on which definition a
reader applies, and a matrix mismatch cannot be told apart from a labelling ambiguity.

## Decision

The labels are defined by three observations, and the table in `docs/fixture-spec.md`, section
2, is authoritative:

| Label | Original PoC | Variant search | Benign tests | Interface |
|---|---|---|---|---|
| `good` | BLOCKED | BLOCKED | pass | same |
| `overfit` | BLOCKED | EXPLOITED | pass | same |
| `destructive` | BLOCKED | BLOCKED | FAIL | same or changed |
| `regressing` | BLOCKED | BLOCKED | pass | changed |

- A failing benign test makes a patch `destructive`, whatever happened to the interface.
- `regressing` requires passing benign tests and a breaking interface change (storage layout,
  ABI or events).
- Every patch must block the original PoC. A patch whose observations match no row is invalid
  and is rewritten; its label is not changed.
- A `destructive` patch keeps the symbols that the benign tests and the PoC reference, so that
  every variant compiles. It disables behavior instead of deleting declarations.

## Consequences

- Each patch has exactly one expected final verdict and a fixed set of acceptable reasons:
  `variant_found` for `overfit`, `benign_test_failed` or an integrity reason for `destructive`,
  and the reason matching an interface kind for `regressing`.
- `make fixtures-check` can decide every row mechanically from the observations.
- A patch that only removes a function cannot be `destructive` unless a benign test fails
  because of it; when the benign tests still pass, it is `regressing` (`abi_changed`).
