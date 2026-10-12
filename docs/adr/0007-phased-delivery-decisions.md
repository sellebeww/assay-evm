# ADR 0007: Phased delivery decisions

- Status: Accepted
- Date: 2026-10-02

## Context

The full scope of Assay spans eleven phases (see `docs/roadmap.md`). The order of delivery
determines when the central claim can first be demonstrated end to end: a patch is classified,
the result is recorded, and the evidence can be replayed. Some features, such as a server or a
dashboard, would widen the attack surface without serving that claim.

## Decision

1. The VariantOracle is delivered in two steps.
   - Basic version, Phase 2: fuzz the PoC parameters through Foundry (`testFuzz_variants`) with a
     fixed seed and a configurable number of runs, plus the sanity check that the same search finds
     the exploit on the vulnerable revision.
   - Full version, Phase 4: call sequences (invariant mode), an alternative attacker contract,
     profiles, counterexample confirmation with a generated `variant_poc`, and Medusa as an
     optional second engine.
2. The evidence bundle and `assay replay` are delivered in Phase 2, together with the first
   oracles, and not with the reporting work in Phase 7.
3. No server mode, no network API and no dashboard are built. Phase 10 is the final audit.
4. Names: the PyPI distribution is `assay-evm`, the Python import name is `assay`, and the CLI
   command is `assay`.

## Consequences

- From Phase 2 on, every verification produces a bundle that can be replayed offline, so every
  later feature is built on replayable evidence.
- In Phase 2 the basic VariantOracle is the variant oracle used for the final verdict. The bounds
  of a Phase 2 `VERIFIED_WITHIN_BOUNDS` verdict contain fuzz bounds only (seed and runs); invariant
  and symbolic bounds are added in Phase 4.
- Every `overfit` patch in the development fixtures must be defeatable by parameter fuzzing of its
  PoC alone, because the Phase 2 classification matrix runs before the full variant search exists.
- The Phase 4 matrix re-run must show that the full version does not change the verdicts of
  `good` and `overfit` patches.
- Assay remains a local, single-user CLI. CI use goes through the CLI and a composite GitHub
  Action, not through a service.
- The `-evm` suffix makes the scope explicit in the distribution name. Installation instructions
  must state that `assay-evm` installs the `assay` package and command.
