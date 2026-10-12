# ADR 0002: Verification first

- Status: Accepted
- Date: 2026-10-02

## Context

A patch that makes the existing tests pass can still be wrong in several ways. It can block only
the exact proof-of-concept (PoC) and leave a close variant open (overfit). It can disable
legitimate behavior (destructive). It can close the hole while changing storage layout, ABI or
events (regressing). Tests alone cannot tell these cases apart from a correct patch (good).

Static analyzers for Solidity already exist. Another detector would add little. What is missing
is a reproducible way to decide whether a proposed fix is acceptable, and to state the limits of
that decision.

## Decision

Assay is a verification tool, not a detector.

- The pipeline is Detect, Prove, Fix, Verify. Verify is the core of the project.
- Detect reuses existing analyzers (Slither, Aderyn). Their output is an unverified hint
  (evidence level E0, status `candidate (unverified)`), never a confirmed vulnerability.
- Prove requires a PoC that reproduces on the vulnerable revision (evidence level E1).
- Verify runs deterministic oracles (integrity, exploit, variant, behavior, regression, and an
  optional symbolic oracle) against the patched revision.
- The only positive final verdict is `VERIFIED_WITHIN_BOUNDS`: no variant was found within the
  recorded bounds (seeds, runs, depth, time, symbolic bounds). The other final verdicts are
  `REJECTED` and `INCONCLUSIVE`.
- Every verification produces an evidence bundle that can be replayed offline.

## Consequences

- Assay makes no claim about detection rates on real code.
- A positive verdict is never stated as a proof of absence; reports always carry the bounds that
  actually ran.
- Most engineering effort goes into oracles, evidence formats and honest reporting rather than
  into new detection rules.
- Classes that existing analyzers miss can still be verified, as long as a PoC exists.
