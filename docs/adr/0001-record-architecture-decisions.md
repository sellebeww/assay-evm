# ADR 0001: Record architecture decisions

- Status: Accepted
- Date: 2026-10-02

## Context

Assay makes claims about patches, and the credibility of those claims depends on design choices
that must stay visible over time: what counts as evidence, which tools are pinned, which features
are deliberately left out. Choices made only in code or in conversation are lost or silently
reversed.

## Decision

Architecture decisions are recorded as Architecture Decision Records (ADRs) in `docs/adr/`.

- One decision per file, named `NNNN-short-title.md` with a four-digit sequence number.
- Each ADR has a status (Proposed, Accepted, Superseded by ADR NNNN) and the sections Context,
  Decision and Consequences.
- An accepted ADR is not rewritten. A changed decision gets a new ADR that supersedes the old one,
  and the old one is marked as superseded.
- An ADR is required for any change to a decision recorded here, for any change to a pinned tool
  version (base image, Foundry, solc, forge-std, analyzers, solver), and for any platform or
  fallback choice that affects results.

## Consequences

- The reasons behind the design remain reviewable next to the code.
- Pinned versions cannot drift without a written reason.
- Writing an ADR adds a small cost to every significant change; this cost is intended.
