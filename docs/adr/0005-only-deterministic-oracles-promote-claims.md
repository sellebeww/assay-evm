# ADR 0005: Only deterministic oracles may promote claims

- Status: Accepted
- Date: 2026-10-02

## Context

Assay receives assertions from several sources: static analyzers, language models, humans and the
target project itself (test names, comments, revert messages). None of these sources can be
trusted to decide whether a vulnerability is real or a patch is acceptable. If any of them could
change a status directly, the verdicts would carry no weight.

## Decision

- Every statement Assay makes is a claim with status `asserted`, `trusted`, `refuted` or
  `inconclusive`.
- A claim may become `trusted` or `refuted` only when an `oracle_run` with a matching verdict
  exists. The only public function that promotes a claim is
  `promote_claim(claim_id, oracle_run_id)`. SQLite triggers enforce the same rule.
- An oracle is a deterministic check that returns `PASS`, `FAIL` or `INCONCLUSIVE` with structured
  reasons. Determinism means fixed seeds, pinned tools and normalized output, so the same inputs
  give the same verdict.
- Results that are not reproducible never count as positive. Disagreeing runs, timeouts,
  out-of-memory conditions and solver "unknown" results are `INCONCLUSIVE`, never `PASS`.
- Final verdict rule: `VERIFIED_WITHIN_BOUNDS` only if every required oracle passes; `REJECTED` if
  any oracle fails; otherwise `INCONCLUSIVE`. While the oracle set is incomplete, a patch that
  passes every existing oracle is `INCONCLUSIVE` with reason `missing_oracles`.
- Every `oracle_run` records argv, image digest, seed, exit code, verdict, reason and a trace blob,
  and is immutable.

## Consequences

- Analyzer output and model output can raise a finding to a candidate or a hypothesis (evidence
  level E0) but never further.
- Every positive verdict can be traced to specific, replayable oracle runs.
- Oracles must be written so that their verdicts are reproducible; flaky checks surface as
  `INCONCLUSIVE` instead of being hidden.
