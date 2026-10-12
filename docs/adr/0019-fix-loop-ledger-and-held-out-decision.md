# ADR 0019: The fix loop in the ledger, the integrity gate and the held-out decision

- Status: Accepted
- Date: 2026-10-05

## Context

`assay fix` asks a model for a patch, verifies it with the oracles, and repeats with feedback for
a bounded number of attempts. Three things were open when the loop was built:

1. The ledger lets a finding leave `PATCH_PROPOSED` for `VERIFIED_WITHIN_BOUNDS`, `REJECTED` or
   `INCONCLUSIVE` only on oracle runs that all lie on one patched revision of that finding. The
   verification of a human patch (`assay verify`) records its runs under a finding of its own, so
   it could not move the finding that `assay prove` reproduced. A patch that was refused before a
   patched tree existed (traversal, protected path, too large, does not apply) has no patched
   revision at all.
2. The loop must not teach the model the campaign it is judged by. A patch that passes every
   oracle with the seeds of the loop may still fail with other seeds.
3. A patch that the IntegrityOracle already rejects does not need the other oracles, which cost
   minutes. `assay verify` keeps running them for a patch that fails an integrity check without a
   hard violation, so that its report is complete (ADR 0012).

## Decision

- **Ledger.** `run_verification` can record a verification under an existing finding. The fix loop
  uses this: every attempt is a patch row (`source = model`, `attempt_no` is the attempt number)
  of the reproduced finding, with its own patched revision. The finding goes
  `REPRODUCED -> PATCH_PROPOSED` once a patch was judged, and stays there between attempts. The
  deciding verification then moves it to `VERIFIED_WITHIN_BOUNDS`, `REJECTED` or `INCONCLUSIVE`,
  naming the runs of that verification on its patched revision. When no patched revision carries
  the evidence (every patch was refused before it could be applied), the finding stays
  `PATCH_PROPOSED`, the result says so, and the verdict of the command is still `REJECTED`. The
  ledger is never given a status that its triggers would refuse, and the transition table is
  unchanged.
- **Integrity gate.** In the fix loop a failure of the IntegrityOracle of any kind ends the
  verification of that attempt: the other oracles are reported as skipped and nothing from the
  patch runs. `assay verify` is unchanged unless asked (`integrity_gate`).
- **Held-out decision.** The first attempt that passes every oracle is verified once more with a
  base seed taken from a different seed family (`held-out`) of the loop's base seed. Every
  campaign of that run (exploit replays, variant search, fuzz runs of the project's tests)
  derives from it, so it uses seeds that no attempt and no prompt has seen. Its verdict is the
  verdict of the loop; when it differs from the in-loop verdict, the result says so and the held-out
  verdict applies. The held-out run is recorded as patch `100 + n` of the finding. Its findings
  are not fed back to the model, and the loop does not continue after it: continuing would let the
  held-out seeds leak into later prompts. A patch that failed in the loop is rejected on evidence
  (a variant that three replays reproduced, a changed behavior, a changed interface) that another
  seed can only repeat, so the last judged attempt stands when the attempts run out.
- **Bundle.** The bundle of a fix loop is the bundle of the deciding verification plus
  `fix/history.json`, listed in the manifest like any other file, so that tampering with it is
  detected. The manifest format is unchanged. Replay re-runs the oracles only.
- **Exit codes.** 0 for `VERIFIED_WITHIN_BOUNDS`, 1 for `REJECTED`, 3 for `INCONCLUSIVE`, which
  includes a loop in which no reply gave a patch that could be judged and a loop that a budget
  limit ended before any patch was judged. 5 when the deciding patch was an integrity violation
  (the same cases as `assay verify`), so that 5 still means that nothing from the patch ran.

## Consequences

- The attempt history of a finding is its list of patch rows; the held-out verification of attempt
  `n` is the row `100 + n`.
- A single `assay fix` costs at most `--max-attempts` verifications plus one held-out
  verification. A passing patch always costs two.
- The result of a held-out run that differs from the loop is visible in the output, in the JSON
  output and in `fix/history.json`.
- A finding whose patches were all refused before they could be applied stays `PATCH_PROPOSED` in
  the ledger while the command reports `REJECTED`; the note in the result names the reason.
