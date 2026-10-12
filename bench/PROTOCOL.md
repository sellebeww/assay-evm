# Benchmark protocol

This protocol is written before any held-out result exists. Nothing in it may be softened,
reworded to a weaker claim or removed afterwards. Corrections that make a rule stricter and
additions go to the amendment log at the end, as new entries.

The benchmark is a self-validation of the oracles on synthetic fixtures. It is not a measurement
of detection quality on real contracts (see section 9).

## 1. Questions

1. How often does a weaker verification configuration accept a wrong patch?
2. Does the full configuration reject more wrong patches without rejecting good ones?
3. Do the verdicts of the oracles equal the labels of the fixtures on cases that were written after
   the oracles were frozen?

The benchmark answers 1 and 3. Question 2 is answered by comparing the configurations of
section 6 on the same cases. A fourth question, about a model pipeline (how often it reaches
`REPRODUCED` and `VERIFIED_WITHIN_BOUNDS`), needs recorded model answers and is outside this
protocol until such a run exists.

## 2. Definitions

- A **case** is one patch of one fixture: a fixture directory, a label and the patch file of that
  label. A fixture has four cases, one per label: `good`, `overfit`, `destructive`, `regressing`.
- The **label** is the ground truth of the case. It is established with plain Foundry, without any
  oracle, by `make fixtures-check` (`docs/fixture-spec.md`, section 8). A label changes only through
  human review. If a patch does not match its label, the patch is fixed, never the label.
- A case is **accepted** by a configuration when that configuration returns the verdict
  `VERIFIED_WITHIN_BOUNDS`. Every other result (`REJECTED`, `INCONCLUSIVE`, an error) is not an
  acceptance. A timeout or an unknown result is never an acceptance.
- A case **matches** when the final verdict of the full configuration equals the verdict that
  `expected.json` gives for the label and the expected reason, if there is one, is among the
  reported reasons. Every other case is a **mismatch**.
- A patch labelled `overfit`, `destructive` or `regressing` is a **bad** patch. A patch labelled
  `good` is a **good** patch.

## 3. Metrics

- **False-accept rate**: bad patches that a configuration accepted, over bad patches. It is
  reported for each bad label and for all bad patches together.
- **False-reject rate**: good patches that a configuration did not accept, over good patches.
- **Match rate**: matching cases over cases, for the full configuration.
- Every rate is reported as a count over a sample size and with its Wilson 95 percent confidence
  interval, because the samples are small. Reference values, which the unit tests check: 0 of 8
  gives an upper bound of about 0.324; 4 of 8 gives about 0.215 to 0.785; 0 of 24 gives an upper
  bound of about 0.14.
- Percentages are never rounded in the favorable direction. A rate where lower is better is
  rounded up, a rate where higher is better is rounded down, and the lower and upper bounds of an
  interval are rounded outward.
- The counts come first; percentages are secondary.

## 4. Splits

- `dev`: the eight fixtures in `fixtures/`, used to build and tune the oracles
  (`bench/splits/dev.json`). Results on this split are development results and prove nothing
  about generalization.
- `heldout`: eight fixtures in `bench/heldout/`, one per vulnerability class, created after the
  oracles were frozen and with code shapes that differ from the development fixtures
  (`bench/splits/heldout.json`).

A split file lists the root directory of its fixtures and their ids. A fixture belongs to exactly
one split.

## 5. Freeze rule

- The frozen paths are the tree `src/assay/oracles/`, the directory `solidity/` and the file
  `docker/runner/versions.lock`. Their combined hash is stored in `bench/FROZEN_HASH` by
  `make bench-freeze`. The hash covers the names and contents of the files and ignores caches
  (`__pycache__`, `*.pyc`).
- After the freeze nothing in the frozen paths changes until the benchmark has finished.
- Every benchmark run records the hash of the frozen paths at run time in its `run.json`. The
  report marks the results of the `heldout` split as held-out only if that hash equals
  `bench/FROZEN_HASH`. Otherwise it marks them `NOT HELD-OUT`.
- An oracle bug that is found after the freeze is not fixed. It is recorded as a finding (section
  8). Its fix is made after the benchmark has finished and produces a new result version (section
  10), which is reported next to the earlier one.
- The hash covers the oracle package, the shared harness and the tool pins. It does not cover the
  rest of the Python code that the oracles call (for example the sandbox runner or ingest). This
  is a limit of the freeze and is listed among the threats to validity.

## 6. Configurations

The ablations are computed from the stored per-oracle results of one run, without running the
cases again.

| Config | Accepts a case when |
|---|---|
| V0 | the benign tests pass on the patched revision (tests only) |
| V1 | V0 and the original PoC is blocked (exploit oracle passes) |
| V2 | V1 and the variant search finds no variant (variant oracle passes) |
| V3 | all non-symbolic oracles pass (integrity, exploit, variant, behavior, regression): the full configuration |
| V4 | V3 and the symbolic oracle passes, when the run included it |

V0 and V1 deliberately omit the oracles that the later configurations add. They show what a
patch pipeline that stops at the tests, or at the tests and the PoC, would accept.

## 7. Procedure

The order is part of the protocol.

1. Write this protocol.
2. Build the benchmark runner and report generator, and run the `dev` split.
3. Freeze the oracles with `make bench-freeze`. From here on the frozen paths do not change.
4. Write the held-out fixtures (section 11). Run no oracle on them. The only check allowed before
   the held-out run is `make fixtures-check`, which uses plain Foundry and no oracle code, and
   exists to confirm that the labels are true.
5. Run the `heldout` split with `make bench-oracles SPLIT=heldout`.
6. Generate the report with `make bench-report`.
7. Examine every mismatch (section 8). Record the findings.

## 8. Mismatches and findings

Every mismatch between a verdict and a label is a finding. The numbers are not adjusted, and the
oracles are not changed, to make them better.

For each mismatch, the cause is established in this order:

1. **Fixture.** Re-run `make fixtures-check` and read the fixture's README. If the patch does not
   match its label, or the label description is wrong in the fixture's own terms, the patch is
   fixed (never the label), the correction is recorded as a finding of kind `fixture`, and the
   split is run again. Earlier runs are kept in `bench/results/`, and the report lists the
   correction.
2. **Oracle.** If the fixture is right, the oracle is wrong or too weak. The finding is recorded
   with kind `oracle` and the oracle is not touched until the benchmark has finished.
3. **Infrastructure.** If the run stopped because of Docker, memory or the runner image, the run
   is repeated; the finding is recorded only if the problem repeats.

The findings are stored in `bench/findings.json` and rendered into the "Findings" section of
`docs/results.md` by `assay bench report`. The report lists every mismatch. A mismatch without a
recorded cause is listed as unexplained. When there is no mismatch and no correction, the section
says so.

## 9. Threats to validity

1. The fixtures are written by the same party as the oracles. The held-out cases are written after
   the freeze and without running the oracles on them, but by the same author, who knows what the
   oracles check. The freeze limits only the oracle side. A truly independent set would need other
   authors.
2. The samples are small, so the intervals are wide. Eight cases of a kind cannot separate rates
   that differ by a few tens of percentage points.
3. The ablation on synthetic fixtures is partly tautological, because the fixtures are designed so
   that overfit and regressing patches pass the old tests.
4. Labels may be wrong. They are established with plain Foundry under the same bounds as the
   oracles use (fixed seed, fixed number of runs), so a label that holds only within those bounds
   is a label within them.
5. Model non-determinism. The oracle benchmark uses no model. A model pipeline would need
   repeated runs or recorded answers.
6. Results are tied to the pinned tool versions and to the runner image of the run, and to the
   machine architecture.
7. Synthetic code is not real-world contract code. Fixtures are small, single-purpose and
   readable.
8. The freeze hash does not cover the Python code outside the oracle package (section 5).
9. The variant search is bounded by its campaign profile. A label `overfit` is a statement that a
   variant exists within the fixture checker's bounds, and a `good` verdict is a statement that
   none was found within the profile's bounds; neither is a proof.
10. The classes are the eight classes of the fixture specification. Results say nothing about
    other classes.

## 10. Result versions

The first complete benchmark is result version `v1`. If an oracle bug is found, it is fixed only
after `v1` is complete. The fixed oracles are frozen again, the splits are run again, and the
outcome is reported as `v2` next to `v1`. The held-out cases of `v1` then count as seen by the
author of the fix and are not held-out for `v2`.

## 11. How the held-out cases were made

The held-out fixtures were written after `bench/FROZEN_HASH` was created, as the procedure of
section 7 requires. This section is appended to the protocol after the cases were written and
before any held-out result exists.

- Each of the eight fixtures was written from scratch with an original contract. No development
  contract was copied or adapted; the contracts differ in purpose, state layout and call
  structure.
- Each fixture follows the format and rules of `docs/fixture-spec.md`: the mandatory header, the
  pinned compiler, benign tests that record their results, a PoC with knobs, four labelled
  patches, `expected.json` and a README.
- The code shape of each fixture differs from the development fixture of the same class. The
  table lists the difference.
- No oracle ran on any held-out fixture before the held-out run. The only tool run on them was
  `make fixtures-check`, which uses plain Foundry. At the first check, six of the eight fixtures
  matched all five rows. Two did not, because of mistakes in the benign tests and the PoCs: a
  test that recorded nothing (in `dos/forced_ether` and `rounding/fee_floor`) and a PoC setup that
  gave an account less ether than it spent (in `dos/forced_ether`). The tests and the PoC were
  corrected. No patch and no label was changed to make a row match.
- The held-out fixtures were written by the same party as the oracles (section 9, threat 1).

| Class | Development fixture | Held-out fixture and its different shape |
|---|---|---|
| `reentrancy` | `single_function`: one function sends ether before it updates the state, and the attack re-enters that function | `cross_function`: `cashOut` sends ether before it clears the credit, and the attack re-enters two other functions (`moveCredit`, `moveAllCredit`) that move the credit that is still shown |
| `access_control` | `missing_modifier`: a privileged function lacks a permission check | `reinitializable`: the check is missing on the initializers that create the owner, so a second call takes over the contract; the patches differ in which initializer they guard |
| `unchecked_call` | `ignored_return`: the result of a low-level call that sends ether is ignored | `token_return`: the boolean that a token answers to `transferFrom` is ignored, so a deposit that was never paid is credited |
| `signature_replay` | `missing_nonce`: a signed claim can be redeemed again on the same contract | `cross_chain`: claims have nonces, but the signed digest names neither the chain nor the contract, so a claim pays again on a second deployment |
| `delegatecall` | `user_controlled_target`: the module to run is passed in the call that runs it | `strategy_registry`: the target is registered by the account in one call and run with `delegatecall` by a second call; an allowlist exists but is not consulted |
| `oracle_manipulation` | `spot_price`: a swap moves the reserves of a small exchange pool whose price a lender uses | `donation_price`: the pool does not trade; its price follows its token balances, which a plain transfer or a one-sided deposit changes |
| `dos` | `payout_loop`: one reverting recipient blocks a loop of refunds | `forced_ether`: a strict equality between the balance and the pledges is broken by ether that is forced into the contract, which blocks the finalization |
| `rounding` | `share_inflation`: the first depositor inflates the price per share of a vault | `fee_floor`: the fee on a withdrawal is rounded down, so many small withdrawals pay no fee |

## 12. Reproduce

```sh
make image
make bench-oracles SPLIT=dev
make bench-freeze
make bench-oracles SPLIT=heldout
make bench-report RESULTS="bench/results/<dev-run> bench/results/<heldout-run>"
```

`make bench-oracles` takes between ten minutes and about two hours per split, depending on the
machine and the campaign profile. The report is written to `docs/results.md` and
`docs/results.json` and is deterministic for the same result folders.

## Amendment log

Entries are appended. None removes or weakens an earlier rule.

- Initial version.
- Section 11 completed: the held-out fixtures were written after the freeze and before any
  held-out result existed, and the shapes of the table replace the placeholder text that the
  initial version carried. The table adds detail; no rule changed.
