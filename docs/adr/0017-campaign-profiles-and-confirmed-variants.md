# ADR 0017: Campaign profiles, confirmed variants and the timing record

- Status: Accepted
- Date: 2026-10-05

## Context

The basic VariantOracle ran one fuzz campaign per revision with one seed and a number of runs,
and failed a patch as soon as forge reported a variant. The full version adds three things:

- campaign profiles (`quick`, `standard`, `thorough`) that fix the number of seeds, the runs per
  seed, the invariant runs and depth and a time limit per campaign, with every seed derived from
  one recorded base seed;
- an invariant mode for variants made of several calls, driven by fixture invariants;
- a counterexample flow: the reported input is replayed three times through a generated concrete
  test before it can fail a patch.

The design also asks that the report and the bundle manifest record the base seed, the number of
seeds, the runs per seed, the invariant depth and the actual duration, and that two verifications
of the same inputs give byte-identical manifests. Durations differ between runs, so both cannot
hold for the same file. Implementing the rest raised further questions: how a seed is derived,
what "replay three times" runs, what may enter a generated test, how Foundry 1.8.4 reports
invariant failures, and how the invariant settings reach forge.

## Decision

1. Profiles live in one file, `src/assay/oracles/variant/profiles.toml`, checked when loaded.
   `assay verify --profile` selects one (default `standard`) and `--seed` the base seed (default
   `0x1`); `--fuzz-runs` still replaces the runs per seed when given. Seed `i` of a family is the
   first 16 hex digits of sha256(`assay-variant-seed-v1`, family, base seed, `i`); the search uses
   the family `search`, and other families (such as a held-out family for the fix loop) are kept
   apart by name.
2. Each mode runs its seeds in order and stops at the first seed that finds something. The time
   limit applies to each campaign as the wall-clock limit of its container run; reaching it is
   `INCONCLUSIVE` (`timeout`). The sanity check applies per mode: a mode that finds nothing on the
   vulnerable revision does not count towards a pass and is named in a warning and in the bounds
   statement; only when no mode finds the exploit is the verdict `variant_search_ineffective`.
3. Invariant mode: a fixture provides at most one contract deriving from `AssayInvariant`
   (`solidity/AssayInvariant.sol`) in its PoC directory, a protected path. Foundry has no command
   line options for invariant runs and depth, so the run trees of the variant search are
   snapshotted with a rewritten `foundry.toml` that adds `runs`, `depth` and
   `fail_on_revert = false` to `[invariant]`; nothing else changes. Foundry 1.8.4 reports a broken
   invariant in `invariant_failures` (reason and shrunk sequence with sender, target and calldata)
   rather than in `reason` and `counterexample`; the forge parser reads that field strictly.
   With the same seed, Foundry 1.8.4 still drew some senders of an invariant sequence from a
   source its seed does not cover: the calls ran the same, but the reported (and shrunk)
   sequences differed between runs. `AssayInvariant` therefore registers one fixed sender
   (`targetSender`), and handlers must not depend on `msg.sender`; with that, a campaign and its
   shrunk sequence repeat exactly.
4. "Replay three times" means three runs of the generated test `variant_poc.t.sol` on the patched
   revision, in three containers. The variant is confirmed only when all three pass with the
   predicate from the test contract; otherwise `INCONCLUSIVE` (`flaky_counterexample`). A fuzz
   input is replayed from the fuzzer's raw arguments through `assayReplayVariant`, which maps them
   exactly as `testFuzz_variants` does; a sequence is replayed call by call with the recorded
   sender, target and calldata through `assayReplayCall`, then `assayCheckInvariant`.
5. Only numbers and a checked identifier enter the generated test. Every value is printed as a
   64-digit hex literal from a Python integer parsed out of strictly validated hex (never a
   40-digit literal, so no address checksum applies, and never text), the base contract's name and
   file must match plain identifier and path patterns, and the pragma copies the harness's exact
   solc version. Input that does not fit is refused (`counterexample_rejected`); a sequence with a
   time or block shift is refused as well, since the profiles do not configure shifts.
6. Timing. The report and the manifest keep every deterministic number of the search in
   `bounds.variant` (profile, base seed, seeds, runs per seed, invariant runs and depth, the time
   limit, the seeds that ran, the runs and calls forge reported, where a variant was found, the
   replays that reproduced it), and the bounds statement is built from those numbers only. The
   measured durations go into a separate `timing` section of the report and the manifest, rounded
   to 0.1 s, and into the ledger as whole milliseconds. The determinism property becomes: two
   verifications of the same inputs give manifests that are byte-identical apart from `timing`,
   and `timing` holds durations and nothing else. The determinism tests compare manifests without
   `timing` and check the shape of `timing`. `assay replay` compares bounds, not durations. The
   manifest schema version becomes 2; a version 1 bundle is refused with a format message
   (exit code 2), not reported as tampered.

## Consequences

- A verification with the `standard` profile runs up to three fuzz and three invariant campaigns
  per revision instead of one fuzz campaign, and takes longer; `quick` is cheaper and can miss
  variants, which `make variant-power` measures on the fixtures.
- An overfit patch is rejected only after its variant reproduced three times in a concrete test
  that ships in the bundle, so a reader can run the witness without the fuzzer.
- A replay checks that the same seeds find the same variants with the same confirmation, which
  ties the bundle to the search more tightly than before.
- The manifest is no longer byte-identical as a whole between two runs; tools that compare
  manifests must drop `timing` first (`assay.report.bundle.without_timing`). The ledger's
  manifest hash identifies one run's manifest, durations included.
- Fixtures gain invariant files under `poc/`; `make fixtures-check` runs them with a fixed number
  of runs and depth and requires that they break on the vulnerable revision and hold under the
  `good` patch. Labels and `expected.json` do not change.
