# ADR 0014: Single-threaded `forge test` runs

- Status: Accepted
- Date: 2026-10-04

## Context

Verifications must be deterministic: the same inputs give the same verdicts, the same evidence
and a byte-identical bundle manifest. The fuzz seed is fixed, so a fuzz campaign was expected to
be repeatable.

With the pinned Foundry v1.8.4, `forge test` uses as many threads as the machine has logical
cores, and a fuzz campaign is split over parallel workers. The container's `--cpus 2` limit does
not change the number of cores forge sees. When a fuzz test fails, the counterexample it reports
was the same in every measurement, but the number of completed runs and the gas figures it
reports depend on how far the other workers got before the campaign stopped.

Measured on the reentrancy fixture with the `overfit` patch (`testFuzz_variants`, seed `0x1`,
256 runs), twelve runs each, six at a time:

| Setting | Reported runs | Mean gas | Counterexample |
|---|---|---|---|
| default threads | 3 to 8 | 720,994 to 745,673 | fuzz run 3 of worker 0 every time |
| `threads = 1` in `foundry.toml` | 2 to 8 | not recorded | the same |
| `--threads 1` on the command line | 2 every time | 714,044 every time | the same |

The varying run count reached the report text, the counterexample document and the stored forge
results, so two verifications of the same patch could produce different manifests, which a
determinism test showed under load. The configuration-file key had no visible effect; the
command-line option did.

Splitting a campaign over a machine-dependent number of workers also means that the set of inputs
tried can differ between machines, which would make the recorded bounds ("N runs with seed S")
mean different searches.

## Decision

- Every `forge test` that Assay runs passes `--threads 1`: the Foundry adapter's base argv is
  `forge test --json -vv --threads 1`. The fixture checker passes the same option, so that the
  ground truth and the oracles run the same campaigns.
- The sandbox allowlist accepts `--threads` for `forge test` with the value `1` only.
- The VariantOracle states when a variant was found by the counterexample's own run index
  (`fuzz_run`), not by the reported run count.

## Consequences

- Fuzz campaigns, their counterexamples and the reported figures are repeatable for the same
  inputs and image, including when several verifications run at the same time.
- Test runs use one core. Projects with many test contracts take longer; the fixtures are small
  enough that the difference is a few seconds.
- A higher thread count can be allowed later only with evidence that the results stay
  deterministic, and through a new ADR.
