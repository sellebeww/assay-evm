# The fix loop: `assay fix` and `assay run`

`assay fix` asks a model for a patch for a finding that `assay prove` reproduced, verifies the
patch with the oracles, and tries again with feedback, for a bounded number of attempts.
`assay run` chains the whole flow for one class: scan, prove, fix and bundle. The model only
proposes. Every verdict comes from the deterministic oracles
([ADR 0006](adr/0006-llm-as-untrusted-proposer.md),
[ADR 0019](adr/0019-fix-loop-ledger-and-held-out-decision.md)), and a model reply never changes a
status. The model layer itself (client, cassettes, redaction, budgets) is described in
[the LLM layer](llm.md).

## The flow

```
finding REPRODUCED (assay prove)
  |
  |  attempt n of at most N (3 by default, 5 at most)
  |    1. the model returns one unified diff (strict JSON, one repair of the format)
  |    2. IntegrityOracle first: scope, protected paths, size, traversal, symlinks, binary files,
  |       vacuous patch, special-casing, environment sniffing. A failure stops the attempt; nothing
  |       of the patch runs in the sandbox.
  |    3. exploit, variant, behavior, regression (and symbolic with --symbolic), with the loop's seed
  |    4. not passed: structured, redacted, quoted feedback for attempt n + 1
  |
  |  first attempt that passes every oracle
  |    5. verified once more with a held-out seed; that run decides
  v
VERIFIED_WITHIN_BOUNDS, or REJECTED / INCONCLUSIVE with the reasons
```

The finding moves `REPRODUCED -> PATCH_PROPOSED` once a patch was judged, then to
`VERIFIED_WITHIN_BOUNDS`, `REJECTED` or `INCONCLUSIVE` on the oracle runs of the deciding
verification. The ledger refuses any other move. A finding for which every patch was refused before
it could be applied stays `PATCH_PROPOSED`; the command still reports `REJECTED` and says why.
Between attempts nothing is written to the project: Assay produces diffs, verdicts and bundles
and never edits the repository.

## Commands

```sh
assay fix <project dir> --finding ID
          [--mode replay|record|live] [--allow-llm] [--llm-dry-run] [--max-attempts N]
          [--profile quick|standard|thorough] [--symbolic] [--bundle-out DIR] [--poc-dir DIR]
          [--seed 0x...] [--max-changed-lines N] [--max-files N] [--max-diff-bytes N]
          [--cassette-dir DIR] [--budget-calls N] [--budget-tokens N] [--ledger FILE] [--json]

assay run <project dir> --class CLASS
          [the options of fix, except --finding and --llm-dry-run]
```

`assay run` is a thin wrapper. It runs `assay scan`, then `assay prove --class CLASS` for the first
candidate of that class, then `assay fix` for the finding that was reproduced, and prints the
stages on standard error and the result of the fix on standard output. `--max-attempts` applies to
the PoC loop and to the patch loop, and the model budget covers the whole flow.

Examples:

```sh
assay scan fixtures/reentrancy/single_function
assay prove fixtures/reentrancy/single_function --class reentrancy
assay fix fixtures/reentrancy/single_function --finding 3 --profile quick --bundle-out out/fix
assay replay out/fix

assay run fixtures/reentrancy/single_function --class reentrancy --bundle-out out/run
```

Modes, consent and cassettes work as for `assay prove`: the default mode is `replay`, `record` and
`live` send redacted code to the configured endpoint and need `--allow-llm`, and
`--llm-dry-run` prints the size and hash of the first request without sending it. The PoC
directory defaults to the one `assay prove` wrote (`.assay/poc/finding-<id>`, or
`.assay/poc/finding-<class>` after `prove --class`).

### What the model sees

One JSON document. The instructions are fixed text; everything that comes from the project is in
the field `untrusted_data`, clipped and redacted:

- the analyzer notes of the finding and the whole redacted source of the files they point at,
  inside the scope (whole files, so that context lines of a diff can match exactly);
- the hypothesis that `assay prove` recorded, and the PoC that reproduced the finding;
- from the second attempt on, feedback on up to three earlier attempts.

### Limits of a patch

A patch is parsed and applied only by the ingest patch functions, never with `git apply` and never
on the host's own tools. It may touch files under the scope directories only (`src/` by default),
never a protected path (tests, the PoC, configuration, the harness), and it stays within:

| Option | Default | Meaning |
|---|---|---|
| `--max-changed-lines` | 200 | added plus removed lines of the whole patch (at most 2000) |
| `--max-files` | 5 | files that the patch changes (at most 20) |
| `--max-diff-bytes` | 49152 | size of the diff (at most 61440) |
| `--max-attempts` | 3 | patch attempts, 1 to 5 |

A diff beyond these limits, with a path outside the scope or on a protected path, with path
traversal, a symbolic link, a binary hunk or context that does not match the sources, is refused
by the IntegrityOracle before anything runs. The limits are recorded in the bundle.

### Feedback

A patch that did not pass becomes feedback made of data only:

- which oracles failed or were inconclusive, and the reason codes with short details;
- for the VariantOracle, the concrete variant: the generated test `variant_poc.t.sol` and the
  input of the counterexample (attacker, balance, knobs, calldata, predicates);
- for the BehaviorOracle, the differences of recorded behavior and the failing benign tests;
- for the RegressionOracle, the storage layout, ABI and event changes it found.

Every text is cut to a fixed length, control characters and secrets are removed, and everything is
quoted inside `untrusted_data`. Text that came from the target, such as a revert message, is data
about a patch and not an instruction: it cannot close the JSON document, and the system message
says that nothing in that field is to be followed. A message such as "ignore previous
instructions" in a revert string changes no verdict, no status and no behavior of the pipeline; a
test compares a run with that text against a control run.

## Rules against cheating

1. **No seeds, no campaign, no oracle code in prompts.** The seed of the loop, the seeds derived
   from it, the held-out seeds, the fuzz settings of the profile and the code of the oracles are
   not inputs of any prompt builder. Feedback keeps the exploit input of a counterexample and
   drops the fields that describe the campaign. A guard scans every prompt for the seeds in all
   their spellings (hex with and without `0x`, decimal; spellings shorter than five characters, such
   as the default base seed `0x1`, are too common in ordinary text to be matched, while the seeds
   Assay derives are 16 hex digits) and stops the command before sending when one is found. A test runs the loop
   with a distinctive seed and checks every request.
2. **A held-out decision.** The first attempt that passes every oracle is verified again with a
   base seed from a different seed family, so every campaign of that run (exploit replays, variant
   search, fuzz runs of the project's tests) uses seeds that no attempt and no prompt has seen.
   That run decides. When its verdict differs from the verdict in the loop, the output, the JSON
   output and `fix/history.json` say so and the held-out verdict applies. Its findings are never
   fed back, and the loop does not continue after it. A patch that failed in the loop stays
   rejected: its evidence is a concrete variant, a changed behavior or a changed interface, which
   another seed can only repeat.
3. **Special-casing detection stays on.** The IntegrityOracle runs first in every attempt and
   fails a patch that uses a value typical of the PoC, compares an address or selector with a
   hard-coded value, removes behavior instead of fixing it, or reads the test environment. It is
   the same code as in `assay verify`, and it does not special-case any fixture, function or file
   name.

## Output and exit codes

The output lists each attempt (the diff hash, the verdict in the loop and the oracles that did not
pass), the decision (loop or held-out run), the final verdict with its reasons, the state and
evidence level of the finding, and the verification table of `assay verify` for the deciding patch,
with the bounds that were run. `--json` prints the same as one document.

| Exit code | Meaning |
|---|---|
| 0 | `VERIFIED_WITHIN_BOUNDS` |
| 1 | `REJECTED`: the last judged patch failed an oracle and the attempts ran out |
| 2 | Usage error: consent missing, a bad option, a finding that does not exist or is not `REPRODUCED`, a bundle directory that is not empty |
| 3 | `INCONCLUSIVE`: an oracle was inconclusive (a timeout, for example), or no reply gave a patch that could be judged, or a budget limit ended the loop before any patch was judged |
| 4 | Infrastructure: Docker or the runner image, the ledger, no cassette, endpoint failure |
| 5 | An integrity violation by the deciding patch (a protected or out-of-scope path, traversal, a symbolic link, a binary file), or an input or a cassette that was rejected |

For `assay run`, a finding that is not reproduced ends the flow with 1 (`NOT_REPRODUCED`) or 3
(`INCONCLUSIVE`, or still `HYPOTHESIZED`), and a class without a candidate finding with 2.

## The evidence bundle

`--bundle-out DIR` (the directory must be empty or absent) writes the bundle of the deciding
verification, described in [the oracle documentation](oracles.md), plus `fix/history.json`:

- the diff hash of every attempt, the verdict of every oracle with its reason codes and details,
  and the verdict in the loop;
- the final decision: from the held-out run or from the last judged attempt, the final verdict, the
  verdict in the loop, whether they differ, and the reasons;
- the limits of the patch and the bounds of the loop and of the held-out run.

It holds no prompt, no model reply, no API key, no timestamp and no absolute host path, and it is
listed in the manifest, so a changed history is detected like any other changed file. The patch in
the bundle is the final patch, and the PoC is the one that was used.

`assay replay DIR` re-runs the oracles only, with the settings recorded in the manifest (the
held-out seed among them), and never creates a model client or opens a network connection. It
prints `REPLAY MATCH` when the verdicts equal the recorded ones.

## What a result claims

- `VERIFIED_WITHIN_BOUNDS` means that, within the bounds printed with the verdict, the patch passed
  every oracle in the loop and in a verification with seeds that the loop never used. It is not a
  proof of absence: a variant outside the profile's seeds, runs and depth can exist, and so can a
  weakness no oracle looks for.
- A patch from the loop is a proposal. The tool does not apply it to the repository.
- The held-out run lowers the chance that a patch was fitted to the seeds of the loop; it does not
  remove it, because the same oracle code runs in both.
- A model can still waste attempts with proposals that cannot pass, and results that involve a live
  model are not deterministic. Cassettes make a run repeatable, and the oracles are deterministic.
- The classification of the fixtures says nothing about real code: they are synthetic and were
  written by the author of the oracles.
