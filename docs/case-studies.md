# Case studies

All four cases use one fixture of this repository, `fixtures/reentrancy/single_function`: a vault
whose `withdraw` sends ether before it writes the reduced credit back (single-function
reentrancy). The fixture is synthetic test material with a known hole, written by the same author
as the oracles. The table is the **expected** result recorded in the fixture's `expected.json`,
which `make fixtures-check` establishes with plain Foundry and no oracle code, and which
[the classification matrix](classification-matrix.md) compares with what `assay verify` returns
(32 of 32 matched in the recorded run, for all eight fixtures and four patches each). Nothing
here is a measured detection rate on real code.

| Patch | PoC replay | Variant search | Benign tests | Interface | Verdict | Reason |
|---|---|---|---|---|---|---|
| (none, original code) | exploited | exploited | pass | baseline | | |
| `good.diff` | blocked | blocked | pass | same | `VERIFIED_WITHIN_BOUNDS` | |
| `overfit.diff` | blocked | **exploited** | pass | same | `REJECTED` | `variant_found` |
| `destructive.diff` | blocked | blocked | **fail** | same | `REJECTED` | `benign_test_failed` |
| `regressing.diff` | blocked | blocked | pass | **layout changed** | `REJECTED` | `layout_changed` |

## Overfit: stops the reported exploit, leaves a variant

The patch re-checks something that makes the original PoC fail, so the PoC no longer works and
every old test passes. A reviewer reading the diff, or a pipeline that runs the tests and the PoC,
would accept it. The variant search fuzzes the PoC's parameters on the patched code, finds a call
that still drains the vault, writes it as a Foundry test and replays it three times before it
counts. See [the demo](demo.md) for the output of `make demo-overfit` and the test that ships in
the evidence bundle.

## Destructive: closes the hole by removing the feature

The patch blocks the exploit and every variant, because the vault no longer does what it exists
to do. The behavior oracle runs the benign tests that passed before and finds one that fails.

## Regressing: closes the hole and breaks the deployed layout

The patch blocks everything and the benign tests pass, but it changes the storage layout. For a
deployed, upgradeable contract that corrupts state. The regression oracle compares layout, ABI
and events of the two revisions and reports `layout_changed`.

## Good: accepted, within bounds

All oracles pass. The verdict is `VERIFIED_WITHIN_BOUNDS`: nothing was found within the recorded
seeds, runs and depth. It is not a proof that the patch is correct.

## Try it

```sh
for patch in good overfit destructive regressing; do
  uv run assay verify --base fixtures/reentrancy/single_function \
    --patch fixtures/reentrancy/single_function/patches/$patch.diff \
    --poc fixtures/reentrancy/single_function/poc --profile standard
done
```

Needs Docker and the runner image ([quickstart](quickstart.md)). The other seven fixtures cover
access control, unchecked calls, signature replay, delegatecall, oracle manipulation, denial of
service and rounding; see [the fixture specification](fixture-spec.md).
