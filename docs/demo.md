# Demo

Two commands show what Assay does on one of its own fixtures, offline, without an API key and
without a model. Both need Docker and the runner image (`make image`, once) and the Python
environment (`make install`).

```sh
make demo-overfit   # about half a minute
make demo           # one to three minutes
```

Everything they write goes to `demo-out/`, which Git ignores. Timings are from an otherwise
idle development machine with a native linux/arm64 image and the `quick` campaign profile; yours
differ. Every step starts a container, so a machine under load (or Docker under emulation) can take
several times longer.

## `make demo-overfit`: a patch that passes the tests and is still open

The fixture `fixtures/reentrancy/single_function` is a vault with a reentrancy hole. Its
`overfit.diff` adds a re-check that stops the original exploit but leaves a close variant
reachable. The command runs `assay verify` on that patch:

```
oracle      verdict  reason
integrity   PASS     -
exploit     PASS     -
variant     FAIL     variant_found
behavior    PASS     -
regression  PASS     -

final verdict: REJECTED
reason: variant_found
```

Read it from the top. The patch stays inside its scope and touches no test (`integrity`). The
original PoC no longer works (`exploit`: reproduced on the vulnerable revision, blocked on the
patched one). The benign tests that existed before still pass with the same recorded results
(`behavior`), and storage layout, ABI and events are unchanged (`regression`). A check that stops
there would accept the patch. The variant search (`variant`) fuzzes the parameters of the PoC on
the patched revision, finds a call that still drains the vault, writes it as a Foundry test
(`variant_poc.t.sol`) and replays that test three times before it counts.

The command exits with code 1, which is the expected result, and then prints where the test is:

```
demo-out/overfit/bundle/evidence/variant/variant_poc.t.sol
demo-out/overfit/report.html
```

`variant_poc.t.sol` runs with plain Foundry. The report shows the same verdict table, the PoC, the
variant test and the patch with its diff.

## `make demo`: the whole flow, from recorded answers

`make demo` runs `assay run` on the same fixture:

1. `assay scan` runs Slither and Aderyn in the sandbox; the findings are candidates (unverified).
2. `assay prove` asks for a hypothesis and a PoC. The answers come from cassettes, and the PoC is
   checked statically before it runs. It is reproduced on the vulnerable code (evidence level E1).
3. `assay fix` asks for a patch. The first answer is the overfit patch: the oracles reject it, and
   the rejection (`variant_found`) goes back to the "model" as structured feedback. The second
   answer is the good patch.
4. The first patch that passes is verified once more with a seed no attempt has seen. That run
   decides: `VERIFIED_WITHIN_BOUNDS`.
5. The evidence bundle and an HTML report are written to `demo-out/run/`.

At the end the command prints how to open the report and how to re-check the bundle offline:

```sh
open demo-out/run/report.html          # xdg-open on Linux
uv run assay replay demo-out/run/bundle
```

`VERIFIED_WITHIN_BOUNDS` means that nothing was found within the bounds that ran (the report lists
them). It is not a proof that the patch is correct for inputs and call sequences the search did not
reach.

## What the cassettes are

`demo/cassettes/` holds four cassettes: a hypothesis, the PoC, the overfit patch and the good
patch. They are synthetic: the answers are the fixture's own PoC and patches, and no model wrote
them. Every cassette says so (`synthetic: true`). The demo therefore shows how Assay judges
proposals, not how well a model proposes: no live model has been evaluated (see
[limitations](limitations.md)).

A cassette is found by the hash of the request, which includes the findings of the scan and the
feedback of the oracles. A change that alters either makes `make demo` stop with a missing
cassette (exit code 4). `make demo-cassettes` records them again from the real scanner, sandbox
and oracles against a scripted endpoint and marks them synthetic; the integration test
`tests/integration/test_demo.py` fails when they are out of date.

## Options and variations

- `assay report demo-out/run/bundle --out report.html` renders the report again; the same bundle
  always gives the same bytes.
- Use `--profile standard` with `assay run` or `assay verify` for the default campaign. The
  `quick` profile runs one seed of 64 runs; a larger profile can find a variant it misses
  ([variant search power](variant-power.md)). The cassettes were recorded with `quick`: another
  profile can change the oracle feedback in the second prompt, and a changed prompt has no
  cassette.
- The other fixtures work the same way with `assay verify` and their `patches/*.diff`; see the
  [classification matrix](classification-matrix.md).
