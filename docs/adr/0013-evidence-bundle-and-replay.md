# ADR 0013: Evidence bundle contents and the replay environment

- Status: Accepted
- Date: 2026-10-04

## Context

`assay verify --bundle-out DIR` packages a verification so that `assay replay DIR` can re-run it
offline and compare the verdicts. The planned bundle holds `manifest.json`, `base/` (the
vulnerable tree), `patch.diff`, `poc/` and `evidence/`. Building it raised four questions that
the plan leaves open.

1. The harness. Every run tree contains the shared harness `solidity/*.sol` under `assay/`
   (ADR 0011). The harness decides how predicates, variants and behavior records are reported,
   so it is part of what ran. A replay that uses the harness of the current checkout re-runs a
   different experiment as soon as the harness changes.
2. The runner image. A bundle records the content-addressed id of the runner image. ADR 0008
   notes that image ids are not reproducible: they differ between platforms and between two
   builds of the same `versions.lock`, because layer timestamps are not normalized. A replay that
   requires the recorded id fails on every other machine and after every rebuild, and the hint
   "run make image" cannot help.
3. The target contracts of the RegressionOracle. The oracle compares the interface of "the target
   contract". Fixtures name one in `expected.json`, but oracles must not read fixture metadata,
   and an ordinary project has no such file.
4. The ledger of a replay. A replay runs every oracle again, and every oracle run is recorded in
   a ledger.

## Decision

1. The bundle also holds `harness/`, a copy of the harness files that ran. `manifest.json` lists
   their sha256 like every other file, and `assay replay` runs with that copy.
2. `assay replay` selects the runner image as follows:
   - the image with the id recorded in the manifest, when it exists locally;
   - otherwise `assay-runner:dev`, when the tool versions in its labels (`assay.<tool>.version`)
     and the `versions.lock` of the current checkout equal the ones recorded in the manifest;
     the output then starts with a note that names both image ids;
   - otherwise the replay stops with exit code 4 and the message to run `make image` (with the
     `versions.lock` recorded in the bundle).
   The manifest records the image id, the tool versions from the image labels and the full text
   of `versions.lock` with its sha256.
3. The target contracts are every concrete contract (not abstract, not an interface, not a
   library) declared in a Solidity file under `src/` of the vulnerable revision, as
   `<path>:<Name>`, sorted. A target that is no longer a concrete contract on the patched
   revision counts as `abi_changed`; a new concrete contract is a warning. The list is part of
   the recorded bounds.
4. A replay records its oracle runs in a temporary ledger that is removed afterwards. The
   bundle, not the ledger, is the record a replay checks.

Further rules of the bundle:

- `base/` and `poc/` hold the inputs as ingested: the snapshot files without the rewritten
  `foundry.toml`, plus the project's own `foundry.toml` and `remappings.txt`, byte for byte.
  Ingesting them again gives the recorded tree hashes.
- `manifest.json` also records the settings (fuzz seed, fuzz runs, replays of the PoC) and the
  patch policy (scope and protected paths), and the replay uses them.
- The manifest and the evidence pass through a sanitizer that replaces known host paths (working
  directory, inputs, bundle directory, home directory, temporary directory) with placeholders.
  The inputs in `base/`, `poc/`, `harness/` and `patch.diff` are copied unchanged.
- `--bundle-out` refuses a path that exists and is not an empty directory, a symlink, and a
  directory inside the base project or the PoC directory. The manifest is written last.

## Consequences

- A bundle can be replayed on another machine with the same pinned toolchain, and after a
  rebuild of the image, without weakening the file check: any changed byte still stops the
  replay with exit code 5 before anything runs.
- When the recorded image is not used, the replay says so. Two images built from the same
  `versions.lock` are expected to behave the same; this is an assumption, checked so far only
  for the smoke project across platforms (ADR 0008).
- The harness in a bundle can differ from the harness of the checkout. A replay reproduces the
  recorded verification; it does not say whether the current harness would agree.
- Interface comparison covers mocks and helper contracts under `src/` as well. A patch that
  changes their interface in a breaking way is rejected even when the vulnerable contract keeps
  its interface.
- Projects with many contracts pay two `forge inspect` runs per contract and revision.
- A bundle is tamper-evident, not a signature: whoever can rewrite both the files and the
  manifest can forge a bundle.
