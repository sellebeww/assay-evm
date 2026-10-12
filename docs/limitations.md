# Limitations

This page says what Assay cannot do, which vulnerability classes it does not cover, and which
assumptions its results rest on. It complements [the threat model](threat-model.md) and the "What
this result means" sections of the generated result pages. Nothing here is an apology: a result is
only as useful as the reader's knowledge of its limits.

## What a verdict means

- **`VERIFIED_WITHIN_BOUNDS` is not a proof.** It means that every required oracle passed and that
  no variant of the exploit was found within the bounds that ran: the seeds, the number of fuzz
  runs and invariant sequences, their depth, the time limit, and, if the symbolic oracle ran, the
  loop bound and calldata. A variant outside the bounds can exist. Every output lists the bounds.
- **Only the checks that ran count.** The oracles check one exploit, its close variants, the
  benign tests that exist, and the interface. A patch can still be wrong in ways none of them looks
  at: a different bug in the same function, a flaw in logic that no test or PoC exercises, a
  change in economic behavior behind an unchanged interface.
- **The variant search does not randomize the block environment.** It randomizes the attacker, the
  attacker's balance and the PoC knobs, not `block.timestamp`, `block.number`, `block.basefee`,
  `block.prevrandao`, `block.coinbase`, `block.gaslimit`, `gasleft()`, `tx.origin` or the chain id
  (beyond rejecting the literal 31337 statically). A patch that applies the real fix only when one
  of these has its default test value can therefore pass. This gap is finding B1 of
  [the self-audit](audit.md); it is scheduled for the v2 result version, when the variant search
  may change and the benchmark is re-run.
- **`REJECTED` is also bounded.** It says that an oracle failed on the evidence it had. A rejected
  patch is not a statement about the rest of the code, and a failing benign test can come from a
  test that is itself wrong.
- **`INCONCLUSIVE` is a result.** A timeout, an out-of-memory kill, an unknown solver result or
  replays that disagree are never counted as a pass. Large or slow projects may end here often.
- **The PoC is an input, not a finding.** Assay takes a PoC as given (or reproduces a model's
  attempt at one). If the PoC does not show the real flaw, a patch that blocks it and its variants
  has closed something else.
- **Candidate findings are hints.** Slither and Aderyn results stay at evidence level E0. A clean
  scan says nothing about the code.

## What Assay does not do

- It does not find vulnerabilities at any measured rate in real contracts. It checks patches for a
  known problem.
- It does not call code secure, safe, proven or guaranteed, and it is not a replacement for an
  audit. Its own final audit, when it exists, is a self-audit.
- It does not modify a repository. It produces diffs, verdicts, bundles and reports.
- It has no server mode, network API, dashboard, accounts or hosted service.
- It has no mainnet fork, RPC access or transaction broadcasting, and no tooling aimed at live
  systems. State that depends on a live chain is out of reach.
- It supports the EVM, Solidity and Foundry project layouts only.
- It does not train or fine-tune models, and it has no vendor-specific model code: one
  OpenAI-compatible client.

## Vulnerability classes

The development fixtures cover eight classes: reentrancy, access control, unchecked call,
signature replay, delegatecall, oracle manipulation, denial of service and rounding. Each class has
one small synthetic fixture (a contract of about a hundred lines or less) with a PoC and four
labelled patches. Beyond them:

- **Other classes are not modelled.** Examples: front-running and other ordering effects, flash-loan
  economics beyond a toy price oracle, governance and upgrade mechanics, proxy storage collisions,
  cross-contract and cross-chain flows, gas-related griefing, token-standard quirks, and business
  logic that has no crisp exploit predicate. Assay can verify a patch for any issue that has a PoC
  and a predicate in the harness, but nothing has been measured outside the eight classes.
- **Within a class, only the fixture's shape was tested.** A reentrancy fixture with one function
  says little about cross-function or read-only reentrancy in a large protocol.
- **The static analyzers miss classes.** On the eight fixtures, neither Slither nor Aderyn reported
  anything mapped to `oracle_manipulation` or `rounding`
  ([static coverage](static-coverage.md)). Where the analyzers report nothing, there is no
  candidate to prove or fix, unless a human supplies one.

## What the measurements show, and do not show

- The [classification matrix](classification-matrix.md) is a self-validation. The fixtures, their
  patches and the oracles were written by the same author, and the overfit and regressing
  patches were designed so that the oracles have something to find. A full match shows that the
  oracles reproduce these labels. It is not a detection rate on real code.
- [Variant search power](variant-power.md) covers the overfit and good patches of the same eight
  fixtures, with two profiles. The search found the variant of every overfit patch in that run, and
  none for a good patch. The overfit patches were built to be reachable by fuzzing the PoC
  parameters. Real overfit patches may need sequences or inputs that a bounded search does not
  reach, and the `quick` profile can pass a patch that `standard` or `thorough` reject.
- The [symbolic checks](symbolic.md) cover four of the eight fixtures. For `rounding`, every run
  ended `INCONCLUSIVE` (out of memory at 4096 MiB), so the symbolic oracle decided nothing there.
  The four other classes have no symbolic properties, for reasons the page lists.
- No live model has been evaluated. The fix loop is tested with synthetic cassettes in which the
  fixtures' own patches play the model. How often a real model proposes a patch that passes is
  unknown, and results that involve a live model are not deterministic.
- There is no benchmark on code that did not come from the author. The held-out cases of the
  [benchmark](results.md) were written after the oracles were frozen, but by the same party that
  wrote the oracles, and the samples are small.

## Assumptions

- **Docker and the pinned tools are correct.** forge, solc, Slither, Aderyn, Halmos and z3 are
  trusted to do what their versions do. A bug in one can change a result without crossing the
  sandbox boundary. The checksums in `versions.lock` detect a changed download, not a release that
  was hostile when it was pinned.
- **One solc.** The analyzers and tests compile with the single pinned solc (0.8.36). A project
  whose pragma excludes it cannot be analyzed.
- **The sandbox holds.** Untrusted code is contained by the container policy. Kernel flaws, virtual
  machine flaws and side channels are outside what Assay can promise
  ([sandbox](sandbox.md#what-the-sandbox-does-not-cover)).
- **Determinism across image builds.** The image id differs between builds and platforms. A replay
  on another image accepts it when the tool versions and `versions.lock` match, and says so. That
  two such images behave the same is an assumption, checked for the smoke project across
  platforms ([ADR 0013](adr/0013-evidence-bundle-and-replay.md)).
- **The harness defines what an exploit is.** A predicate counts when the PoC contract emits the
  harness event. A PoC that proves something other than what its author meant is still counted as
  what it emits.
- **One user, one machine.** The ledger has no concurrent multi-user access, and a bundle is
  tamper-evident, not signed.

## Project layout limits

- The snapshot layout is fixed: `src/`, `test/` and `script/`, with forge-std from the image as the
  only remapped library. Libraries under `lib/` are copied and can be imported by relative path
  only.
- Inline Foundry configuration (`forge-config` comments) is rejected at ingest
  ([ADR 0009](adr/0009-reject-inline-foundry-config.md)). The check is textual, so a file that only
  mentions the string is rejected too.
- A patch may change files under `src/` only, within size limits, and cannot add binary files or
  symlinks.
- Projects with many contracts pay two `forge inspect` runs per contract and revision for the
  interface check.

## Platforms

- The runner image is built for the host: linux/arm64 on Apple silicon, linux/amd64 elsewhere. The
  symbolic image is linux/amd64 only and runs under emulation on arm64: slower, and with an
  emulator inside the trust boundary for Halmos runs
  ([ADR 0018](adr/0018-halmos-in-a-linux-amd64-image.md)).
- Docker Engine and Docker Desktop are tested. Rootless Docker, Podman and other runtimes are not.
- Halmos deploys contracts at other addresses than Foundry, so a counterexample that names a
  deployed contract cannot be replayed and is reported as `flaky_counterexample`, never as a
  variant.

## Status

Assay is in early development and has no release. Planned work not yet done includes a GitHub
Action for pull requests, a benchmark protocol with held-out fixtures, and the final self-audit
([roadmap](roadmap.md)). A built runner image is not distributed; it is built locally from the
Dockerfile and `versions.lock`.
