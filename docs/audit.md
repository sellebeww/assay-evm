# Self-audit

This is a self-audit. The same author wrote Assay, its tests and this page; no independent party
reviewed the code. It is evidence of the checks that were run, not an assurance that the risks are
gone. It complements [the threat model](threat-model.md), [the limitations](limitations.md),
[the sandbox](sandbox.md) and [the claims table](claims.md).

The audit worked through seven areas: the sandbox, environment sniffing, evidence forgery, the
supply chain, secrets, the claims table, and this summary. Each finding is numbered and decided:
fixed, deferred to a later result version, or recorded as a limit.

## Tools

| Tool | Version | Used for |
|---|---|---|
| `pip-audit` | 2.10.1 | known vulnerabilities in Assay's dependencies and in the images' Python packages |
| Trivy | 0.57.1 | vulnerability scan of the runner and symbolic images and the Debian base |
| actionlint | 1.7.12 | the workflows and `action.yml` (through `make lint-actions`) |
| zizmor | 1.16.3 | a second audit of the workflows and the Action |
| gitleaks | 8.21.2 | secrets in the working tree |

The scanners were pinned by image digest or version at audit time. The commands are in the
sections below and in the `Makefile`.

## A. Sandbox and process execution

Every path that starts a process was reviewed. Untrusted code runs only through `SandboxRunner`,
which builds an argument vector and calls `docker run` directly, never through a shell, a string
command, `eval`, `exec`, `pickle`, an unsafe YAML loader or an archive extraction. The other
`subprocess` users are the CI diff (`git` with a hardened environment and `diff.external=`
disabled), the benchmark runner (`git rev-parse`), the fixture checker (`git apply` on trusted
fixtures only) and the Action linter (reads one named member of a checksum-verified archive). YAML
is parsed with `safe_load`; JSON from tools is bounded before parsing and read into strict models.

**Finding A1 (medium, fixed).** The security claims S3 to S6 had no test in the security suite,
and S5 (fork bomb) and S6 (no network) were not exercised against the real image at all. Added
`tests/security/test_s3_s6_container_policy.py`: it runs a probe under the full container policy
and checks that enormous output is cut without exhausting the runner's memory (S3), an endless
loop is killed and the container removed (S4), forking stops at the pids limit (S5), there is no
network beyond loopback (S6), and the process sees no host environment, runs as uid 10001 and
holds no capability (a new claim S9). `docs/sandbox.md` and `docs/threat-model.md` record the new
tests.

## B. Environment sniffing

A patch or target can behave one way inside Foundry's test environment and another on a real
chain. The IntegrityOracle already refuses a patch that imports a test library, names Foundry's
cheatcode, console, default-sender or test-contract address, derives the cheatcode address, or
uses the local chain id 31337 (`tests/unit/test_integrity_environment_attacks.py`).

**Finding B1 (medium, deferred to v2, recorded as a limit).** The static check does not catch a
patch that reads `block.timestamp`, `block.number`, `block.basefee`, `block.prevrandao`,
`block.coinbase`, `block.gaslimit`, `gasleft()`, `tx.origin` or a chain-id comparison other than
the literal 31337, and the variant search does not randomize the block environment. A patch that
applies the real fix only when such a value has its default test value, and leaves the hole open
otherwise, therefore passes `assay verify` within the current bounds.

This is not fixed in place for two reasons. A blanket static flag on reading the block
environment would wrongly reject a legitimate good patch: the `oracle_manipulation/spot_price`
good patch reads `block.timestamp` to compute a time-weighted price. The correct fix is to
randomize the block environment in the variant search, which changes the frozen oracle tree and
the shared harness; under the [benchmark freeze](../bench/PROTOCOL.md) an oracle change after the
freeze is recorded as a finding and made in a new result version (v2), re-running both splits.
Until then the gap is stated in [the limitations](limitations.md) and as the claim
`environment-variants` in [the claims table](claims.md), and no output suggests the variant
search covers environment-dependent variants.

## C. Evidence forgery

The ways to forge a positive verdict or a bundle were reviewed and are covered by tests. Forged
console lines and copied harness events do not count: the exploit oracle reads only an
`AssayPredicate` event emitted by the test contract's own address
(`tests/security/test_oracle_forgery.py`). A timeout, an out-of-memory kill, unusable output or
disagreeing replays are INCONCLUSIVE, never a pass
(`tests/unit/test_oracle_exploit.py::test_a_timeout_is_never_a_pass`,
`tests/unit/test_oracle_behavior.py::test_a_patched_timeout_is_never_a_pass`). A bundle whose
files were changed is rejected before anything runs, and a manifest edited to claim another
verdict is caught because replay re-runs the oracles and compares
(`tests/unit/test_bundle_replay.py`). A ledger edited directly with `sqlite3` breaks the
hash-chained audit log, which `assay dev ledger-verify` and `ledger-audit` detect
(`tests/unit/test_ledger_audit.py`, `tests/unit/test_ledger_invariants.py`). No new weakness was
found; the bundle remains tamper-evident, not signed, which is stated wherever a verdict is
shown.

## D. Supply chain

`pip-audit` reported no known vulnerabilities in Assay's dependencies or in the Python packages
pinned for the runner and symbolic images. A Trivy scan of both images found no vulnerabilities in
their Python or Node layers. The Debian `trixie-slim` base, pinned by index digest, carries
unpatched advisories in its shared libraries (glibc, libstdc++, libgcc, libudev and others): at
the audit, Trivy reported 46 that it rated high on the full base, almost all in packages that the
runtime image does not include. The runtime image copies only the C runtime and a few `lib*.so`
files that the pinned tools link against; it has no shell, package manager or network at run time,
and the container has no network, so these advisories are not reachable through Assay's use of the
image. They are a reason to rebuild from an updated base when one is published, tracked by
dependabot and an ADR for any pin change.

The workflows pass `actionlint` and, as a second opinion, `zizmor`. They use no
`pull_request_target`, pass no secret to any step that handles pull-request content, and pin every
Action to a full commit SHA (`tests/unit/test_github_actions.py`). zizmor's two remaining notes
are template expansions of `github.action_path` in `action.yml`, which is the path of the Action's
own code, not pull-request input; they are documented in `action.yml` and are not a finding.

The licenses of every bundled tool were read from their own license files or packaging metadata
at the pinned version and are summarized in [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).

**Finding D1 (informational, recorded).** Several tools in the image are copyleft: Slither,
crytic-compile and Halmos are AGPL-3.0, solc and Aderyn are GPL-3.0, and certifi is MPL-2.0.
Assay distributes only the Dockerfile and its own MIT code, so it conveys no copyleft binary, and
it runs these tools offline for the local operator, not as a network service, so AGPL section 13
is not triggered by ordinary use. Redistributing a built image, or offering Assay as a hosted
service, takes on those obligations. This is spelled out in the third-party notices.

## E. Secrets

The repository has no commit history yet, so there is nothing to scan there; `.env`, `*.pem`,
`*.key` and similar files are ignored (`.gitignore`) and none is tracked. A gitleaks scan of the
working tree reported 33 matches, all verified as false positives: 32 are the `"key"` field of
recorded cassettes, which holds the sha256 cassette key (the hash of the request), not an API
key, and one is a deliberately fake PEM block in `tests/unit/test_llm_redact.py` that tests the
redaction. No real secret is present. The model API key is read only from the environment and is
removed before anything is logged, recorded or sent (`tests/unit/test_llm_redact.py`).

## F. Claims

Every claim in the README and the documentation was listed in [the claims table](claims.md) with
an evidence path and a status, and `make claims-check` (`tools/claims_check.py`) checks that every
evidence path exists and that every claim area the README marks has a row. It runs as part of
`make check`. Claims that hold only within bounds, or that are statements of a limit, carry that
status; the quantitative results are all `bounded` because they come from a synthetic sample that
the same author wrote.

## G. Summary of findings

| Id | Area | Severity | Decision |
|---|---|---|---|
| A1 | security suite missing S3-S6 tests | medium | fixed: added `test_s3_s6_container_policy.py` (and claim S9) |
| B1 | variant search does not randomize the block environment | medium | deferred to v2 and recorded as a limit; not fixed in place because the correct fix changes the frozen oracle tree |
| C | evidence and bundle forgery | — | no new weakness; covered by existing tests |
| D1 | copyleft tools in the image | informational | recorded in the third-party notices; no obligation for local use |

No finding lets a wrong patch receive `VERIFIED_WITHIN_BOUNDS` within the stated bounds, forges a
bundle that replay accepts, or breaks the sandbox. Finding B1 is a bound on what the variant
search covers, stated in the limitations and the claims table; it is scheduled for the v2 result
version, when the oracle may change and the benchmark is re-run.

## Reproduce

```sh
make check            # includes claims-check
make test-security    # the sandbox claims against the real image
make lint-actions     # actionlint over the workflows and the Action
make third-party-notices
# dependency and image audit (Docker):
uv run pip-audit -r docker/runner/slither-requirements.txt --require-hashes --disable-pip
uv run pip-audit -r docker/runner/halmos-requirements.txt --require-hashes --disable-pip
```

The exact scanner versions are in the tools table above; another version may report other
advisories as databases change.
