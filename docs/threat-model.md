# Threat model

This page lists what Assay protects, who it protects against, and which defenses exist, with the
tests that check them and the risk that remains. It is a statement of design and of what the
repository tests, not a claim that the risks are gone. The sandbox is described in
[the runner sandbox](sandbox.md), the model layer in [the LLM layer](llm.md), and the structure in
[the design](design.md).

## Assets

- **The integrity of verdicts.** This is the product. A wrong patch that receives
  `VERIFIED_WITHIN_BOUNDS`, or an oracle result that was forged, defeats the tool.
- **The user's machine and files.** Assay runs code it did not write.
- **Secrets.** The model API key and any credentials in the user's environment or project.
- **The ledger and evidence bundles.**
- **The credibility of what Assay says.** A claim stronger than the evidence is a defect.

## Adversaries

- The author of a hostile project or pull request: code, tests, `foundry.toml`, patches.
- A hostile patch author who tries to fool the oracles.
- Hostile text inside code: comments, NatSpec, identifiers, strings, revert messages.
- A compromised or buggy analyzer or tool binary.
- A supply-chain attacker (a dependency, a download, an image layer).
- An honest but careless user.
- A language model that follows instructions planted in the code it reads.

## Trust boundaries

Host and container; Assay's own logic and untrusted data; the local machine and any model
endpoint. Nothing from a project, patch, tool or model is evaluated, unpickled or passed to a shell
by the host. Analyzer binaries count as untrusted and run in the same sandbox as the project.

## Threats and defenses

| Threat | Defense | Tests and documentation | What remains |
|---|---|---|---|
| A hostile `foundry.toml` turns on `ffi`, widens file access, names another compiler or an RPC endpoint | Ingest ignores the file and writes a fixed configuration; inline `forge-config` comments are rejected ([ADR 0009](adr/0009-reject-inline-foundry-config.md)); analyzer and Halmos configuration files in the project have no effect | Security suite claims S1 and S2 (`make test-security`) | Nothing known beyond a flaw in the pinned tools |
| A hostile test or PoC reads host files, runs commands or opens a network connection | One allowlisted command per container, no shell, no network, read-only root, no capabilities, non-root, empty environment, only a scratch directory writable | Claims S1, S6, S7 and S9; unit tests of the container policy; [sandbox](sandbox.md) | Kernel and virtual-machine flaws (below) |
| Exhausting resources: endless loops, memory, forks, huge output | Wall-clock kill, memory, CPU and process limits, output caps | Security suite claims S3 to S6 (output cap, timeout and removal, fork bomb, no network) against the real image | A denial of service of the local run is possible within the limits |
| Path traversal, symlinks, special files, oversized trees | Rejected at ingest, with size and file-count limits; exit code 5 | Claim S8 | None known |
| A hostile patch edits tests or the PoC, leaves its scope, adds binary or symlink hunks | The IntegrityOracle checks protected path hashes, scope, binary and symlink hunks; the patch parser is Assay's own; verification stops before anything runs ([ADR 0012](adr/0012-patches-that-cannot-be-applied.md)) | `test_s8_patches.py`, [oracles](oracles.md) | |
| Forged evidence: text on the console that looks like a predicate, a copied event, `tx.origin` or chain-id games | The ExploitOracle counts only the harness event emitted by the PoC contract itself, never output; the IntegrityOracle flags environment sniffing | `tests/security/test_oracle_forgery.py` | A creative forgery may remain undiscovered |
| An overfit or special-cased patch that passes the original PoC | The VariantOracle (fuzz, invariants, an optional symbolic check), special-casing detection, a sanity check that the search finds the exploit on the vulnerable revision, a held-out seed for the fix loop's final decision | [classification matrix](classification-matrix.md), [variant search power](variant-power.md) | The search is bounded: a variant can exist and not be found |
| A vacuous patch (a deleted function, `require(false)`) | Vacuous-change detection, benign tests and the interface check | Matrix patches labelled `destructive` and `regressing` | |
| Prompt injection through target code, revert messages or analyzer text | Model output is untrusted data under strict schemas; the prompt quotes project text as data; a default-deny static checker reads every generated PoC before it runs; nothing from a model runs on the host; a model cannot change a status | `tests/security/test_injection.py`, `test_fix_injection.py`, the injection data and an "obedient" cassette ([LLM layer](llm.md#threat-model)) | A model can be misled into a useless proposal and waste attempts. It cannot gain authority |
| Leaking secrets to a model endpoint | A file allowlist, pattern-based redaction, consent with `--allow-llm`, `--llm-dry-run`, https or localhost only, the key only in the environment and never logged | `tests/unit/test_llm_redact.py` and the other LLM tests | Redaction is pattern based and can miss an unusual secret |
| A tampered evidence bundle | A sha256 manifest; replay and report refuse a mismatch with exit code 5 before anything runs; an immutable `oracle_run`; a hash-chained audit log | `tests/unit/test_bundle_replay.py`, the ledger tests | The bundle is evidence, not a signature: someone who rewrites both the files and the manifest can forge both |
| Hostile analyzer output: giant JSON, deep nesting, huge strings | Strict models, size and depth limits, structured errors | `tests/unit/test_analysis_hostile_output.py` | |
| Script or markup injection through the HTML report | Text is escaped for its context and placed only in element content; no JavaScript; a content security policy of `default-src 'none'; style-src 'unsafe-inline'; img-src data:` | `tests/unit/test_report_html.py` parses the page with an HTML parser and checks hostile payloads in names, comments, revert messages and diffs | Viewers that ignore the policy still get a page without scripts |
| CI abuse: `pull_request_target`, secrets exposed to pull requests from forks, unpinned Actions, text from a pull request turned into a workflow command, markup or a mention | The Action uses no secret and passes no token to the step that handles the pull request; the repository's workflows use `pull_request` with minimal permissions per job; Actions are pinned to full commit SHAs and dependabot updates them; the comment is posted only for pull requests of the same repository; the summary quotes every string of the pull request as code and standard output lines start with a fixed word; the diff is computed with git configured to run nothing from the repository and refuses binary files, symlinks, renames across the scope and unsafe paths | `tests/unit/test_github_actions.py` (no `pull_request_target`, no `secrets`, pinning, privileges, actionlint), `tests/unit/test_ci_summary.py` (a Markdown parser checks hostile text), `tests/unit/test_ci_diff.py`, [GitHub Action](github-action.md) | A workflow of a user who ignores the warning and uses `pull_request_target`; the PoC directory is read from the checked-out head, so a pull request that edits it can change the result (the summary flags it) |
| Supply chain: a changed dependency, download or image layer | Pinned versions, sha256-verified downloads in the image build, `pip-audit` in the development dependencies, dependency update monitoring | `docker/runner/versions.lock`, `.github/dependabot.yml` | A release that was already hostile when it was pinned |
| Misleading claims | Fixed verdict vocabulary; every output carries the bounds that ran; a documentation check rejects the words the project never uses | `tools/docs_check.py` (`make docs-check`), the vocabulary tests of each command | Human judgement is still needed |

## What the sandbox does not cover

A container escape cannot be excluded. The defenses are layered to make one harder, and the
following are outside what Assay or its tests can promise:

- kernel vulnerabilities, including unknown ones; every container shares the kernel of the host
  or of the Docker Desktop virtual machine;
- flaws in Docker Desktop's virtual machine and file sharing, in the Docker Engine or in the
  container runtime;
- hardware side channels;
- access to the Docker daemon, which Assay needs and does not restrict;
- the correctness of the pinned tools (forge, solc, Slither, Aderyn, Halmos, z3);
- container setups other than the tested one (rootless Docker, Podman and others).

The full list is in [the sandbox page](sandbox.md#what-the-sandbox-does-not-cover).

## Residual risks, in short

1. **A false `VERIFIED_WITHIN_BOUNDS`.** The variant search and the symbolic check are bounded, so
   a patch can pass and still be exploitable by an input the checks did not reach. The verdict says
   so by name, and every output lists the bounds.
2. **A sandbox escape** through a flaw below Assay.
3. **A leak through redaction misses** when code is sent to a model endpoint.
4. **Forgery of a bundle** by someone who controls both the files and the manifest.
5. **Unknown bugs in Assay.** The repository's tests are the only evidence of the properties
   above; no independent audit has been done.

Report a problem in any of these as described in [SECURITY.md](../SECURITY.md).
