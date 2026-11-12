# Improvement plan (branch `improve/showcase`)

This page records the audit that started the work, the technology choices and why, and the order
of the work. It is a working document: the status column is updated as items land.

## Audit (baseline, commit 2274fce)

Measured by running the tools, not assumed:

- `make check` (ruff, `mypy --strict src tools`, unit tests, docs-check, claims-check) passed:
  2183 unit tests in about 85 seconds. The brief mentioned 149 tests; the suite is larger.
- Docker is installed but the sandbox that ran this audit cannot download from
  `binaries.soliditylang.org`, so the runner image could not be built there. Integration, security
  and matrix tests, and the demo, were therefore **not** run in this environment.
- The slowest test is a Hypothesis state machine (`test_ledger_properties`, 15 s); everything else
  is under 4 s. No test was found to be flaky in two full runs.
- Found: `Ledger.findings` used SQLite numbered placeholders with a sequence of parameters. That is
  a `DeprecationWarning` on Python 3.12 and an error on 3.14. Fixed, with a guard.
- Already present and kept as is: SARIF for `assay scan`, JSON schemas for seven commands
  (`docs/schemas/`), documented exit codes 0 to 5, a composite Action pinned to commit SHAs,
  `CHANGELOG.md`, evidence bundles, HTML report, ADRs, claims checking.
- Gaps against the goals: no verification SARIF; a wheel without the Dockerfile (an installed user
  could not build the image); no PyPI metadata beyond the basics, and a README with relative links
  that PyPI cannot resolve; no release workflow; no Marketplace branding; no documentation site;
  no report viewer; Foundry only.

## Decisions

| Topic | Decision | Why |
|---|---|---|
| Docs site | MkDocs Material, `docs/` as the source, deployed with GitHub Pages | The docs are already Markdown with relative links and Mermaid; MkDocs needs no conversion and no Node toolchain for the docs. Starlight would be a second build system for the same files. |
| Viewer | Vite + React + TypeScript + Vitest in `web/` | As the brief proposed; a static bundle, no backend, tests run in jsdom. |
| Verification SARIF | One run, one result per oracle that did not pass | Matches how code scanning shows alerts on a diff; a passing patch gives an empty run, stated as not a proof. |
| Publishing | `uv publish` with trusted publishing in one job | The pinned Actions in this repository are known; the PyPI action and the download action would need SHAs that could not be verified here. Environment `pypi` with a reviewer gives the gate. |
| Version | Left at `0.1.0.dev0` | Choosing the first public version is the owner's decision; `docs/releasing.md` says where to change it. |
| Hardhat | Design and a seam, not an implementation (`docs/hardhat-design.md`) | The oracles, the harness, the ingest rules and the sandbox image all assume Foundry. A real Hardhat adapter needs a Node toolchain in the image and new fixtures; that is larger than this branch. |
| Python versions | Still 3.12 only | Tests ran on 3.12; claiming 3.13 without a CI matrix would be an unmeasured claim. |

## Order of work

| # | Item | Status |
|---|---|---|
| 1 | Fix the SQLite placeholder bug, guard against Assay deprecations | done |
| 2 | Verification SARIF (`--sarif`, `verify.sarif`, Action upload) | done |
| 3 | Release preparation: metadata, wheel contents, `assay image build`, release workflow, branding | done |
| 4 | Hardhat design and seam | see commits |
| 5 | MkDocs Material site and Pages workflow | see commits |
| 6 | Report viewer in `web/` with tests and a CI job | see commits |
| 7 | One-command demo script | see commits |
| 8 | Final verification and the pull request | last |
