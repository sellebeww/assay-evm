# GitHub Action

The Action verifies the Solidity changes of a pull request. It computes the diff of the pull
request, runs `assay verify` on it against the PoCs of the project, writes the result to the job
summary, uploads the evidence bundles as an artifact and fails the job according to a policy. It
uses no model and reads no secret. Its verdicts are the ones of [the oracles](oracles.md): the
only positive one is `VERIFIED_WITHIN_BOUNDS`, which says that nothing was found within the
recorded bounds and is not a proof of absence.

## Warning: never use `pull_request_target`

> **Do not run this Action from a workflow that is triggered by `pull_request_target`, or by
> `workflow_run` after one.** Those triggers run with the permissions and secrets of the base
> repository, and the Action checks out and executes content from the pull request: a contract, a
> test, a PoC, and with `uses: ./` even the Action itself. That combination hands a stranger's
> code a write token and your secrets. Use `pull_request`. For pull requests from forks GitHub
> then gives the job a read-only token and no secrets, which is what this Action is designed for.

The Action itself never uses a secret and never needs one. The repository's tests fail when a
workflow of this repository uses `pull_request_target` or reads `secrets`.

## Using the Action from another repository

```yaml
name: Assay

on:
  pull_request:
    paths:
      - "src/**"
      - "poc/**"

permissions: {}

concurrency:
  group: assay-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  verify:
    runs-on: ubuntu-24.04
    timeout-minutes: 45
    permissions:
      contents: read
      pull-requests: write   # only with comment: "true"
    steps:
      - uses: actions/checkout@<full commit sha> # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: sellebeww/assay-evm@main
        with:
          poc-dir: poc
          comment: "true"
```

The `sellebeww/assay-evm@main` form names the repository that publishes the Action. There is no
release yet, so the examples use `main`; once a release exists, pin the Action to its tag or,
better, to the full commit SHA of that tag, as the workflows of this repository do for the Actions
they use.

The project needs a `foundry.toml`, a `src/` directory, benign tests in `test/` and a PoC directory
(see [the fixture specification](fixture-spec.md) for the PoC format). Copy
[`examples/demo-project`](../examples/demo-project/README.md) to start.

### Inputs

| Input | Default | Meaning |
|---|---|---|
| `project-dir` | `.` | Directory of the Foundry project inside the repository. |
| `poc-dir` | required | The PoCs: Solidity files directly inside it make one PoC; otherwise every subdirectory with Solidity files is one PoC. |
| `scope` | `src` | Directory of the project whose changes are the patch. Changes elsewhere are ignored. |
| `base-ref` | the pull request's base commit | The revision without the patch. The checkout must contain it. |
| `profile` | `standard` | Campaign profile of the variant search: `quick`, `standard`, `thorough`. |
| `symbolic` | `false` | Also run the symbolic oracle; builds the second image. |
| `fail-on` | `inconclusive` | `rejected` fails on REJECTED and integrity violations; `inconclusive` also fails on INCONCLUSIVE; `never` reports only. Infrastructure and usage problems always fail. |
| `comment` | `false` | Post the summary as one pull request comment (same-repository pull requests only). |
| `upload-sarif` | `false` | Also scan the project with the static analyzers and upload SARIF to code scanning. |

The default for `fail-on` is `inconclusive` because an unknown result must not look like a pass.

### Outputs

| Output | Meaning |
|---|---|
| `verdict` | `VERIFIED_WITHIN_BOUNDS`, `REJECTED`, `INCONCLUSIVE`, `ERROR` or `NO_CHANGES_IN_SCOPE`. |
| `exit-code` | The exit code of `assay ci verify` ([exit codes](cli.md#exit-codes)). |
| `bundle-path` | Directory on the runner with the bundles, `summary.md` and `result.json`. |

## What happens

1. Uv and Assay are installed from the Action's own code, with the lock file of the Action. The
   project of the pull request is never installed.
2. The sandbox image is built with Docker Buildx from the Action's `docker/runner`, with the
   GitHub Actions cache ([ADR 0021](adr/0021-sandbox-image-in-github-actions.md)).
3. `assay ci verify` runs ([the command](cli.md#assay-ci-verify)). No token is passed to this step.
4. The summary is appended to the job summary, the output directory is uploaded as the artifact
   `assay-evidence-<job id>`, and the optional comment and SARIF steps run.
5. The job fails when the verdicts and `fail-on` say so. The failure comes last, so that the
   summary and the artifact exist for a failed job as well.

## Pull requests from forks

For a pull request from a fork the job gets a read-only token and no secrets. The Action then
writes the job summary and uploads the artifact, and does nothing else: **no comment is posted**
and **no SARIF is uploaded**, whatever `comment` and `upload-sarif` say. A comment is created only
when the pull request's head repository is the repository running the workflow. The Action posts
at most one comment per pull request, finds it by a hidden marker and an author check (the
`github-actions[bot]` user), and updates it on the next run.

## What is uploaded

- The artifact: one evidence bundle per PoC under `bundles/<name>/` (inputs, evidence and a
  `manifest.json`; re-check one with `assay replay`), `summary.md` (the Markdown shown in the job
  summary) and `result.json` (verdicts and exit codes). The bundle holds the base tree, the PoC,
  the patch and the oracle evidence, so treat it like the repository's source.
- With `upload-sarif: "true"`: the SARIF of `assay scan` to code scanning, category `assay`. It
  is skipped, with a notice in the log, for pull requests from forks and for private repositories
  on which code scanning is not available (it needs GitHub Advanced Security) or cannot be read
  with the job's token. The job needs `security-events: write`.

Everything in the summary that comes from the pull request (file and PoC names, contract names,
reasons) is shown as code, never as HTML, a mention, a link or an image.

## How the diff is computed

`assay ci verify` computes the diff between `base-ref` and `HEAD` with git, limited to the
`scope`. Git runs without the user's or the system's configuration, with `--no-ext-diff` and
`--no-textconv` and literal pathspecs, so nothing in the pull request chooses a program to run.
The command refuses, with exit code 5 (an integrity violation), a binary file, a symlink, a
submodule, a type change, a rename across the scope boundary and an unsafe path. The base tree
is written from git blobs, not from the working directory, so a pull request cannot change what
counts as the vulnerable revision. With no change in the scope the command prints `no changes in
scope` and exits 0.

## Limits

- **The PoCs are read from the checked-out head.** A pull request that edits the PoC directory can
  change the result. The summary says so when it happens; review those changes first, or protect
  the directory with a code owner rule. The tests of the project (`test/`) come from the base
  revision, so a pull request cannot weaken them.
- A verdict is bounded by the profile and the PoCs. A pull request can pass and still be
  exploitable by an input that nothing here tried. See [the limitations](limitations.md).
- Only the layouts that [ingest](design.md) can rewrite are supported; the project's own
  `foundry.toml` is ignored, and `forge-std` and the exploit harness come from the image.
- Hosted Linux runners with Docker only. The first run builds the image (several minutes); later
  runs use the Actions cache. The symbolic image is built for linux/amd64.
- Two uses of the Action in one job (or in a matrix) collide on the artifact name.
- `comment` and the SARIF probe call the `gh` command, which GitHub-hosted runners provide.
- With `uses: ./` (as in the repository's own demo workflow) the Action is the code of the pull
  request. That is for trying the Action; consumers should pin a tag of the published Action.

## Try it in this repository

The workflow [`action-demo.yml`](../.github/workflows/action-demo.yml) runs the Action on
[`examples/demo-project`](../examples/demo-project/README.md) for pull requests that change
`examples/**`. `make lint-actions` runs a pinned actionlint over the workflows and `action.yml`;
the command is described in [the command line reference](cli.md#assay-ci-verify).
