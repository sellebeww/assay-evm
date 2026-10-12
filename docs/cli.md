# Command line reference

Assay is one program, `assay`. This page lists the commands, the exit codes, the machine-readable
output and the HTML report. Every command has `--help` with an example.

```
assay --version
assay <command> --help
```

`assay --version` (and `assay version`) print the version from the package metadata.

## Commands

| Command | Purpose |
|---|---|
| `assay scan PROJECT` | Run the static analyzers in the sandbox and record the results as candidate findings (unverified, evidence level E0). |
| `assay prove PROJECT (--finding ID or --class CLASS)` | Reproduce a candidate with a model-written PoC. Ends REPRODUCED, NOT_REPRODUCED or INCONCLUSIVE. |
| `assay verify --base DIR --patch FILE --poc DIR` | Run the oracles on a patch and print a verdict per oracle and the final verdict. `--bundle-out DIR` writes an evidence bundle. |
| `assay fix PROJECT --finding ID` | Ask a model for a patch for a reproduced finding and verify it, within bounds. |
| `assay run PROJECT --class CLASS` | The whole flow: scan, prove, fix and bundle. |
| `assay replay BUNDLE` | Re-check an evidence bundle offline and compare the verdicts with its manifest. |
| `assay report BUNDLE --out FILE.html` | Write a self-contained HTML report of an evidence bundle. |
| `assay ci verify --project DIR --poc-dir DIR --base REF --head REF` | Verify the Solidity diff of a pull request against the PoCs of a project, without a model and without secrets. See [assay ci verify](#assay-ci-verify). |
| `assay doctor` | Check Docker, the runner image, the platform, disk space and the model variables. |
| `assay version` | Print the version. |

The verdicts are `VERIFIED_WITHIN_BOUNDS`, `REJECTED` and `INCONCLUSIVE`; the states of a finding
are listed in [the oracle documentation](oracles.md). `VERIFIED_WITHIN_BOUNDS` means that nothing
was found within the recorded bounds. It is not a proof of absence.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success: VERIFIED_WITHIN_BOUNDS, scan finished, REPRODUCED, REPLAY MATCH, report written, doctor found nothing wrong. |
| 1 | Negative result: REJECTED, NOT_REPRODUCED, the verdicts of a replay differ, or `assay scan --fail-on` was met. |
| 2 | Usage error: a bad option or argument, a missing file, an option combination that makes no sense, or a bundle of another format version. |
| 3 | INCONCLUSIVE: no oracle failed, but a required one was inconclusive or did not run; an incomplete scan; a model budget that ran out. |
| 4 | Infrastructure problem: Docker missing or not running, the runner image missing, out of memory, an unwritable ledger or output file. |
| 5 | Integrity violation: a protected path touched, a path traversal, a symlink, a binary file, inputs rejected at ingest, a damaged cassette, or a bundle that does not match its manifest. |

A timeout or an unknown result is never reported as a pass. Error messages go to standard error and
say what to do next, for example `run make image`.

## Output and color

Output is plain text. Color is used only when standard output is a terminal and `NO_COLOR` is
unset or empty; piped output never contains escape codes. Output holds no timestamps unless the
purpose of the command is to show durations (`assay verify` prints how long the oracles took).
Text that comes from a project, a patch, a tool or a model is printed with control and invisible
characters escaped.

Variables of the model endpoint are `ASSAY_LLM_BASE_URL`, `ASSAY_LLM_API_KEY`, `ASSAY_LLM_MODEL`,
and optionally `ASSAY_LLM_TIMEOUT_S` and `ASSAY_LLM_MAX_TOKENS` (see [the LLM layer](llm.md)).
No command prints their values; `assay doctor` shows each as `SET` or `NOT SET`.

## Machine-readable output

`--json` prints one JSON document on standard output instead of text, with sorted keys, no
timestamps and no host paths. The exit code is the same as for text output. The schemas are
exported from the Pydantic models that the commands validate their output against, so the output
cannot drift from them; `make schemas` rewrites them and the unit tests fail when they are out of
date.

| Command | Option | Schema |
|---|---|---|
| `assay scan` | `--json` (same as `--format json`) | [docs/schemas/scan.schema.json](schemas/scan.schema.json) |
| `assay verify` | `--json` | [docs/schemas/verify.schema.json](schemas/verify.schema.json) |
| `assay prove` | `--json` | [docs/schemas/prove.schema.json](schemas/prove.schema.json) |
| `assay fix` | `--json` | [docs/schemas/fix.schema.json](schemas/fix.schema.json) |
| `assay run` | `--json` | [docs/schemas/run.schema.json](schemas/run.schema.json) |
| `assay replay` | `--json` | [docs/schemas/replay.schema.json](schemas/replay.schema.json) |
| `assay doctor` | `--json` | [docs/schemas/doctor.schema.json](schemas/doctor.schema.json) |

Every document except the one of `verify` has a `format` field (`assay-scan/1`, `assay-prove/1`,
`assay-fix/1`, `assay-run/1`, `assay-replay/1`, `assay-doctor/1`); the document of `verify` has
`schema_version`. `fix` and `run` share one schema; their `format` tells them apart. A change that
is not backward compatible changes the version in `format` or `schema_version`.

## assay report

```
assay report out/good --out out/good.html
```

The command first checks the sha256 of every file of the bundle against `manifest.json`; a bundle
that does not match is refused (exit code 5) and no report is written. The report is a single file:

- CSS is inline; there is no JavaScript and no external resource. A `Content-Security-Policy`
  meta tag restricts the page to `default-src 'none'; style-src 'unsafe-inline'; img-src data:`.
- It shows the verdict banner, a box with what the result means and what it does not (the bounds
  that ran, and that it is not a proof of absence), a finding summary with the evidence level, a
  status timeline, the verdict and reasons of every oracle, the PoC and the `variant_poc` when
  a variant was found, the patch as a coloured diff, the attempt history of a fix loop, the
  manifest hash, the tool versions and how to replay the bundle (`assay replay <bundle>`).
- The same bundle always gives the same bytes: the page holds no clock time, host path or user
  name.
- Everything that comes from the target code, the patch, the PoC or a model is data. It is only
  placed in element content, after control characters are escaped and `& < > " '` are replaced by
  entities, never in an attribute, a URL, a style or a script. The tests parse the page with an
  HTML parser and check that payloads such as `<script>`, `"><img onerror=...>`,
  `</style><script>` and `javascript:` appear only as text.
- A file larger than 256 KiB is cut at that size, with a note that says so.

## assay doctor

```
assay doctor
assay doctor --json
```

| Check | Problem when |
|---|---|
| docker command | the `docker` command is not found. |
| docker daemon | the daemon does not answer. |
| runner image | `assay-runner:dev` is not built. The symbolic image `assay-runner-symbolic:dev` is optional: it is only needed for `--symbolic`, and a missing one is information, not a problem. |
| tool versions | a tool version declared by the image labels differs from `docker/runner/versions.lock`, or the file cannot be read. |
| platform | never a problem; it shows the platform of the image and whether it runs natively or under emulation. |
| disk space | less than 5 GiB are free in the temporary directory. |
| model endpoint | never a problem; it shows each `ASSAY_LLM_*` variable as `SET` or `NOT SET`. |

Exit code 0 when no check is a problem, 4 otherwise, with a one-line fix under every problem.

The image is matched to `versions.lock` by the tool versions that its labels declare, not by its
digest: an image id differs between builds and between platforms, so it cannot be compared with a
file (see [ADR 0020](adr/0020-doctor-matches-the-image-by-pinned-versions.md)). The labels are
written from `versions.lock` when the image is built; `make image-check` runs the tools themselves.

## assay ci verify

```
assay ci verify --project . --poc-dir poc --base origin/main --head HEAD \
  --scope src --profile standard --fail-on inconclusive --out assay-out
```

The command is the core of [the GitHub Action](github-action.md), and works the same on any
machine with Docker and the runner image. It uses no model and reads no secret.

| Option | Meaning |
|---|---|
| `--project DIR` | The Foundry project, inside a git work tree. |
| `--poc-dir DIR` | The PoCs, read from the work tree: Solidity files directly inside make one PoC; otherwise each subdirectory with Solidity files is one PoC. |
| `--base REF`, `--head REF` | The revisions to compare. They are resolved to commit ids first; a name that looks like an option or a range is refused. |
| `--scope DIR` | The directory of the project whose changes are the patch (default `src`). |
| `--profile`, `--symbolic` | As for `assay verify`. |
| `--fail-on rejected\|inconclusive\|never` | Which results give a non-zero exit code (default `inconclusive`). |
| `--out DIR` | Output directory, empty or absent (default `assay-out`): `bundles/<poc>/`, `summary.md`, `result.json`. |
| `--summary-file FILE` | Also append the Markdown summary to FILE, for example `$GITHUB_STEP_SUMMARY`. |

The diff is text only. A binary file, a symlink, a submodule, a type change, a rename across the
scope boundary and an unsafe path in the scope are refused with exit code 5. Git runs with a fixed
environment, `--no-ext-diff`, `--no-textconv` and literal pathspecs, and the base tree comes from
git blobs. With no change in the scope the command prints `no changes in scope` and exits 0.

Exit codes follow [the table above](#exit-codes) and `--fail-on`:

| `--fail-on` | Fails (non-zero) on |
|---|---|
| `rejected` | REJECTED (1) and an integrity violation (5) |
| `inconclusive` | the same, and INCONCLUSIVE (3) |
| `never` | nothing that is a verdict |

A usage error (2) and an infrastructure problem (4) fail under every policy, because no verdict
exists. With several PoCs the most serious failing code wins: 2, 4, 5, 1, 3. `result.json`
(`format` `assay-ci-verify/1`) holds the overall verdict (`VERIFIED_WITHIN_BOUNDS`, `REJECTED`,
`INCONCLUSIVE`, `ERROR` or `NO_CHANGES_IN_SCOPE`), the exit code and the verdict of each PoC.

The summary has a verdict table per PoC with the five oracles (and the symbolic one when it ran),
the reasons, the bounds that ran, and how to re-check a bundle with `assay replay`. Text that comes
from the pull request appears only as code spans or code blocks. Every line of standard output
starts with a fixed word, so text from a pull request cannot form a workflow command.
