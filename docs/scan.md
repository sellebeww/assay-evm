# Static analysis and `assay scan`

`assay scan` runs the static analyzers Slither and Aderyn on a Foundry project and records their
results as candidate findings. A candidate is an unverified hint at evidence level E0: no
exploit was reproduced and no oracle has run. Scan output says "candidate (unverified)" and
nothing stronger, and no code path turns analyzer output into a `trusted` claim; only oracle
runs change a status ([ADR 0005](adr/0005-only-deterministic-oracles-promote-claims.md)).

How the analyzers run inside the sandbox, and how their output is parsed as untrusted input, is
described in [the runner sandbox](sandbox.md#static-analyzers). How well they cover the eight
vulnerability classes of the fixtures is measured in [static coverage](static-coverage.md).

## `assay scan`

```sh
assay scan <project dir> [--format table|json|sarif] [--out FILE]
           [--fail-on optimization|informational|low|medium|high] [--ledger FILE]
```

- `<project dir>`: the Foundry project. It goes through ingest first, like `assay verify`:
  snapshot, rewritten `foundry.toml`, analyzer configuration files left out, rejection of
  symlinks out of the tree and other dangerous entries.
- `--format`: `table` (default) for people, `json` for machines, `sarif` for code-scanning tools.
- `--out`: write the output to this file instead of standard output.
- `--fail-on`: exit with 1 when a finding has a reported severity at or above this one (see
  [Severities](#severities)). Without it, findings never fail the command.
- `--ledger`: the ledger database, by default `.assay/ledger.db` with its blobs in
  `.assay/blobs/`.

| Exit code | Meaning |
|---|---|
| 0 | The scan finished, with or without findings |
| 1 | `--fail-on` was given and a finding meets it |
| 2 | Usage error |
| 3 | Incomplete scan: an analyzer timed out, failed (for example a compile error) or wrote unusable output; the other analyzer's results are still recorded and printed |
| 4 | Infrastructure problem: Docker, the runner image (run `make image`), the ledger, or an analyzer that ran out of memory |
| 5 | The project was rejected at ingest |

The ledger summary (new and known findings, recorded and unchanged scans) goes to standard error,
so that standard output holds only the chosen format.

## From analyzer results to findings

Each result that has a location in the project becomes a candidate finding:

| Field | Value |
|---|---|
| Class | The detector id mapped through `src/assay/analysis/class_map.toml` to one of the eight classes of the [fixture specification](fixture-spec.md), or `other` |
| Location | The first location the tool reported: a path relative to the project root and an ordered line range, plus the enclosing function when the range lies inside one |
| Severity, rule, message | Exactly as the tool reported them; Assay adds no severity of its own |
| State | `CANDIDATE` at evidence level E0 |
| Id | sha256 of the class, the path, the line range and the sha256 of the code in that range |

Results without a location in the project (for example results that lie only in a dependency)
give no finding; the output counts them per analyzer.

The class mapping lives only in `class_map.toml`. A detector maps to a class only when the defect
it is documented to look for is the defect that defines the class; everything else, and every
detector the file does not list, maps to `other`. The file gives the reason for every choice that
could surprise a reader.

### Stable ids

The id is computed from data only: the class, the project-relative path, the line range and a
hash of the lines in the range, each stripped of surrounding whitespace. It contains no time and
no host path. The same code gives the same id on every machine and in every run; re-indenting
the code or changing code outside the range keeps the id, changing the code inside the range or
moving it changes the id. In SARIF the id is the partial fingerprint `assayFindingId/v1`.

### Deduplication

Results of the same class in the same file merge into one finding when they lie in the same
function, or when both lie outside every function and their line ranges overlap. A range that
spans several functions (a whole contract) counts as outside every function, so it does not
absorb the findings inside the functions. The functions are found in the snapshot itself, the
same way for both tools. A merged finding lists every source (tool, version, rule, severity,
message, locations) and covers the union of their line ranges. The details and their reasons are
in [ADR 0016](adr/0016-normalization-of-scan-findings.md).

### Severities

Severities stay as reported: Slither reports an impact and a confidence (`High (confidence
Medium)`), Aderyn reports `High` or `Low`. The first word selects the SARIF level and the place
in the order used by `--fail-on`, both from the table in `class_map.toml`:

| First word | SARIF level | `--fail-on` order |
|---|---|---|
| `High` | `error` | highest |
| `Medium` | `warning` | |
| `Low` | `note` | |
| `Informational` | `note` | |
| `Optimization` | `note` | lowest |

A severity whose first word is not in the table gets the level `warning` and meets every
`--fail-on` threshold. A merged finding gets the most severe level among its sources.

## The ledger

A scan records:

- the raw output of each analyzer as a content-addressed blob;
- a project named `scan` per input tree (root label `tree:` and the first 16 hex digits of the
  tree hash);
- one finding per normalized finding, as `CANDIDATE` at E0, under the key
  `scan:<id>:<first 16 hex digits of the tree hash>`;
- one scan per analyzer run, with one observation per result, each linked to its finding.

No claim is created and no status changes. Repeating a scan of the same input adds nothing: the
findings exist already, and a scan whose raw output is byte-identical, with its results belonging
to the same findings, is reused. When a result belongs to a different finding than before (for
example because the other analyzer failed the first time), the run is recorded as a new scan;
findings are never duplicated.

## Output

All three formats hold no timestamps and no host paths, and the same input gives the same bytes.

- `table`: the analyzers with their versions, status and result counts; one line per finding
  with its short id, class, location, function and sources; then what a candidate is.
- `json`: the format `assay-scan/1`, with the input tree hash, whether the scan is complete, each
  analyzer's status, version, result count and raw output hash, a summary per class, and every
  finding with its sources and their messages.
- `sarif`: one SARIF 2.1.0 run. `tool.driver` is Assay and lists exactly the rules
  (`<tool>/<detector>`) that occur among the sources; the analyzers appear as extensions with
  their versions. Each finding is one result with `ruleId` (the rule of its first source),
  `level`, a location relative to `PROJECTROOT`, the enclosing function as a logical location,
  `partialFingerprints` and the properties `assayEvidenceLevel` = `E0`, `assayStatus` =
  `candidate`, `assayClass` and `assaySources`. The message of every result states that it is an
  unverified hint. An analyzer that did not finish is reported as a tool execution notification,
  and the invocation is then marked unsuccessful. The tests validate the output against the
  official schema.

Tool messages are free text. Scan output never contains the words confirmed, vulnerable, secure,
safe, proven, guaranteed or unhackable: before tool text appears in any output, each of them is
replaced by `[term withheld]`. The ledger and the raw output keep the original text. Paths and
Solidity identifiers are printed as found.

## Limits

- A finding is a hint about code, not about a defect: it may be a false positive, and a defect
  may have no finding at all. [Static coverage](static-coverage.md) lists the fixture classes
  that neither analyzer detects.
- The function lookup is a token scan, not a compiler: unusual code can leave a location without
  a function, which only affects deduplication.
- Only Slither and Aderyn are supported, in the versions pinned in `docker/runner/versions.lock`.
  A new tool version can report results under new detector ids, which map to `other` until the
  mapping file lists them.
