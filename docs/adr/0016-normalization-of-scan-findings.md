# ADR 0016: Normalization, deduplication and ledger keys of scan findings

- Status: Accepted
- Date: 2026-10-04

## Context

`assay scan` runs Slither and Aderyn on a snapshot of a project and turns their results into
normalized candidate findings: a class from a mapping file, a stable id, the severity as the
tool reported it, the state `CANDIDATE` at evidence level E0. The design asks for three more
properties:

- results of both tools at the same place merge into one finding when they have the same class
  and lie in the same file and function, or when their line ranges overlap;
- the stable id is the sha256 of the class, the relative path, the normalized line range and a
  hash of the code snippet;
- repeating a scan on the same input does not duplicate findings in the ledger and produces
  byte-identical JSON; scan output never calls code confirmed, vulnerable, secure or safe.

Implementing them raised five questions the design does not answer.

1. Slither places many results on a whole contract (its first element is the contract), and
   such a range overlaps every function of the contract. Merging by overlap alone would fold
   unrelated results of one class in one contract into a single finding.
2. Slither reports the function of a result, Aderyn reports only a line. "Same function" needs
   one definition for both tools.
3. The ledger's `finding.stable_id` is unique across the whole database, while the same code
   (and so the same stable id) occurs in different projects and in different revisions of one
   project.
4. The finding that a result belongs to depends on what the other tool reported in the same
   scan: alone, a result is its own finding; next to a result of the other tool in the same
   function, it is part of a merged finding with another range and id. An observation row can be
   linked to a finding only once.
5. A scan in which one analyzer timed out or failed has finished, but it is not a full result,
   and tool messages are free text that can contain any word.

## Decision

1. Deduplication. Candidates merge when they have the same class and the same file, and either
   lie in the same function, or both lie outside every function and their line ranges overlap.
   A location that spans more than one function (a whole contract) counts as outside every
   function, so it never merges with a location inside a function. Merging is transitive among
   overlapping ranges. A merged finding covers the union of the line ranges and keeps every
   source.
2. Functions are taken from the snapshot, not from the tools: a single linear pass over the
   Solidity tokens of the file (comments and strings skipped, braces counted, nothing evaluated)
   finds the line range of every function, modifier, constructor, fallback and receive body.
   A location belongs to the function whose body contains its whole range. A file that cannot be
   read (missing, a symlink, larger than 2 MiB) has no functions and an empty snippet.
3. Line ranges are normalized by ordering start and end. The snippet is the lines of the range,
   each stripped of surrounding whitespace; the id is the sha256 of
   `assay-finding-v1`, class, path, `start:end` and the sha256 of the snippet, joined by
   newlines. The id therefore changes when the code in the range or the range itself changes,
   and not when indentation or code elsewhere changes.
4. Ledger keys. A scan records its findings under a project named `scan` with the root label
   `tree:<first 16 hex digits of the input tree hash>`, and a finding's `stable_id` in the ledger
   is `scan:<stable id>:<same 16 hex digits>`. Output shows the plain stable id. The same input
   always maps to the same project and keys; a changed project is a new project.
5. A scan whose raw output is byte-identical to one already recorded for the same project, tool
   and version is reused only if each of its observations is unlinked or already linked to the
   finding it belongs to now. Otherwise the run is recorded as a new scan with new observations.
   Findings are never duplicated either way.
6. Exit codes. A finished scan exits with 0 whether or not it found anything, and with 1 when
   `--fail-on` is given and a finding has a reported severity at or above the threshold. A scan in
   which an analyzer timed out, failed or wrote unusable output exits with 3 (incomplete; its other
   results are still recorded and printed), unless `--fail-on` already decided 1. An analyzer that
   ran out of memory gives 4, as do Docker, image and ledger problems; ingest rejection gives 5.
7. Wording. Assay's own scan text uses "candidate (unverified)". Scan output never contains
   the words confirmed, vulnerable, secure, safe, proven, guaranteed or unhackable: before tool
   text (detector messages, the last line of an error stream) appears in it, each of them is
   replaced by `[term withheld]`. The ledger and the stored raw output keep the tool's text
   unchanged. Structured fields (paths, Solidity identifiers) are printed as found.

## Consequences

- Two results of one class in different functions of a contract stay separate findings, even
  when a contract-wide result of the same class exists.
- Dropping or adding an analyzer can change the range, and so the id, of a merged finding. The
  findings of both runs stay in the ledger, each linked to the observations it came from.
- A finding id is meaningful only together with the input tree in the ledger; a later command
  that refers to a scan finding looks it up with the tree of the project it runs on.
- A partial scan is never reported as a clean success: CI sees exit code 3, and the SARIF log
  marks the invocation as unsuccessful with a notification per failed analyzer.
- Tool text in scan output can contain `[term withheld]`; the original wording is available in
  the ledger.
