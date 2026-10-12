# ADR 0004: SQLite ledger with content-addressed blobs

- Status: Accepted
- Date: 2026-10-02

## Context

Assay needs a system of record for findings, claims, oracle runs, patches and verifications. The
record must be auditable, must enforce its own invariants, and must work on one machine for one
user without any server. Large artifacts (tool output, traces, diffs, logs) must be stored without
duplication and checked for corruption.

## Decision

- The ledger is a SQLite database at `.assay/ledger.db`, accessed through the standard library
  `sqlite3` module. Schema migrations are numbered with `PRAGMA user_version`.
- Large artifacts are stored as content-addressed blobs under `.assay/blobs/`, keyed by sha256,
  written once and verified on every read. The `artifact` table indexes them.
- Invariants are enforced in two places: application code and SQLite triggers. Triggers reject a
  claim moving to `trusted` or `refuted` without a matching `oracle_run`, and reject UPDATE and
  DELETE on `oracle_run` and `audit_log`.
- `audit_log` is append-only and hash-chained: each row's hash is the sha256 of the previous hash
  plus the canonical content of the row. A verification routine walks the chain and reports the
  first violation.
- Timestamps live only in the ledger, never in bundles or reports.

## Consequences

- No database server, no network service and no extra runtime dependency.
- A raw `UPDATE` through the `sqlite3` shell cannot promote a claim; tests prove this.
- The hash chain detects edits to individual rows. It is tamper-evident, not a signature: a party
  with write access can rebuild the whole chain. Bundles state this limit.
- Concurrent multi-user access is out of scope.
