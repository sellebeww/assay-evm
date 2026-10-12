"""Ledger schema and numbered migrations (`PRAGMA user_version`).

A migration is a tuple of SQL statements. Released migrations never change; a schema change is a
new migration. Each migration runs in one transaction together with its `schema.migrated` audit
event and the new `user_version`.

Migration 2 adds the static-analysis tables `scan` and `observation`. Migration 3 adds
`model_run`, the provenance of each model call. Tables of later phases (`benchmark`) come with
their own migrations.

Invariants enforced by triggers, independent of the application code:

- `claim`: a new claim is `asserted`; only `status` may change, along `asserted -> trusted,
  refuted, inconclusive` and `inconclusive -> trusted, refuted`; a `trusted`, `refuted` or
  `inconclusive` claim needs an `oracle_run` for that claim with the verdict `PASS`, `FAIL` or
  `INCONCLUSIVE`.
- `finding`: a new finding is `CANDIDATE` at E0; only the legal transitions of the lifecycle
  are accepted, each with minimal evidence (the full rules are in `lifecycle`): an exploit run
  on a vulnerable revision with the matching verdict after `POC_DRAFTED`, a patch for
  `PATCH_PROPOSED`, and runs on a patched revision of the finding after it (a `FAIL` for
  `REJECTED`, a `PASS` from each required oracle for `VERIFIED_WITHIN_BOUNDS`). Nothing else
  changes without a transition.
  CHECK constraints tie the evidence level to the state and require a reason for `REJECTED`.
- `oracle_run`, `artifact`, `verification` and `audit_log` reject UPDATE and DELETE.
- `audit_log` accepts only an INSERT that continues the chain; the hashes themselves are
  checked by `verify_chain`.
- `verification` accepts `VERIFIED_WITHIN_BOUNDS` only with a `PASS` from every required
  oracle on a revision of that patch and no `FAIL`.
- `scan` rejects UPDATE and DELETE. `observation` rejects DELETE, holds at most the number of
  results its scan reported, and allows one change only: linking it to a finding
  (`finding_id` from NULL to a finding). Analyzer output never touches `claim`; a claim's status
  still needs an `oracle_run`.
- `model_run` rejects UPDATE and DELETE. Nothing refers to it: no trigger, view or key of
  `claim` or `finding` reads it, so a model call cannot raise a status.
"""

import sqlite3
from typing import Final

from assay.ledger import audit
from assay.ledger.errors import SchemaVersionError

_HEX64: Final = "length({col}) = 64 AND {col} NOT GLOB '*[^0-9a-f]*'"


def _hex64(column: str) -> str:
    return _HEX64.format(col=column)


def _immutable(table: str) -> tuple[str, str]:
    return (
        f"CREATE TRIGGER {table}_no_update BEFORE UPDATE ON {table} "
        f"BEGIN SELECT RAISE(ABORT, '{table} rows are immutable'); END",
        f"CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table} "
        f"BEGIN SELECT RAISE(ABORT, '{table} rows are immutable'); END",
    )


def _finding_runs(condition: str) -> str:
    return f"EXISTS (SELECT 1 FROM finding_oracle_run WHERE finding_id = NEW.id AND {condition})"


_EXPLOIT_ON_VULNERABLE: Final = "oracle = 'exploit' AND revision_kind = 'vulnerable'"
_ON_OWN_PATCH: Final = "revision_kind = 'patched' AND patch_finding_id = NEW.id"
_REQUIRED_ORACLES_SQL: Final = "('integrity', 'exploit', 'variant', 'behavior', 'regression')"
_TRANSITION: Final = "(OLD.state || '>' || NEW.state)"
_LEGAL_TRANSITIONS: Final = """(
        'CANDIDATE>HYPOTHESIZED',
        'HYPOTHESIZED>POC_DRAFTED',
        'POC_DRAFTED>REPRODUCED',
        'POC_DRAFTED>NOT_REPRODUCED',
        'POC_DRAFTED>INCONCLUSIVE',
        'REPRODUCED>PATCH_PROPOSED',
        'PATCH_PROPOSED>VERIFIED_WITHIN_BOUNDS',
        'PATCH_PROPOSED>REJECTED',
        'PATCH_PROPOSED>INCONCLUSIVE'
    )"""

MIGRATION_1: Final[tuple[str, ...]] = (
    """
    CREATE TABLE project (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
        root_label TEXT NOT NULL CHECK (length(root_label) BETWEEN 1 AND 200),
        created_seq INTEGER NOT NULL
    ) STRICT
    """,
    f"""
    CREATE TABLE artifact (
        sha256 TEXT PRIMARY KEY CHECK ({_hex64("sha256")}),
        size INTEGER NOT NULL CHECK (size >= 0),
        media_type TEXT NOT NULL CHECK (length(media_type) BETWEEN 3 AND 100),
        label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 200),
        created_seq INTEGER NOT NULL
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE TABLE finding (
        id INTEGER PRIMARY KEY,
        project_id INTEGER NOT NULL REFERENCES project (id),
        stable_id TEXT NOT NULL UNIQUE CHECK (length(stable_id) BETWEEN 1 AND 128),
        class TEXT NOT NULL CHECK (length(class) BETWEEN 1 AND 64),
        state TEXT NOT NULL,
        evidence_level TEXT NOT NULL,
        reason TEXT CHECK (reason IS NULL OR length(reason) BETWEEN 1 AND 2000),
        created_seq INTEGER NOT NULL,
        updated_seq INTEGER NOT NULL,
        CHECK (
            (state IN ('CANDIDATE', 'HYPOTHESIZED', 'POC_DRAFTED', 'NOT_REPRODUCED')
                AND evidence_level = 'E0')
            OR (state IN ('REPRODUCED', 'PATCH_PROPOSED', 'REJECTED') AND evidence_level = 'E1')
            OR (state = 'INCONCLUSIVE' AND evidence_level IN ('E0', 'E1', 'E2'))
            OR (state = 'VERIFIED_WITHIN_BOUNDS' AND evidence_level = 'E3')
        ),
        -- A CHECK passes on NULL, so the reason is tested for NULL explicitly.
        CHECK (state <> 'REJECTED' OR (reason IS NOT NULL AND length(trim(reason)) > 0))
    ) STRICT
    """,
    """
    CREATE TABLE claim (
        id INTEGER PRIMARY KEY,
        finding_id INTEGER NOT NULL REFERENCES finding (id),
        text TEXT NOT NULL CHECK (length(text) BETWEEN 1 AND 2000),
        status TEXT NOT NULL
            CHECK (status IN ('asserted', 'trusted', 'refuted', 'inconclusive')),
        created_seq INTEGER NOT NULL
    ) STRICT
    """,
    f"""
    CREATE TABLE patch (
        id INTEGER PRIMARY KEY,
        finding_id INTEGER NOT NULL REFERENCES finding (id),
        source TEXT NOT NULL CHECK (source IN ('human', 'model', 'fixture')),
        diff_blob_sha256 TEXT NOT NULL REFERENCES artifact (sha256),
        diff_sha256 TEXT NOT NULL CHECK ({_hex64("diff_sha256")}),
        attempt_no INTEGER NOT NULL CHECK (attempt_no >= 1),
        created_seq INTEGER NOT NULL,
        UNIQUE (finding_id, attempt_no)
    ) STRICT
    """,
    f"""
    CREATE TABLE revision (
        id INTEGER PRIMARY KEY,
        project_id INTEGER NOT NULL REFERENCES project (id),
        kind TEXT NOT NULL CHECK (kind IN ('vulnerable', 'patched')),
        tree_sha256 TEXT NOT NULL CHECK ({_hex64("tree_sha256")}),
        patch_id INTEGER REFERENCES patch (id),
        created_seq INTEGER NOT NULL,
        CHECK ((kind = 'vulnerable') = (patch_id IS NULL))
    ) STRICT
    """,
    f"""
    CREATE TABLE oracle_run (
        id INTEGER PRIMARY KEY,
        claim_id INTEGER REFERENCES claim (id),
        revision_id INTEGER NOT NULL REFERENCES revision (id),
        oracle TEXT NOT NULL CHECK (
            oracle IN ('integrity', 'exploit', 'variant', 'behavior', 'regression', 'symbolic')
        ),
        argv_json TEXT NOT NULL
            CHECK (json_valid(argv_json) AND json_type(argv_json) = 'array'),
        image_digest TEXT NOT NULL CHECK (
            substr(image_digest, 1, 7) = 'sha256:' AND {_hex64("substr(image_digest, 8)")}
        ),
        seed TEXT CHECK (
            seed IS NULL OR (
                length(seed) BETWEEN 1 AND 78 AND seed NOT GLOB '*[^0-9]*'
                AND (seed = '0' OR seed NOT GLOB '0*')
            )
        ),
        exit_code INTEGER,
        verdict TEXT NOT NULL CHECK (verdict IN ('PASS', 'FAIL', 'INCONCLUSIVE')),
        reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 2000),
        trace_blob_sha256 TEXT NOT NULL REFERENCES artifact (sha256),
        created_seq INTEGER NOT NULL
    ) STRICT
    """,
    f"""
    CREATE TABLE verification (
        id INTEGER PRIMARY KEY,
        patch_id INTEGER NOT NULL REFERENCES patch (id),
        final_verdict TEXT NOT NULL
            CHECK (final_verdict IN ('VERIFIED_WITHIN_BOUNDS', 'REJECTED', 'INCONCLUSIVE')),
        reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 2000),
        bounds_json TEXT NOT NULL
            CHECK (json_valid(bounds_json) AND json_type(bounds_json) = 'object'),
        bundle_manifest_sha256 TEXT
            CHECK (bundle_manifest_sha256 IS NULL OR {_hex64("bundle_manifest_sha256")}),
        created_seq INTEGER NOT NULL
    ) STRICT
    """,
    f"""
    CREATE TABLE audit_log (
        seq INTEGER PRIMARY KEY CHECK (seq >= 1),
        event TEXT NOT NULL CHECK (length(event) BETWEEN 1 AND 64),
        payload_json TEXT NOT NULL,
        prev_hash TEXT NOT NULL CHECK ({_hex64("prev_hash")}),
        hash TEXT NOT NULL UNIQUE CHECK ({_hex64("hash")})
    ) STRICT
    """,
    "CREATE INDEX finding_project ON finding (project_id)",
    "CREATE INDEX claim_finding ON claim (finding_id)",
    "CREATE INDEX patch_finding ON patch (finding_id)",
    "CREATE INDEX revision_patch ON revision (patch_id)",
    "CREATE INDEX oracle_run_claim ON oracle_run (claim_id)",
    "CREATE INDEX oracle_run_revision ON oracle_run (revision_id)",
    """
    CREATE VIEW finding_oracle_run AS
    SELECT
        c.finding_id AS finding_id,
        r.id AS oracle_run_id,
        r.oracle AS oracle,
        r.verdict AS verdict,
        v.id AS revision_id,
        v.kind AS revision_kind,
        p.finding_id AS patch_finding_id
    FROM oracle_run AS r
    JOIN claim AS c ON c.id = r.claim_id
    JOIN revision AS v ON v.id = r.revision_id
    LEFT JOIN patch AS p ON p.id = v.patch_id
    """,
    # claim
    """
    CREATE TRIGGER claim_insert_asserted BEFORE INSERT ON claim
    WHEN NEW.status IS NOT 'asserted'
    BEGIN SELECT RAISE(ABORT, 'a new claim must be asserted'); END
    """,
    """
    CREATE TRIGGER claim_fixed_fields BEFORE UPDATE ON claim
    WHEN NEW.id IS NOT OLD.id OR NEW.finding_id IS NOT OLD.finding_id
        OR NEW.text IS NOT OLD.text OR NEW.created_seq IS NOT OLD.created_seq
    BEGIN SELECT RAISE(ABORT, 'only the status of a claim can change'); END
    """,
    """
    CREATE TRIGGER claim_status_change BEFORE UPDATE ON claim
    WHEN NEW.status IS NOT OLD.status AND NOT (
        (OLD.status = 'asserted' AND NEW.status IN ('trusted', 'refuted', 'inconclusive'))
        OR (OLD.status = 'inconclusive' AND NEW.status IN ('trusted', 'refuted'))
    )
    BEGIN SELECT RAISE(ABORT, 'illegal claim status change'); END
    """,
    """
    CREATE TRIGGER claim_status_requires_oracle_run BEFORE UPDATE ON claim
    WHEN NEW.status IN ('trusted', 'refuted', 'inconclusive') AND NOT EXISTS (
        SELECT 1 FROM oracle_run AS r
        WHERE r.claim_id = NEW.id AND r.verdict = CASE NEW.status
            WHEN 'trusted' THEN 'PASS'
            WHEN 'refuted' THEN 'FAIL'
            ELSE 'INCONCLUSIVE'
        END
    )
    BEGIN SELECT RAISE(ABORT, 'claim status requires an oracle_run with a matching verdict'); END
    """,
    # finding
    """
    CREATE TRIGGER finding_insert_candidate BEFORE INSERT ON finding
    WHEN NEW.state IS NOT 'CANDIDATE' OR NEW.evidence_level IS NOT 'E0' OR NEW.reason IS NOT NULL
    BEGIN SELECT RAISE(ABORT, 'a new finding must be a CANDIDATE at E0'); END
    """,
    """
    CREATE TRIGGER finding_fixed_fields BEFORE UPDATE ON finding
    WHEN NEW.id IS NOT OLD.id OR NEW.project_id IS NOT OLD.project_id
        OR NEW.stable_id IS NOT OLD.stable_id OR NEW.class IS NOT OLD.class
        OR NEW.created_seq IS NOT OLD.created_seq
    BEGIN SELECT RAISE(ABORT, 'finding identity fields are immutable'); END
    """,
    """
    CREATE TRIGGER finding_changes_by_transition BEFORE UPDATE ON finding
    WHEN NEW.state IS OLD.state AND (
        NEW.evidence_level IS NOT OLD.evidence_level OR NEW.reason IS NOT OLD.reason
        OR NEW.updated_seq IS NOT OLD.updated_seq
    )
    BEGIN SELECT RAISE(ABORT, 'a finding changes only through a state transition'); END
    """,
    f"""
    CREATE TRIGGER finding_legal_transition BEFORE UPDATE ON finding
    WHEN NEW.state IS NOT OLD.state AND {_TRANSITION} NOT IN {_LEGAL_TRANSITIONS}
    BEGIN SELECT RAISE(ABORT, 'illegal finding transition'); END
    """,
    f"""
    CREATE TRIGGER finding_transition_evidence BEFORE UPDATE ON finding
    WHEN NEW.state IS NOT OLD.state AND {_TRANSITION} IN {_LEGAL_TRANSITIONS}
    AND NOT (CASE NEW.state
        WHEN 'REPRODUCED' THEN
            {_finding_runs(_EXPLOIT_ON_VULNERABLE + " AND verdict = 'PASS'")}
        WHEN 'NOT_REPRODUCED' THEN
            {_finding_runs(_EXPLOIT_ON_VULNERABLE + " AND verdict = 'FAIL'")}
        WHEN 'INCONCLUSIVE' THEN CASE OLD.state
            WHEN 'POC_DRAFTED' THEN
                {_finding_runs(_EXPLOIT_ON_VULNERABLE + " AND verdict = 'INCONCLUSIVE'")}
            ELSE {_finding_runs(_ON_OWN_PATCH)}
            END
        WHEN 'PATCH_PROPOSED' THEN EXISTS (SELECT 1 FROM patch WHERE finding_id = NEW.id)
        WHEN 'VERIFIED_WITHIN_BOUNDS' THEN (
            SELECT count(DISTINCT oracle) FROM finding_oracle_run
            WHERE finding_id = NEW.id AND {_ON_OWN_PATCH} AND verdict = 'PASS'
                AND oracle IN {_REQUIRED_ORACLES_SQL}
        ) = 5
        WHEN 'REJECTED' THEN {_finding_runs(_ON_OWN_PATCH + " AND verdict = 'FAIL'")}
        ELSE 1
    END)
    BEGIN SELECT RAISE(ABORT, 'finding transition lacks the required oracle evidence'); END
    """,
    # immutable tables
    *_immutable("oracle_run"),
    *_immutable("artifact"),
    *_immutable("verification"),
    f"""
    CREATE TRIGGER verification_verified_requires_runs BEFORE INSERT ON verification
    WHEN NEW.final_verdict = 'VERIFIED_WITHIN_BOUNDS' AND (
        (
            SELECT count(DISTINCT r.oracle) FROM oracle_run AS r
            JOIN revision AS v ON v.id = r.revision_id
            WHERE v.patch_id = NEW.patch_id AND r.verdict = 'PASS'
                AND r.oracle IN {_REQUIRED_ORACLES_SQL}
        ) < 5
        OR EXISTS (
            SELECT 1 FROM oracle_run AS r JOIN revision AS v ON v.id = r.revision_id
            WHERE v.patch_id = NEW.patch_id AND r.verdict = 'FAIL'
        )
    )
    BEGIN SELECT RAISE(ABORT, 'VERIFIED_WITHIN_BOUNDS needs every required oracle PASS, no FAIL');
    END
    """,
    # audit_log
    """
    CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
    BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END
    """,
    """
    CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
    BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END
    """,
    f"""
    CREATE TRIGGER audit_log_continues_chain BEFORE INSERT ON audit_log
    WHEN NEW.seq IS NOT coalesce((SELECT max(seq) FROM audit_log), 0) + 1
        OR NEW.prev_hash IS NOT coalesce(
            (SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1), '{audit.GENESIS_HASH}'
        )
    BEGIN SELECT RAISE(ABORT, 'audit_log row does not continue the chain'); END
    """,
)

MIGRATION_2: Final[tuple[str, ...]] = (
    f"""
    CREATE TABLE scan (
        id INTEGER PRIMARY KEY,
        project_id INTEGER NOT NULL REFERENCES project (id),
        tool TEXT NOT NULL CHECK (tool IN ('slither', 'aderyn')),
        tool_version TEXT NOT NULL CHECK (length(tool_version) BETWEEN 1 AND 64),
        raw_blob_sha256 TEXT NOT NULL REFERENCES artifact (sha256),
        input_tree_sha256 TEXT NOT NULL CHECK ({_hex64("input_tree_sha256")}),
        result_count INTEGER NOT NULL CHECK (result_count >= 0),
        created_seq INTEGER NOT NULL
    ) STRICT
    """,
    """
    CREATE TABLE observation (
        id INTEGER PRIMARY KEY,
        scan_id INTEGER NOT NULL REFERENCES scan (id),
        finding_id INTEGER REFERENCES finding (id),
        rule_id TEXT NOT NULL CHECK (length(rule_id) BETWEEN 1 AND 200),
        severity_reported TEXT NOT NULL CHECK (length(severity_reported) BETWEEN 1 AND 64),
        location_json TEXT NOT NULL
            CHECK (json_valid(location_json) AND json_type(location_json) = 'array'),
        message TEXT NOT NULL CHECK (length(message) BETWEEN 1 AND 4000),
        created_seq INTEGER NOT NULL
    ) STRICT
    """,
    "CREATE INDEX scan_project ON scan (project_id)",
    "CREATE INDEX observation_scan ON observation (scan_id)",
    "CREATE INDEX observation_finding ON observation (finding_id)",
    *_immutable("scan"),
    """
    CREATE TRIGGER observation_no_delete BEFORE DELETE ON observation
    BEGIN SELECT RAISE(ABORT, 'observation rows cannot be deleted'); END
    """,
    """
    CREATE TRIGGER observation_link_only BEFORE UPDATE ON observation
    WHEN NEW.id IS NOT OLD.id OR NEW.scan_id IS NOT OLD.scan_id
        OR NEW.rule_id IS NOT OLD.rule_id OR NEW.severity_reported IS NOT OLD.severity_reported
        OR NEW.location_json IS NOT OLD.location_json OR NEW.message IS NOT OLD.message
        OR NEW.created_seq IS NOT OLD.created_seq
        OR OLD.finding_id IS NOT NULL OR NEW.finding_id IS NULL
    BEGIN SELECT RAISE(ABORT, 'an observation can only be linked to a finding, once'); END
    """,
    """
    CREATE TRIGGER observation_within_result_count BEFORE INSERT ON observation
    WHEN (SELECT count(*) FROM observation WHERE scan_id = NEW.scan_id)
        >= (SELECT result_count FROM scan WHERE id = NEW.scan_id)
    BEGIN SELECT RAISE(ABORT, 'more observations than the scan reported'); END
    """,
)

MIGRATION_3: Final[tuple[str, ...]] = (
    f"""
    CREATE TABLE model_run (
        id INTEGER PRIMARY KEY,
        finding_id INTEGER REFERENCES finding (id),
        endpoint_host TEXT NOT NULL CHECK (
            length(endpoint_host) BETWEEN 1 AND 255 AND endpoint_host NOT GLOB '*[@/?# ]*'
        ),
        model TEXT NOT NULL CHECK (length(model) BETWEEN 1 AND 200),
        prompt_sha256 TEXT NOT NULL CHECK ({_hex64("prompt_sha256")}),
        response_sha256 TEXT NOT NULL CHECK ({_hex64("response_sha256")}),
        tokens_in INTEGER NOT NULL CHECK (tokens_in >= 0),
        tokens_out INTEGER NOT NULL CHECK (tokens_out >= 0),
        latency_ms INTEGER NOT NULL CHECK (latency_ms >= 0),
        cassette_mode TEXT NOT NULL CHECK (cassette_mode IN ('replay', 'record', 'live')),
        created_seq INTEGER NOT NULL
    ) STRICT
    """,
    "CREATE INDEX model_run_finding ON model_run (finding_id)",
    *_immutable("model_run"),
)

MIGRATIONS: Final[tuple[tuple[str, ...], ...]] = (MIGRATION_1, MIGRATION_2, MIGRATION_3)
SCHEMA_VERSION: Final = len(MIGRATIONS)


def user_version(conn: sqlite3.Connection) -> int:
    return int(conn.execute("PRAGMA user_version").fetchone()[0])


def migrate(conn: sqlite3.Connection) -> int:
    """Apply every pending migration and return the schema version.

    `conn` must be in autocommit mode (`isolation_level=None`); each migration runs in its own
    `BEGIN IMMEDIATE` transaction.
    """
    for version, statements in enumerate(MIGRATIONS, start=1):
        conn.execute("BEGIN IMMEDIATE")
        try:
            current = user_version(conn)
            if current > SCHEMA_VERSION:
                raise SchemaVersionError(
                    f"ledger schema version {current} is newer than this Assay supports "
                    f"({SCHEMA_VERSION})"
                )
            if current >= version:
                conn.execute("ROLLBACK")
                continue
            if current != version - 1:
                raise SchemaVersionError(f"ledger schema version {current} is not consistent")
            for statement in statements:
                conn.execute(statement)
            audit.append(conn, "schema.migrated", {"version": version})
            # `version` is an int from MIGRATIONS, never outside input.
            conn.execute(f"PRAGMA user_version = {version:d}")
        except BaseException:
            rollback(conn)
            raise
        conn.execute("COMMIT")
    return check_version(conn)


def rollback(conn: sqlite3.Connection) -> None:
    """Roll back the open transaction, if SQLite has not already done so after an error."""
    if conn.in_transaction:
        conn.execute("ROLLBACK")


def check_version(conn: sqlite3.Connection) -> int:
    """Return the schema version, or raise if it is not the version this code supports."""
    current = user_version(conn)
    if current == 0:
        raise SchemaVersionError("not an Assay ledger (schema version 0)")
    if current != SCHEMA_VERSION:
        raise SchemaVersionError(
            f"ledger schema version {current} is not supported (expected {SCHEMA_VERSION})"
        )
    return current
