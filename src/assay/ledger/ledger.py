"""The ledger: the system of record for findings, claims, oracle runs and blobs.

Every change runs in one transaction together with its `audit_log` event, and every row records
the `created_seq` of that event. A claim's status changes only in `promote_claim`, a finding's
state only in `transition_finding`; the schema's triggers apply the same rules to any other
writer of the database.
"""

import json
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from types import TracebackType
from typing import Annotated, Any, NewType, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
)

from assay.ledger import audit
from assay.ledger.audit import ChainReport
from assay.ledger.blobs import BlobStore, is_sha256_hex
from assay.ledger.errors import (
    BlobCorrupted,
    ClaimPromotionError,
    IllegalTransition,
    InvalidInput,
    LedgerError,
    LedgerIntegrityError,
    NotFound,
)
from assay.ledger.invariants import Violation, check_invariants
from assay.ledger.lifecycle import (
    REQUIRED_ORACLES,
    CassetteMode,
    ClaimStatus,
    EvidenceLevel,
    FinalVerdict,
    FindingState,
    OracleName,
    PatchSource,
    RevisionKind,
    RunFacts,
    ScanTool,
    Verdict,
    check_transition,
    claim_status_after,
)
from assay.ledger.schema import check_version, migrate, rollback

ProjectId = NewType("ProjectId", int)
RevisionId = NewType("RevisionId", int)
FindingId = NewType("FindingId", int)
ClaimId = NewType("ClaimId", int)
PatchId = NewType("PatchId", int)
OracleRunId = NewType("OracleRunId", int)
VerificationId = NewType("VerificationId", int)
ScanId = NewType("ScanId", int)
ObservationId = NewType("ObservationId", int)
ModelRunId = NewType("ModelRunId", int)


def _no_nul(value: str) -> str:
    if "\x00" in value:
        raise ValueError("must not contain NUL characters")
    return value


def _plain_text(value: str) -> str:
    _no_nul(value)
    if not value.strip():
        raise ValueError("must not be blank")
    return value


Text = Annotated[str, StringConstraints(max_length=2000), AfterValidator(_plain_text)]
Label = Annotated[str, StringConstraints(max_length=200), AfterValidator(_plain_text)]
Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
ImageDigest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
StableId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")]
ClassId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
MediaType = Annotated[
    str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9.+-]{0,47}/[a-z0-9][a-z0-9.+-]{0,47}$")
]
Seed = Annotated[int, Field(ge=0, lt=2**256)]
Argument = Annotated[str, StringConstraints(max_length=4096), AfterValidator(_no_nul)]

MAX_PATCH_BYTES = 1024 * 1024
MAX_SCAN_OBSERVATIONS = 10_000


class _Input(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")


class OracleRunInput(_Input):
    """One oracle execution, as `record_oracle_run` stores it."""

    claim_id: ClaimId | None
    revision_id: RevisionId
    oracle: OracleName
    argv: tuple[Argument, ...] = Field(max_length=256)
    image_digest: ImageDigest
    seed: Seed | None
    exit_code: int | None
    verdict: Verdict
    reason: Text
    trace_blob_sha256: Sha256Hex


class _NewProject(_Input):
    name: Label
    root_label: Label


class _NewRevision(_Input):
    project_id: Annotated[ProjectId, Field(ge=1)]
    kind: RevisionKind
    tree_sha256: Sha256Hex
    patch_id: Annotated[PatchId, Field(ge=1)] | None


class _NewFinding(_Input):
    project_id: Annotated[ProjectId, Field(ge=1)]
    stable_id: StableId
    vuln_class: ClassId


class _NewClaim(_Input):
    finding_id: Annotated[FindingId, Field(ge=1)]
    text: Text


class _NewPatch(_Input):
    finding_id: Annotated[FindingId, Field(ge=1)]
    source: PatchSource
    # An empty diff is a patch that changes nothing; its verification is still recorded.
    diff: bytes = Field(max_length=MAX_PATCH_BYTES)
    attempt_no: Annotated[int, Field(ge=1, le=1000)]


class _NewVerification(_Input):
    patch_id: Annotated[PatchId, Field(ge=1)]
    final_verdict: FinalVerdict
    reason: Text
    bundle_manifest_sha256: Sha256Hex | None


class _NewBlob(_Input):
    data: bytes
    media_type: MediaType
    label: Label


ToolVersion = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")]
RuleId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,199}$")]
Severity = Annotated[str, StringConstraints(pattern=r"^[A-Za-z][A-Za-z0-9 _()-]{0,63}$")]
Message = Annotated[str, StringConstraints(max_length=4000), AfterValidator(_plain_text)]
LocationPath = Annotated[
    str, StringConstraints(min_length=1, max_length=1024), AfterValidator(_no_nul)
]


class ScanLocation(_Input):
    """A location reported by an analyzer: a project-relative path and a line range."""

    path: LocationPath
    start_line: Annotated[int, Field(ge=1, le=10_000_000)]
    end_line: Annotated[int, Field(ge=1, le=10_000_000)]


class ObservationInput(_Input):
    """One analyzer result, as `record_scan` stores it. Unverified (evidence level E0)."""

    rule_id: RuleId
    severity_reported: Severity
    message: Message
    locations: tuple[ScanLocation, ...] = Field(max_length=64)


EndpointHost = Annotated[
    str, StringConstraints(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9.:\[\]_-]+$")
]
Count = Annotated[int, Field(ge=0, le=10**9)]


class _NewModelRun(_Input):
    finding_id: Annotated[FindingId, Field(ge=1)] | None
    endpoint_host: EndpointHost
    model: Label
    prompt_sha256: Sha256Hex
    response_sha256: Sha256Hex
    tokens_in: Count
    tokens_out: Count
    latency_ms: Count
    cassette_mode: CassetteMode


class _NewScan(_Input):
    project_id: Annotated[ProjectId, Field(ge=1)]
    tool: ScanTool
    tool_version: ToolVersion
    raw_blob_sha256: Sha256Hex
    input_tree_sha256: Sha256Hex
    observations: tuple[ObservationInput, ...] = Field(max_length=MAX_SCAN_OBSERVATIONS)


class _ScanKey(_Input):
    project_id: Annotated[ProjectId, Field(ge=1)]
    tool: ScanTool
    tool_version: ToolVersion
    raw_blob_sha256: Sha256Hex
    input_tree_sha256: Sha256Hex


class _Link(_Input):
    observation_id: Annotated[ObservationId, Field(ge=1)]
    finding_id: Annotated[FindingId, Field(ge=1)]


class _Promotion(_Input):
    claim_id: Annotated[ClaimId, Field(ge=1)]
    oracle_run_id: Annotated[OracleRunId, Field(ge=1)]


class _Transition(_Input):
    finding_id: Annotated[FindingId, Field(ge=1)]
    target: FindingState
    oracle_run_ids: tuple[Annotated[OracleRunId, Field(ge=1)], ...] = Field(max_length=64)
    reason: Text | None


def _validate[M: _Input](model_type: type[M], /, **values: Any) -> M:
    try:
        return model_type(**values)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in exc.errors(include_url=False, include_input=False)
        )
        raise InvalidInput(problems) from exc


class _Record(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Finding(_Record):
    id: FindingId
    project_id: ProjectId
    stable_id: str
    vuln_class: str
    state: FindingState
    evidence_level: EvidenceLevel
    reason: str | None


class FindingTransition(_Record):
    """One recorded state change of a finding."""

    source: FindingState
    target: FindingState
    reason: str | None


class Claim(_Record):
    id: ClaimId
    finding_id: FindingId
    text: str
    status: ClaimStatus


class OracleRun(_Record):
    id: OracleRunId
    claim_id: ClaimId | None
    revision_id: RevisionId
    oracle: OracleName
    argv: tuple[str, ...]
    image_digest: str
    seed: int | None
    exit_code: int | None
    verdict: Verdict
    reason: str
    trace_blob_sha256: str


class Scan(_Record):
    id: ScanId
    project_id: ProjectId
    tool: ScanTool
    tool_version: str
    raw_blob_sha256: str
    input_tree_sha256: str
    result_count: int


class Observation(_Record):
    id: ObservationId
    scan_id: ScanId
    finding_id: FindingId | None
    rule_id: str
    severity_reported: str
    locations: tuple[ScanLocation, ...]
    message: str


class ModelRun(_Record):
    """One model call: provenance only. It has no verdict and never changes a status."""

    id: ModelRunId
    finding_id: FindingId | None
    endpoint_host: str
    model: str
    prompt_sha256: str
    response_sha256: str
    tokens_in: int
    tokens_out: int
    latency_ms: int
    cassette_mode: CassetteMode


def connect(path: Path, *, read_only: bool = False) -> sqlite3.Connection:
    """Open `path` with the settings every ledger connection uses (autocommit mode).

    Defensive mode and an untrusted schema keep a crafted database file from running more
    than plain SQL; foreign keys are enforced.
    """
    if read_only:
        uri = f"{path.resolve(strict=True).as_uri()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, isolation_level=None)
    else:
        conn = sqlite3.connect(path, isolation_level=None)
    try:
        conn.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)
        conn.setconfig(sqlite3.SQLITE_DBCONFIG_TRUSTED_SCHEMA, False)
        conn.execute("PRAGMA foreign_keys = ON")
    except BaseException:
        conn.close()
        raise
    return conn


class Ledger:
    """Typed access to a ledger database and its blob store.

    Open it with `Ledger.open`, and close it with `close` or a `with` block.
    """

    def __init__(self, connection: sqlite3.Connection, blobs: BlobStore) -> None:
        self._conn = connection
        self.blobs = blobs

    @classmethod
    def open(cls, path: Path, *, blob_dir: Path | None = None, read_only: bool = False) -> Self:
        """Open (and create or migrate) the ledger at `path`.

        Blobs live in `blob_dir`, by default `blobs/` next to the database file (for
        `.assay/ledger.db` that is `.assay/blobs/`). A read-only ledger is never migrated and
        must already have the current schema version.
        """
        conn = connect(path, read_only=read_only)
        try:
            if read_only:
                check_version(conn)
            else:
                migrate(conn)
        except BaseException:
            conn.close()
            raise
        return cls(conn, BlobStore(blob_dir if blob_dir is not None else path.parent / "blobs"))

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        conn = self._conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except sqlite3.IntegrityError as exc:
            rollback(conn)
            raise LedgerIntegrityError(str(exc)) from exc
        except BaseException:
            rollback(conn)
            raise
        conn.execute("COMMIT")

    @staticmethod
    def _audit(conn: sqlite3.Connection, seq: int, event: str, payload: dict[str, object]) -> None:
        appended = audit.append(conn, event, payload)
        if appended != seq:
            raise LedgerError(f"audit_log moved from seq {seq} to {appended} during a write")

    @staticmethod
    def _insert(conn: sqlite3.Connection, sql: str, values: tuple[object, ...]) -> int:
        row_id = conn.execute(sql, values).lastrowid
        if row_id is None:
            raise LedgerError("insert did not return a row id")
        return row_id

    @staticmethod
    def _require(conn: sqlite3.Connection, table: str, row_id: int) -> None:
        # `table` is one of the fixed names used in this module, never outside input.
        if conn.execute(f"SELECT 1 FROM {table} WHERE id = ?", (row_id,)).fetchone() is None:
            raise NotFound(f"{table} {row_id} does not exist")

    # Projects, revisions, patches

    def add_project(self, name: str, root_label: str) -> ProjectId:
        """Add a project. `root_label` is a stable label, never an absolute host path."""
        data = _validate(_NewProject, name=name, root_label=root_label)
        with self._write() as conn:
            seq = audit.next_seq(conn)
            project_id = ProjectId(
                self._insert(
                    conn,
                    "INSERT INTO project (name, root_label, created_seq) VALUES (?, ?, ?)",
                    (data.name, data.root_label, seq),
                )
            )
            self._audit(
                conn,
                seq,
                "project.added",
                {"project_id": project_id, "name": data.name, "root_label": data.root_label},
            )
        return project_id

    def add_revision(
        self,
        project_id: ProjectId,
        kind: RevisionKind,
        tree_sha256: str,
        patch_id: PatchId | None = None,
    ) -> RevisionId:
        """Add a snapshot of a project. A patched revision names its patch, a vulnerable one not."""
        data = _validate(
            _NewRevision,
            project_id=project_id,
            kind=kind,
            tree_sha256=tree_sha256,
            patch_id=patch_id,
        )
        if (data.kind is RevisionKind.PATCHED) != (data.patch_id is not None):
            raise InvalidInput("a patched revision needs a patch_id; a vulnerable one has none")
        with self._write() as conn:
            self._require(conn, "project", data.project_id)
            if data.patch_id is not None:
                owner = conn.execute(
                    "SELECT f.project_id FROM patch AS p JOIN finding AS f ON f.id = p.finding_id "
                    "WHERE p.id = ?",
                    (data.patch_id,),
                ).fetchone()
                if owner is None:
                    raise NotFound(f"patch {data.patch_id} does not exist")
                if owner[0] != data.project_id:
                    raise InvalidInput(f"patch {data.patch_id} belongs to another project")
            seq = audit.next_seq(conn)
            revision_id = RevisionId(
                self._insert(
                    conn,
                    "INSERT INTO revision (project_id, kind, tree_sha256, patch_id, created_seq) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (data.project_id, data.kind.value, data.tree_sha256, data.patch_id, seq),
                )
            )
            self._audit(
                conn,
                seq,
                "revision.added",
                {
                    "revision_id": revision_id,
                    "project_id": data.project_id,
                    "kind": data.kind.value,
                    "tree_sha256": data.tree_sha256,
                    "patch_id": data.patch_id,
                },
            )
        return revision_id

    def add_patch(
        self, finding_id: FindingId, source: PatchSource, diff: bytes, attempt_no: int
    ) -> PatchId:
        """Store `diff` as a blob and record it as attempt `attempt_no` for the finding."""
        data = _validate(
            _NewPatch, finding_id=finding_id, source=source, diff=diff, attempt_no=attempt_no
        )
        digest = self.blobs.put(data.diff)
        with self._write() as conn:
            self._require(conn, "finding", data.finding_id)
            taken = conn.execute(
                "SELECT 1 FROM patch WHERE finding_id = ? AND attempt_no = ?",
                (data.finding_id, data.attempt_no),
            ).fetchone()
            if taken is not None:
                raise InvalidInput(
                    f"finding {data.finding_id} already has a patch for attempt {data.attempt_no}"
                )
            self._index_blob(conn, digest, len(data.diff), "text/x-diff", "patch diff")
            seq = audit.next_seq(conn)
            patch_id = PatchId(
                self._insert(
                    conn,
                    "INSERT INTO patch (finding_id, source, diff_blob_sha256, diff_sha256, "
                    "attempt_no, created_seq) VALUES (?, ?, ?, ?, ?, ?)",
                    (data.finding_id, data.source.value, digest, digest, data.attempt_no, seq),
                )
            )
            self._audit(
                conn,
                seq,
                "patch.added",
                {
                    "patch_id": patch_id,
                    "finding_id": data.finding_id,
                    "source": data.source.value,
                    "diff_sha256": digest,
                    "attempt_no": data.attempt_no,
                },
            )
        return patch_id

    # Findings and claims

    def add_finding(self, project_id: ProjectId, stable_id: str, vuln_class: str) -> FindingId:
        """Add a finding as `CANDIDATE` at evidence level E0."""
        data = _validate(
            _NewFinding, project_id=project_id, stable_id=stable_id, vuln_class=vuln_class
        )
        with self._write() as conn:
            self._require(conn, "project", data.project_id)
            if conn.execute(
                "SELECT 1 FROM finding WHERE stable_id = ?", (data.stable_id,)
            ).fetchone():
                raise InvalidInput(f"a finding with stable_id {data.stable_id!r} already exists")
            seq = audit.next_seq(conn)
            finding_id = FindingId(
                self._insert(
                    conn,
                    "INSERT INTO finding (project_id, stable_id, class, state, evidence_level, "
                    "reason, created_seq, updated_seq) VALUES (?, ?, ?, ?, ?, NULL, ?, ?)",
                    (
                        data.project_id,
                        data.stable_id,
                        data.vuln_class,
                        FindingState.CANDIDATE.value,
                        EvidenceLevel.E0.value,
                        seq,
                        seq,
                    ),
                )
            )
            self._audit(
                conn,
                seq,
                "finding.added",
                {
                    "finding_id": finding_id,
                    "project_id": data.project_id,
                    "stable_id": data.stable_id,
                    "class": data.vuln_class,
                    "state": FindingState.CANDIDATE.value,
                    "evidence_level": EvidenceLevel.E0.value,
                },
            )
        return finding_id

    def add_claim(self, finding_id: FindingId, text: str) -> ClaimId:
        """Add an `asserted` claim about a finding."""
        data = _validate(_NewClaim, finding_id=finding_id, text=text)
        with self._write() as conn:
            self._require(conn, "finding", data.finding_id)
            seq = audit.next_seq(conn)
            claim_id = ClaimId(
                self._insert(
                    conn,
                    "INSERT INTO claim (finding_id, text, status, created_seq) VALUES (?, ?, ?, ?)",
                    (data.finding_id, data.text, ClaimStatus.ASSERTED.value, seq),
                )
            )
            self._audit(
                conn,
                seq,
                "claim.added",
                {"claim_id": claim_id, "finding_id": data.finding_id, "text": data.text},
            )
        return claim_id

    def record_oracle_run(self, run: OracleRunInput) -> OracleRunId:
        """Record one oracle execution. Recorded runs are immutable."""
        if not isinstance(run, OracleRunInput):
            raise InvalidInput("record_oracle_run expects an OracleRunInput")
        with self._write() as conn:
            revision = conn.execute(
                "SELECT project_id FROM revision WHERE id = ?", (run.revision_id,)
            ).fetchone()
            if revision is None:
                raise NotFound(f"revision {run.revision_id} does not exist")
            if run.claim_id is not None:
                claim = conn.execute(
                    "SELECT f.project_id FROM claim AS c JOIN finding AS f ON f.id = c.finding_id "
                    "WHERE c.id = ?",
                    (run.claim_id,),
                ).fetchone()
                if claim is None:
                    raise NotFound(f"claim {run.claim_id} does not exist")
                if claim[0] != revision[0]:
                    raise InvalidInput(
                        f"claim {run.claim_id} and revision {run.revision_id} belong to "
                        "different projects"
                    )
            if not conn.execute(
                "SELECT 1 FROM artifact WHERE sha256 = ?", (run.trace_blob_sha256,)
            ).fetchone():
                raise NotFound(f"trace blob {run.trace_blob_sha256} is not in the ledger")
            seq = audit.next_seq(conn)
            seed = None if run.seed is None else str(run.seed)
            run_id = OracleRunId(
                self._insert(
                    conn,
                    "INSERT INTO oracle_run (claim_id, revision_id, oracle, argv_json, "
                    "image_digest, seed, exit_code, verdict, reason, trace_blob_sha256, "
                    "created_seq) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        run.claim_id,
                        run.revision_id,
                        run.oracle.value,
                        audit.canonical_json(list(run.argv)),
                        run.image_digest,
                        seed,
                        run.exit_code,
                        run.verdict.value,
                        run.reason,
                        run.trace_blob_sha256,
                        seq,
                    ),
                )
            )
            self._audit(
                conn,
                seq,
                "oracle_run.recorded",
                {
                    "oracle_run_id": run_id,
                    "claim_id": run.claim_id,
                    "revision_id": run.revision_id,
                    "oracle": run.oracle.value,
                    "argv": list(run.argv),
                    "image_digest": run.image_digest,
                    "seed": seed,
                    "exit_code": run.exit_code,
                    "verdict": run.verdict.value,
                    "reason": run.reason,
                    "trace_blob_sha256": run.trace_blob_sha256,
                },
            )
        return run_id

    def promote_claim(self, claim_id: ClaimId, oracle_run_id: OracleRunId) -> ClaimStatus:
        """Set a claim's status from the verdict of an oracle run for that claim.

        `PASS` makes the claim `trusted`, `FAIL` `refuted`, `INCONCLUSIVE` `inconclusive`. This
        is the only code path that changes a claim's status.
        """
        data = _validate(_Promotion, claim_id=claim_id, oracle_run_id=oracle_run_id)
        with self._write() as conn:
            claim = conn.execute(
                "SELECT status FROM claim WHERE id = ?", (data.claim_id,)
            ).fetchone()
            if claim is None:
                raise NotFound(f"claim {data.claim_id} does not exist")
            run = conn.execute(
                "SELECT claim_id, verdict FROM oracle_run WHERE id = ?", (data.oracle_run_id,)
            ).fetchone()
            if run is None:
                raise NotFound(f"oracle_run {data.oracle_run_id} does not exist")
            if run[0] != data.claim_id:
                raise ClaimPromotionError(
                    f"oracle_run {data.oracle_run_id} is not a run for claim {data.claim_id}"
                )
            current = ClaimStatus(claim[0])
            verdict = Verdict(run[1])
            status = claim_status_after(current, verdict)
            seq = audit.next_seq(conn)
            conn.execute("UPDATE claim SET status = ? WHERE id = ?", (status.value, data.claim_id))
            self._audit(
                conn,
                seq,
                "claim.promoted",
                {
                    "claim_id": data.claim_id,
                    "oracle_run_id": data.oracle_run_id,
                    "verdict": verdict.value,
                    "from": current.value,
                    "to": status.value,
                },
            )
        return status

    def transition_finding(
        self,
        finding_id: FindingId,
        target: FindingState,
        *,
        oracle_run_ids: Sequence[OracleRunId] = (),
        reason: str | None = None,
    ) -> Finding:
        """Move a finding along the lifecycle; see `assay.ledger.lifecycle` for the rules.

        Transitions caused by an oracle result name the oracle runs that back them. Each run
        must be a run for a claim of this finding. The evidence level follows from the rules.
        """
        data = _validate(
            _Transition,
            finding_id=finding_id,
            target=target,
            oracle_run_ids=tuple(oracle_run_ids),
            reason=reason,
        )
        with self._write() as conn:
            row = conn.execute(
                "SELECT state FROM finding WHERE id = ?", (data.finding_id,)
            ).fetchone()
            if row is None:
                raise NotFound(f"finding {data.finding_id} does not exist")
            source = FindingState(row[0])
            if len(set(data.oracle_run_ids)) != len(data.oracle_run_ids):
                raise IllegalTransition("an oracle run is referenced more than once")
            runs = [
                self._run_facts(conn, data.finding_id, run_id) for run_id in data.oracle_run_ids
            ]
            has_patch = (
                conn.execute(
                    "SELECT 1 FROM patch WHERE finding_id = ?", (data.finding_id,)
                ).fetchone()
                is not None
            )
            level = check_transition(
                source, data.target, runs=runs, has_patch=has_patch, reason=data.reason
            )
            seq = audit.next_seq(conn)
            conn.execute(
                "UPDATE finding SET state = ?, evidence_level = ?, reason = ?, updated_seq = ? "
                "WHERE id = ?",
                (data.target.value, level.value, data.reason, seq, data.finding_id),
            )
            self._audit(
                conn,
                seq,
                "finding.transitioned",
                {
                    "finding_id": data.finding_id,
                    "from": source.value,
                    "to": data.target.value,
                    "evidence_level": level.value,
                    "oracle_run_ids": list(data.oracle_run_ids),
                    "reason": data.reason,
                },
            )
        return self.get_finding(data.finding_id)

    @staticmethod
    def _run_facts(conn: sqlite3.Connection, finding_id: int, run_id: int) -> RunFacts:
        row = conn.execute(
            "SELECT oracle, verdict, revision_id, revision_kind, patch_finding_id "
            "FROM finding_oracle_run WHERE oracle_run_id = ? AND finding_id = ?",
            (run_id, finding_id),
        ).fetchone()
        if row is None:
            if conn.execute("SELECT 1 FROM oracle_run WHERE id = ?", (run_id,)).fetchone() is None:
                raise NotFound(f"oracle_run {run_id} does not exist")
            raise IllegalTransition(
                f"oracle_run {run_id} is not a run for a claim of finding {finding_id}"
            )
        oracle, verdict, revision_id, revision_kind, patch_finding_id = row
        kind = RevisionKind(revision_kind)
        if kind is RevisionKind.PATCHED and patch_finding_id != finding_id:
            raise IllegalTransition(
                f"oracle_run {run_id} ran on a patch of another finding than {finding_id}"
            )
        return RunFacts(OracleName(oracle), Verdict(verdict), int(revision_id), kind)

    def add_verification(
        self,
        patch_id: PatchId,
        final_verdict: FinalVerdict,
        reason: str,
        bounds: Mapping[str, object],
        bundle_manifest_sha256: str | None = None,
    ) -> VerificationId:
        """Record the final verdict of a verification of a patch. Verifications are immutable.

        `bounds` is what actually ran (seeds, run counts, oracles), stored as canonical JSON.
        `VERIFIED_WITHIN_BOUNDS` needs a `PASS` from every required oracle on a revision of the
        patch and no `FAIL` on any of them.
        """
        data = _validate(
            _NewVerification,
            patch_id=patch_id,
            final_verdict=final_verdict,
            reason=reason,
            bundle_manifest_sha256=bundle_manifest_sha256,
        )
        try:
            bounds_json = audit.canonical_json(dict(bounds))
        except TypeError as exc:
            raise InvalidInput(f"bounds: {exc}") from exc
        with self._write() as conn:
            self._require(conn, "patch", data.patch_id)
            if data.final_verdict is FinalVerdict.VERIFIED_WITHIN_BOUNDS:
                self._check_verified(conn, data.patch_id)
            seq = audit.next_seq(conn)
            verification_id = VerificationId(
                self._insert(
                    conn,
                    "INSERT INTO verification (patch_id, final_verdict, reason, bounds_json, "
                    "bundle_manifest_sha256, created_seq) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        data.patch_id,
                        data.final_verdict.value,
                        data.reason,
                        bounds_json,
                        data.bundle_manifest_sha256,
                        seq,
                    ),
                )
            )
            self._audit(
                conn,
                seq,
                "verification.recorded",
                {
                    "verification_id": verification_id,
                    "patch_id": data.patch_id,
                    "final_verdict": data.final_verdict.value,
                    "reason": data.reason,
                    "bounds_json": bounds_json,
                    "bundle_manifest_sha256": data.bundle_manifest_sha256,
                },
            )
        return verification_id

    @staticmethod
    def _check_verified(conn: sqlite3.Connection, patch_id: int) -> None:
        rows = conn.execute(
            "SELECT r.oracle, r.verdict FROM oracle_run AS r "
            "JOIN revision AS v ON v.id = r.revision_id WHERE v.patch_id = ?",
            (patch_id,),
        ).fetchall()
        passed = {OracleName(oracle) for oracle, verdict in rows if verdict == Verdict.PASS}
        missing = sorted(REQUIRED_ORACLES - passed)
        if missing or any(verdict == Verdict.FAIL for _, verdict in rows):
            raise IllegalTransition(
                "VERIFIED_WITHIN_BOUNDS needs a PASS from every required oracle and no FAIL; "
                f"missing: {', '.join(missing) or 'none'}"
            )

    # Static analysis

    def record_scan(
        self,
        project_id: ProjectId,
        *,
        tool: ScanTool,
        tool_version: str,
        raw_blob_sha256: str,
        input_tree_sha256: str,
        observations: Sequence[ObservationInput],
    ) -> ScanId:
        """Record one analyzer run and its results.

        The raw output must already be stored as a blob (`store_blob`). The observations are
        unverified hints: recording them creates no finding and no claim and changes no
        status. Only oracle runs do that.
        """
        data = _validate(
            _NewScan,
            project_id=project_id,
            tool=tool,
            tool_version=tool_version,
            raw_blob_sha256=raw_blob_sha256,
            input_tree_sha256=input_tree_sha256,
            observations=tuple(observations),
        )
        with self._write() as conn:
            self._require(conn, "project", data.project_id)
            if (
                conn.execute(
                    "SELECT 1 FROM artifact WHERE sha256 = ?", (data.raw_blob_sha256,)
                ).fetchone()
                is None
            ):
                raise NotFound(f"artifact {data.raw_blob_sha256} is not in the ledger")
            seq = audit.next_seq(conn)
            scan_id = ScanId(
                self._insert(
                    conn,
                    "INSERT INTO scan (project_id, tool, tool_version, raw_blob_sha256, "
                    "input_tree_sha256, result_count, created_seq) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        data.project_id,
                        data.tool.value,
                        data.tool_version,
                        data.raw_blob_sha256,
                        data.input_tree_sha256,
                        len(data.observations),
                        seq,
                    ),
                )
            )
            conn.executemany(
                "INSERT INTO observation (scan_id, rule_id, severity_reported, location_json, "
                "message, created_seq) VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (
                        scan_id,
                        item.rule_id,
                        item.severity_reported,
                        audit.canonical_json([loc.model_dump() for loc in item.locations]),
                        item.message,
                        seq,
                    )
                    for item in data.observations
                ],
            )
            self._audit(
                conn,
                seq,
                "scan.recorded",
                {
                    "scan_id": scan_id,
                    "project_id": data.project_id,
                    "tool": data.tool.value,
                    "tool_version": data.tool_version,
                    "raw_blob_sha256": data.raw_blob_sha256,
                    "input_tree_sha256": data.input_tree_sha256,
                    "result_count": len(data.observations),
                },
            )
        return scan_id

    def record_model_run(
        self,
        *,
        finding_id: FindingId | None,
        endpoint_host: str,
        model: str,
        prompt_sha256: str,
        response_sha256: str,
        tokens_in: int,
        tokens_out: int,
        latency_ms: int,
        cassette_mode: CassetteMode,
    ) -> ModelRunId:
        """Record one model call (host without credentials, hashes, never the prompt itself).

        This is provenance only. It creates no claim and changes no status, whatever the model
        said; only `record_oracle_run`, `promote_claim` and `transition_finding` do that, and
        they need oracle evidence.
        """
        data = _validate(
            _NewModelRun,
            finding_id=finding_id,
            endpoint_host=endpoint_host,
            model=model,
            prompt_sha256=prompt_sha256,
            response_sha256=response_sha256,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            latency_ms=latency_ms,
            cassette_mode=cassette_mode,
        )
        with self._write() as conn:
            if data.finding_id is not None:
                self._require(conn, "finding", data.finding_id)
            seq = audit.next_seq(conn)
            run_id = ModelRunId(
                self._insert(
                    conn,
                    "INSERT INTO model_run (finding_id, endpoint_host, model, prompt_sha256, "
                    "response_sha256, tokens_in, tokens_out, latency_ms, cassette_mode, "
                    "created_seq) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        data.finding_id,
                        data.endpoint_host,
                        data.model,
                        data.prompt_sha256,
                        data.response_sha256,
                        data.tokens_in,
                        data.tokens_out,
                        data.latency_ms,
                        data.cassette_mode.value,
                        seq,
                    ),
                )
            )
            self._audit(
                conn,
                seq,
                "model_run.recorded",
                {
                    "model_run_id": run_id,
                    "finding_id": data.finding_id,
                    "endpoint_host": data.endpoint_host,
                    "model": data.model,
                    "prompt_sha256": data.prompt_sha256,
                    "response_sha256": data.response_sha256,
                    "tokens_in": data.tokens_in,
                    "tokens_out": data.tokens_out,
                    "latency_ms": data.latency_ms,
                    "cassette_mode": data.cassette_mode.value,
                },
            )
        return run_id

    def get_model_run(self, model_run_id: ModelRunId) -> ModelRun:
        row = self._conn.execute(
            "SELECT id, finding_id, endpoint_host, model, prompt_sha256, response_sha256, "
            "tokens_in, tokens_out, latency_ms, cassette_mode FROM model_run WHERE id = ?",
            (model_run_id,),
        ).fetchone()
        if row is None:
            raise NotFound(f"model_run {model_run_id} does not exist")
        return ModelRun(
            id=ModelRunId(row[0]),
            finding_id=None if row[1] is None else FindingId(row[1]),
            endpoint_host=row[2],
            model=row[3],
            prompt_sha256=row[4],
            response_sha256=row[5],
            tokens_in=row[6],
            tokens_out=row[7],
            latency_ms=row[8],
            cassette_mode=CassetteMode(row[9]),
        )

    def get_scan(self, scan_id: ScanId) -> Scan:
        row = self._conn.execute(
            "SELECT id, project_id, tool, tool_version, raw_blob_sha256, input_tree_sha256, "
            "result_count FROM scan WHERE id = ?",
            (scan_id,),
        ).fetchone()
        if row is None:
            raise NotFound(f"scan {scan_id} does not exist")
        return Scan(
            id=ScanId(row[0]),
            project_id=ProjectId(row[1]),
            tool=ScanTool(row[2]),
            tool_version=row[3],
            raw_blob_sha256=row[4],
            input_tree_sha256=row[5],
            result_count=row[6],
        )

    def scan_observations(self, scan_id: ScanId) -> tuple[Observation, ...]:
        """The observations of a scan, in the order the tool reported them."""
        self._require(self._conn, "scan", scan_id)
        rows = self._conn.execute(
            "SELECT id, scan_id, finding_id, rule_id, severity_reported, location_json, message "
            "FROM observation WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ).fetchall()
        return tuple(
            Observation(
                id=ObservationId(row[0]),
                scan_id=ScanId(row[1]),
                finding_id=None if row[2] is None else FindingId(row[2]),
                rule_id=row[3],
                severity_reported=row[4],
                locations=tuple(ScanLocation(**item) for item in json.loads(row[5])),
                message=row[6],
            )
            for row in rows
        )

    def find_scans(
        self,
        project_id: ProjectId,
        *,
        tool: ScanTool,
        tool_version: str,
        raw_blob_sha256: str,
        input_tree_sha256: str,
    ) -> tuple[Scan, ...]:
        """Return the scans of the project with exactly this tool, input and raw output.

        A repeated scan whose raw output is byte-identical adds nothing new; callers use this to
        avoid recording it twice. The scans come in the order they were recorded.
        """
        key = _validate(
            _ScanKey,
            project_id=project_id,
            tool=tool,
            tool_version=tool_version,
            raw_blob_sha256=raw_blob_sha256,
            input_tree_sha256=input_tree_sha256,
        )
        rows = self._conn.execute(
            "SELECT id FROM scan WHERE project_id = ? AND tool = ? AND tool_version = ? "
            "AND raw_blob_sha256 = ? AND input_tree_sha256 = ? ORDER BY id",
            (
                key.project_id,
                key.tool.value,
                key.tool_version,
                key.raw_blob_sha256,
                key.input_tree_sha256,
            ),
        ).fetchall()
        return tuple(self.get_scan(ScanId(row[0])) for row in rows)

    def link_observation(self, observation_id: ObservationId, finding_id: FindingId) -> bool:
        """Link an observation to the finding it supports; return False if it already was.

        A link records which analyzer result a finding came from. It is evidence of an
        unverified hint only: it creates no claim and changes no status. An observation is
        linked once, to a finding of its own scan's project.
        """
        data = _validate(_Link, observation_id=observation_id, finding_id=finding_id)
        with self._write() as conn:
            row = conn.execute(
                "SELECT o.finding_id, s.project_id FROM observation AS o "
                "JOIN scan AS s ON s.id = o.scan_id WHERE o.id = ?",
                (data.observation_id,),
            ).fetchone()
            if row is None:
                raise NotFound(f"observation {data.observation_id} does not exist")
            linked, scan_project = row
            target = conn.execute(
                "SELECT project_id FROM finding WHERE id = ?", (data.finding_id,)
            ).fetchone()
            if target is None:
                raise NotFound(f"finding {data.finding_id} does not exist")
            if target[0] != scan_project:
                raise InvalidInput(
                    f"observation {data.observation_id} and finding {data.finding_id} belong to "
                    "different projects"
                )
            if linked == data.finding_id:
                return False
            if linked is not None:
                raise InvalidInput(
                    f"observation {data.observation_id} is already linked to finding {linked}"
                )
            seq = audit.next_seq(conn)
            conn.execute(
                "UPDATE observation SET finding_id = ? WHERE id = ?",
                (data.finding_id, data.observation_id),
            )
            self._audit(
                conn,
                seq,
                "observation.linked",
                {"observation_id": data.observation_id, "finding_id": data.finding_id},
            )
        return True

    # Blobs and the audit chain

    def store_blob(self, data: bytes, *, media_type: str, label: str) -> str:
        """Store `data` once, index it in `artifact`, and return its sha256."""
        blob = _validate(_NewBlob, data=data, media_type=media_type, label=label)
        digest = self.blobs.put(blob.data)
        with self._write() as conn:
            self._index_blob(conn, digest, len(blob.data), blob.media_type, blob.label)
        return digest

    def _index_blob(
        self, conn: sqlite3.Connection, digest: str, size: int, media_type: str, label: str
    ) -> None:
        row = conn.execute("SELECT size FROM artifact WHERE sha256 = ?", (digest,)).fetchone()
        if row is not None:
            if row[0] != size:
                raise BlobCorrupted(f"artifact {digest} is indexed with another size")
            return
        seq = audit.next_seq(conn)
        conn.execute(
            "INSERT INTO artifact (sha256, size, media_type, label, created_seq) "
            "VALUES (?, ?, ?, ?, ?)",
            (digest, size, media_type, label, seq),
        )
        self._audit(
            conn,
            seq,
            "artifact.stored",
            {"sha256": digest, "size": size, "media_type": media_type, "label": label},
        )

    def read_blob(self, sha256: str) -> bytes:
        """Return a stored blob after checking its hash and its indexed size."""
        if not isinstance(sha256, str) or not is_sha256_hex(sha256):
            raise InvalidInput(f"not a lowercase sha256 hex digest: {sha256!r}")
        row = self._conn.execute("SELECT size FROM artifact WHERE sha256 = ?", (sha256,)).fetchone()
        if row is None:
            raise NotFound(f"artifact {sha256} is not in the ledger")
        data = self.blobs.get(sha256)
        if len(data) != row[0]:
            raise BlobCorrupted(f"blob {sha256} does not have its indexed size")
        return data

    def check_invariants(self) -> list[Violation]:
        """Check the global invariants (see `assay.ledger.invariants`); read-only."""
        return check_invariants(self._conn)

    def verify_chain(self) -> ChainReport:
        """Check the `audit_log` hash chain; see `assay.ledger.audit`."""
        return audit.verify_chain(self._conn)

    # Reads

    def get_finding(self, finding_id: FindingId) -> Finding:
        row = self._conn.execute(
            "SELECT id, project_id, stable_id, class, state, evidence_level, reason "
            "FROM finding WHERE id = ?",
            (finding_id,),
        ).fetchone()
        if row is None:
            raise NotFound(f"finding {finding_id} does not exist")
        return Finding(
            id=FindingId(row[0]),
            project_id=ProjectId(row[1]),
            stable_id=row[2],
            vuln_class=row[3],
            state=FindingState(row[4]),
            evidence_level=EvidenceLevel(row[5]),
            reason=row[6],
        )

    def findings(
        self, *, vuln_class: str | None = None, state: FindingState | None = None
    ) -> tuple[Finding, ...]:
        """Findings in creation order, optionally of one class and one state."""
        rows = self._conn.execute(
            "SELECT id FROM finding WHERE (?1 IS NULL OR class = ?1) "
            "AND (?2 IS NULL OR state = ?2) ORDER BY id",
            (vuln_class, None if state is None else state.value),
        ).fetchall()
        return tuple(self.get_finding(FindingId(row[0])) for row in rows)

    def finding_observations(self, finding_id: FindingId) -> tuple[Observation, ...]:
        """The analyzer observations linked to a finding, in creation order."""
        self._require(self._conn, "finding", finding_id)
        rows = self._conn.execute(
            "SELECT id FROM observation WHERE finding_id = ? ORDER BY id", (finding_id,)
        ).fetchall()
        found: list[Observation] = []
        for (observation_id,) in rows:
            scan_id = self._conn.execute(
                "SELECT scan_id FROM observation WHERE id = ?", (observation_id,)
            ).fetchone()[0]
            found.extend(
                item
                for item in self.scan_observations(ScanId(scan_id))
                if item.id == observation_id
            )
        return tuple(found)

    def finding_transitions(self, finding_id: FindingId) -> tuple[FindingTransition, ...]:
        """The recorded state changes of a finding, oldest first, read from the audit log."""
        self._require(self._conn, "finding", finding_id)
        found: list[FindingTransition] = []
        rows = self._conn.execute(
            "SELECT payload_json FROM audit_log WHERE event = 'finding.transitioned' ORDER BY seq"
        ).fetchall()
        for (payload_json,) in rows:
            payload = json.loads(payload_json)
            if payload.get("finding_id") != int(finding_id):
                continue
            found.append(
                FindingTransition(
                    source=FindingState(payload["from"]),
                    target=FindingState(payload["to"]),
                    reason=payload.get("reason"),
                )
            )
        return tuple(found)

    def find_project(self, name: str, root_label: str) -> ProjectId | None:
        """Return the first project with this name and root label, or `None` if there is none."""
        data = _validate(_NewProject, name=name, root_label=root_label)
        row = self._conn.execute(
            "SELECT id FROM project WHERE name = ? AND root_label = ? ORDER BY id LIMIT 1",
            (data.name, data.root_label),
        ).fetchone()
        return None if row is None else ProjectId(row[0])

    def find_finding(self, stable_id: str) -> Finding | None:
        """Return the finding with `stable_id`, or `None` if there is none."""
        row = self._conn.execute(
            "SELECT id FROM finding WHERE stable_id = ?", (stable_id,)
        ).fetchone()
        return None if row is None else self.get_finding(FindingId(row[0]))

    def get_claim(self, claim_id: ClaimId) -> Claim:
        row = self._conn.execute(
            "SELECT id, finding_id, text, status FROM claim WHERE id = ?", (claim_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"claim {claim_id} does not exist")
        return Claim(
            id=ClaimId(row[0]),
            finding_id=FindingId(row[1]),
            text=row[2],
            status=ClaimStatus(row[3]),
        )

    def get_oracle_run(self, oracle_run_id: OracleRunId) -> OracleRun:
        row = self._conn.execute(
            "SELECT id, claim_id, revision_id, oracle, argv_json, image_digest, seed, exit_code, "
            "verdict, reason, trace_blob_sha256 FROM oracle_run WHERE id = ?",
            (oracle_run_id,),
        ).fetchone()
        if row is None:
            raise NotFound(f"oracle_run {oracle_run_id} does not exist")
        return OracleRun(
            id=OracleRunId(row[0]),
            claim_id=None if row[1] is None else ClaimId(row[1]),
            revision_id=RevisionId(row[2]),
            oracle=OracleName(row[3]),
            argv=tuple(json.loads(row[4])),
            image_digest=row[5],
            seed=None if row[6] is None else int(row[6]),
            exit_code=row[7],
            verdict=Verdict(row[8]),
            reason=row[9],
            trace_blob_sha256=row[10],
        )
