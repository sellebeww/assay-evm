"""The machine-readable output (`--json`) of the commands, as Pydantic models.

Each command validates the document it prints against one of these models, so the output cannot
drift from the schema; `tools/export_schemas.py` writes the JSON Schemas to `docs/schemas/`.
`assay verify --json` prints a `VerifyReport` (its `schema_version` is the version of that
document) and `assay doctor --json` a `DoctorReport`; the others are defined here. Documents hold
no timestamp and no host path. Text that comes from a tool, a project or a model is data.
"""

from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field

from assay.analysis.base import AnalyzerName
from assay.doctor import DoctorReport
from assay.llm.hypothesize import Hypothesis
from assay.orchestrator.fix import FixHistory
from assay.orchestrator.models import VerifyReport
from assay.orchestrator.scan import ToolStatus

SCAN_FORMAT: Final = "assay-scan/1"
PROVE_FORMAT: Final = "assay-prove/1"
FIX_FORMAT: Final = "assay-fix/1"
RUN_FORMAT: Final = "assay-run/1"
REPLAY_FORMAT: Final = "assay-replay/1"


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)


class ScanLocation(_Model):
    path: str
    start_line: int
    end_line: int
    function: str | None


class ScanSource(_Model):
    tool: AnalyzerName
    tool_version: str
    rule_id: str
    severity_reported: str
    message: str
    locations: tuple[ScanLocation, ...]


class ScanFinding(_Model):
    id: str
    vuln_class: str = Field(alias="class")
    state: Literal["CANDIDATE"]
    status: str
    evidence_level: Literal["E0"]
    location: ScanLocation
    snippet_sha256: str
    message: str
    sources: tuple[ScanSource, ...]


class ScanTool(_Model):
    tool: AnalyzerName
    version: str
    status: ToolStatus
    detail: str | None
    results: int
    unplaced_results: int
    raw_output_sha256: str | None


class ScanSummary(_Model):
    findings: int
    by_class: dict[str, int]


class ScanDocument(_Model):
    """`assay scan --json` (or `--format json`)."""

    format: Literal["assay-scan/1"] = SCAN_FORMAT
    assay_version: str
    input_tree_sha256: str
    complete: bool
    note: str
    tools: tuple[ScanTool, ...]
    summary: ScanSummary
    findings: tuple[ScanFinding, ...]


class ProveAttempt(_Model):
    number: int
    outcome: str
    codes: tuple[str, ...]


class ProveDocument(_Model):
    """`assay prove --json`."""

    format: Literal["assay-prove/1"] = PROVE_FORMAT
    finding: int
    stable_id: str
    vuln_class: str
    final_state: Literal[
        "HYPOTHESIZED", "POC_DRAFTED", "REPRODUCED", "NOT_REPRODUCED", "INCONCLUSIVE"
    ]
    evidence_level: Literal["E0", "E1", "E2", "E3"]
    hypothesis: Hypothesis
    attempts: tuple[ProveAttempt, ...]
    max_attempts: int
    stopped: str | None
    poc_dir: str | None
    notes: tuple[str, ...]


class FixDocument(_Model):
    """`assay fix --json` and `assay run --json`; `format` tells them apart."""

    format: Literal["assay-fix/1", "assay-run/1"]
    finding: int
    vuln_class: str
    final_verdict: Literal["VERIFIED_WITHIN_BOUNDS", "REJECTED", "INCONCLUSIVE"]
    reasons: tuple[str, ...]
    finding_state: str
    evidence_level: Literal["E0", "E1", "E2", "E3"]
    history: FixHistory
    report: VerifyReport | None
    bundle_manifest_sha256: str | None
    notes: tuple[str, ...]


class ReplayDocument(_Model):
    """`assay replay --json`."""

    format: Literal["assay-replay/1"] = REPLAY_FORMAT
    match: bool
    differences: tuple[str, ...]
    notes: tuple[str, ...]
    bundle_final_verdict: Literal["VERIFIED_WITHIN_BOUNDS", "REJECTED", "INCONCLUSIVE"]
    replay_final_verdict: Literal["VERIFIED_WITHIN_BOUNDS", "REJECTED", "INCONCLUSIVE"]


SCHEMAS: Final[dict[str, type[BaseModel]]] = {
    "scan": ScanDocument,
    "verify": VerifyReport,
    "prove": ProveDocument,
    "fix": FixDocument,
    "run": FixDocument,
    "replay": ReplayDocument,
    "doctor": DoctorReport,
}
"""The model behind the `--json` output of every command, by command name."""
