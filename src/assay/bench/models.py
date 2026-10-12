"""Models of a benchmark: splits, per-case results, the run record and the findings file.

Everything stored under `bench/results/<run-id>/` is validated with these strict models when the
report reads it. No model holds a timestamp, a host path or a user name.
"""

from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

CLASS_IDS: Final = (
    "reentrancy",
    "access_control",
    "unchecked_call",
    "signature_replay",
    "delegatecall",
    "oracle_manipulation",
    "dos",
    "rounding",
)
PATCH_LABELS: Final = ("good", "overfit", "destructive", "regressing")
BAD_LABELS: Final = ("overfit", "destructive", "regressing")
SPLIT_NAMES: Final = ("dev", "heldout")
CONFIGS: Final = ("V0", "V1", "V2", "V3", "V4")

Label = Literal["good", "overfit", "destructive", "regressing"]
SplitName = Literal["dev", "heldout"]
FinalVerdictName = Literal["VERIFIED_WITHIN_BOUNDS", "REJECTED", "INCONCLUSIVE"]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
_FixtureId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]*/[a-z0-9][a-z0-9_]*$")]
_Code = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]*$")]
_RunId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$")]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Split(_Model):
    """`bench/splits/<name>.json`: where the fixtures of a split live and which they are."""

    schema_version: Literal[1] = 1
    name: SplitName
    root: str
    """Directory of the fixtures, relative to the repository root."""
    fixtures: tuple[_FixtureId, ...]


class OracleOutcome(_Model):
    """What one oracle reported for a case."""

    oracle: Literal["integrity", "exploit", "variant", "symbolic", "behavior", "regression"]
    status: Literal["ran", "skipped", "missing"]
    verdict: Literal["PASS", "FAIL", "INCONCLUSIVE"] | None
    codes: tuple[_Code, ...]


class CaseResult(_Model):
    """The outcome of `assay verify` for one patch of one fixture, with the expected outcome."""

    fixture: _FixtureId
    label: Label
    expected_verdict: Literal["VERIFIED_WITHIN_BOUNDS", "REJECTED"]
    expected_reason: _Code | None
    exit_code: int
    final_verdict: FinalVerdictName | None
    reasons: tuple[_Code, ...]
    evidence_level: Literal["E0", "E1", "E2", "E3"] | None
    oracles: tuple[OracleOutcome, ...]
    base_tree_sha256: Sha256 | None
    poc_tree_sha256: Sha256 | None
    patch_sha256: Sha256 | None
    seconds: float = Field(ge=0)
    error: str | None = None


class RunInfo(_Model):
    """`run.json`: the environment, the bounds and the identity of the oracles of one run."""

    schema_version: Literal[1] = 1
    run_id: _RunId
    split: SplitName
    split_file_sha256: Sha256
    fixtures_tree_sha256: Sha256
    cases: int = Field(ge=0)
    assay_version: str
    git_commit: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")] | None
    oracle_tree_sha256: Sha256
    image_digest: Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
    tool_versions: dict[str, str]
    versions_lock_sha256: Sha256
    machine: str
    profile: Literal["quick", "standard", "thorough"]
    fuzz_seed: str
    fuzz_runs: int = Field(ge=1)
    variant_seeds: int = Field(ge=1)
    invariant_runs: int = Field(ge=1)
    invariant_depth: int = Field(ge=1)
    exploit_replays: int = Field(ge=1)
    symbolic: bool
    total_seconds: float = Field(ge=0)


class Finding(_Model):
    """A recorded cause for a mismatch between a verdict and a label, or another observation."""

    id: Annotated[str, StringConstraints(pattern=r"^F[0-9]{1,3}$")]
    kind: Literal["oracle", "fixture", "infrastructure", "other"]
    split: SplitName
    case: Annotated[str, StringConstraints(pattern=r"^[a-z0-9_]+/[a-z0-9_]+/[a-z]+$")] | None = None
    """`<class>/<name>/<label>` of the mismatching case, when the finding explains one."""
    summary: str
    cause: str
    status: Literal["open", "fixed-in-fixture", "deferred-to-v2", "no-action"]


class Correction(_Model):
    """A fix of a fixture that was made after a run showed a mismatch (protocol, section 8)."""

    fixture: _FixtureId
    split: SplitName
    run: _RunId
    what: str


class Findings(_Model):
    """`bench/findings.json`."""

    schema_version: Literal[1] = 1
    result_version: Annotated[str, StringConstraints(pattern=r"^v[0-9]+$")]
    findings: tuple[Finding, ...] = ()
    corrections: tuple[Correction, ...] = ()
