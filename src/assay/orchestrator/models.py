"""Models of a verification: its settings and its report.

The report holds no timestamps, host paths or ledger ids, so the same inputs give the same
report. The evidence bundle and `assay replay` use the same models.
"""

from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from assay.ingest.config import DEFAULT_FUZZ_SEED
from assay.ledger import FinalVerdict, OracleName, Verdict
from assay.oracles.base import Reason
from assay.oracles.behavior import SuiteSettings
from assay.oracles.exploit import ExploitSettings
from assay.oracles.symbolic import SymbolicBounds, SymbolicSettings, SymbolicTiming
from assay.oracles.variant import (
    DEFAULT_PROFILE,
    MAX_FUZZ_RUNS,
    ProfileName,
    VariantBounds,
    VariantSettings,
    VariantTiming,
    profile,
)

ORACLE_ORDER: Final = (
    OracleName.INTEGRITY,
    OracleName.EXPLOIT,
    OracleName.VARIANT,
    OracleName.BEHAVIOR,
    OracleName.REGRESSION,
)
"""The required oracles, in the order in which reports list them."""

REPORT_ORDER: Final = (
    OracleName.INTEGRITY,
    OracleName.EXPLOIT,
    OracleName.VARIANT,
    OracleName.SYMBOLIC,
    OracleName.BEHAVIOR,
    OracleName.REGRESSION,
)
"""Every oracle in the order in which `assay verify` runs them; the symbolic oracle runs after
the VariantOracle, and only with `--symbolic`."""

EvidenceLevel = Literal["E0", "E1", "E2", "E3"]


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class VerifySettings(_Model):
    """The bounds of a verification: replays of the PoC, the campaign profile, the base seed
    and optionally a number of fuzz runs that replaces the profile's runs per seed.

    The base seed is the fuzz seed of the exploit replays and of the project's own fuzz tests,
    and the root from which the variant search derives its seeds. The number of fuzz runs (the
    profile's runs per seed unless given) applies to every fuzz campaign Assay starts.
    `symbolic` adds the SymbolicOracle (Halmos), with the bounds of `SymbolicSettings`.
    """

    replays: int = Field(default=3, ge=1, le=10)
    profile: ProfileName = DEFAULT_PROFILE
    fuzz_seed: Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{1,16}$")] = DEFAULT_FUZZ_SEED
    fuzz_runs: int | None = Field(default=None, ge=1, le=MAX_FUZZ_RUNS)
    symbolic: bool = False

    @property
    def runs(self) -> int:
        """Fuzz runs per campaign: `fuzz_runs`, or the profile's runs per seed."""
        return self.fuzz_runs if self.fuzz_runs is not None else profile(self.profile).runs_per_seed

    def exploit(self) -> ExploitSettings:
        return ExploitSettings(replays=self.replays, fuzz_seed=self.fuzz_seed)

    def variant(self) -> VariantSettings:
        return VariantSettings(
            profile=profile(self.profile), base_seed=self.fuzz_seed, runs_per_seed=self.fuzz_runs
        )

    def suite(self) -> SuiteSettings:
        return SuiteSettings(fuzz_seed=self.fuzz_seed, fuzz_runs=self.runs)

    def symbolic_settings(self) -> SymbolicSettings:
        return SymbolicSettings(fuzz_seed=self.fuzz_seed)


OracleStatus = Literal["ran", "skipped", "missing"]


class OracleRow(_Model):
    oracle: OracleName
    status: OracleStatus
    verdict: Verdict | None
    reasons: tuple[Reason, ...]
    summary: str
    warnings: tuple[Reason, ...] = ()

    def codes(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(item.code for item in self.reasons))

    def warning_codes(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(item.code for item in self.warnings))


class Inputs(_Model):
    base_tree_sha256: str
    poc_tree_sha256: str
    patch_sha256: str
    patched_tree_sha256: str | None
    harness_sha256: str


class Bounds(_Model):
    """What ran, as numbers. Deterministic: the same inputs give the same bounds."""

    exploit_replays_per_revision: int
    profile: ProfileName
    fuzz_seed: str
    fuzz_runs: int
    interface_contracts: tuple[str, ...]
    oracles_run: tuple[OracleName, ...]
    oracles_not_run: tuple[OracleName, ...]
    variant: VariantBounds | None
    """The campaigns of the variant search, or `None` when it did not run."""
    symbolic: SymbolicBounds | None = None
    """The Halmos properties and bounds, or `None` when the symbolic oracle did not run."""


class Timing(_Model):
    """Wall-clock durations in seconds, rounded to 0.1 s. Unlike everything else in a report,
    they differ between two runs of the same inputs."""

    total_s: float
    oracles: dict[OracleName, float]
    variant: VariantTiming | None
    symbolic: SymbolicTiming | None = None


class VerifyReport(_Model):
    """The result of `assay verify`. It holds no timestamps, host paths or ledger ids; apart
    from `timing`, the same inputs give the same report."""

    schema_version: Literal[3] = 3
    inputs: Inputs
    oracles: tuple[OracleRow, ...]
    final_verdict: FinalVerdict
    reasons: tuple[str, ...]
    integrity_violation: bool
    bounds: Bounds
    bounds_statement: str
    timing: Timing
    evidence_level: EvidenceLevel | None = None
    """E3 for VERIFIED_WITHIN_BOUNDS; E2 when integrity, exploit, behavior and regression
    passed without a failure; E1 when the PoC reproduced on the vulnerable revision; else E0."""
    annotations: tuple[str, ...] = ()
    """Statements that make the bounds more precise without changing the evidence level: the
    symbolic result and the bounded-equivalence result, worded as what ran."""
