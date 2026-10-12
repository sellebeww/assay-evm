"""IntegrityOracle: scope, protected paths, vacuous patches, special-casing, sniffing."""

from assay.oracles.integrity.oracle import (
    CLAIM,
    HARD_REASONS,
    IntegrityContext,
    IntegrityOracle,
    is_hard,
)

__all__ = ["CLAIM", "HARD_REASONS", "IntegrityContext", "IntegrityOracle", "is_hard"]
