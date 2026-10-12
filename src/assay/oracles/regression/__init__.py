"""RegressionOracle: storage layout, ABI and events without breaking changes; the whole test
suite passes."""

from assay.oracles.regression.interface import (
    Change,
    Interface,
    InterfaceError,
    StorageVariable,
    compare_interface,
    compare_layout,
    parse_abi,
    parse_interface,
    parse_layout,
)
from assay.oracles.regression.oracle import (
    CLAIM_PATCHED,
    CLAIM_VULNERABLE,
    RegressionContext,
    RegressionOracle,
    target_contracts,
)

__all__ = [
    "CLAIM_PATCHED",
    "CLAIM_VULNERABLE",
    "Change",
    "Interface",
    "InterfaceError",
    "RegressionContext",
    "RegressionOracle",
    "StorageVariable",
    "compare_interface",
    "compare_layout",
    "parse_abi",
    "parse_interface",
    "parse_layout",
    "target_contracts",
]
