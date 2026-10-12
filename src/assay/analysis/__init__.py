"""Static analyzers (Slither, Aderyn) run in the sandbox; their output is untrusted input."""

from typing import Final

from assay.analysis.aderyn import Aderyn
from assay.analysis.base import (
    Analysis,
    Analyzer,
    AnalyzerError,
    AnalyzerFailed,
    AnalyzerName,
    AnalyzerOutOfMemory,
    AnalyzerTimeout,
    Location,
    Observation,
    RawAnalysis,
    check_target,
)
from assay.analysis.limits import AnalyzerOutputError, OutputLimits, load_json
from assay.analysis.slither import Slither

ANALYZERS: Final[dict[AnalyzerName, type[Analyzer]]] = {
    AnalyzerName.SLITHER: Slither,
    AnalyzerName.ADERYN: Aderyn,
}

__all__ = [
    "ANALYZERS",
    "Aderyn",
    "Analysis",
    "Analyzer",
    "AnalyzerError",
    "AnalyzerFailed",
    "AnalyzerName",
    "AnalyzerOutOfMemory",
    "AnalyzerOutputError",
    "AnalyzerTimeout",
    "Location",
    "Observation",
    "OutputLimits",
    "RawAnalysis",
    "Slither",
    "check_target",
    "load_json",
]
