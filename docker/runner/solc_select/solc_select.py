"""The three functions of `solc_select.solc_select` that crytic-compile imports (ADR 0015)."""

from pathlib import Path

_REFUSED = (
    "solc-select is not available in the Assay runner image: the only compiler is the pinned "
    "solc at /opt/assay/bin/solc, and nothing is downloaded at run time"
)


def installed_versions() -> list[str]:
    """No compiler is managed by solc-select in the image."""
    return []


def install_artifacts(versions: list[str]) -> bool:
    """Refuse to download a compiler."""
    raise RuntimeError(_REFUSED)


def artifact_path(version: str) -> Path:
    """No compiler path is managed by solc-select in the image."""
    raise RuntimeError(_REFUSED)
