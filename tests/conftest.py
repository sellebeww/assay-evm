"""Fixtures shared by the integration and security tests (they need Docker and the runner image)."""

import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from assay.ingest import Snapshot, create_snapshot
from assay.oracles.symbolic import symbolic_runner as make_symbolic_runner
from assay.sandbox import SandboxRunner, SandboxUnavailable

DATA = Path(__file__).resolve().parent / "data"

# The integration and security tests share the scenario builders of the unit tests
# (`prove_support`, `llm_support`).
_UNIT = str(Path(__file__).resolve().parent / "unit")
if _UNIT not in sys.path:
    sys.path.insert(0, _UNIT)


@pytest.fixture(scope="session")
def runner() -> SandboxRunner:
    sandbox = SandboxRunner()
    try:
        sandbox.image_id()
    except SandboxUnavailable as exc:
        pytest.fail(f"integration tests need Docker and the runner image (`make image`): {exc}")
    return sandbox


@pytest.fixture(scope="session")
def symbolic_runner() -> SandboxRunner:
    sandbox = make_symbolic_runner()
    try:
        sandbox.image_id()
    except SandboxUnavailable as exc:
        pytest.fail(f"symbolic tests need the symbolic runner image (`make image`): {exc}")
    return sandbox


@pytest.fixture
def data_dir() -> Path:
    return DATA


@pytest.fixture
def snapshot_of(tmp_path: Path) -> Callable[[Path], Snapshot]:
    """Return a function that snapshots a project into a new directory under tmp_path."""
    counter = iter(range(1_000_000))

    def snapshot(project: Path) -> Snapshot:
        return create_snapshot(project, tmp_path / f"snapshot-{next(counter)}")

    return snapshot


@pytest.fixture
def make_project(tmp_path: Path) -> Callable[[str, dict[str, str]], Path]:
    """Return a function that writes a project with the given files under tmp_path."""

    def make(name: str, files: dict[str, str]) -> Path:
        root = tmp_path / name
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        return root

    return make
