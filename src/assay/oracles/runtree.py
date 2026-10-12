"""Run trees of the oracles (ADR 0011).

A run tree holds `src/` of the revision under test, a copy of the shared harness under
`assay/`, and the files that forge runs as tests under `test/`: the PoC directory for the PoC
tree, the project's own `test/` directory for the benign tree. Every run tree goes through the
ingest snapshot step, so it runs under the same rewritten Foundry configuration as any project,
and gets its own scratch directory.

The `symbolic/` subdirectory of a PoC directory holds Halmos properties (ADR 0018). They may
import the vulnerable revision from `baseline/`, which only the symbolic tree has, so the PoC tree
leaves them out; the symbolic tree holds the whole PoC directory and `baseline/`.
"""

import hashlib
import os
import shutil
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

from assay.ingest import IngestError, Snapshot, create_snapshot, tree_digest
from assay.ingest.config import safe_foundry_toml
from assay.sandbox import make_scratch_dir

HARNESS_MOUNT: Final = "assay"
SOURCE_DIR: Final = "src"
TEST_DIR: Final = "test"
CONFIG_FILE: Final = "foundry.toml"
SYMBOLIC_DIR: Final = "symbolic"
"""Subdirectory of a PoC directory with the symbolic properties; only the symbolic tree has it."""
BASELINE_DIR: Final = "baseline"
"""Directory of the symbolic tree with the `src/` files of the vulnerable revision."""
_STAGING: Final = "staging"
_SNAPSHOT: Final = "snapshot"
_MAX_HARNESS_FILE_BYTES: Final = 1024 * 1024


class RunTreeError(Exception):
    """A run tree could not be built from the given inputs."""


class HarnessUnavailable(Exception):
    """The shared harness (`solidity/*.sol`) cannot be found or read."""


@dataclass(frozen=True, slots=True)
class Harness:
    files: tuple[tuple[str, bytes], ...]
    """`(file name, content)` of every `solidity/*.sol` file, sorted by name."""
    sha256: str
    """Tree hash of the files as they appear in a run tree (under `assay/`)."""


def default_harness_dir() -> Path:
    """`solidity/` of the source checkout this package runs from, or, in an installed wheel, the
    copy that the wheel carries."""
    packaged = Path(__file__).resolve().parents[1] / "_data" / "solidity"
    if packaged.is_dir():
        return packaged
    return Path(__file__).resolve().parents[3] / "solidity"


def load_harness(directory: Path | None = None) -> Harness:
    """Read the harness files; refuse symlinks, special files and an empty directory."""
    directory = directory if directory is not None else default_harness_dir()
    try:
        names = sorted(entry.name for entry in os.scandir(directory) if entry.name.endswith(".sol"))
    except OSError as exc:
        raise HarnessUnavailable(f"harness directory not readable: {directory}") from exc
    files: list[tuple[str, bytes]] = []
    for name in names:
        path = directory / name
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as exc:
            raise HarnessUnavailable(f"harness file cannot be read: {name}") from exc
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise HarnessUnavailable(f"harness file is not a regular file: {name}")
            data = handle.read(_MAX_HARNESS_FILE_BYTES + 1)
        if len(data) > _MAX_HARNESS_FILE_BYTES:
            raise HarnessUnavailable(f"harness file too large: {name}")
        files.append((name, data))
    if not files:
        raise HarnessUnavailable(f"no harness files in {directory}")
    digest = tree_digest((f"{HARNESS_MOUNT}/{name}", _sha256(data)) for name, data in files)
    return Harness(files=tuple(files), sha256=digest)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True, slots=True)
class RunTree:
    snapshot: Snapshot
    scratch: Path

    @property
    def tree(self) -> Path:
        return self.snapshot.tree_dir

    def digest_outside(self, directory: str) -> str:
        """Tree hash of every file that is not under `directory/` (for example `src`)."""
        return tree_digest(
            (item.path, item.sha256)
            for item in self.snapshot.files
            if PurePosixPath(item.path).parts[:1] != (directory,)
        )


def build_poc_tree(
    revision: Snapshot,
    poc: Snapshot,
    harness: Harness,
    dest: Path,
    *,
    config: bytes | None = None,
    extra_tests: Sequence[tuple[str, bytes]] = (),
) -> RunTree:
    """Build the PoC tree: `src/` of `revision`, the PoC files under `test/`, the harness.

    `poc` is the snapshot of the PoC directory; its rewritten `foundry.toml` and its
    `symbolic/` subdirectory are left out. `config` replaces the rewritten configuration of the
    tree (from `safe_foundry_toml`), and `extra_tests` adds generated test files under `test/`;
    a name that a PoC file already uses is refused.
    """
    tests = _poc_tests(poc, symbolic=False)
    return _build(revision, _with_extra(tests, extra_tests), harness, dest, config)


def symbolic_paths(poc: Snapshot) -> list[str]:
    """Paths of the files under `symbolic/` of a PoC directory, relative to it."""
    return [
        item.path for item in poc.files if PurePosixPath(item.path).parts[:1] == (SYMBOLIC_DIR,)
    ]


def build_symbolic_tree(
    revision: Snapshot,
    baseline: Snapshot,
    poc: Snapshot,
    harness: Harness,
    dest: Path,
    *,
    extra_tests: Sequence[tuple[str, bytes]] = (),
) -> RunTree:
    """Build the symbolic tree: `src/` of `revision`, the whole PoC directory (with
    `symbolic/`) under `test/`, `src/` of `baseline` under `baseline/`, the harness, and the
    configuration with dynamic test linking off (Halmos reads the compiled tests)."""
    source = baseline.tree_dir / SOURCE_DIR
    baseline_files = [
        (path.split("/", 1)[1], (baseline.tree_dir / path).read_bytes())
        for path in (item.path for item in baseline.files)
        if PurePosixPath(path).parts[:1] == (SOURCE_DIR,)
    ]
    if not source.is_dir():
        raise RunTreeError("the baseline revision has no src/ directory")
    tests = _with_extra(_poc_tests(poc, symbolic=True), extra_tests)
    return _build(
        revision,
        tests,
        harness,
        dest,
        safe_foundry_toml(for_halmos=True),
        extra_dirs=((BASELINE_DIR, baseline_files),),
    )


def _poc_tests(poc: Snapshot, *, symbolic: bool) -> list[tuple[str, bytes]]:
    return [
        (item.path, (poc.tree_dir / item.path).read_bytes())
        for item in poc.files
        if item.path != CONFIG_FILE
        and (symbolic or PurePosixPath(item.path).parts[:1] != (SYMBOLIC_DIR,))
    ]


def _with_extra(
    tests: list[tuple[str, bytes]], extra_tests: Sequence[tuple[str, bytes]]
) -> list[tuple[str, bytes]]:
    taken = {path for path, _ in tests}
    for path, _ in extra_tests:
        if path in taken or PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts:
            raise RunTreeError(f"a generated test file cannot be added as {path!r}")
    return [*tests, *extra_tests]


def benign_paths(revision: Snapshot) -> list[str]:
    """Paths of the files under `test/` of a revision, relative to the revision."""
    return [
        item.path for item in revision.files if PurePosixPath(item.path).parts[:1] == (TEST_DIR,)
    ]


def build_benign_tree(revision: Snapshot, harness: Harness, dest: Path) -> RunTree:
    """Build the benign tree: `src/` and `test/` of `revision`, the harness."""
    tests = [
        (path.split("/", 1)[1], (revision.tree_dir / path).read_bytes())
        for path in benign_paths(revision)
    ]
    return _build(revision, tests, harness, dest)


def _build(
    revision: Snapshot,
    tests: list[tuple[str, bytes]],
    harness: Harness,
    dest: Path,
    config: bytes | None = None,
    extra_dirs: Sequence[tuple[str, list[tuple[str, bytes]]]] = (),
) -> RunTree:
    source = revision.tree_dir / SOURCE_DIR
    if not source.is_dir():
        raise RunTreeError("the revision has no src/ directory")
    dest.mkdir(mode=0o700)
    staging = dest / _STAGING
    shutil.copytree(source, staging / SOURCE_DIR, symlinks=True)
    for directory, files in ((TEST_DIR, tests), *extra_dirs):
        for relative, data in files:
            target = staging / directory / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    (staging / HARNESS_MOUNT).mkdir()
    for name, data in harness.files:
        (staging / HARNESS_MOUNT / name).write_bytes(data)
    try:
        snapshot = create_snapshot(staging, dest / _SNAPSHOT, foundry_toml=config)
    except IngestError as exc:
        raise RunTreeError(f"ingest rejected the run tree: {exc}") from exc
    harness_files = [
        (item.path, item.sha256)
        for item in snapshot.files
        if PurePosixPath(item.path).parts[:1] == (HARNESS_MOUNT,)
    ]
    if tree_digest(harness_files) != harness.sha256:
        raise RunTreeError("the harness in the run tree differs from the shared harness")
    return RunTree(snapshot=snapshot, scratch=make_scratch_dir(dest))
