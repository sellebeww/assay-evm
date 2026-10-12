"""Snapshot of an untrusted project directory.

`create_snapshot` copies a project into a fresh directory in two passes. The first pass walks
the source tree without writing anything: it applies the skip rules, rejects dangerous entries
and enforces the limits. The second pass copies the planned files, opening each one without
following symlinks and re-checking type and size, so a tree that changes during the copy is
rejected rather than trusted.

Layout of the destination directory:

    <dest>/tree/       the snapshot that is mounted read-only into the sandbox
    <dest>/evidence/   the project's own configuration files (foundry.toml, remappings.txt,
                       slither.config.json, aderyn.toml, halmos.toml), never used by a tool

The snapshot contains only directories and regular files (modes 0755 and 0644). A symlink
inside the source tree that points at a regular file inside the tree is copied as a regular
file; every other symlink is rejected.

Solidity files that contain inline Foundry configuration (`forge-config:` in a comment) are
rejected: forge applies such settings per test on top of the rewritten foundry.toml, including
`fs_permissions` and the fuzz and invariant settings.
"""

import hashlib
import os
import re
import shutil
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field

from assay.ingest.config import safe_foundry_toml
from assay.ingest.paths import UnsafePathError, safe_relative_path
from assay.ingest.tree import tree_digest

SkipReason = Literal[
    "vcs_metadata", "dependencies", "assay_data", "build_output", "secret", "project_config"
]
IngestErrorCode = Literal[
    "not_a_directory",
    "unreadable",
    "unsafe_path",
    "path_collision",
    "symlink_outside_tree",
    "symlink_unresolvable",
    "symlink_to_directory",
    "symlink_to_excluded_path",
    "special_file",
    "too_many_files",
    "too_many_directories",
    "file_too_large",
    "tree_too_large",
    "changed_during_copy",
    "inline_config",
]

TREE_DIR: Final = "tree"
EVIDENCE_DIR: Final = "evidence"
CONFIG_FILE: Final = "foundry.toml"

_MIB: Final = 1024 * 1024

# Entries left out wherever they appear.
_SKIP_ANYWHERE: Final[Mapping[str, SkipReason]] = {
    ".git": "vcs_metadata",
    "node_modules": "dependencies",
    ".assay": "assay_data",
}
# Entries left out only at the project root.
_SKIP_AT_ROOT: Final[Mapping[str, SkipReason]] = {
    "out": "build_output",
    "cache": "build_output",
}
# The project's own configuration, left out and kept as evidence: forge's files (foundry.toml is
# replaced by the snapshot configuration), and the files that Slither and Aderyn read from the
# project root, with which a project could switch detectors off, filter paths or set
# environment variables for the analyzer (ADR 0015), and Halmos's `halmos.toml`, with which a
# project could switch FFI on or change the solver and the bounds (ADR 0018). Matched in any
# letter case: on a case-insensitive filesystem forge opens `Remappings.txt` when it asks for
# `remappings.txt`.
_PROJECT_CONFIG: Final = frozenset(
    {"foundry.toml", "remappings.txt", "slither.config.json", "aderyn.toml", "halmos.toml"}
)
_KEY_SUFFIXES: Final = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore")
_KEY_PREFIXES: Final = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")
_PEM_PRIVATE_KEY: Final = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
# Matched anywhere in a Solidity file, case-insensitively, so that no spelling forge might
# accept slips through; a mention in an ordinary comment or string is rejected as well.
_INLINE_CONFIG: Final = re.compile(rb"forge-config", re.IGNORECASE)
_SOLIDITY_SUFFIX: Final = ".sol"
_OPEN_FOR_READ: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_OPEN_FOR_WRITE: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


class IngestLimits(BaseModel):
    """Size limits for a snapshot. Every limit is checked before anything is written."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_files: int = Field(default=20_000, ge=1)
    max_directories: int = Field(default=10_000, ge=1)
    max_file_bytes: int = Field(default=16 * _MIB, ge=1)
    max_total_bytes: int = Field(default=256 * _MIB, ge=1)


class IngestError(Exception):
    """The project was rejected. `path` is relative to the project root."""

    def __init__(self, code: IngestErrorCode, path: str, detail: str = "") -> None:
        message = f"{code}: {path!r}"
        if detail:
            message += f" ({detail})"
        super().__init__(message)
        self.code: IngestErrorCode = code
        self.path = path


class SnapshotFile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    size: int
    sha256: str


class SkippedPath(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    reason: SkipReason


class Snapshot(BaseModel):
    """Result of `create_snapshot`. Host paths are excluded from serialization."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tree_dir: Path = Field(exclude=True)
    evidence_dir: Path = Field(exclude=True)
    tree_sha256: str
    files: tuple[SnapshotFile, ...]
    skipped: tuple[SkippedPath, ...]
    project_config: tuple[SnapshotFile, ...]


@dataclass(frozen=True)
class _Planned:
    path: PurePosixPath
    source: str


@dataclass
class _Plan:
    files: list[_Planned] = field(default_factory=list)
    evidence: list[_Planned] = field(default_factory=list)
    skipped: list[SkippedPath] = field(default_factory=list)
    file_count: int = 0
    directory_count: int = 0
    total_bytes: int = 0


def _skip_reason(path: PurePosixPath) -> SkipReason | None:
    name = path.name
    if name in _SKIP_ANYWHERE:
        return _SKIP_ANYWHERE[name]
    lowered = name.lower()
    if len(path.parts) == 1:
        if name in _SKIP_AT_ROOT:
            return _SKIP_AT_ROOT[name]
        if lowered in _PROJECT_CONFIG:
            return "project_config"
    if (
        lowered.startswith(".env")
        or lowered.endswith(_KEY_SUFFIXES)
        or lowered.startswith(_KEY_PREFIXES)
    ):
        return "secret"
    return None


def _excluded(path: PurePosixPath) -> SkipReason | None:
    for depth in range(1, len(path.parts) + 1):
        reason = _skip_reason(PurePosixPath(*path.parts[:depth]))
        if reason is not None:
            return reason
    return None


def _relative(text: str) -> PurePosixPath:
    try:
        return safe_relative_path(text)
    except UnsafePathError as exc:
        raise IngestError("unsafe_path", text, exc.reason) from exc


def _resolve_symlink(root: str, link: str, relative: str) -> tuple[str, int]:
    """Return the target and size of an in-tree symlink to a regular file, or reject it."""
    # Checked on the lexical resolution first, so that a dangling link out of the tree is
    # reported as such; the strict resolution then rejects missing targets and loops.
    if os.path.commonpath([root, os.path.realpath(link)]) != root:
        raise IngestError("symlink_outside_tree", relative)
    try:
        target = os.path.realpath(link, strict=True)
        status = os.stat(target)
    except OSError as exc:
        raise IngestError("symlink_unresolvable", relative) from exc
    if os.path.commonpath([root, target]) != root:
        raise IngestError("symlink_outside_tree", relative)
    if target == root:
        raise IngestError("symlink_to_directory", relative)
    target_relative = _relative(os.path.relpath(target, root).replace(os.sep, "/"))
    if _excluded(target_relative) is not None:
        raise IngestError("symlink_to_excluded_path", relative)
    if stat.S_ISDIR(status.st_mode):
        raise IngestError("symlink_to_directory", relative)
    if not stat.S_ISREG(status.st_mode):
        raise IngestError("special_file", relative)
    return target, status.st_size


def _plan_file(plan: _Plan, limits: IngestLimits, relative: str, size: int) -> None:
    plan.file_count += 1
    plan.total_bytes += size
    if plan.file_count > limits.max_files:
        raise IngestError("too_many_files", relative, f"limit {limits.max_files}")
    if size > limits.max_file_bytes:
        raise IngestError("file_too_large", relative, f"limit {limits.max_file_bytes} bytes")
    if plan.total_bytes > limits.max_total_bytes:
        raise IngestError("tree_too_large", relative, f"limit {limits.max_total_bytes} bytes")


def _scan(root: str, limits: IngestLimits) -> _Plan:
    plan = _Plan()
    pending = [""]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(os.path.join(root, directory) if directory else root) as listing:
                entries = sorted(listing, key=lambda entry: entry.name)
        except OSError as exc:
            raise IngestError("unreadable", directory or ".") from exc
        for entry in entries:
            text = f"{directory}/{entry.name}" if directory else entry.name
            relative = _relative(text)
            try:
                status = os.lstat(entry.path)
            except OSError as exc:
                raise IngestError("unreadable", text) from exc
            reason = _skip_reason(relative)
            if reason is not None:
                plan.skipped.append(SkippedPath(path=text, reason=reason))
                # The project's configuration is read (as evidence only), so it goes through
                # the same symlink checks as every other file that is read.
                if reason == "project_config" and not stat.S_ISDIR(status.st_mode):
                    source, size = _source_of(root, entry.path, text, status)
                    _plan_file(plan, limits, text, size)
                    plan.evidence.append(_Planned(relative, source))
                continue
            if stat.S_ISDIR(status.st_mode):
                plan.directory_count += 1
                if plan.directory_count > limits.max_directories:
                    raise IngestError(
                        "too_many_directories", text, f"limit {limits.max_directories}"
                    )
                pending.append(text)
                continue
            source, size = _source_of(root, entry.path, text, status)
            _plan_file(plan, limits, text, size)
            plan.files.append(_Planned(relative, source))
    return plan


def _source_of(root: str, path: str, relative: str, status: os.stat_result) -> tuple[str, int]:
    if stat.S_ISLNK(status.st_mode):
        return _resolve_symlink(root, path, relative)
    if stat.S_ISREG(status.st_mode):
        return path, status.st_size
    raise IngestError("special_file", relative)


def _read(item: _Planned, limits: IngestLimits) -> bytes:
    try:
        fd = os.open(item.source, _OPEN_FOR_READ)
    except PermissionError as exc:
        raise IngestError("unreadable", str(item.path)) from exc
    except OSError as exc:
        # Missing, or replaced by a symlink (ELOOP) since the scan.
        raise IngestError("changed_during_copy", str(item.path)) from exc
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise IngestError("changed_during_copy", str(item.path))
        data = handle.read(limits.max_file_bytes + 1)
    if len(data) > limits.max_file_bytes:
        raise IngestError("file_too_large", str(item.path), f"limit {limits.max_file_bytes} bytes")
    return data


def _make_directory(path: Path) -> None:
    path.mkdir(mode=0o755)
    path.chmod(0o755)


def _write(base: Path, relative: PurePosixPath, data: bytes) -> SnapshotFile:
    directory = base
    for part in relative.parts[:-1]:
        directory = directory / part
        if not directory.is_dir():
            _make_directory(directory)
    try:
        fd = os.open(base.joinpath(*relative.parts), _OPEN_FOR_WRITE, 0o644)
    except FileExistsError as exc:
        raise IngestError("path_collision", str(relative)) from exc
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        os.fchmod(handle.fileno(), 0o644)
    return SnapshotFile(path=str(relative), size=len(data), sha256=hashlib.sha256(data).hexdigest())


def _path_key(path: str) -> bytes:
    return path.encode("utf-8")


def create_snapshot(
    source: Path,
    dest: Path,
    limits: IngestLimits | None = None,
    *,
    foundry_toml: bytes | None = None,
) -> Snapshot:
    """Copy the project at `source` into the new directory `dest` and return its description.

    `dest` must not exist. On any error, `dest` is removed again and the error is raised;
    rejections of the project raise `IngestError`. `foundry_toml` replaces the default rewritten
    configuration; it must come from `safe_foundry_toml` (used for the run trees of the oracles).
    """
    limits = limits if limits is not None else IngestLimits()
    root = os.path.realpath(source)
    if not os.path.isdir(root):
        raise IngestError("not_a_directory", ".")
    plan = _scan(root, limits)

    dest.mkdir(mode=0o700)
    try:
        tree_dir = dest / TREE_DIR
        evidence_dir = dest / EVIDENCE_DIR
        _make_directory(tree_dir)
        _make_directory(evidence_dir)
        skipped = list(plan.skipped)
        written = 0

        def copy(item: _Planned, base: Path) -> SnapshotFile | None:
            nonlocal written
            data = _read(item, limits)
            written += len(data)
            if written > limits.max_total_bytes:
                raise IngestError("changed_during_copy", str(item.path), "tree grew during copy")
            if item.path.suffix.lower() == _SOLIDITY_SUFFIX and _INLINE_CONFIG.search(data):
                raise IngestError("inline_config", str(item.path))
            if _PEM_PRIVATE_KEY.search(data):
                skipped.append(SkippedPath(path=str(item.path), reason="secret"))
                return None
            return _write(base, item.path, data)

        files = [copied for item in plan.files if (copied := copy(item, tree_dir)) is not None]
        config = foundry_toml if foundry_toml is not None else safe_foundry_toml()
        files.append(_write(tree_dir, PurePosixPath(CONFIG_FILE), config))
        evidence = [
            copied for item in plan.evidence if (copied := copy(item, evidence_dir)) is not None
        ]
    except BaseException:
        shutil.rmtree(dest, ignore_errors=True)
        raise

    files.sort(key=lambda item: _path_key(item.path))
    evidence.sort(key=lambda item: _path_key(item.path))
    skipped.sort(key=lambda item: _path_key(item.path))
    return Snapshot(
        tree_dir=tree_dir,
        evidence_dir=evidence_dir,
        tree_sha256=tree_digest((item.path, item.sha256) for item in files),
        files=tuple(files),
        skipped=tuple(skipped),
        project_config=tuple(evidence),
    )
