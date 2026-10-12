"""The Solidity diff of a pull request, computed with git and checked before anything uses it.

Everything in the compared revisions is hostile data. The diff is computed from git objects only:

- git runs with a fixed environment (no global or system configuration, no external diff driver,
  no pager), with `--no-ext-diff` and `--no-textconv`, and with literal pathspecs;
- revisions are resolved to full commit ids first, and a revision that looks like an option is
  refused;
- only paths inside the scope are looked at. A rename that crosses the scope boundary, a symlink,
  a submodule, a type change, a binary file and an unsafe path are refused (`DiffError` of kind
  `rejected`, exit code 5);
- the base tree is written from git blobs with `git cat-file`, which applies no filter, so no
  `.gitattributes` or configuration of the pull request is evaluated.
"""

import os
import re
import subprocess
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from assay.ingest import IngestLimits, UnsafePathError, safe_relative_path
from assay.ledger.ledger import MAX_PATCH_BYTES

__all__ = ["DiffError", "ScopedChange", "ScopedDiff", "export_tree", "scoped_diff"]

GIT_TIMEOUT_S: Final = 120
MAX_LISTING_BYTES: Final = 64 * 1024 * 1024
_REGULAR_MODES: Final = frozenset({"100644", "100755"})
_SYMLINK: Final = "120000"
_GITLINK: Final = "160000"
_NO_FILE: Final = "000000"
_REVISION: Final = re.compile(r"[0-9A-Za-z][0-9A-Za-z._/@{}^~:+-]*")
_SHA: Final = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_STATUSES: Final = frozenset("AMD")


class DiffError(Exception):
    """The diff cannot be computed or must not be used.

    `usage` is a wrong argument (exit code 2), `rejected` is hostile or unsupported content
    (exit code 5) and `infrastructure` is a git failure (exit code 4).
    """

    def __init__(self, kind: Literal["usage", "rejected", "infrastructure"], message: str) -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True, slots=True)
class ScopedChange:
    """One changed file inside the scope; `path` is relative to the project directory."""

    status: Literal["A", "M", "D"]
    path: str


@dataclass(frozen=True, slots=True)
class ScopedDiff:
    base_sha: str
    head_sha: str
    changes: tuple[ScopedChange, ...]
    patch: bytes
    """A unified diff with `a/` and `b/` prefixes, relative to the project directory; empty when
    nothing changed in scope."""
    outside_changes: tuple[str, ...]
    """Changed paths outside the scope, relative to the repository root (only used to look for
    changes of the PoC directory)."""
    prefix: str
    """The project directory relative to the repository root, `""` or ending in `/`."""


def _git_env() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", os.defpath),
        "LC_ALL": "C",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_LITERAL_PATHSPECS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "GIT_OPTIONAL_LOCKS": "0",
    }


def _run(
    cwd: Path, args: Sequence[str], *, stdin: bytes | None = None, limit: int = MAX_LISTING_BYTES
) -> bytes:
    command = [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.quotePath=false",
        "-c",
        "diff.external=",
        *args,
    ]
    try:
        done = subprocess.run(
            command,
            cwd=cwd,
            env=_git_env(),
            input=stdin,
            capture_output=True,
            timeout=GIT_TIMEOUT_S,
            check=False,
        )
    except FileNotFoundError as exc:
        raise DiffError("infrastructure", "git is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise DiffError("infrastructure", f"git {args[0]} timed out") from exc
    if done.returncode != 0:
        detail = done.stderr.decode("utf-8", "replace").strip().splitlines()
        raise DiffError(
            "usage", f"git {args[0]} failed: {detail[-1] if detail else 'no error message'}"
        )
    if len(done.stdout) > limit:
        raise DiffError("rejected", f"git {args[0]} produced more than {limit} bytes")
    return done.stdout


def _clean_scope(scope: str) -> str:
    try:
        path = safe_relative_path(scope.rstrip("/"))
    except UnsafePathError as exc:
        raise DiffError("usage", f"--scope is not a safe relative directory: {exc}") from exc
    return path.as_posix()


def _resolve(repo: Path, revision: str, option: str) -> str:
    if not _REVISION.fullmatch(revision) or ".." in revision:
        raise DiffError("usage", f"{option} is not a plain revision name or commit id")
    out = _run(
        repo, ["rev-parse", "--verify", "--quiet", "--end-of-options", f"{revision}^{{commit}}"]
    )
    sha = out.decode("ascii", "replace").strip()
    if not _SHA.fullmatch(sha):
        raise DiffError("usage", f"{option} does not name a commit")
    return sha


def _repository(project: Path) -> tuple[Path, Path, str]:
    """The project directory, the repository root and the project directory relative to the
    root (`""` or ending in `/`)."""
    if project.is_symlink() or not project.is_dir():
        raise DiffError("usage", "the project directory must be a directory and not a symlink")
    resolved = project.resolve()
    top = _run(resolved, ["rev-parse", "--show-toplevel"]).decode("utf-8", "replace").strip()
    prefix = _run(resolved, ["rev-parse", "--show-prefix"]).decode("utf-8", "replace").strip()
    if not top:
        raise DiffError("usage", "the project directory is not inside a git work tree")
    return resolved, Path(top), prefix


def _fields(raw: bytes) -> list[bytes]:
    if not raw:
        return []
    return raw.split(b"\0")[:-1] if raw.endswith(b"\0") else raw.split(b"\0")


def _text(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DiffError("rejected", "a path in the diff is not valid UTF-8") from exc


def _relative(path: str, prefix: str) -> str | None:
    """`path` relative to the project directory, or None when it lies outside it."""
    if prefix and not path.startswith(prefix):
        return None
    return path[len(prefix) :]


def _in_scope(path: str, prefix: str, scope: str) -> bool:
    relative = _relative(path, prefix)
    return relative is not None and relative.startswith(f"{scope}/")


def _check_path(relative: str) -> None:
    try:
        safe_relative_path(relative)
    except UnsafePathError as exc:
        raise DiffError("rejected", f"unsafe path in the diff: {exc}") from exc
    if any(unicodedata.category(ch) == "Cf" for ch in relative):
        raise DiffError("rejected", f"invisible formatting character in a path: {relative!r}")


def _raw_entries(repo: Path, base: str, head: str) -> list[tuple[str, str, str, tuple[str, ...]]]:
    """`(status, old mode, new mode, paths)` for every change of the repository, renames found."""
    out = _run(
        repo,
        ["diff", "--raw", "-z", "-M", "--no-abbrev", "--no-ext-diff", "--no-textconv",
         "--no-color", base, head, "--"],
    )  # fmt: skip
    parts = _fields(out)
    entries: list[tuple[str, str, str, tuple[str, ...]]] = []
    index = 0
    while index < len(parts):
        header = _text(parts[index])
        match = re.fullmatch(r":(\d{6}) (\d{6}) [0-9a-f]+ [0-9a-f]+ ([A-Z])\d*", header)
        if match is None:
            raise DiffError("infrastructure", "unexpected output of git diff --raw")
        old_mode, new_mode, status = match.groups()
        count = 2 if status in ("R", "C") else 1
        paths = tuple(_text(item) for item in parts[index + 1 : index + 1 + count])
        if len(paths) != count:
            raise DiffError("infrastructure", "truncated output of git diff --raw")
        entries.append((status, old_mode, new_mode, paths))
        index += 1 + count
    return entries


def scoped_diff(project: Path, base: str, head: str, scope: str = "src") -> ScopedDiff:
    """The diff from `base` to `head` limited to `scope` (a directory of the project).

    Raises `DiffError`. A scope without changes gives a `ScopedDiff` with no changes and an empty
    patch.
    """
    scope = _clean_scope(scope)
    cwd, _, prefix = _repository(project)
    base_sha = _resolve(cwd, base, "--base")
    head_sha = _resolve(cwd, head, "--head")

    in_scope: list[ScopedChange] = []
    outside: list[str] = []
    for status, old_mode, new_mode, paths in _raw_entries(cwd, base_sha, head_sha):
        inside = [_in_scope(path, prefix, scope) for path in paths]
        if not any(inside):
            outside.extend(paths)
            continue
        if not all(inside):
            raise DiffError(
                "rejected",
                f"a {'rename' if status == 'R' else 'copy'} crosses the boundary of the scope "
                f"{scope!r}: {paths[0]!r} to {paths[1]!r}",
            )
        for path in paths:
            relative = _relative(path, prefix) or ""
            _check_path(relative)
        for mode in (old_mode, new_mode):
            if mode == _SYMLINK:
                raise DiffError("rejected", f"a symlink is part of the diff: {paths[-1]!r}")
            if mode == _GITLINK:
                raise DiffError("rejected", f"a submodule is part of the diff: {paths[-1]!r}")
            if mode != _NO_FILE and mode not in _REGULAR_MODES:
                raise DiffError("rejected", f"an unsupported file mode in the diff: {paths[-1]!r}")
        if status == "T":
            raise DiffError("rejected", f"a file type change is part of the diff: {paths[0]!r}")
        if status in ("R", "C"):
            # Both sides are in scope: the patch lists them as a deletion and an addition.
            in_scope.append(ScopedChange("D", _relative(paths[0], prefix) or ""))
            in_scope.append(ScopedChange("A", _relative(paths[1], prefix) or ""))
        elif status in _STATUSES:
            in_scope.append(ScopedChange(status, _relative(paths[0], prefix) or ""))  # type: ignore[arg-type]
        else:
            raise DiffError("rejected", f"an unsupported change status in the diff: {status}")
    changes = tuple(sorted(set(in_scope), key=lambda item: (item.path, item.status)))
    if not changes:
        return ScopedDiff(base_sha, head_sha, (), b"", tuple(sorted(set(outside))), prefix)

    common = ["diff", "--no-ext-diff", "--no-textconv", "--no-color", "--no-renames", "--relative"]
    numstat = _run(cwd, [*common, "--numstat", "-z", base_sha, head_sha, "--", scope])
    for field in _fields(numstat):
        if _text(field).startswith("-\t-\t"):
            raise DiffError("rejected", "a binary file is part of the diff")
    patch = _run(
        cwd,
        [*common, "--src-prefix=a/", "--dst-prefix=b/", "-U3", base_sha, head_sha, "--", scope],
        limit=MAX_PATCH_BYTES,
    )
    if re.search(rb"^(Binary files |GIT binary patch)", patch, re.MULTILINE):
        raise DiffError("rejected", "a binary file is part of the diff")
    return ScopedDiff(base_sha, head_sha, changes, patch, tuple(sorted(set(outside))), prefix)


def _blob_listing(cwd: Path, sha: str, prefix: str) -> list[tuple[str, str, str, int, str]]:
    pathspec = [prefix.rstrip("/")] if prefix else []
    out = _run(cwd, ["ls-tree", "-r", "-z", "-l", "--full-name", sha, "--", *pathspec])
    entries: list[tuple[str, str, str, int, str]] = []
    for field in _fields(out):
        meta, _, path = _text(field).partition("\t")
        mode, kind, object_id, size = meta.split()
        entries.append((mode, kind, object_id, 0 if size == "-" else int(size), path))
    return entries


def export_tree(
    project: Path,
    revision_sha: str,
    dest: Path,
    *,
    limits: IngestLimits | None = None,
) -> int:
    """Write the project directory as it is at `revision_sha` into the empty directory `dest`.

    Files are written from git blobs, so no filter or attribute of the revision is evaluated.
    Symlinks are refused, and submodules are left out (the runner image provides forge-std).
    Returns the number of files written. Raises `DiffError`.
    """
    limits = limits or IngestLimits()
    cwd, top, prefix = _repository(project)
    if not _SHA.fullmatch(revision_sha):
        raise DiffError("usage", "the revision must be a full commit id")
    files: list[tuple[str, str, int]] = []
    total = 0
    for mode, kind, object_id, size, path in _blob_listing(top, revision_sha, prefix):
        relative = _relative(path, prefix)
        if relative is None:
            continue
        _check_path(relative)
        if mode == _SYMLINK:
            raise DiffError("rejected", f"the base revision contains a symlink: {relative!r}")
        if kind != "blob":
            continue
        if mode not in _REGULAR_MODES:
            raise DiffError(
                "rejected", f"the base revision has an unsupported file mode: {relative!r}"
            )
        if size > limits.max_file_bytes:
            raise DiffError("rejected", f"a file of the base revision is too large: {relative!r}")
        total += size
        files.append((relative, object_id, size))
    if len(files) > limits.max_files or total > limits.max_total_bytes:
        raise DiffError("rejected", "the base revision is larger than the ingest limits")
    if not files:
        raise DiffError("usage", "the project directory has no files at the base revision")
    request = "".join(f"{object_id}\n" for _, object_id, _ in files).encode("ascii")
    out = _run(cwd, ["cat-file", "--batch"], stdin=request, limit=total + 64 * len(files) + 1024)
    position = 0
    for relative, object_id, size in files:
        end = out.find(b"\n", position)
        header = out[position:end].decode("ascii", "replace").split()
        if end < 0 or header != [object_id, "blob", str(size)]:
            raise DiffError("infrastructure", "unexpected output of git cat-file")
        data = out[end + 1 : end + 1 + size]
        position = end + 1 + size + 1
        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o644)
    return len(files)


def changed_under(diff: ScopedDiff, directory: Path, project: Path) -> bool:
    """True when the diff changed a path under `directory` (a path on disk), inside or outside
    the scope. False when `directory` is not inside the repository of `project`."""
    _, top, prefix = _repository(project)
    try:
        relative = directory.resolve().relative_to(top.resolve()).as_posix()
    except ValueError:
        return False
    if relative == ".":
        return bool(diff.changes) or bool(diff.outside_changes)
    inside = [f"{prefix}{change.path}" for change in diff.changes]
    return any(path.startswith(f"{relative}/") for path in (*inside, *diff.outside_changes))
