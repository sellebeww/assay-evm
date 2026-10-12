"""Parsing and application of unified diffs, without trusting their paths or content.

A patch is untrusted input. `parse_patch` reads it as data only: it accepts unified diffs of
text files with `a/` and `b/` path prefixes, as `git diff` writes them, and rejects everything
else with a structured problem. `apply_patch` writes a parsed patch into a tree that Assay owns
(a copy of a snapshot), after checking every path against a `PatchPolicy`. Nothing here runs
`git apply` or any other program.

Problem codes double as the IntegrityOracle's reason codes:

- `path_traversal`: an absolute path, a `..` component, or another path that could leave the
  tree or be read differently by another tool (backslash, control character, empty component);
- `symlink`: a file mode of a symbolic link (`120000`), or a symlink on the way to a target;
- `binary_file`: a binary hunk, a NUL byte, text that is not UTF-8, or a binary target file;
- `protected_path_modified`: a change to a protected path (tests, PoC, harness, configuration);
- `out_of_scope`: a change outside the allowed scope (by default `src/`);
- `malformed_patch`: anything that is not a plain diff of text files: no file sections in a
  non-empty patch, bad hunk headers or counts, quoted paths, missing prefixes, renames, copies,
  mode changes, or a file changed twice;
- `patch_too_large`: a size limit is exceeded;
- `patch_does_not_apply`: the context does not match the tree;
- `ingest_rejected`: the patched tree breaks an ingest rule (see `prepare_patched_revision`).

An empty patch (no bytes, or whitespace only) is valid and changes nothing.
"""

import hashlib
import os
import re
import shutil
import stat
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field

from assay.ingest.paths import UnsafePathError, safe_relative_path
from assay.ingest.snapshot import IngestError, Snapshot, create_snapshot

PatchProblemCode = Literal[
    "path_traversal",
    "symlink",
    "binary_file",
    "protected_path_modified",
    "out_of_scope",
    "malformed_patch",
    "patch_too_large",
    "patch_does_not_apply",
    "ingest_rejected",
]

DEFAULT_SCOPE: Final = ("src",)
# Top-level paths a patch must never change, compared case-insensitively because a
# case-insensitive filesystem opens `Test/A.sol` when asked for `test/A.sol`.
DEFAULT_PROTECTED: Final = (
    "test",
    "poc",
    "solidity",
    "assay",
    "foundry.toml",
    "remappings.txt",
    "expected.json",
)

_MIB: Final = 1024 * 1024
_DEV_NULL: Final = "/dev/null"
_REGULAR_MODE: Final = "100644"
_SYMLINK_MODE: Final = "120000"
_MAX_LINE_NUMBER: Final = 10_000_000
_HUNK_HEADER: Final = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?")
_INDEX_LINE: Final = re.compile(r"index [0-9a-f]{4,64}\.\.[0-9a-f]{4,64}(?: ([0-7]{6}))?")
_MODE_LINE: Final = re.compile(r"(new file mode|deleted file mode|old mode|new mode) ([0-7]{6})")
_PATH_HEADERS: Final = ("rename from ", "rename to ", "copy from ", "copy to ")
_UNSUPPORTED_HEADERS: Final = ("similarity index ", "dissimilarity index ")
_OPEN_FOR_READ: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_OPEN_EXISTING: Final = os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC
_OPEN_NEW: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


class PatchProblem(BaseModel):
    """One reason a patch is not accepted. `path` is relative to the tree, when known."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: PatchProblemCode
    path: str | None
    detail: str


class PatchRejected(Exception):
    """The patch was not accepted; nothing was written."""

    def __init__(self, problems: Sequence[PatchProblem]) -> None:
        if not problems:
            raise ValueError("PatchRejected needs at least one problem")
        super().__init__("; ".join(f"{p.code}: {p.detail}" for p in problems))
        self.problems = tuple(problems)


class PatchLimits(BaseModel):
    """Size limits for a patch and for each file it produces."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_bytes: int = Field(default=_MIB, ge=1)
    max_files: int = Field(default=100, ge=1)
    max_changed_lines: int = Field(default=20_000, ge=1)
    max_file_bytes: int = Field(default=16 * _MIB, ge=1)


class PatchPolicy(BaseModel):
    """Where a patch may write. A protected path is refused even inside the scope."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scope: tuple[str, ...] = DEFAULT_SCOPE
    protected: tuple[str, ...] = DEFAULT_PROTECTED


LineKind = Literal[" ", "-", "+"]
_LINE_KINDS: Final[dict[str, LineKind]] = {" ": " ", "-": "-", "+": "+"}


@dataclass(frozen=True, slots=True)
class HunkLine:
    kind: LineKind
    text: str
    """The line with its terminator: `\\n`, unless the patch marks it as having none."""


@dataclass(frozen=True, slots=True)
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: tuple[HunkLine, ...]

    @property
    def old_lines(self) -> list[str]:
        return [line.text for line in self.lines if line.kind != "+"]

    @property
    def new_lines(self) -> list[str]:
        return [line.text for line in self.lines if line.kind != "-"]


@dataclass(frozen=True, slots=True)
class AddedLine:
    path: str
    line: int
    """Line number in the patched file, starting at 1."""
    text: str


@dataclass(frozen=True, slots=True)
class FilePatch:
    old_path: PurePosixPath | None
    """`None` when the file is created (`/dev/null`)."""
    new_path: PurePosixPath | None
    """`None` when the file is deleted (`/dev/null`)."""
    hunks: tuple[Hunk, ...]

    @property
    def path(self) -> PurePosixPath:
        path = self.new_path if self.new_path is not None else self.old_path
        assert path is not None
        return path

    def added_lines(self) -> list[AddedLine]:
        added: list[AddedLine] = []
        for hunk in self.hunks:
            number = hunk.new_start
            for line in hunk.lines:
                if line.kind == "+":
                    added.append(AddedLine(str(self.path), number, line.text.rstrip("\r\n")))
                if line.kind != "-":
                    number += 1
        return added


@dataclass(frozen=True, slots=True)
class ParsedPatch:
    files: tuple[FilePatch, ...]
    sha256: str
    """sha256 of the patch bytes as given."""

    @property
    def paths(self) -> list[str]:
        return [str(item.path) for item in self.files]

    def added_lines(self) -> list[AddedLine]:
        return [line for item in self.files for line in item.added_lines()]


# ---------------------------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------------------------


class _Parser:
    def __init__(self, lines: list[str], limits: PatchLimits) -> None:
        self.lines = lines
        self.limits = limits
        self.index = 0
        self.problems: list[PatchProblem] = []
        self.files: list[FilePatch] = []

    def problem(self, code: PatchProblemCode, detail: str, path: str | None = None) -> None:
        item = PatchProblem(code=code, path=path, detail=detail)
        if item not in self.problems:
            self.problems.append(item)

    def peek(self) -> str | None:
        return self.lines[self.index] if self.index < len(self.lines) else None

    def take(self) -> str:
        line = self.lines[self.index]
        self.index += 1
        return line

    # -- paths --------------------------------------------------------------------------------

    def path(self, raw: str, prefix: str) -> PurePosixPath | None:
        """Return the path of a `---`/`+++` line without its prefix, or `None` for /dev/null.

        Unsafe paths are reported before the prefix is checked, so that `/etc/passwd` is a
        traversal and not merely a missing prefix.
        """
        text = raw.split("\t", 1)[0]
        if text == _DEV_NULL:
            return None
        if text.startswith('"'):
            self.problem("malformed_patch", "quoted paths are not supported", text[:200])
            return None
        if not self.checked_path(text):
            return None
        if not text.startswith(prefix):
            self.problem("malformed_patch", f"path does not start with {prefix!r}", text)
            return None
        stripped = text[len(prefix) :]
        return PurePosixPath(stripped) if self.checked_path(stripped) else None

    def checked_path(self, text: str) -> bool:
        try:
            safe_relative_path(text)
        except UnsafePathError as exc:
            self.problem("path_traversal", exc.reason, text[:200])
            return False
        return True

    # -- sections -----------------------------------------------------------------------------

    def parse(self) -> None:
        while (line := self.peek()) is not None:
            body = line.rstrip("\r\n")
            if body.startswith("diff --git "):
                self.git_section(body)
            elif body.startswith("--- ") and self._next_starts_with("+++ "):
                self.plain_section()
            elif body.startswith("@@"):
                self.take()
                self.problem("malformed_patch", "hunk outside a file section")
            else:
                self.take()
                self.check_binary_marker(body)

    def _next_starts_with(self, text: str) -> bool:
        following = self.index + 1
        return following < len(self.lines) and self.lines[following].startswith(text)

    def check_binary_marker(self, body: str) -> bool:
        if body.startswith("GIT binary patch") or (
            body.startswith("Binary files ") and body.endswith(" differ")
        ):
            self.problem("binary_file", "binary hunk")
            return True
        return False

    def git_section(self, header: str) -> None:
        self.take()
        tokens = header[len("diff --git ") :].split(" ")
        header_paths: list[PurePosixPath | None] = []
        if len(tokens) != 2:
            self.problem("malformed_patch", "diff header must name two paths without spaces")
        else:
            header_paths = [self.path(tokens[0], "a/"), self.path(tokens[1], "b/")]
        created = deleted = False
        while (line := self.peek()) is not None:
            body = line.rstrip("\r\n")
            if body.startswith(("diff --git ", "--- ", "@@")):
                break
            self.take()
            if self.check_binary_marker(body):
                continue
            if mode := _MODE_LINE.fullmatch(body):
                kind, value = mode.groups()
                if value == _SYMLINK_MODE:
                    self.problem("symlink", "symbolic link mode 120000", _first(header_paths))
                elif kind in ("old mode", "new mode"):
                    self.problem("malformed_patch", "mode changes are not supported")
                elif value != _REGULAR_MODE:
                    self.problem("malformed_patch", f"file mode {value} is not supported")
                created = created or kind == "new file mode"
                deleted = deleted or kind == "deleted file mode"
            elif index := _INDEX_LINE.fullmatch(body):
                if index.group(1) == _SYMLINK_MODE:
                    self.problem("symlink", "symbolic link mode 120000", _first(header_paths))
            elif body.startswith(_PATH_HEADERS):
                self.checked_path(body.split(" ", 2)[2].split("\t", 1)[0])
                self.problem("malformed_patch", "renames and copies are not supported")
            elif body.startswith(_UNSUPPORTED_HEADERS):
                self.problem("malformed_patch", "renames and copies are not supported")
            else:
                self.problem("malformed_patch", "unexpected line in a diff header")
        old: PurePosixPath | None
        new: PurePosixPath | None
        line = self.peek()
        if line is not None and line.startswith("--- "):
            old, new = self.path_pair()
        elif len(header_paths) == 2 and None not in header_paths:
            # A section without `---`/`+++` lines: an empty file created or deleted.
            old = None if created else header_paths[0]
            new = None if deleted else header_paths[1]
        else:
            return
        if len(header_paths) == 2 and None not in header_paths:
            expected_old = None if created else header_paths[0]
            expected_new = None if deleted else header_paths[1]
            if (old, new) != (expected_old, expected_new):
                self.problem("malformed_patch", "file header and diff header disagree")
                return
        self.add_file(old, new, self.hunks())

    def plain_section(self) -> None:
        old, new = self.path_pair()
        self.add_file(old, new, self.hunks())

    def path_pair(self) -> tuple[PurePosixPath | None, PurePosixPath | None]:
        old_line = self.take().rstrip("\r\n")
        new_line = self.peek()
        if new_line is None or not new_line.startswith("+++ "):
            self.problem("malformed_patch", "'---' line without a '+++' line")
            return None, None
        self.take()
        old = self.path(old_line[4:], "a/")
        new = self.path(new_line.rstrip("\r\n")[4:], "b/")
        return old, new

    def add_file(
        self, old: PurePosixPath | None, new: PurePosixPath | None, hunks: list[Hunk]
    ) -> None:
        if old is None and new is None:
            if not self.problems:
                self.problem("malformed_patch", "file section without a usable path")
            return
        if old is not None and new is not None and old != new:
            self.problem("malformed_patch", "renames are not supported", str(new))
            return
        item = FilePatch(old_path=old, new_path=new, hunks=tuple(hunks))
        if old is None and any(h.old_count for h in hunks):
            self.problem("malformed_patch", "a new file cannot have old lines", str(item.path))
        if new is None and any(h.new_count for h in hunks):
            self.problem("malformed_patch", "a deleted file cannot have new lines", str(item.path))
        if any(existing.path == item.path for existing in self.files):
            self.problem("malformed_patch", "file is changed more than once", str(item.path))
            return
        if old is not None and new is not None and not hunks:
            self.problem("malformed_patch", "file section without hunks", str(item.path))
            return
        self.files.append(item)

    def hunks(self) -> list[Hunk]:
        hunks: list[Hunk] = []
        while (line := self.peek()) is not None and line.startswith("@@"):
            hunk = self.hunk(self.take().rstrip("\r\n"))
            if hunk is None:
                break
            hunks.append(hunk)
        return hunks

    def hunk(self, header: str) -> Hunk | None:
        match = _HUNK_HEADER.fullmatch(header)
        if match is None:
            self.problem("malformed_patch", "bad hunk header")
            return None
        old_start, old_count, new_start, new_count = (
            int(value) if value is not None else 1 for value in match.groups()
        )
        if max(old_start, old_count, new_start, new_count) > _MAX_LINE_NUMBER:
            self.problem("patch_too_large", "hunk line numbers exceed the limit")
            return None
        old_left, new_left = old_count, new_count
        lines: list[HunkLine] = []
        while old_left > 0 or new_left > 0:
            line = self.peek()
            if line is None:
                break
            if line in ("\n", "\r\n"):
                # An empty context line whose leading space was removed by an editor.
                line = " " + line
            kind = _LINE_KINDS.get(line[:1])
            if kind is None:
                break
            self.take()
            text = line[1:]
            if not text.endswith("\n"):
                text += "\n"  # the last line of the patch without a terminator
            lines.append(HunkLine(kind, text))
            if kind != "+":
                old_left -= 1
            if kind != "-":
                new_left -= 1
            if old_left < 0 or new_left < 0:
                break
            self.no_newline_marker(lines)
        if old_left != 0 or new_left != 0:
            self.problem("malformed_patch", "hunk line counts do not match its header")
            return None
        self.no_newline_marker(lines)
        return Hunk(old_start, old_count, new_start, new_count, tuple(lines))

    def no_newline_marker(self, lines: list[HunkLine]) -> None:
        line = self.peek()
        if line is not None and line.startswith("\\") and lines:
            self.take()
            last = lines[-1]
            lines[-1] = HunkLine(last.kind, last.text[:-1])


def _first(paths: Sequence[PurePosixPath | None]) -> str | None:
    for path in paths:
        if path is not None:
            return str(path)
    return None


def _split_lines(text: str) -> list[str]:
    """Split on `\\n` only, keeping the terminators; `\\r` stays part of the line."""
    parts = text.split("\n")
    lines = [part + "\n" for part in parts[:-1]]
    if parts[-1]:
        lines.append(parts[-1])
    return lines


def parse_patch(data: bytes, limits: PatchLimits | None = None) -> ParsedPatch:
    """Parse `data` as a unified diff, or raise `PatchRejected` with every problem found."""
    limits = limits if limits is not None else PatchLimits()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) > limits.max_bytes:
        raise PatchRejected(
            [
                PatchProblem(
                    code="patch_too_large", path=None, detail=f"more than {limits.max_bytes} bytes"
                )
            ]
        )
    if b"\0" in data:
        raise PatchRejected([PatchProblem(code="binary_file", path=None, detail="NUL byte")])
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PatchRejected(
            [PatchProblem(code="binary_file", path=None, detail="patch is not UTF-8 text")]
        ) from exc
    if not text.strip():
        return ParsedPatch(files=(), sha256=digest)

    parser = _Parser(_split_lines(text), limits)
    parser.parse()
    if not parser.files and not parser.problems:
        parser.problem("malformed_patch", "no file changes found")
    paths = {item.path for item in parser.files}
    for item in parser.files:
        if any(parent in paths for parent in item.path.parents):
            parser.problem(
                "malformed_patch", "a path is both a file and a directory", str(item.path)
            )
    if len(parser.files) > limits.max_files:
        parser.problem("patch_too_large", f"more than {limits.max_files} files")
    changed = sum(
        1 for item in parser.files for h in item.hunks for line in h.lines if line.kind != " "
    )
    if changed > limits.max_changed_lines:
        parser.problem("patch_too_large", f"more than {limits.max_changed_lines} changed lines")
    if parser.problems:
        raise PatchRejected(parser.problems)
    return ParsedPatch(files=tuple(parser.files), sha256=digest)


# ---------------------------------------------------------------------------------------------
# Path policy
# ---------------------------------------------------------------------------------------------


def _parts(text: str) -> tuple[str, ...]:
    return safe_relative_path(text).parts


def _fold(part: str) -> str:
    # Case-insensitive filesystems usually ignore the Unicode normalization form as well.
    return unicodedata.normalize("NFD", part).casefold()


def is_protected(path: PurePosixPath | str, policy: PatchPolicy) -> bool:
    """True when `path` is a protected path or lies under one (case-insensitive)."""
    folded = tuple(_fold(part) for part in PurePosixPath(path).parts)
    for protected in policy.protected:
        prefix = tuple(_fold(part) for part in _parts(protected))
        if folded[: len(prefix)] == prefix:
            return True
    return False


def in_scope(path: PurePosixPath | str, policy: PatchPolicy) -> bool:
    """True when `path` lies strictly under one of the scope directories (case-sensitive)."""
    parts = PurePosixPath(path).parts
    return any(
        len(parts) > len(prefix) and parts[: len(prefix)] == prefix
        for prefix in (_parts(scope) for scope in policy.scope)
    )


def check_patch_paths(patch: ParsedPatch, policy: PatchPolicy) -> tuple[PatchProblem, ...]:
    """Return a problem for every changed path that is protected or outside the scope."""
    problems: list[PatchProblem] = []
    for item in patch.files:
        path = str(item.path)
        if is_protected(item.path, policy):
            problems.append(
                PatchProblem(code="protected_path_modified", path=path, detail="protected path")
            )
        elif not in_scope(item.path, policy):
            allowed = ", ".join(f"{scope}/" for scope in policy.scope)
            problems.append(
                PatchProblem(code="out_of_scope", path=path, detail=f"outside {allowed}")
            )
    return tuple(problems)


# ---------------------------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------------------------


def _locate(root: Path, relative: PurePosixPath) -> tuple[Path, bool]:
    """Return the target path and whether it exists, refusing symlinks and non-directories.

    Every component is checked with `lstat`, so a symlink anywhere on the way is refused even
    if it points inside the tree.
    """
    current = root
    parts = relative.parts
    for depth, part in enumerate(parts):
        current = current / part
        try:
            status = os.lstat(current)
        except FileNotFoundError:
            return root.joinpath(*parts), False
        if stat.S_ISLNK(status.st_mode):
            raise PatchRejected(
                [PatchProblem(code="symlink", path=str(relative), detail="symlink in the tree")]
            )
        last = depth == len(parts) - 1
        if not last and not stat.S_ISDIR(status.st_mode):
            raise PatchRejected(
                [
                    PatchProblem(
                        code="patch_does_not_apply",
                        path=str(relative),
                        detail="a parent of the path is not a directory",
                    )
                ]
            )
        if last and not stat.S_ISREG(status.st_mode):
            raise PatchRejected(
                [
                    PatchProblem(
                        code="patch_does_not_apply",
                        path=str(relative),
                        detail="target is not a regular file",
                    )
                ]
            )
    return current, True


def _read_text(path: Path, relative: str, limits: PatchLimits) -> str:
    fd = os.open(path, _OPEN_FOR_READ)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise PatchRejected(
                [PatchProblem(code="patch_does_not_apply", path=relative, detail="not a file")]
            )
        data = handle.read(limits.max_file_bytes + 1)
    if len(data) > limits.max_file_bytes:
        raise PatchRejected(
            [PatchProblem(code="patch_too_large", path=relative, detail="target file too large")]
        )
    if b"\0" in data:
        raise PatchRejected(
            [PatchProblem(code="binary_file", path=relative, detail="target is a binary file")]
        )
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PatchRejected(
            [PatchProblem(code="binary_file", path=relative, detail="target is not UTF-8 text")]
        ) from exc


def _candidates(expected: int, low: int, high: int) -> Iterable[int]:
    """Positions from `low` to `high` (inclusive), nearest to `expected` first."""
    if low > high:
        return
    expected = min(max(expected, low), high)
    yield expected
    for distance in range(1, high - low + 1):
        for position in (expected - distance, expected + distance):
            if low <= position <= high:
                yield position


def _apply_hunks(lines: list[str], hunks: Sequence[Hunk]) -> list[str] | None:
    """Apply `hunks` in order; each may move from its stated position, never back over another.

    Context must match exactly (no fuzz). Returns `None` when a hunk does not match.
    """
    result: list[str] = []
    position = 0
    shift = 0
    for hunk in hunks:
        old = hunk.old_lines
        expected = (hunk.old_start - 1 if hunk.old_count else hunk.old_start) + shift
        if not old:
            found: int | None = expected if position <= expected <= len(lines) else None
        else:
            found = next(
                (
                    candidate
                    for candidate in _candidates(expected, position, len(lines) - len(old))
                    if lines[candidate : candidate + len(old)] == old
                ),
                None,
            )
        if found is None:
            return None
        start = found
        shift += start - expected
        result += lines[position:start] + hunk.new_lines
        position = start + len(old)
    return result + lines[position:]


@dataclass(frozen=True, slots=True)
class _Planned:
    relative: PurePosixPath
    target: Path
    exists: bool
    content: bytes | None
    """New content, or `None` to delete."""


def _not_applying(relative: str, detail: str) -> PatchRejected:
    return PatchRejected([PatchProblem(code="patch_does_not_apply", path=relative, detail=detail)])


def _plan(root: Path, item: FilePatch, limits: PatchLimits) -> _Planned:
    relative = str(item.path)
    target, exists = _locate(root, item.path)
    if item.old_path is None:
        if exists:
            raise _not_applying(relative, "the file to create already exists")
        content = "".join(line for hunk in item.hunks for line in hunk.new_lines)
    else:
        if not exists:
            raise _not_applying(relative, "the file does not exist")
        original = _split_lines(_read_text(target, relative, limits))
        if item.new_path is None:
            removed = [line for hunk in item.hunks for line in hunk.old_lines]
            if removed != original:
                raise _not_applying(relative, "the file to delete has other content")
            return _Planned(item.path, target, exists, None)
        patched = _apply_hunks(original, item.hunks)
        if patched is None:
            raise _not_applying(relative, "hunk context does not match")
        content = "".join(patched)
    data = content.encode("utf-8")
    if len(data) > limits.max_file_bytes:
        raise PatchRejected(
            [PatchProblem(code="patch_too_large", path=relative, detail="patched file too large")]
        )
    return _Planned(item.path, target, exists, data)


def _write(root: Path, planned: _Planned) -> None:
    if planned.content is None:
        os.unlink(planned.target)
        return
    directory = root
    for part in planned.relative.parts[:-1]:
        directory = directory / part
        if not os.path.lexists(directory):
            directory.mkdir(mode=0o755)
            directory.chmod(0o755)
        elif not stat.S_ISDIR(os.lstat(directory).st_mode):
            raise _not_applying(str(planned.relative), "a parent of the path is not a directory")
    fd = os.open(planned.target, _OPEN_EXISTING if planned.exists else _OPEN_NEW, 0o644)
    with os.fdopen(fd, "wb") as handle:
        handle.write(planned.content)
        os.fchmod(handle.fileno(), 0o644)


def apply_patch(
    tree: Path,
    patch: ParsedPatch,
    *,
    policy: PatchPolicy | None = None,
    limits: PatchLimits | None = None,
) -> None:
    """Apply `patch` to the files under `tree`, or raise `PatchRejected` and write nothing.

    Every path is checked against `policy` first. Then every file is planned in memory (target
    located without following symlinks, context matched exactly), and only when all files apply
    are they written. `tree` must be a directory that Assay owns, such as a snapshot copy.
    """
    policy = policy if policy is not None else PatchPolicy()
    limits = limits if limits is not None else PatchLimits()
    problems = check_patch_paths(patch, policy)
    if problems:
        raise PatchRejected(problems)
    root = tree.resolve(strict=True)
    planned = [_plan(root, item, limits) for item in patch.files]
    for item in planned:
        _write(root, item)


# ---------------------------------------------------------------------------------------------
# The patched revision
# ---------------------------------------------------------------------------------------------

WORK_DIR: Final = "work"
SNAPSHOT_DIR: Final = "snapshot"


@dataclass(frozen=True, slots=True)
class PreparedPatch:
    """Outcome of `prepare_patched_revision`.

    `snapshot` is the patched revision, or `None` when the patch was not applied; then
    `problems` says why. `patch` is `None` when the patch could not be parsed.
    """

    patch: ParsedPatch | None
    sha256: str
    problems: tuple[PatchProblem, ...]
    snapshot: Snapshot | None


def prepare_patched_revision(
    base: Snapshot,
    data: bytes,
    dest: Path,
    *,
    policy: PatchPolicy | None = None,
    limits: PatchLimits | None = None,
) -> PreparedPatch:
    """Parse `data`, apply it to a copy of the snapshot `base` and snapshot the result.

    The copy lives in `dest/work`; the patched revision is a new snapshot in `dest/snapshot`,
    made by the same ingest rules as any project, so a patch cannot bring in what ingest
    rejects (for example inline Foundry configuration). `dest` must not exist.
    """
    policy = policy if policy is not None else PatchPolicy()
    digest = hashlib.sha256(data).hexdigest()
    try:
        parsed = parse_patch(data, limits)
    except PatchRejected as exc:
        return PreparedPatch(patch=None, sha256=digest, problems=exc.problems, snapshot=None)
    path_problems = check_patch_paths(parsed, policy)
    if path_problems:
        return PreparedPatch(patch=parsed, sha256=digest, problems=path_problems, snapshot=None)
    dest.mkdir(mode=0o700)
    work = dest / WORK_DIR
    shutil.copytree(base.tree_dir, work, symlinks=True)
    try:
        apply_patch(work, parsed, policy=policy, limits=limits)
    except PatchRejected as exc:
        return PreparedPatch(patch=parsed, sha256=digest, problems=exc.problems, snapshot=None)
    try:
        snapshot = create_snapshot(work, dest / SNAPSHOT_DIR)
    except IngestError as exc:
        problem = PatchProblem(code="ingest_rejected", path=exc.path, detail=str(exc))
        return PreparedPatch(patch=parsed, sha256=digest, problems=(problem,), snapshot=None)
    return PreparedPatch(patch=parsed, sha256=digest, problems=(), snapshot=snapshot)
