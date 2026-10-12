"""Validation of relative paths taken from untrusted input."""

import unicodedata
from pathlib import PurePosixPath


class UnsafePathError(ValueError):
    """A path is absolute, escapes its root, or contains characters that are not accepted."""

    def __init__(self, path: str, reason: str) -> None:
        super().__init__(f"{reason}: {path!r}")
        self.path = path
        self.reason = reason


def safe_relative_path(path: str) -> PurePosixPath:
    """Return `path` as a normalized relative POSIX path, or raise `UnsafePathError`.

    Rejected: empty paths, absolute paths, `..` components (path traversal), empty or `.`
    components, backslashes, control characters and text that is not valid UTF-8.
    """
    if not path:
        raise UnsafePathError(path, "empty path")
    if path.startswith("/"):
        raise UnsafePathError(path, "absolute path")
    if "\\" in path:
        raise UnsafePathError(path, "backslash in path")
    if any(unicodedata.category(ch) == "Cc" for ch in path):
        raise UnsafePathError(path, "control character in path")
    try:
        path.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise UnsafePathError(path, "path is not valid UTF-8") from exc
    parts = path.split("/")
    if ".." in parts:
        raise UnsafePathError(path, "path traversal")
    if any(part in ("", ".") for part in parts):
        raise UnsafePathError(path, "empty or '.' path component")
    return PurePosixPath(path)
