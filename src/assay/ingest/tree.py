"""Content hash of a directory tree (`tree_sha256`).

The hash is sha256 over the entries sorted by the UTF-8 bytes of their relative POSIX path.
Each entry is `<path> NUL <sha256 hex of the content> LF`. A path cannot contain NUL and the
content hash has a fixed length, so the encoding is unambiguous. Only regular files take
part; directories are implied by the paths, and file modes and timestamps are ignored.
"""

import hashlib
import os
import re
import stat
from collections.abc import Iterable
from pathlib import Path
from typing import Final

from assay.ingest.paths import UnsafePathError, safe_relative_path

_SHA256_HEX: Final = re.compile(r"[0-9a-f]{64}")
_READ_CHUNK: Final = 1024 * 1024


def tree_digest(entries: Iterable[tuple[str, str]]) -> str:
    """Return the tree hash of `(relative path, content sha256 hex)` pairs."""
    encoded: list[tuple[bytes, str]] = []
    for path, digest in entries:
        safe_relative_path(path)
        if _SHA256_HEX.fullmatch(digest) is None:
            raise ValueError(f"not a lowercase sha256 hex digest: {digest!r}")
        encoded.append((path.encode("utf-8"), digest))
    encoded.sort()
    hasher = hashlib.sha256()
    previous: bytes | None = None
    for path_bytes, digest in encoded:
        if path_bytes == previous:
            raise ValueError(f"duplicate path: {path_bytes.decode('utf-8')!r}")
        previous = path_bytes
        hasher.update(path_bytes + b"\0" + digest.encode("ascii") + b"\n")
    return hasher.hexdigest()


def tree_sha256(root: Path) -> str:
    """Hash every regular file under `root`; refuse symlinks and special files."""
    root = root.resolve(strict=True)
    entries: list[tuple[str, str]] = []
    pending = [""]
    while pending:
        relative_dir = pending.pop()
        with os.scandir(root / relative_dir) as listing:
            items = sorted(listing, key=lambda entry: entry.name)
        for item in items:
            relative = f"{relative_dir}/{item.name}" if relative_dir else item.name
            mode = item.stat(follow_symlinks=False).st_mode
            if stat.S_ISDIR(mode):
                pending.append(relative)
            elif stat.S_ISREG(mode):
                entries.append((relative, _file_sha256(Path(item.path))))
            elif stat.S_ISLNK(mode):
                raise UnsafePathError(relative, "symlink in hashed tree")
            else:
                raise UnsafePathError(relative, "special file in hashed tree")
    return tree_digest(entries)


def _file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as handle:
        while chunk := handle.read(_READ_CHUNK):
            hasher.update(chunk)
    return hasher.hexdigest()
