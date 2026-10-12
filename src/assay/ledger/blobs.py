"""Content-addressed blob store.

A blob lives at `<root>/<first two hex digits>/<sha256>`. It is written once, through a
temporary file that is linked into place, so a reader never sees a partial blob and an existing
blob is never replaced. Every read hashes the content again and refuses a mismatch.
"""

import hashlib
import os
import re
import tempfile
from pathlib import Path
from typing import Final

from assay.ledger.errors import BlobCorrupted, BlobError, NotFound

_SHA256_HEX: Final = re.compile(r"[0-9a-f]{64}")
_READ_CHUNK: Final = 1024 * 1024


def is_sha256_hex(value: str) -> bool:
    return _SHA256_HEX.fullmatch(value) is not None


class BlobStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def path_for(self, sha256: str) -> Path:
        """Return where the blob with `sha256` is stored; refuse anything but a sha256 hex."""
        if not is_sha256_hex(sha256):
            raise BlobError(f"not a lowercase sha256 hex digest: {sha256!r}")
        return self.root / sha256[:2] / sha256

    def put(self, data: bytes) -> str:
        """Store `data` once and return its sha256. An existing blob is checked, not replaced."""
        digest = hashlib.sha256(data).hexdigest()
        target = self.path_for(digest)
        if os.path.lexists(target):
            self._check_existing(target, digest)
            return digest
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".incoming-", dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o444)
            try:
                os.link(temporary, target)
            except FileExistsError:
                self._check_existing(target, digest)
        finally:
            os.unlink(temporary)
        return digest

    def get(self, sha256: str) -> bytes:
        """Return the content of a blob after checking it against `sha256`."""
        path = self.path_for(sha256)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError as exc:
            raise NotFound(f"blob {sha256} is missing from {self.root}") from exc
        except OSError as exc:
            raise BlobError(f"blob {sha256} cannot be read: {exc.strerror}") from exc
        hasher = hashlib.sha256()
        chunks: list[bytes] = []
        with os.fdopen(fd, "rb") as handle:
            while chunk := handle.read(_READ_CHUNK):
                hasher.update(chunk)
                chunks.append(chunk)
        if hasher.hexdigest() != sha256:
            raise BlobCorrupted(f"blob {sha256} does not match its sha256")
        return b"".join(chunks)

    def _check_existing(self, path: Path, digest: str) -> None:
        if path.is_symlink() or not path.is_file():
            raise BlobCorrupted(f"blob {digest} is not a regular file")
        self.get(digest)
