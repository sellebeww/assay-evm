"""The oracle freeze: a hash of the paths that must not change during the benchmark.

The hash covers `src/assay/oracles/`, `solidity/` and `docker/runner/versions.lock`: the names and
the contents of their files, without caches. `bench/FROZEN_HASH` holds it from `make bench-freeze`
on; every benchmark run records the hash at run time, and the report marks held-out results only
if the two are equal (bench/PROTOCOL.md, section 5).
"""

import hashlib
import re
from pathlib import Path
from typing import Final

FROZEN_PATHS: Final = ("src/assay/oracles", "solidity", "docker/runner/versions.lock")
FROZEN_FILE: Final = Path("bench") / "FROZEN_HASH"
_SCHEME: Final = b"assay-frozen-v1\n"
_IGNORED_DIRS: Final = frozenset({"__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache"})
_IGNORED_NAMES: Final = frozenset({".DS_Store"})
_HASH: Final = re.compile(r"[0-9a-f]{64}")


class FreezeError(Exception):
    """The frozen paths cannot be hashed or the freeze file is malformed."""


def _files(path: Path) -> list[Path]:
    if path.is_symlink():
        raise FreezeError(f"a symbolic link in the frozen paths: {path.name}")
    if path.is_file():
        return [path]
    if not path.is_dir():
        raise FreezeError(f"frozen path missing: {path.name}")
    found: list[Path] = []
    for item in sorted(path.rglob("*")):
        relative = item.relative_to(path).parts
        if any(part in _IGNORED_DIRS for part in relative):
            continue
        if item.name in _IGNORED_NAMES or item.suffix == ".pyc":
            continue
        if item.is_symlink():
            raise FreezeError(f"a symbolic link in the frozen paths: {item.name}")
        if item.is_file():
            found.append(item)
    return found


def tree_hash(root: Path, frozen: tuple[str, ...] = FROZEN_PATHS) -> str:
    """sha256 over the sorted (path, content hash) pairs of the frozen paths below `root`."""
    digest = hashlib.sha256(_SCHEME)
    entries: list[tuple[str, str]] = []
    for name in frozen:
        base = root / name
        for item in _files(base):
            relative = name if item == base else f"{name}/{item.relative_to(base).as_posix()}"
            entries.append((relative, hashlib.sha256(item.read_bytes()).hexdigest()))
    for relative, content in sorted(entries):
        digest.update(f"{relative}\0{content}\n".encode())
    return digest.hexdigest()


def read_frozen(root: Path) -> str | None:
    """The hash in `bench/FROZEN_HASH`, or `None` when the oracles have not been frozen."""
    path = root / FROZEN_FILE
    try:
        text = path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError) as exc:
        raise FreezeError(f"{FROZEN_FILE.as_posix()} cannot be read: {exc}") from exc
    if _HASH.fullmatch(text) is None:
        raise FreezeError(f"{FROZEN_FILE.as_posix()} does not hold a sha256 hash")
    return text


def write_frozen(root: Path) -> str:
    """Write the current hash to `bench/FROZEN_HASH` and return it."""
    value = tree_hash(root)
    path = root / FROZEN_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value + "\n", encoding="ascii")
    return value
