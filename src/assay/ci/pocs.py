"""Finding the PoCs in the PoC directory of `assay ci verify`."""

from dataclasses import dataclass
from pathlib import Path


class PocDirError(Exception):
    """The PoC directory cannot be used. `rejected` is a symlink; `usage` is anything else."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True, slots=True)
class Poc:
    name: str
    path: Path


def _has_solidity(directory: Path) -> bool:
    return any(item.is_file() and not item.is_symlink() for item in directory.rglob("*.sol"))


def discover(poc_dir: Path) -> tuple[Poc, ...]:
    """The PoCs of `poc_dir`, sorted by name.

    A directory with Solidity files directly inside is one PoC (the layout of `assay verify
    --poc`). Otherwise every subdirectory that holds a Solidity file is one PoC. A symlink as the
    PoC directory or as a subdirectory is refused.
    """
    if poc_dir.is_symlink():
        raise PocDirError("rejected", "the PoC directory must not be a symlink")
    if not poc_dir.is_dir():
        raise PocDirError("usage", "the PoC directory is not a directory")
    if any(item.is_file() and item.suffix == ".sol" for item in poc_dir.iterdir()):
        return (Poc(poc_dir.resolve().name, poc_dir),)
    found: list[Poc] = []
    for item in sorted(poc_dir.iterdir(), key=lambda entry: entry.name):
        if item.is_symlink():
            raise PocDirError("rejected", f"a PoC directory entry is a symlink: {item.name!r}")
        if item.is_dir() and _has_solidity(item):
            found.append(Poc(item.name, item))
    if not found:
        raise PocDirError("usage", "the PoC directory holds no Solidity files")
    return tuple(found)
