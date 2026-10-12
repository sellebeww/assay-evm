"""Splits: reading `bench/splits/<name>.json`, the expected outcomes of their fixtures and the
hash of the fixture files."""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from pydantic import ValidationError

from assay.bench.models import PATCH_LABELS, Split, SplitName

SPLITS_DIR: Final = Path("bench") / "splits"


class SplitError(Exception):
    """A split file or one of its fixtures is missing or malformed."""


@dataclass(frozen=True, slots=True)
class Expectation:
    fixture: str
    label: str
    verdict: str
    reason: str | None


def load_split(root: Path, name: str) -> Split:
    path = root / SPLITS_DIR / f"{name}.json"
    try:
        split = Split.model_validate_json(path.read_bytes())
    except (OSError, ValueError, ValidationError) as exc:
        raise SplitError(f"split file {path.name} cannot be read: {exc}") from exc
    if split.name != name:
        raise SplitError(f"split file {path.name} names the split {split.name!r}")
    if len(set(split.fixtures)) != len(split.fixtures):
        raise SplitError(f"split {name} lists a fixture twice")
    for fixture in split.fixtures:
        directory = root / split.root / fixture
        if not (directory / "expected.json").is_file():
            raise SplitError(f"split {name}: {fixture} has no expected.json")
    return split


def split_file_sha256(root: Path, name: SplitName) -> str:
    return hashlib.sha256((root / SPLITS_DIR / f"{name}.json").read_bytes()).hexdigest()


def fixtures_tree_sha256(root: Path, split: Split) -> str:
    """sha256 over the paths and contents of every file of the split's fixtures."""
    digest = hashlib.sha256(b"assay-bench-fixtures-v1\n")
    for fixture in sorted(split.fixtures):
        base = root / split.root / fixture
        for item in sorted(base.rglob("*")):
            if item.is_symlink():
                raise SplitError(f"a symbolic link in fixture {fixture}")
            if item.is_file() and item.name != ".DS_Store" and "__pycache__" not in item.parts:
                relative = f"{fixture}/{item.relative_to(base).as_posix()}"
                content = hashlib.sha256(item.read_bytes()).hexdigest()
                digest.update(f"{relative}\0{content}\n".encode())
    return digest.hexdigest()


def load_expectations(root: Path, split: Split) -> list[Expectation]:
    """The expected verdict and reason of every patch of the split, in split order."""
    found: list[Expectation] = []
    for fixture in split.fixtures:
        path = root / split.root / fixture / "expected.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            variants = data["variants"]
            for label in PATCH_LABELS:
                entry = variants[label]
                reason = entry.get("reason")
                if entry["verdict"] not in ("VERIFIED_WITHIN_BOUNDS", "REJECTED"):
                    raise ValueError(f"unknown verdict for {label}")
                if reason is not None and not isinstance(reason, str):
                    raise ValueError(f"reason of {label} is not a string")
                found.append(Expectation(fixture, label, entry["verdict"], reason))
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            raise SplitError(f"{fixture}/expected.json cannot be used: {exc}") from exc
    return found
