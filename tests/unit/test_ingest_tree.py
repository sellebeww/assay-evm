import hashlib
import os
import random
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from assay.ingest import UnsafePathError, tree_digest, tree_sha256


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_tree(root: Path, files: dict[str, bytes]) -> Path:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return root


FILES = {
    "src/Counter.sol": b"contract Counter {}\n",
    "test/Counter.t.sol": b"contract CounterTest {}\n",
    "foundry.toml": b"[profile.default]\n",
}


def test_digest_follows_the_documented_encoding() -> None:
    entries = [("b.sol", sha(b"B")), ("a.sol", sha(b"A"))]
    expected = hashlib.sha256(
        b"a.sol\0" + sha(b"A").encode() + b"\n" + b"b.sol\0" + sha(b"B").encode() + b"\n"
    ).hexdigest()
    assert tree_digest(entries) == expected


def test_digest_of_an_empty_tree_is_the_hash_of_nothing() -> None:
    assert tree_digest([]) == sha(b"")


def test_digest_sorts_by_utf8_bytes() -> None:
    # Byte order puts "Z" (0x5a) before "a" (0x61) and "é" (0xc3 0xa9) after "z".
    entries = [("é", sha(b"3")), ("a", sha(b"2")), ("Z", sha(b"1"))]
    expected = hashlib.sha256(
        b"".join(
            name.encode() + b"\0" + digest.encode() + b"\n"
            for name, digest in [("Z", sha(b"1")), ("a", sha(b"2")), ("é", sha(b"3"))]
        )
    ).hexdigest()
    assert tree_digest(entries) == expected


@given(
    files=st.dictionaries(
        keys=st.from_regex(r"[A-Za-z0-9_.]{1,8}(/[A-Za-z0-9_]{1,8}){0,2}", fullmatch=True).filter(
            lambda p: all(part not in (".", "..") for part in p.split("/"))
        ),
        values=st.binary(max_size=32),
        max_size=20,
    ),
    seed=st.integers(),
)
def test_digest_does_not_depend_on_entry_order(files: dict[str, bytes], seed: int) -> None:
    entries = [(path, sha(content)) for path, content in files.items()]
    shuffled = list(entries)
    random.Random(seed).shuffle(shuffled)
    assert tree_digest(entries) == tree_digest(shuffled)


def test_digest_rejects_duplicates_bad_digests_and_unsafe_paths() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        tree_digest([("a", sha(b"1")), ("a", sha(b"2"))])
    with pytest.raises(ValueError, match="sha256"):
        tree_digest([("a", "ABC")])
    with pytest.raises(UnsafePathError):
        tree_digest([("../a", sha(b"1"))])


def test_same_tree_in_two_places_has_the_same_hash(tmp_path: Path) -> None:
    first = write_tree(tmp_path / "first", FILES)
    second = write_tree(tmp_path / "second", dict(reversed(list(FILES.items()))))
    assert tree_sha256(first) == tree_sha256(second)
    expected = tree_digest((path, sha(content)) for path, content in FILES.items())
    assert tree_sha256(first) == expected


def test_hash_changes_with_content_and_with_names(tmp_path: Path) -> None:
    base = tree_sha256(write_tree(tmp_path / "base", FILES))
    changed = tree_sha256(write_tree(tmp_path / "changed", {**FILES, "foundry.toml": b"x"}))
    renamed_files = {k.replace("Counter.sol", "Other.sol"): v for k, v in FILES.items()}
    renamed = tree_sha256(write_tree(tmp_path / "renamed", renamed_files))
    assert len({base, changed, renamed}) == 3


def test_hash_ignores_modes_timestamps_and_empty_directories(tmp_path: Path) -> None:
    root = write_tree(tmp_path / "tree", FILES)
    before = tree_sha256(root)
    (root / "src" / "Counter.sol").chmod(0o700)
    os.utime(root / "foundry.toml", (0, 0))
    (root / "empty").mkdir()
    assert tree_sha256(root) == before


def test_hash_refuses_symlinks_and_special_files(tmp_path: Path) -> None:
    linked = write_tree(tmp_path / "linked", FILES)
    (linked / "alias.sol").symlink_to("src/Counter.sol")
    with pytest.raises(UnsafePathError, match="symlink"):
        tree_sha256(linked)

    special = write_tree(tmp_path / "special", FILES)
    os.mkfifo(special / "pipe")
    with pytest.raises(UnsafePathError, match="special file"):
        tree_sha256(special)
