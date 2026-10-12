"""Patch parsing and application (`assay.ingest.patch`), including hostile patches."""

import os
from pathlib import Path

import pytest

from assay.ingest import create_snapshot
from assay.ingest.patch import (
    PatchLimits,
    PatchPolicy,
    PatchRejected,
    apply_patch,
    check_patch_paths,
    in_scope,
    is_protected,
    parse_patch,
    prepare_patched_revision,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures" / "reentrancy" / "single_function"

SOURCE = "line 1\nline 2\nline 3\nline 4\nline 5\n"
MODIFY = b"""\
diff --git a/src/A.sol b/src/A.sol
index 1111111..2222222 100644
--- a/src/A.sol
+++ b/src/A.sol
@@ -2,3 +2,3 @@
 line 2
-line 3
+line three
 line 4
"""


def codes(data: bytes, limits: PatchLimits | None = None) -> set[str]:
    with pytest.raises(PatchRejected) as info:
        parse_patch(data, limits)
    return {problem.code for problem in info.value.problems}


def tree(tmp_path: Path, files: dict[str, str] | None = None) -> Path:
    root = tmp_path / "tree"
    for relative, content in (files if files is not None else {"src/A.sol": SOURCE}).items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    root.mkdir(exist_ok=True)
    return root


def apply_codes(root: Path, data: bytes, policy: PatchPolicy | None = None) -> set[str]:
    patch = parse_patch(data)
    before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    with pytest.raises(PatchRejected) as info:
        apply_patch(root, patch, policy=policy)
    after = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    assert after == before, "a rejected patch must leave the tree unchanged"
    return {problem.code for problem in info.value.problems}


# -- parsing and applying valid patches -------------------------------------------------------


def test_a_modification_is_parsed_and_applied(tmp_path: Path) -> None:
    patch = parse_patch(MODIFY)
    assert patch.paths == ["src/A.sol"]
    assert [(line.path, line.line, line.text) for line in patch.added_lines()] == [
        ("src/A.sol", 3, "line three")
    ]
    root = tree(tmp_path)
    apply_patch(root, patch)
    assert (root / "src/A.sol").read_text() == SOURCE.replace("line 3", "line three")


def test_a_plain_unified_diff_without_git_headers_applies(tmp_path: Path) -> None:
    data = MODIFY.split(b"\n", 2)[2].replace(b"+++ b/src/A.sol", b"+++ b/src/A.sol\t2026-01-01")
    root = tree(tmp_path)
    apply_patch(root, parse_patch(data))
    assert "line three" in (root / "src/A.sol").read_text()


def test_hunks_may_move_but_context_must_match_exactly(tmp_path: Path) -> None:
    root = tree(tmp_path, {"src/A.sol": "header\nextra\n" + SOURCE})
    apply_patch(root, parse_patch(MODIFY))
    assert (root / "src/A.sol").read_text() == "header\nextra\n" + SOURCE.replace(
        "line 3", "line three"
    )
    other = tree(tmp_path / "other", {"src/A.sol": SOURCE.replace("line 2", "line  2")})
    assert apply_codes(other, MODIFY) == {"patch_does_not_apply"}


def test_files_are_created_and_deleted(tmp_path: Path) -> None:
    data = b"""\
diff --git a/src/New.sol b/src/New.sol
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/src/New.sol
@@ -0,0 +1,2 @@
+contract New {}
+// end
diff --git a/src/A.sol b/src/A.sol
deleted file mode 100644
index 1111111..0000000
--- a/src/A.sol
+++ /dev/null
@@ -1,5 +0,0 @@
-line 1
-line 2
-line 3
-line 4
-line 5
"""
    root = tree(tmp_path)
    apply_patch(root, parse_patch(data))
    assert (root / "src/New.sol").read_text() == "contract New {}\n// end\n"
    assert not (root / "src/A.sol").exists()
    assert oct((root / "src/New.sol").stat().st_mode & 0o777) == "0o644"


def test_missing_newline_markers_are_honoured(tmp_path: Path) -> None:
    data = b"""\
--- a/src/A.sol
+++ b/src/A.sol
@@ -1 +1 @@
-old
\\ No newline at end of file
+new
\\ No newline at end of file
"""
    root = tree(tmp_path, {"src/A.sol": "old"})
    apply_patch(root, parse_patch(data))
    assert (root / "src/A.sol").read_bytes() == b"new"


@pytest.mark.parametrize("data", [b"", b"  \n\n"])
def test_an_empty_patch_changes_nothing(tmp_path: Path, data: bytes) -> None:
    patch = parse_patch(data)
    assert patch.files == ()
    root = tree(tmp_path)
    apply_patch(root, patch)
    assert (root / "src/A.sol").read_text() == SOURCE


@pytest.mark.parametrize("label", ["good", "overfit", "destructive", "regressing"])
def test_every_fixture_patch_parses_and_stays_in_scope(label: str) -> None:
    patch = parse_patch((FIXTURE / "patches" / f"{label}.diff").read_bytes())
    assert patch.paths == ["src/Vault.sol"]
    assert check_patch_paths(patch, PatchPolicy()) == ()


# -- hostile and malformed patches ------------------------------------------------------------


@pytest.mark.parametrize(
    "header",
    [
        "--- a/../outside.sol\n+++ b/../outside.sol\n",
        "--- a/src/../../outside.sol\n+++ b/src/../../outside.sol\n",
        "--- /etc/passwd\n+++ /etc/passwd\n",
        "--- a//etc/passwd\n+++ b//etc/passwd\n",
        "--- a/src\\..\\x.sol\n+++ b/src\\..\\x.sol\n",
        "--- a/src/./A.sol\n+++ b/src/./A.sol\n",
        "--- a/src/A\x1b.sol\n+++ b/src/A\x1b.sol\n",
        "diff --git a/../x b/../x\n--- a/../x\n+++ b/../x\n",
    ],
)
def test_path_traversal_is_rejected(header: str) -> None:
    data = (header + "@@ -1 +1 @@\n-a\n+b\n").encode()
    assert "path_traversal" in codes(data)


def test_traversal_in_a_rename_header_is_reported_as_traversal() -> None:
    data = b"diff --git a/src/A.sol b/src/B.sol\nrename from ../../etc/x\nrename to src/B.sol\n"
    assert {"path_traversal", "malformed_patch"} <= codes(data)


@pytest.mark.parametrize(
    "data",
    [
        b"diff --git a/src/L.sol b/src/L.sol\nnew file mode 120000\nindex 0000000..1111111\n"
        b"--- /dev/null\n+++ b/src/L.sol\n@@ -0,0 +1 @@\n+/etc/passwd\n"
        b"\\ No newline at end of file\n",
        b"diff --git a/src/A.sol b/src/A.sol\nindex 1111111..2222222 120000\n"
        b"--- a/src/A.sol\n+++ b/src/A.sol\n@@ -1 +1 @@\n-a\n+b\n",
        b"diff --git a/src/A.sol b/src/A.sol\nold mode 100644\nnew mode 120000\n",
    ],
)
def test_symlinks_are_rejected(data: bytes) -> None:
    assert "symlink" in codes(data)


@pytest.mark.parametrize(
    "data",
    [
        b"diff --git a/src/a.bin b/src/a.bin\nindex 1111111..2222222 100644\n"
        b"GIT binary patch\nliteral 3\nKcmZ?wbN~PV\n",
        b"diff --git a/src/a.bin b/src/a.bin\nindex 1111111..2222222 100644\n"
        b"Binary files a/src/a.bin and b/src/a.bin differ\n",
        MODIFY.replace(b"line three", b"line\x00three"),
        MODIFY.replace(b"line three", b"line \xff three"),
    ],
)
def test_binary_content_is_rejected(data: bytes) -> None:
    assert "binary_file" in codes(data)


def test_a_binary_target_file_is_rejected(tmp_path: Path) -> None:
    root = tree(tmp_path)
    (root / "src/A.sol").write_bytes(SOURCE.encode() + b"\x00")
    assert apply_codes(root, MODIFY) == {"binary_file"}


@pytest.mark.parametrize(
    ("data", "detail"),
    [
        (b"this is not a diff\n", "no file changes"),
        (b"--- a/src/A.sol\n+++ b/src/A.sol\n@@ -1,2 +1,2 @@\n-a\n+b\n", "line counts"),
        (b"--- a/src/A.sol\n+++ b/src/A.sol\n@@ bogus @@\n", "bad hunk header"),
        (b'--- "a/src/A.sol"\n+++ "b/src/A.sol"\n@@ -1 +1 @@\n-a\n+b\n', "quoted"),
        (b"--- src/A.sol\n+++ src/A.sol\n@@ -1 +1 @@\n-a\n+b\n", "does not start with"),
        (b"--- a/src/A.sol\n+++ b/src/B.sol\n@@ -1 +1 @@\n-a\n+b\n", "renames"),
        (b"diff --git a/src/A.sol b/src/A.sol\nold mode 100644\nnew mode 100755\n", "mode"),
        (MODIFY + MODIFY, "more than once"),
        (b"@@ -1 +1 @@\n-a\n+b\n", "outside a file section"),
        (
            b"--- /dev/null\n+++ b/src/a\n@@ -0,0 +1 @@\n+x\n"
            b"--- /dev/null\n+++ b/src/a/b.sol\n@@ -0,0 +1 @@\n+y\n",
            "both a file and a directory",
        ),
    ],
)
def test_malformed_patches_are_rejected(data: bytes, detail: str) -> None:
    with pytest.raises(PatchRejected) as info:
        parse_patch(data)
    problems = info.value.problems
    assert {problem.code for problem in problems} == {"malformed_patch"}
    assert any(detail in problem.detail for problem in problems), problems


def test_size_limits_are_enforced() -> None:
    assert codes(MODIFY, PatchLimits(max_bytes=10)) == {"patch_too_large"}
    assert codes(MODIFY, PatchLimits(max_changed_lines=1)) == {"patch_too_large"}
    two_files = MODIFY + MODIFY.replace(b"src/A.sol", b"src/B.sol")
    assert codes(two_files, PatchLimits(max_files=1)) == {"patch_too_large"}


# -- path policy ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "code"),
    [
        ("test/Vault.t.sol", "protected_path_modified"),
        ("Test/Vault.t.sol", "protected_path_modified"),
        ("POC/Exploit.t.sol", "protected_path_modified"),
        ("solidity/AssayExploit.sol", "protected_path_modified"),
        ("assay/AssayExploit.sol", "protected_path_modified"),
        ("foundry.toml", "protected_path_modified"),
        ("Remappings.txt", "protected_path_modified"),
        ("expected.json", "protected_path_modified"),
        ("script/Deploy.s.sol", "out_of_scope"),
        ("lib/forge-std/src/Test.sol", "out_of_scope"),
        ("SRC/Vault.sol", "out_of_scope"),
        ("README.md", "out_of_scope"),
    ],
)
def test_protected_and_out_of_scope_paths_are_refused(tmp_path: Path, path: str, code: str) -> None:
    data = MODIFY.replace(b"src/A.sol", path.encode())
    patch = parse_patch(data)
    assert [problem.code for problem in check_patch_paths(patch, PatchPolicy())] == [code]
    root = tree(tmp_path, {"src/A.sol": SOURCE, path: SOURCE})
    assert apply_codes(root, data) == {code}


def test_policy_helpers() -> None:
    policy = PatchPolicy(scope=("src", "contracts/core"), protected=("test", "src/poc"))
    assert in_scope("src/A.sol", policy)
    assert in_scope("contracts/core/B.sol", policy)
    assert not in_scope("src", policy)
    assert not in_scope("contracts/C.sol", policy)
    assert is_protected("src/poc/X.sol", policy)
    assert is_protected("TEST", policy)
    assert not is_protected("tests/x", policy)
    composed = PatchPolicy(protected=("caf\u00e9",))
    assert is_protected("CAFE\u0301/x.sol", composed)


# -- the tree is never left through the filesystem --------------------------------------------


def test_a_symlinked_directory_in_the_tree_is_refused(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "A.sol").write_text(SOURCE)
    root = tmp_path / "tree"
    root.mkdir()
    (root / "src").symlink_to(outside, target_is_directory=True)
    assert apply_codes(root, MODIFY) == {"symlink"}
    assert (outside / "A.sol").read_text() == SOURCE


def test_a_symlinked_file_in_the_tree_is_refused(tmp_path: Path) -> None:
    outside = tmp_path / "outside.sol"
    outside.write_text(SOURCE)
    root = tree(tmp_path, {"src/B.sol": ""})
    os.symlink(outside, root / "src" / "A.sol")
    assert apply_codes(root, MODIFY) == {"symlink"}
    assert outside.read_text() == SOURCE


def test_creating_an_existing_file_or_deleting_a_changed_one_does_not_apply(
    tmp_path: Path,
) -> None:
    create = b"--- /dev/null\n+++ b/src/A.sol\n@@ -0,0 +1 @@\n+x\n"
    assert apply_codes(tree(tmp_path / "a"), create) == {"patch_does_not_apply"}
    delete = b"--- a/src/A.sol\n+++ /dev/null\n@@ -1 +0,0 @@\n-line 1\n"
    assert apply_codes(tree(tmp_path / "b"), delete) == {"patch_does_not_apply"}
    missing = MODIFY.replace(b"src/A.sol", b"src/Missing.sol")
    assert apply_codes(tree(tmp_path / "c"), missing) == {"patch_does_not_apply"}


def test_nothing_is_written_when_a_later_file_does_not_apply(tmp_path: Path) -> None:
    data = MODIFY + MODIFY.replace(b"src/A.sol", b"src/B.sol")
    root = tree(tmp_path, {"src/A.sol": SOURCE, "src/B.sol": "other\n"})
    assert apply_codes(root, data) == {"patch_does_not_apply"}


# -- the patched revision ---------------------------------------------------------------------


def test_the_patched_revision_is_a_new_snapshot(tmp_path: Path) -> None:
    base = create_snapshot(FIXTURE, tmp_path / "base")
    data = (FIXTURE / "patches" / "good.diff").read_bytes()
    prepared = prepare_patched_revision(base, data, tmp_path / "patched")
    assert prepared.problems == ()
    assert prepared.snapshot is not None
    assert prepared.snapshot.tree_sha256 != base.tree_sha256
    patched = (prepared.snapshot.tree_dir / "src" / "Vault.sol").read_text()
    assert patched.index("balanceOf[msg.sender] = available") < patched.index(".call{value")
    assert (base.tree_dir / "src" / "Vault.sol").read_text() == (
        FIXTURE / "src" / "Vault.sol"
    ).read_text()


def test_an_empty_patch_gives_the_same_tree(tmp_path: Path) -> None:
    base = create_snapshot(FIXTURE, tmp_path / "base")
    prepared = prepare_patched_revision(base, b"", tmp_path / "patched")
    assert prepared.snapshot is not None
    assert prepared.snapshot.tree_sha256 == base.tree_sha256


def test_a_patch_that_adds_inline_config_is_rejected_at_ingest(tmp_path: Path) -> None:
    base = create_snapshot(FIXTURE, tmp_path / "base")
    data = b"""\
--- a/src/Vault.sol
+++ b/src/Vault.sol
@@ -4,2 +4,3 @@

+/// forge-config: default.fuzz.runs = 1
 /// @title Vault
"""
    prepared = prepare_patched_revision(base, data, tmp_path / "patched")
    assert prepared.snapshot is None
    assert [problem.code for problem in prepared.problems] == ["ingest_rejected"]


def test_rejections_keep_the_patch_digest(tmp_path: Path) -> None:
    base = create_snapshot(FIXTURE, tmp_path / "base")
    data = b"--- a/../x\n+++ b/../x\n@@ -1 +1 @@\n-a\n+b\n"
    prepared = prepare_patched_revision(base, data, tmp_path / "patched")
    assert prepared.patch is None
    assert prepared.snapshot is None
    assert not (tmp_path / "patched").exists()
    assert len(prepared.sha256) == 64
