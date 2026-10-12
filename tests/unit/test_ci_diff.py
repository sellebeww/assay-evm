"""The diff of `assay ci verify`: scope filter, binary files, symlinks, renames, traversal."""

import os
from pathlib import Path

import pytest
from ci_support import VAULT, commit, git, init_repo, write

from assay.ci import gitdiff
from assay.ci.gitdiff import DiffError, changed_under, export_tree, scoped_diff


def repo_with_vault(tmp_path: Path) -> tuple[Path, str]:
    repo = init_repo(tmp_path / "repo")
    write(repo, "src/Vault.sol", VAULT)
    write(repo, "test/Vault.t.sol", "contract T {}\n")
    write(repo, "foundry.toml", "[profile.default]\n")
    return repo, commit(repo, "base")


def expect(kind: str, project: Path, base: str, head: str = "HEAD", scope: str = "src") -> str:
    with pytest.raises(DiffError) as caught:
        scoped_diff(project, base, head, scope)
    assert caught.value.kind == kind
    return str(caught.value)


def test_only_the_scope_is_in_the_patch(tmp_path: Path) -> None:
    repo, base = repo_with_vault(tmp_path)
    write(repo, "src/Vault.sol", VAULT.replace("total;", "total;\n    uint256 public extra;"))
    write(repo, "test/Vault.t.sol", "contract T { uint256 x; }\n")
    write(repo, "README.md", "changed\n")
    commit(repo)
    diff = scoped_diff(repo, base, "HEAD")
    assert [(item.status, item.path) for item in diff.changes] == [("M", "src/Vault.sol")]
    text = diff.patch.decode()
    assert "--- a/src/Vault.sol" in text
    assert "+++ b/src/Vault.sol" in text
    assert "test/" not in text
    assert "README" not in text
    assert set(diff.outside_changes) == {"test/Vault.t.sol", "README.md"}
    assert len(diff.base_sha) == 40
    assert diff.head_sha == git(repo, "rev-parse", "HEAD")


def test_added_and_deleted_files_in_scope(tmp_path: Path) -> None:
    repo, base = repo_with_vault(tmp_path)
    write(repo, "src/Lib.sol", "contract Lib {}\n")
    (repo / "src/Vault.sol").unlink()
    commit(repo)
    diff = scoped_diff(repo, base, "HEAD")
    assert [(item.status, item.path) for item in diff.changes] == [
        ("A", "src/Lib.sol"),
        ("D", "src/Vault.sol"),
    ]


def test_no_change_in_scope_gives_an_empty_diff(tmp_path: Path) -> None:
    repo, base = repo_with_vault(tmp_path)
    write(repo, "test/Vault.t.sol", "contract T { uint256 x; }\n")
    commit(repo)
    diff = scoped_diff(repo, base, "HEAD")
    assert diff.changes == ()
    assert diff.patch == b""


def test_project_in_a_subdirectory_has_project_relative_paths(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    write(repo, "examples/demo/src/Vault.sol", VAULT)
    write(repo, "src/Other.sol", "contract O {}\n")
    base = commit(repo, "base")
    write(repo, "examples/demo/src/Vault.sol", VAULT + "// edit\n")
    write(repo, "src/Other.sol", "contract O { uint256 x; }\n")
    commit(repo)
    diff = scoped_diff(repo / "examples" / "demo", base, "HEAD")
    assert [item.path for item in diff.changes] == ["src/Vault.sol"]
    assert "--- a/src/Vault.sol" in diff.patch.decode()
    assert "Other" not in diff.patch.decode()
    assert diff.prefix == "examples/demo/"


def test_binary_file_in_scope_is_refused(tmp_path: Path) -> None:
    repo, base = repo_with_vault(tmp_path)
    write(repo, "src/blob.bin", b"\x00\x01\x02binary\x00")
    commit(repo)
    assert "binary" in expect("rejected", repo, base)


def test_binary_outside_the_scope_is_ignored(tmp_path: Path) -> None:
    repo, base = repo_with_vault(tmp_path)
    write(repo, "docs/logo.png", b"\x89PNG\x00\x00")
    commit(repo)
    assert scoped_diff(repo, base, "HEAD").changes == ()


def test_symlink_in_scope_is_refused(tmp_path: Path) -> None:
    repo, base = repo_with_vault(tmp_path)
    os.symlink("/etc/passwd", repo / "src" / "Link.sol")
    commit(repo)
    assert "symlink" in expect("rejected", repo, base)


def test_symlink_replacing_a_file_is_refused(tmp_path: Path) -> None:
    repo, base = repo_with_vault(tmp_path)
    (repo / "src/Vault.sol").unlink()
    os.symlink("../test/Vault.t.sol", repo / "src" / "Vault.sol")
    commit(repo)
    expect("rejected", repo, base)


def test_symlink_outside_the_scope_is_ignored(tmp_path: Path) -> None:
    repo, base = repo_with_vault(tmp_path)
    os.symlink("/etc/passwd", repo / "link")
    commit(repo)
    assert scoped_diff(repo, base, "HEAD").changes == ()


def test_submodule_in_scope_is_refused(tmp_path: Path) -> None:
    repo, base = repo_with_vault(tmp_path)
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{base},src/sub")
    git(repo, "commit", "-q", "-m", "submodule")
    assert "submodule" in expect("rejected", repo, base)


def test_rename_out_of_the_scope_is_refused(tmp_path: Path) -> None:
    repo, base = repo_with_vault(tmp_path)
    git(repo, "mv", "src/Vault.sol", "test/Vault.sol")
    commit(repo)
    assert "boundary" in expect("rejected", repo, base)


def test_rename_into_the_scope_is_refused(tmp_path: Path) -> None:
    repo, base = repo_with_vault(tmp_path)
    write(repo, "script/Deploy.sol", VAULT.replace("Vault", "Deploy"))
    base = commit(repo, "script")
    git(repo, "mv", "script/Deploy.sol", "src/Deploy.sol")
    commit(repo)
    assert "boundary" in expect("rejected", repo, base)


def test_rename_inside_the_scope_is_a_deletion_and_an_addition(tmp_path: Path) -> None:
    repo, base = repo_with_vault(tmp_path)
    git(repo, "mv", "src/Vault.sol", "src/Vault2.sol")
    commit(repo)
    diff = scoped_diff(repo, base, "HEAD")
    assert [(item.status, item.path) for item in diff.changes] == [
        ("D", "src/Vault.sol"),
        ("A", "src/Vault2.sol"),
    ]
    assert "rename" not in diff.patch.decode()


@pytest.mark.parametrize("scope", ["../test", "/etc", "src/../../x", "a\\b", "", "./src"])
def test_unsafe_scope_is_a_usage_error(tmp_path: Path, scope: str) -> None:
    repo, base = repo_with_vault(tmp_path)
    expect("usage", repo, base, scope=scope)


@pytest.mark.parametrize(
    "revision", ["--upload-pack=touch x", "-h", "main; touch x", "a..b", "main\nother", ""]
)
def test_revision_that_looks_like_an_option_or_range_is_refused(
    tmp_path: Path, revision: str
) -> None:
    repo, base = repo_with_vault(tmp_path)
    expect("usage", repo, revision)
    expect("usage", repo, base, head=revision)


def test_unknown_revision_is_a_usage_error(tmp_path: Path) -> None:
    repo, _ = repo_with_vault(tmp_path)
    expect("usage", repo, "no-such-branch")


def test_project_outside_a_work_tree_is_a_usage_error(tmp_path: Path) -> None:
    loose = tmp_path / "loose"
    loose.mkdir()
    expect("usage", loose, "HEAD")


@pytest.mark.parametrize(
    "path", ["src/../../x.sol", "src//x.sol", "src/./x.sol", "src/a\x01b.sol", "src/\u202eb.sol"]
)
def test_unsafe_path_in_the_listing_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    repo, base = repo_with_vault(tmp_path)
    monkeypatch.setattr(gitdiff, "_raw_entries", lambda *_a: [("A", "000000", "100644", (path,))])
    assert "path" in expect("rejected", repo, base)


def test_git_does_not_run_programs_named_by_the_repository(tmp_path: Path) -> None:
    repo, base = repo_with_vault(tmp_path)
    marker = tmp_path / "executed"
    write(repo, ".gitattributes", "*.sol diff=evil\n")
    write(repo, "src/Vault.sol", VAULT + "// edit\n")
    commit(repo)
    # The hostile settings are written after the commits, because git itself would run them.
    for key in ("diff.evil.textconv", "diff.external", "core.fsmonitor", "core.pager"):
        git(repo, "config", key, f"touch {marker} #")
    diff = scoped_diff(repo, base, "HEAD")
    assert [item.path for item in diff.changes] == ["src/Vault.sol"]
    assert not marker.exists()
    dest = tmp_path / "export"
    dest.mkdir()
    export_tree(repo, diff.base_sha, dest)
    assert not marker.exists()


def test_ignore_space_and_prefix_settings_of_the_repository_do_not_change_the_patch(
    tmp_path: Path,
) -> None:
    repo, base = repo_with_vault(tmp_path)
    git(repo, "config", "diff.noprefix", "true")
    git(repo, "config", "diff.mnemonicPrefix", "true")
    git(repo, "config", "diff.renames", "copies")
    write(repo, "src/Vault.sol", VAULT + "// edit\n")
    commit(repo)
    text = scoped_diff(repo, base, "HEAD").patch.decode()
    assert "--- a/src/Vault.sol" in text
    assert "+++ b/src/Vault.sol" in text


def test_export_writes_the_base_tree_from_blobs(tmp_path: Path) -> None:
    repo, base = repo_with_vault(tmp_path)
    write(repo, "src/Vault.sol", VAULT + "// head only\n")
    write(repo, "poc/Exploit.t.sol", "contract E {}\n")
    commit(repo)
    dest = tmp_path / "export"
    dest.mkdir()
    full = git(repo, "rev-parse", base)
    count = export_tree(repo, full, dest)
    assert count == 3
    assert (dest / "src/Vault.sol").read_text() == VAULT
    assert (dest / "foundry.toml").exists()
    assert not (dest / "poc").exists()
    assert not any(item.is_symlink() for item in dest.rglob("*"))


def test_export_uses_the_project_directory_only(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    write(repo, "examples/demo/src/Vault.sol", VAULT)
    write(repo, "src/Other.sol", "contract O {}\n")
    base = commit(repo)
    dest = tmp_path / "export"
    dest.mkdir()
    assert export_tree(repo / "examples" / "demo", base, dest) == 1
    assert [item.relative_to(dest).as_posix() for item in dest.rglob("*") if item.is_file()] == [
        "src/Vault.sol"
    ]


def test_export_refuses_a_symlink_and_skips_a_submodule(tmp_path: Path) -> None:
    repo, base = repo_with_vault(tmp_path)
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{base},lib/dep")
    git(repo, "commit", "-q", "-m", "submodule")
    skipped = git(repo, "rev-parse", "HEAD")
    dest = tmp_path / "skipped"
    dest.mkdir()
    export_tree(repo, skipped, dest)
    assert not (dest / "lib").exists()
    os.symlink("src/Vault.sol", repo / "alias.sol")
    linked = commit(repo)
    other = tmp_path / "linked"
    other.mkdir()
    with pytest.raises(DiffError) as caught:
        export_tree(repo, linked, other)
    assert caught.value.kind == "rejected"


def test_export_requires_a_full_commit_id(tmp_path: Path) -> None:
    repo, _ = repo_with_vault(tmp_path)
    dest = tmp_path / "export"
    dest.mkdir()
    with pytest.raises(DiffError) as caught:
        export_tree(repo, "HEAD", dest)
    assert caught.value.kind == "usage"


def test_changed_under_finds_changes_of_the_poc_directory(tmp_path: Path) -> None:
    repo = init_repo(tmp_path / "repo")
    write(repo, "src/Vault.sol", VAULT)
    write(repo, "poc/Exploit.t.sol", "contract E {}\n")
    base = commit(repo)
    write(repo, "src/Vault.sol", VAULT + "// edit\n")
    commit(repo)
    diff = scoped_diff(repo, base, "HEAD")
    assert not changed_under(diff, repo / "poc", repo)
    write(repo, "poc/Exploit.t.sol", "contract E { uint256 x; }\n")
    commit(repo)
    diff = scoped_diff(repo, base, "HEAD")
    assert changed_under(diff, repo / "poc", repo)
    assert not changed_under(diff, tmp_path, repo)
