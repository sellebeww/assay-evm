import os
import stat
from pathlib import Path

import pytest

from assay.ingest import (
    IngestError,
    IngestLimits,
    Snapshot,
    create_snapshot,
    safe_foundry_toml,
    tree_digest,
    tree_sha256,
)

HOSTILE_CONFIG = b"""\
[profile.default]
ffi = true
fs_permissions = [{ access = "read-write", path = "/" }]
solc = "/tmp/evil-solc"
eth_rpc_url = "http://127.0.0.1:8545"
"""


def write(root: Path, relative: str, content: bytes = b"x") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    write(root, "src/Counter.sol", b"contract Counter {}\n")
    write(root, "test/Counter.t.sol", b"contract CounterTest {}\n")
    write(root, "foundry.toml", HOSTILE_CONFIG)
    return root


def snap(project: Path, dest: Path, limits: IngestLimits | None = None) -> Snapshot:
    return create_snapshot(project, dest, limits)


def reject(project: Path, dest: Path, code: str, limits: IngestLimits | None = None) -> IngestError:
    with pytest.raises(IngestError) as info:
        create_snapshot(project, dest, limits)
    assert info.value.code == code
    assert not dest.exists(), "a rejected snapshot must leave nothing behind"
    return info.value


def test_sources_are_copied_and_the_config_is_replaced(project: Path, tmp_path: Path) -> None:
    result = snap(project, tmp_path / "snap")

    assert [f.path for f in result.files] == [
        "foundry.toml",
        "src/Counter.sol",
        "test/Counter.t.sol",
    ]
    assert (result.tree_dir / "foundry.toml").read_bytes() == safe_foundry_toml()
    assert (result.tree_dir / "src/Counter.sol").read_bytes() == b"contract Counter {}\n"
    assert (result.evidence_dir / "foundry.toml").read_bytes() == HOSTILE_CONFIG
    assert [f.path for f in result.project_config] == ["foundry.toml"]
    assert [(s.path, s.reason) for s in result.skipped] == [("foundry.toml", "project_config")]


def test_tree_hash_describes_the_written_tree(project: Path, tmp_path: Path) -> None:
    result = snap(project, tmp_path / "snap")
    assert result.tree_sha256 == tree_sha256(result.tree_dir)
    assert result.tree_sha256 == tree_digest((f.path, f.sha256) for f in result.files)


def test_tree_hash_is_stable_and_ignores_the_project_config(project: Path, tmp_path: Path) -> None:
    other = tmp_path / "elsewhere" / "copy"
    write(other, "test/Counter.t.sol", b"contract CounterTest {}\n")
    write(other, "src/Counter.sol", b"contract Counter {}\n")
    write(other, "foundry.toml", b"[profile.default]\n")

    first = snap(project, tmp_path / "first")
    second = snap(other, tmp_path / "second")
    assert first.tree_sha256 == second.tree_sha256
    assert first.project_config != second.project_config


def test_tree_hash_changes_with_source_content(project: Path, tmp_path: Path) -> None:
    before = snap(project, tmp_path / "before").tree_sha256
    write(project, "src/Counter.sol", b"contract Counter { uint256 x; }\n")
    assert snap(project, tmp_path / "after").tree_sha256 != before


def test_excluded_entries_are_skipped(project: Path, tmp_path: Path) -> None:
    for relative in [
        ".git/config",
        "lib/dep/.git",
        "node_modules/pkg/index.js",
        "lib/dep/node_modules/x.js",
        ".assay/ledger.db",
        "out/Counter.sol/Counter.json",
        "cache/solidity-files-cache.json",
        ".env",
        ".env.local",
        ".envrc",
        "script/.env.production",
        "keys/deployer.pem",
        "keys/signer.KEY",
        "id_ed25519",
        "home/id_rsa.pub",
        "remappings.txt",
    ]:
        write(project, relative)
    kept = ["src/out/Kept.sol", "lib/cache/Kept.sol", "lib/dep/out/Kept.sol"]
    for relative in kept:
        write(project, relative)

    result = snap(project, tmp_path / "snap")
    paths = {f.path for f in result.files}
    assert set(kept) <= paths
    assert paths == {"foundry.toml", "src/Counter.sol", "test/Counter.t.sol", *kept}
    assert {(s.path, s.reason) for s in result.skipped} == {
        (".assay", "assay_data"),
        (".env", "secret"),
        (".env.local", "secret"),
        (".envrc", "secret"),
        (".git", "vcs_metadata"),
        ("cache", "build_output"),
        ("foundry.toml", "project_config"),
        ("home/id_rsa.pub", "secret"),
        ("id_ed25519", "secret"),
        ("keys/deployer.pem", "secret"),
        ("keys/signer.KEY", "secret"),
        ("lib/dep/.git", "vcs_metadata"),
        ("lib/dep/node_modules", "dependencies"),
        ("node_modules", "dependencies"),
        ("out", "build_output"),
        ("remappings.txt", "project_config"),
        ("script/.env.production", "secret"),
    }
    assert [s.path for s in result.skipped] == sorted(s.path for s in result.skipped)


def test_files_containing_a_private_key_are_skipped(project: Path, tmp_path: Path) -> None:
    write(project, "notes/deploy.txt", b"key:\n-----BEGIN EC PRIVATE KEY-----\nMHcC\n")
    result = snap(project, tmp_path / "snap")
    assert "notes/deploy.txt" not in {f.path for f in result.files}
    assert not (result.tree_dir / "notes" / "deploy.txt").exists()
    assert ("notes/deploy.txt", "secret") in {(s.path, s.reason) for s in result.skipped}


def test_remappings_txt_is_kept_only_as_evidence(project: Path, tmp_path: Path) -> None:
    write(project, "remappings.txt", b"forge-std/=/etc/\n")
    result = snap(project, tmp_path / "snap")
    assert not (result.tree_dir / "remappings.txt").exists()
    assert (result.evidence_dir / "remappings.txt").read_bytes() == b"forge-std/=/etc/\n"
    assert [f.path for f in result.project_config] == ["foundry.toml", "remappings.txt"]


@pytest.mark.parametrize(
    ("name", "content"),
    [
        (
            "slither.config.json",
            b'{"detectors_to_exclude": "reentrancy-eth", "filter_paths": "src"}',
        ),
        ("Slither.Config.JSON", b'{"compile_force_framework": "solc", "solc": "./evil"}'),
        ("aderyn.toml", b'version = 1\nexclude = ["src/"]\n[env]\nXDG_DATA_HOME = "evil"\n'),
        ("ADERYN.toml", b"version = 1\n"),
        ("halmos.toml", b"[global]\nffi = true\nloop = 1\n"),
        ("Halmos.TOML", b'[global]\nsolver-command = "./evil"\n'),
    ],
)
def test_analyzer_config_is_kept_only_as_evidence(
    project: Path, tmp_path: Path, name: str, content: bytes
) -> None:
    write(project, name, content)
    result = snap(project, tmp_path / "snap")
    assert not (result.tree_dir / name).exists()
    assert name.lower() not in {entry.name.lower() for entry in result.tree_dir.iterdir()}
    assert (result.evidence_dir / name).read_bytes() == content
    assert (name, "project_config") in {(s.path, s.reason) for s in result.skipped}


def test_analyzer_config_below_the_root_is_an_ordinary_file(project: Path, tmp_path: Path) -> None:
    write(project, "docs/slither.config.json", b"{}")
    result = snap(project, tmp_path / "snap")
    assert (result.tree_dir / "docs" / "slither.config.json").read_bytes() == b"{}"


def test_project_config_in_another_letter_case_is_kept_only_as_evidence(
    project: Path, tmp_path: Path
) -> None:
    # On a case-insensitive filesystem (macOS, shared into Docker Desktop) forge opens
    # `Remappings.txt` when it looks for `remappings.txt`.
    (project / "foundry.toml").unlink()
    write(project, "Foundry.TOML", HOSTILE_CONFIG)
    write(project, "REMAPPINGS.txt", b"forge-std/=lib/fake/\n")
    result = snap(project, tmp_path / "snap")

    assert sorted(entry.name for entry in result.tree_dir.iterdir()) == [
        "foundry.toml",
        "src",
        "test",
    ]
    assert (result.tree_dir / "foundry.toml").read_bytes() == safe_foundry_toml()
    assert [f.path for f in result.project_config] == ["Foundry.TOML", "REMAPPINGS.txt"]
    assert {(s.path, s.reason) for s in result.skipped} >= {
        ("Foundry.TOML", "project_config"),
        ("REMAPPINGS.txt", "project_config"),
    }


def test_symlink_to_project_config_in_another_letter_case_is_rejected(
    project: Path, tmp_path: Path
) -> None:
    write(project, "Remappings.txt", b"forge-std/=lib/fake/\n")
    (project / "src" / "Link.txt").symlink_to("../Remappings.txt")
    reject(project, tmp_path / "snap", "symlink_to_excluded_path")


@pytest.mark.parametrize(
    "target",
    [
        "/etc/hosts",
        "../../outside.sol",
        "../" * 40 + "etc/hosts",
        "../../missing-outside.sol",
        "/nonexistent/target",
    ],
)
def test_symlink_pointing_outside_the_tree_is_rejected(
    project: Path, tmp_path: Path, target: str
) -> None:
    write(tmp_path, "outside.sol", b"contract Outside {}\n")
    (project / "src" / "Link.sol").symlink_to(target)
    reject(project, tmp_path / "snap", "symlink_outside_tree")


def test_symlinked_project_config_outside_the_tree_is_rejected(
    project: Path, tmp_path: Path
) -> None:
    (project / "foundry.toml").unlink()
    (project / "foundry.toml").symlink_to("/etc/hosts")
    reject(project, tmp_path / "snap", "symlink_outside_tree")


def test_skipped_symlink_is_never_followed(project: Path, tmp_path: Path) -> None:
    (project / ".env").symlink_to("/etc/hosts")
    result = snap(project, tmp_path / "snap")
    assert (".env", "secret") in {(s.path, s.reason) for s in result.skipped}


def test_symlink_inside_the_tree_is_copied_as_a_regular_file(project: Path, tmp_path: Path) -> None:
    (project / "src" / "Alias.sol").symlink_to("Counter.sol")
    result = snap(project, tmp_path / "snap")
    alias = result.tree_dir / "src" / "Alias.sol"
    assert not alias.is_symlink()
    assert alias.read_bytes() == b"contract Counter {}\n"
    tree_sha256(result.tree_dir)  # raises if the snapshot contained a symlink


@pytest.mark.parametrize("target", ["../src", "..", "."])
def test_directory_symlink_is_rejected(project: Path, tmp_path: Path, target: str) -> None:
    (project / "test" / "linked").symlink_to(target)
    reject(project, tmp_path / "snap", "symlink_to_directory")


def test_broken_and_looping_symlinks_are_rejected(project: Path, tmp_path: Path) -> None:
    (project / "src" / "Missing.sol").symlink_to("Nowhere.sol")
    reject(project, tmp_path / "snap", "symlink_unresolvable")

    (project / "src" / "Missing.sol").unlink()
    (project / "src" / "A.sol").symlink_to("B.sol")
    (project / "src" / "B.sol").symlink_to("A.sol")
    reject(project, tmp_path / "snap", "symlink_unresolvable")


def test_symlink_into_an_excluded_path_is_rejected(project: Path, tmp_path: Path) -> None:
    write(project, ".env", b"ASSAY_LLM_API_KEY=secret\n")
    (project / "src" / "Leak.sol").symlink_to("../.env")
    reject(project, tmp_path / "snap", "symlink_to_excluded_path")


def test_special_files_are_rejected(project: Path, tmp_path: Path) -> None:
    os.mkfifo(project / "src" / "pipe")
    reject(project, tmp_path / "snap", "special_file")


@pytest.mark.parametrize(
    "comment",
    [
        b'/// forge-config: default.fs_permissions = [{ access = "read", path = "/" }]',
        b"/** FORGE-CONFIG: default.fuzz.runs = 1 */",
        b"// forge-config default.ffi = true",
    ],
)
def test_inline_foundry_config_is_rejected(project: Path, tmp_path: Path, comment: bytes) -> None:
    write(project, "test/Inline.t.sol", comment + b"\ncontract InlineTest {}\n")
    error = reject(project, tmp_path / "snap", "inline_config")
    assert error.path == "test/Inline.t.sol"


def test_inline_config_text_outside_solidity_files_is_accepted(
    project: Path, tmp_path: Path
) -> None:
    write(project, "README.md", b"This project uses no forge-config comments.\n")
    assert "README.md" in {f.path for f in snap(project, tmp_path / "snap").files}


@pytest.mark.parametrize(
    ("limits", "code"),
    [
        (IngestLimits(max_files=3), "too_many_files"),
        (IngestLimits(max_directories=1), "too_many_directories"),
        (IngestLimits(max_file_bytes=20), "file_too_large"),
        (IngestLimits(max_total_bytes=60), "tree_too_large"),
    ],
)
def test_limits_are_enforced_before_anything_is_written(
    project: Path, tmp_path: Path, limits: IngestLimits, code: str
) -> None:
    write(project, "src/Extra.sol", b"contract Extra {}\n")
    reject(project, tmp_path / "snap", code, limits)


def test_the_destination_must_not_exist(project: Path, tmp_path: Path) -> None:
    (tmp_path / "snap").mkdir()
    with pytest.raises(FileExistsError):
        create_snapshot(project, tmp_path / "snap")


def test_source_must_be_a_directory(tmp_path: Path) -> None:
    source = write(tmp_path, "file.sol")
    reject(source, tmp_path / "snap", "not_a_directory")


def test_modes_are_normalized(project: Path, tmp_path: Path) -> None:
    (project / "src" / "Counter.sol").chmod(0o755)
    (project / "test" / "Counter.t.sol").chmod(0o600)
    result = snap(project, tmp_path / "snap")
    for path in result.tree_dir.rglob("*"):
        expected = 0o755 if path.is_dir() else 0o644
        assert stat.S_IMODE(path.stat().st_mode) == expected, path


def test_serialized_snapshot_contains_no_host_paths(project: Path, tmp_path: Path) -> None:
    result = snap(project, tmp_path / "snap")
    serialized = result.model_dump_json()
    assert str(tmp_path) not in serialized
    assert str(tmp_path.resolve()) not in serialized
    assert "tree_dir" not in result.model_dump()
