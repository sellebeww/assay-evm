"""Run trees of the oracles (ADR 0011) and the shared harness."""

import os
from pathlib import Path

import pytest

from assay.ingest import create_snapshot
from assay.ingest.config import DYNAMIC_TEST_LINKING_OFF, safe_foundry_toml
from assay.oracles.runtree import (
    HarnessUnavailable,
    RunTreeError,
    build_poc_tree,
    build_symbolic_tree,
    default_harness_dir,
    load_harness,
    symbolic_paths,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures" / "reentrancy" / "single_function"


def test_the_harness_is_the_repository_copy() -> None:
    assert default_harness_dir() == ROOT / "solidity"
    harness = load_harness()
    assert [name for name, _ in harness.files] == [
        "AssayCheck.sol",
        "AssayExploit.sol",
        "AssayInvariant.sol",
    ]
    for name, data in harness.files:
        assert data == (ROOT / "solidity" / name).read_bytes()
    assert load_harness() == harness


def test_a_missing_or_linked_harness_is_refused(tmp_path: Path) -> None:
    with pytest.raises(HarnessUnavailable):
        load_harness(tmp_path / "missing")
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(HarnessUnavailable):
        load_harness(empty)
    linked = tmp_path / "linked"
    linked.mkdir()
    os.symlink(ROOT / "solidity" / "AssayExploit.sol", linked / "AssayExploit.sol")
    with pytest.raises(HarnessUnavailable, match="cannot be read"):
        load_harness(linked)


def test_the_poc_tree_has_sources_poc_and_harness(tmp_path: Path) -> None:
    revision = create_snapshot(FIXTURE, tmp_path / "revision")
    poc = create_snapshot(FIXTURE / "poc", tmp_path / "poc")
    tree = build_poc_tree(revision, poc, load_harness(), tmp_path / "tree")
    assert [item.path for item in tree.snapshot.files] == [
        "assay/AssayCheck.sol",
        "assay/AssayExploit.sol",
        "assay/AssayInvariant.sol",
        "foundry.toml",
        "src/Vault.sol",
        "test/VaultReentrancy.t.sol",
        "test/VaultSolvency.t.sol",
    ]
    assert tree.scratch.is_dir()
    other = build_poc_tree(revision, poc, load_harness(), tmp_path / "other")
    assert tree.digest_outside("src") == other.digest_outside("src")
    assert tree.snapshot.tree_sha256 == other.snapshot.tree_sha256


def test_a_poc_tree_takes_a_configuration_and_generated_tests(tmp_path: Path) -> None:
    revision = create_snapshot(FIXTURE, tmp_path / "revision")
    poc = create_snapshot(FIXTURE / "poc", tmp_path / "poc")
    config = safe_foundry_toml(invariant_runs=7, invariant_depth=9)
    tree = build_poc_tree(
        revision,
        poc,
        load_harness(),
        tmp_path / "tree",
        config=config,
        extra_tests=(("AssayVariantPoC.t.sol", b"contract AssayVariantPoC {}\n"),),
    )
    assert (tree.tree / "foundry.toml").read_bytes() == config
    text = config.decode()
    assert text.endswith("runs = 7\ndepth = 9\nfail_on_revert = false\n")
    assert (tree.tree / "test" / "AssayVariantPoC.t.sol").is_file()
    for path in ("VaultReentrancy.t.sol", "../x.t.sol", "/abs.t.sol"):
        with pytest.raises(RunTreeError, match="generated test"):
            build_poc_tree(
                revision,
                poc,
                load_harness(),
                tmp_path / f"bad-{len(path)}",
                extra_tests=((path, b"x"),),
            )


@pytest.mark.parametrize(
    ("runs", "depth"), [(7, None), (None, 9), (0, 9), (7, 0), (100_001, 9), (7, 10_001)]
)
def test_invariant_bounds_are_set_together_and_checked(runs: int | None, depth: int | None) -> None:
    with pytest.raises(ValueError, match="invariant"):
        safe_foundry_toml(invariant_runs=runs, invariant_depth=depth)
    assert "runs =" not in safe_foundry_toml().decode()


def test_a_revision_without_sources_cannot_be_run(tmp_path: Path) -> None:
    project = tmp_path / "project"
    (project / "lib").mkdir(parents=True)
    (project / "lib" / "A.sol").write_text("contract A {}\n")
    revision = create_snapshot(project, tmp_path / "revision")
    poc = create_snapshot(FIXTURE / "poc", tmp_path / "poc")
    with pytest.raises(RunTreeError, match="no src/"):
        build_poc_tree(revision, poc, load_harness(), tmp_path / "tree")


def _poc_with_symbolic(tmp_path: Path) -> Path:
    poc = tmp_path / "poc-source"
    poc.mkdir()
    for item in (FIXTURE / "poc").iterdir():
        (poc / item.name).write_bytes(item.read_bytes())
    (poc / "symbolic").mkdir()
    (poc / "symbolic" / "VaultCheck.t.sol").write_bytes(b"contract VaultCheck {}\n")
    return poc


def test_the_poc_tree_leaves_the_symbolic_properties_out(tmp_path: Path) -> None:
    revision = create_snapshot(FIXTURE, tmp_path / "revision")
    plain = create_snapshot(FIXTURE / "poc", tmp_path / "plain")
    poc = create_snapshot(_poc_with_symbolic(tmp_path), tmp_path / "poc")
    assert symbolic_paths(poc) == ["symbolic/VaultCheck.t.sol"]
    assert symbolic_paths(plain) == []
    tree = build_poc_tree(revision, poc, load_harness(), tmp_path / "tree")
    reference = build_poc_tree(revision, plain, load_harness(), tmp_path / "reference")
    assert tree.snapshot.tree_sha256 == reference.snapshot.tree_sha256


def test_the_symbolic_tree_has_the_properties_and_the_baseline(tmp_path: Path) -> None:
    revision = create_snapshot(FIXTURE, tmp_path / "revision")
    baseline_source = tmp_path / "baseline-source"
    (baseline_source / "src").mkdir(parents=True)
    (baseline_source / "src" / "Vault.sol").write_bytes(b"// baseline\n")
    baseline = create_snapshot(baseline_source, tmp_path / "baseline")
    poc = create_snapshot(_poc_with_symbolic(tmp_path), tmp_path / "poc")
    tree = build_symbolic_tree(
        revision,
        baseline,
        poc,
        load_harness(),
        tmp_path / "tree",
        extra_tests=(("AssayVariantPoC.t.sol", b"contract AssayVariantPoC {}\n"),),
    )
    paths = [item.path for item in tree.snapshot.files]
    assert "baseline/Vault.sol" in paths
    assert "test/symbolic/VaultCheck.t.sol" in paths
    assert "test/VaultReentrancy.t.sol" in paths
    assert "test/AssayVariantPoC.t.sol" in paths
    assert (tree.tree / "baseline" / "Vault.sol").read_bytes() == b"// baseline\n"
    config = (tree.tree / "foundry.toml").read_text()
    assert "dynamic_test_linking = false\n\n[fuzz]" in config
    assert config.replace(DYNAMIC_TEST_LINKING_OFF, "") == safe_foundry_toml().decode()
    assert (tree.tree / "src" / "Vault.sol").read_bytes() == (
        FIXTURE / "src" / "Vault.sol"
    ).read_bytes()
    with pytest.raises(RunTreeError, match="generated test"):
        build_symbolic_tree(
            revision,
            baseline,
            poc,
            load_harness(),
            tmp_path / "again",
            extra_tests=(("symbolic/VaultCheck.t.sol", b""),),
        )
