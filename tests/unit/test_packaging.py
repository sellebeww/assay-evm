"""Packaging metadata: one version source, typed marker, and files the build lists exist."""

import tomllib
from pathlib import Path

import pytest

from assay import __version__
from assay.oracles.runtree import default_harness_dir
from assay.report.bundle import default_versions_lock

ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_the_version_has_one_source() -> None:
    project = PYPROJECT["project"]
    assert "version" not in project
    assert "version" in project["dynamic"]
    assert PYPROJECT["tool"]["hatch"]["version"]["path"] == "src/assay/__init__.py"
    assert __version__ in (ROOT / "src/assay/__init__.py").read_text(encoding="utf-8")


def test_the_metadata_is_complete() -> None:
    project = PYPROJECT["project"]
    assert project["name"] == "assay-evm"
    for key in ("description", "readme", "license", "keywords", "classifiers", "requires-python"):
        assert project[key], key
    assert project["scripts"] == {"assay": "assay.cli.main:app"}
    assert (ROOT / project["readme"]).is_file()
    for pattern in project["license-files"]:
        assert (ROOT / pattern).is_file()


def test_the_package_is_marked_typed() -> None:
    assert (ROOT / "src" / "assay" / "py.typed").is_file()


def test_everything_the_build_lists_exists() -> None:
    sdist = PYPROJECT["tool"]["hatch"]["build"]["targets"]["sdist"]["only-include"]
    for entry in sdist:
        assert (ROOT / entry).exists(), entry
    forced = PYPROJECT["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    for source in forced:
        assert (ROOT / source).exists(), source


def test_the_wheel_carries_what_the_commands_read() -> None:
    forced = PYPROJECT["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    assert forced["solidity"] == "assay/_data/solidity"
    assert forced["docker/runner/versions.lock"] == "assay/_data/versions.lock"


def test_a_checkout_reads_the_files_next_to_the_sources() -> None:
    assert default_harness_dir() == ROOT / "solidity"
    assert default_versions_lock() == ROOT / "docker" / "runner" / "versions.lock"


@pytest.mark.parametrize("ignored", ["dist/", "demo-out/", "build/", ".assay/"])
def test_build_and_demo_output_are_ignored_by_git(ignored: str) -> None:
    lines = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ignored in lines
