"""Determinism: the same project gives byte-identical normalized results on every run.

Each run uses a fresh snapshot in a different directory and a fresh scratch directory, so host
paths and leftover build output cannot make the results agree by accident.
"""

import hashlib
import json
import os
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.analyzers import foundry
from assay.cli.main import app
from assay.ingest import Snapshot
from assay.ledger import Ledger
from assay.orchestrator.verify import BundleRequest, VerifyRequest, run_verification
from assay.report.bundle import (
    Environment,
    Sanitizer,
    environment,
    read_versions_lock,
    without_timing,
)
from assay.sandbox import SandboxRunner, make_scratch_dir

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("runner")]

SnapshotOf = Callable[[Path], Snapshot]

RUNS = 3


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# The probe project covers fuzz, table and invariant tests, the kinds that depend on the seed.
@pytest.mark.parametrize("project", ["smoke", "forge/probe"])
def test_normalized_results_are_byte_identical(
    project: str, tmp_path: Path, runner: SandboxRunner, snapshot_of: SnapshotOf, data_dir: Path
) -> None:
    documents = []
    for index in range(RUNS):
        snapshot = snapshot_of(data_dir / project)
        scratch_parent = tmp_path / f"run-{index}"
        scratch_parent.mkdir()
        run = foundry.test(runner, snapshot.tree_dir, scratch_dir=make_scratch_dir(scratch_parent))
        payload = {"tree_sha256": snapshot.tree_sha256, **run.model_dump(mode="json")}
        documents.append(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True))

    assert len({sha256(document) for document in documents}) == 1
    assert json.loads(documents[0])["suites"], "the run produced no results"
    for host_detail in (str(tmp_path), str(data_dir), os.path.expanduser("~"), "duration"):
        assert host_detail not in documents[0]


def test_cli_output_of_the_smoke_project_is_byte_identical(
    snapshot_of: SnapshotOf, data_dir: Path
) -> None:
    cli = CliRunner()
    results = [cli.invoke(app, ["dev", "forge-test", str(data_dir / "smoke")]) for _ in range(RUNS)]

    for result in results:
        assert result.exit_code == 0, result.stderr
    assert len({sha256(result.stdout) for result in results}) == 1
    payload = json.loads(results[0].stdout)
    assert payload["tree_sha256"] == snapshot_of(data_dir / "smoke").tree_sha256
    assert payload["summary"] == {"passed": 1, "failed": 0, "skipped": 0}
    for host_detail in (str(data_dir), os.path.expanduser("~"), "duration"):
        assert host_detail not in results[0].stdout


def test_two_verifications_give_byte_identical_manifests(tmp_path: Path) -> None:
    """The overfit patch exercises every oracle and a counterexample; each run uses its own
    ledger, working directory and bundle directory. Only the durations in `timing` may differ
    (ADR 0017)."""
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "reentrancy" / "single_function"
    cli = CliRunner()
    manifests = []
    for index in range(2):
        run_dir = tmp_path / f"run-{index}"
        run_dir.mkdir()
        bundle = run_dir / f"bundle-{index}"
        result = cli.invoke(
            app,
            [
                "verify",
                "--base",
                str(fixture),
                "--patch",
                str(fixture / "patches" / "overfit.diff"),
                "--poc",
                str(fixture / "poc"),
                "--ledger",
                str(run_dir / "ledger.db"),
                "--bundle-out",
                str(bundle),
            ],
        )
        assert result.exit_code == 1, result.output
        manifests.append((bundle / "manifest.json").read_bytes())

    assert without_timing(manifests[0]) == without_timing(manifests[1])
    for manifest in manifests:
        timing = json.loads(manifest)["timing"]
        assert set(timing) == {"total_s", "oracles", "variant", "symbolic"}
        assert timing["symbolic"] is None
    text = manifests[0].decode("ascii")
    for host_detail in (str(tmp_path), os.path.realpath(tmp_path), os.path.expanduser("~")):
        assert host_detail not in text
    assert '"final_verdict": "REJECTED"' in text


def test_concurrent_verifications_give_byte_identical_manifests(
    tmp_path: Path, runner: SandboxRunner
) -> None:
    """Verifications that run at the same time compete for the CPUs; with several fuzz workers
    the reported fuzz figures depended on scheduling (ADR 0014)."""
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "reentrancy" / "single_function"
    versions_lock = read_versions_lock()

    def record_environment() -> Environment:
        return environment(runner.image_id(), runner.image_labels(), versions_lock)

    def verify(index: int) -> bytes:
        run_dir = tmp_path / f"concurrent-{index}"
        work = run_dir / "work"
        work.mkdir(parents=True)
        with Ledger.open(run_dir / "ledger.db") as ledger:
            run_verification(
                VerifyRequest(
                    base=fixture,
                    patch=fixture / "patches" / "overfit.diff",
                    poc=fixture / "poc",
                ),
                runner=runner,
                ledger=ledger,
                work_dir=work,
                bundle=BundleRequest(
                    dest=run_dir / "bundle",
                    environment=record_environment,
                    sanitizer=Sanitizer([(run_dir, "<run>")]),
                ),
            )
        return (run_dir / "bundle" / "manifest.json").read_bytes()

    with ThreadPoolExecutor(3) as pool:
        manifests = list(pool.map(verify, range(3)))

    assert len({without_timing(manifest) for manifest in manifests}) == 1
    assert '"final_verdict": "REJECTED"' in manifests[0].decode("ascii")
