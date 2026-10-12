"""`make demo` and `make demo-overfit` against the real runner image, offline.

The cassettes in `demo/cassettes/` are found by the hash of the request. When a change alters a
prompt, the replay stops with a missing cassette (exit code 4) and this test fails until
`make demo-cassettes` records them again.
"""

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.cli.main import app

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("runner")]

ROOT = Path(__file__).resolve().parents[2]
PROJECT = ROOT / "fixtures" / "reentrancy" / "single_function"
CASSETTES = ROOT / "demo" / "cassettes"
FORBIDDEN = re.compile(r"\b(secure|safe|proven|guaranteed|unhackable)\b", re.IGNORECASE)
cli = CliRunner()


def test_the_run_demo_reaches_verified_within_bounds_from_the_shipped_cassettes(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "bundle"
    result = cli.invoke(
        app,
        [
            "run",
            str(PROJECT),
            "--class",
            "reentrancy",
            "--mode",
            "replay",
            "--cassette-dir",
            str(CASSETTES),
            "--profile",
            "quick",
            "--ledger",
            str(tmp_path / "ledger.db"),
            "--poc-dir",
            str(tmp_path / "poc"),
            "--bundle-out",
            str(bundle),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "attempt 1" in result.output
    assert "REJECTED in the loop: variant FAIL (variant_found)" in result.output
    assert "final verdict: VERIFIED_WITHIN_BOUNDS" in result.output
    assert FORBIDDEN.search(result.output) is None
    report = tmp_path / "report.html"
    made = cli.invoke(app, ["report", str(bundle), "--out", str(report)])
    assert made.exit_code == 0, made.output
    assert "VERIFIED_WITHIN_BOUNDS" in report.read_text()


def test_the_overfit_demo_is_rejected_with_a_variant_poc(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    result = cli.invoke(
        app,
        [
            "verify",
            "--base",
            str(PROJECT),
            "--patch",
            str(PROJECT / "patches" / "overfit.diff"),
            "--poc",
            str(PROJECT / "poc"),
            "--profile",
            "quick",
            "--ledger",
            str(tmp_path / "ledger.db"),
            "--bundle-out",
            str(bundle),
        ],
    )
    assert result.exit_code == 1, result.output
    assert "final verdict: REJECTED" in result.output
    assert "variant     FAIL     variant_found" in result.output
    assert "behavior    PASS" in result.output
    assert (bundle / "evidence" / "variant" / "variant_poc.t.sol").is_file()
