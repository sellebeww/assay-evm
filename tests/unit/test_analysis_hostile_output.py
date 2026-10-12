"""Hostile analyzer output (threat T13) and paths outside the project, without Docker.

Analyzer output is untrusted input: an enormous document, deep nesting, huge strings, duplicate
keys, non-standard constants, giant integers, invalid UTF-8 or paths outside the project must
end as a structured `AnalyzerOutputError`, never as a crash, a hang or a file read outside the
scratch directory.
"""

import json
import os
import time
from pathlib import Path

import pytest

from assay.analysis import Aderyn, AnalyzerOutputError, OutputLimits, Slither, load_json
from assay.analysis.base import check_target, project_relative, read_report
from assay.sandbox import ArgvRejected, check_argv

LIMITS = OutputLimits()


def code_of(data: bytes, limits: OutputLimits = LIMITS) -> str:
    with pytest.raises(AnalyzerOutputError) as caught:
        load_json(data, limits)
    return caught.value.code


# -- size, depth, strings, values --------------------------------------------------------------


def test_output_over_the_size_limit_is_refused_before_parsing() -> None:
    data = b" " * (LIMITS.max_bytes + 1)
    started = time.monotonic()
    assert code_of(data) == "output_too_large"
    assert time.monotonic() - started < 1


@pytest.mark.parametrize("opener", [b"[", b'{"a":'])
def test_deep_nesting_is_refused_without_recursion(opener: bytes) -> None:
    # A million levels would overflow a recursive parser; the iterative check stops at 65.
    data = opener * 1_000_000
    assert code_of(data) == "too_deep"


def test_nesting_up_to_the_limit_is_accepted() -> None:
    expected: list[object] = []
    for _ in range(63):
        expected = [expected]
    assert load_json(b"[" * 64 + b"]" * 64, OutputLimits(max_depth=64)) == expected
    assert code_of(b"[" * 65 + b"]" * 65, OutputLimits(max_depth=64)) == "too_deep"


def test_a_very_long_string_is_refused() -> None:
    data = b'{"description": "' + b"A" * (LIMITS.max_string_chars + 1) + b'"}'
    assert code_of(data) == "string_too_long"


def test_a_long_string_of_escapes_is_measured_as_written() -> None:
    data = b'["' + b"\\u0041" * (LIMITS.max_string_chars // 6 + 1) + b'"]'
    assert code_of(data) == "string_too_long"


def test_an_unterminated_string_does_not_hang() -> None:
    data = b'["' + b"x" * 1_000_000
    assert code_of(data, OutputLimits(max_string_chars=2_000_000)) == "malformed_json"


def test_too_many_values_are_refused() -> None:
    data = b"[" + b"0," * 1000 + b"0]"
    assert code_of(data, OutputLimits(max_values=500)) == "too_many_values"


@pytest.mark.parametrize(
    ("data", "code"),
    [
        (b'{"a": 1, "a": 2}', "duplicate_key"),
        (b"[NaN]", "malformed_json"),
        (b"[Infinity]", "malformed_json"),
        (b"[" + b"9" * 101 + b"]", "malformed_json"),
        (b"\xff\xfe{}", "not_utf8"),
        (b"", "malformed_json"),
        (b"   \n", "malformed_json"),
        (b"{", "malformed_json"),
        (b'{"a": 1} trailing', "malformed_json"),
    ],
)
def test_malformed_documents_are_structured_errors(data: bytes, code: str) -> None:
    assert code_of(data) == code


def test_a_large_but_valid_document_parses_in_reasonable_time() -> None:
    document = {
        "results": [{"check": "x", "description": "d" * 100, "n": i} for i in range(50_000)]
    }
    data = json.dumps(document).encode()
    started = time.monotonic()
    assert load_json(data, LIMITS) == document
    assert time.monotonic() - started < 10


@pytest.mark.parametrize("analyzer", [Slither(), Aderyn()], ids=["slither", "aderyn"])
@pytest.mark.parametrize(
    "data",
    [
        b"[" * 100_000,
        b'{"success": true, "results": {"detectors": "' + b"x" * 200_000 + b'"}}',
        b'{"success": true, "results": {"detectors": [{"check": 1}]}}',
        b"null",
        b"[]",
        b'"just a string"',
    ],
)
def test_adapters_turn_hostile_reports_into_structured_errors(
    analyzer: Slither | Aderyn, data: bytes
) -> None:
    with pytest.raises(AnalyzerOutputError) as caught:
        analyzer.parse(data)
    assert caught.value.code in {"too_deep", "string_too_long", "schema_mismatch"}


def test_a_report_with_too_many_results_is_refused() -> None:
    detector = {
        "check": "reentrancy-eth",
        "impact": "High",
        "confidence": "Medium",
        "description": "d",
        "elements": [],
    }
    data = json.dumps({"success": True, "results": {"detectors": [detector] * 11}}).encode()
    with pytest.raises(AnalyzerOutputError) as caught:
        Slither(OutputLimits(max_results=10)).parse(data)
    assert caught.value.code == "too_many_results"


# -- paths outside the project -------------------------------------------------------------------


@pytest.mark.parametrize("target", ["/", "/etc", "..", "../other", "src/../../x", "a\\b", ""])
def test_a_target_outside_the_project_is_refused(target: str) -> None:
    with pytest.raises(ValueError, match="outside the project"):
        check_target(target)


@pytest.mark.parametrize("target", [".", "src", "src/Vault.sol"])
def test_targets_inside_the_project_are_accepted(target: str) -> None:
    assert check_target(target) == target


@pytest.mark.parametrize(
    "argv",
    [
        ["slither", "/"],
        ["slither", "..", "--json", "-"],
        ["slither", "../x", "--json", "-"],
        ["slither", ".", "--json", "/work/scratch/out.json"],
        ["slither", ".", "--json", "-", "--solc", "/tmp/solc"],
        ["slither", ".", "--json", "-", "--json", "-"],
        ["slither"],
        ["aderyn", "/etc"],
        ["aderyn", ".", "--output", "/work/project/report.json"],
        ["aderyn", ".", "--output", "/work/scratch/../project/report.json"],
        ["aderyn", ".", "--output", "/work/scratch/sub/report.json"],
        ["aderyn", ".", "--output", "/etc/passwd"],
        ["aderyn", ".", "--output", "-"],
        ["aderyn", ".", "--lsp"],
        ["python3", "-c", "print(1)"],
        ["crytic-compile", "."],
        ["solc-select", "install", "0.8.36"],
    ],
)
def test_the_allowlist_refuses_other_analyzer_commands(argv: list[str]) -> None:
    with pytest.raises(ArgvRejected):
        check_argv(argv)


@pytest.mark.parametrize("analyzer", [Slither(), Aderyn()], ids=["slither", "aderyn"])
def test_the_adapter_commands_are_on_the_allowlist(analyzer: Slither | Aderyn) -> None:
    for target in (".", "src", "src/Vault.sol"):
        assert check_argv(analyzer.argv(target)) == analyzer.argv(target)


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "/work/scratch/out/x.sol",
        "/work/project",
        "/work/projectx/a.sol",
        "../outside.sol",
        "src/../../outside.sol",
        "src\\Vault.sol",
    ],
)
def test_reported_paths_outside_the_project_are_refused(path: str) -> None:
    with pytest.raises(AnalyzerOutputError) as caught:
        project_relative(path)
    assert caught.value.code == "path_outside_project"


def test_reported_paths_under_the_project_mount_become_relative() -> None:
    assert project_relative("/work/project/src/Vault.sol") == "src/Vault.sol"
    assert project_relative("src/Vault.sol") == "src/Vault.sol"


def test_an_aderyn_location_outside_the_project_fails_the_whole_report() -> None:
    issue = {
        "title": "t",
        "description": "d",
        "detector_name": "centralization-risk",
        "instances": [{"contract_path": "/etc/passwd", "line_no": 1}],
    }
    data = json.dumps({"high_issues": {"issues": [issue]}, "low_issues": {"issues": []}})
    with pytest.raises(AnalyzerOutputError) as caught:
        Aderyn().parse(data.encode())
    assert caught.value.code == "path_outside_project"


# -- the report file in the scratch directory -----------------------------------------------------


def test_a_report_symlink_is_not_followed(tmp_path: Path) -> None:
    secret = tmp_path / "secret.json"
    secret.write_text('{"secret": true}')
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "aderyn.json").symlink_to(secret)
    with pytest.raises(AnalyzerOutputError) as caught:
        read_report(scratch / "aderyn.json", 1024)
    assert caught.value.code == "malformed_json"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_a_report_fifo_is_refused_without_blocking(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "aderyn.json")
    started = time.monotonic()
    with pytest.raises(AnalyzerOutputError, match="not a regular file"):
        read_report(tmp_path / "aderyn.json", 1024)
    assert time.monotonic() - started < 1


def test_an_oversized_report_is_refused_before_reading(tmp_path: Path) -> None:
    report = tmp_path / "aderyn.json"
    with report.open("wb") as stream:
        stream.truncate(10 * 1024 * 1024)
    with pytest.raises(AnalyzerOutputError) as caught:
        read_report(report, 1024)
    assert caught.value.code == "output_too_large"


def test_a_missing_report_is_a_structured_error(tmp_path: Path) -> None:
    with pytest.raises(AnalyzerOutputError, match="no report"):
        read_report(tmp_path / "aderyn.json", 1024)
