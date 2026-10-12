"""`assay doctor` with a stand-in Docker: every check, the exit codes, SET and NOT SET."""

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay import doctor as doctor_module
from assay.cli import doctor as doctor_cli
from assay.cli.console import color_enabled
from assay.cli.main import app
from assay.doctor import (
    MIN_FREE_BYTES,
    Check,
    DoctorReport,
    Probes,
    normalize_arch,
    parse_versions_lock,
    run_doctor,
)
from assay.report.bundle import EnvironmentUnavailable
from assay.sandbox import DEFAULT_IMAGE, DEFAULT_SYMBOLIC_IMAGE, SandboxRunner, SandboxUnavailable

ROOT = Path(__file__).resolve().parents[2]
LOCK = (ROOT / "docker" / "runner" / "versions.lock").read_text()
SECRET = "sk-very-secret-value-123"
cli = CliRunner()


def labels_from_lock(
    extra: Mapping[str, str] | None = None, *, symbolic: bool = False
) -> dict[str, str]:
    lock = parse_versions_lock(LOCK)
    tools = {
        "foundry": lock["FOUNDRY_VERSION"],
        "solc": lock["SOLC_VERSION"],
        "forge-std": lock["FORGE_STD_VERSION"],
        "python": lock["PYTHON_VERSION"],
        "slither": lock["SLITHER_VERSION"],
        "aderyn": lock["ADERYN_VERSION"],
    }
    if symbolic:
        tools |= {"halmos": lock["HALMOS_VERSION"], "z3": lock["Z3_SOLVER_VERSION"]}
    labels = {f"assay.{name}.version": value for name, value in tools.items()}
    labels["org.opencontainers.image.title"] = "assay-runner"
    return {**labels, **(extra or {})}


@dataclass
class FakeImage:
    image: str
    present: bool = True
    labels: dict[str, str] = field(default_factory=dict)
    platform: str = "linux/arm64"
    daemon: str | None = "linux/arm64"

    def image_id(self) -> str:
        if not self.present:
            raise SandboxUnavailable(f"runner image {self.image} is not available")
        return "sha256:" + "a" * 64

    def image_labels(self) -> dict[str, str]:
        return self.labels

    def image_platform(self) -> str:
        return self.platform

    def daemon_platform(self) -> str:
        if self.daemon is None:
            raise SandboxUnavailable("docker daemon is not reachable: connection refused")
        return self.daemon


def probes(
    *,
    docker: str | None = "/usr/local/bin/docker",
    daemon: str | None = "linux/arm64",
    runner: FakeImage | None = None,
    symbolic: FakeImage | None = None,
    lock: str | None = LOCK,
    free: int = 50 * 1024**3,
    machine: str = "arm64",
    environ: Mapping[str, str] | None = None,
) -> Probes:
    runner = runner or FakeImage(DEFAULT_IMAGE, labels=labels_from_lock(), daemon=daemon)
    symbolic = symbolic or FakeImage(
        DEFAULT_SYMBOLIC_IMAGE,
        labels=labels_from_lock(symbolic=True),
        platform="linux/amd64",
        daemon=daemon,
    )
    images = {DEFAULT_IMAGE: runner, DEFAULT_SYMBOLIC_IMAGE: symbolic}

    def versions_lock() -> str:
        if lock is None:
            raise EnvironmentUnavailable("versions.lock cannot be read")
        return lock

    return Probes(
        docker_path=lambda: docker,
        make_image=lambda image: _with_daemon(images[image], daemon),
        versions_lock=versions_lock,
        free_bytes=lambda: free,
        host_machine=lambda: machine,
        environ=environ or {},
    )


def _with_daemon(image: FakeImage, daemon: str | None) -> FakeImage:
    image.daemon = daemon
    return image


def by_id(report: DoctorReport) -> dict[str, Check]:
    return {item.id: item for item in report.checks}


def test_a_healthy_machine_passes_every_check() -> None:
    report = run_doctor(probes())
    assert report.ok
    checks = by_id(report)
    assert {item.status for item in report.checks} <= {"ok", "info"}
    assert checks["docker_daemon"].status == "ok"
    assert "native" in checks["runner_platform"].detail
    assert "emulated" in checks["symbolic_platform"].detail
    assert "match versions.lock" in checks["runner_tools"].detail
    assert all(item.fix is None for item in report.checks if item.status == "ok")


def test_a_missing_docker_command_is_a_problem_and_skips_the_rest() -> None:
    report = run_doctor(probes(docker=None))
    checks = by_id(report)
    assert not report.ok
    assert checks["docker_cli"].status == "problem"
    assert "install Docker" in (checks["docker_cli"].fix or "")
    assert checks["docker_daemon"].status == "skipped"
    assert checks["runner"].status == "skipped"


def test_a_stopped_daemon_is_a_problem_with_a_fix() -> None:
    report = run_doctor(probes(daemon=None))
    checks = by_id(report)
    assert checks["docker_daemon"].status == "problem"
    assert "not reachable" in checks["docker_daemon"].detail
    assert "start Docker" in (checks["docker_daemon"].fix or "")
    assert checks["runner"].status == "skipped"


def test_a_missing_runner_image_says_make_image() -> None:
    runner = FakeImage(DEFAULT_IMAGE, present=False)
    report = run_doctor(probes(runner=runner))
    checks = by_id(report)
    assert not report.ok
    assert checks["runner"].status == "problem"
    assert checks["runner"].fix == "run make image"


def test_a_missing_symbolic_image_is_information_not_a_problem() -> None:
    report = run_doctor(probes(symbolic=FakeImage(DEFAULT_SYMBOLIC_IMAGE, present=False)))
    checks = by_id(report)
    assert report.ok
    assert checks["symbolic"].status == "info"
    assert "--symbolic" in checks["symbolic"].detail
    assert checks["symbolic"].fix == "run make image"


def test_a_tool_version_that_differs_from_versions_lock_is_a_problem() -> None:
    labels = labels_from_lock({"assay.solc.version": "0.8.0"})
    runner = FakeImage(DEFAULT_IMAGE, labels=labels)
    checks = by_id(run_doctor(probes(runner=runner)))
    assert checks["runner_tools"].status == "problem"
    assert "solc 0.8.0 (versions.lock: 0.8.36)" in checks["runner_tools"].detail
    assert "make image" in (checks["runner_tools"].fix or "")


def test_a_tool_without_a_label_is_a_problem() -> None:
    labels = labels_from_lock()
    del labels["assay.slither.version"]
    checks = by_id(run_doctor(probes(runner=FakeImage(DEFAULT_IMAGE, labels=labels))))
    assert checks["runner_tools"].status == "problem"
    assert "slither missing" in checks["runner_tools"].detail


def test_an_unreadable_versions_lock_is_a_problem_not_a_pass() -> None:
    checks = by_id(run_doctor(probes(lock=None)))
    assert checks["runner_tools"].status == "problem"
    assert "source checkout" in (checks["runner_tools"].fix or "")


def test_an_image_for_another_architecture_runs_emulated() -> None:
    runner = FakeImage(DEFAULT_IMAGE, labels=labels_from_lock(), platform="linux/amd64")
    detail = by_id(run_doctor(probes(runner=runner)))["runner_platform"].detail
    assert "emulated" in detail
    assert "linux/amd64" in detail


def test_low_disk_space_is_a_problem() -> None:
    checks = by_id(run_doctor(probes(free=MIN_FREE_BYTES - 1)))
    assert checks["disk"].status == "problem"
    assert "free disk space" in (checks["disk"].fix or "")
    assert by_id(run_doctor(probes(free=MIN_FREE_BYTES)))["disk"].status == "ok"


def test_the_model_variables_show_only_set_or_not_set() -> None:
    environ = {"ASSAY_LLM_API_KEY": SECRET, "ASSAY_LLM_BASE_URL": "https://secret.example/v1"}
    report = run_doctor(probes(environ=environ))
    detail = by_id(report)["llm"].detail
    assert "ASSAY_LLM_API_KEY SET" in detail
    assert "ASSAY_LLM_BASE_URL SET" in detail
    assert "ASSAY_LLM_MODEL NOT SET" in detail
    dumped = report.model_dump_json()
    assert SECRET not in dumped
    assert "secret.example" not in dumped
    assert report.ok


def test_an_empty_variable_counts_as_not_set() -> None:
    detail = by_id(run_doctor(probes(environ={"ASSAY_LLM_API_KEY": ""})))["llm"].detail
    assert "ASSAY_LLM_API_KEY NOT SET" in detail


def test_every_problem_has_a_one_line_fix() -> None:
    for broken in (probes(docker=None), probes(daemon=None), probes(lock=None), probes(free=0)):
        report = run_doctor(broken)
        for item in report.checks:
            if item.status == "problem":
                assert item.fix
                assert "\n" not in item.fix, item


@pytest.mark.parametrize(
    ("machine", "expected"),
    [
        ("arm64", "arm64"),
        ("aarch64", "arm64"),
        ("x86_64", "amd64"),
        ("AMD64", "amd64"),
        ("riscv64", "riscv64"),
    ],
)
def test_architecture_names_are_normalized(machine: str, expected: str) -> None:
    assert normalize_arch(machine) == expected


def test_versions_lock_parsing_skips_comments_and_blank_lines() -> None:
    parsed = parse_versions_lock("# c\n\nA=1\n B = two \nnot a pair\n")
    assert parsed == {"A": "1", "B": "two"}


def test_the_checked_in_versions_lock_names_every_pinned_tool() -> None:
    lock = parse_versions_lock(LOCK)
    for key in (*doctor_module.RUNNER_TOOLS.values(), *doctor_module.SYMBOLIC_TOOLS.values()):
        assert key in lock


# -- the command --------------------------------------------------------------------------------


@pytest.fixture
def machine(monkeypatch: pytest.MonkeyPatch) -> None:
    """The command runs against a healthy stand-in unless a test replaces it."""
    monkeypatch.setattr(doctor_cli, "real_probes", lambda environ: probes(environ=environ))


@pytest.mark.usefixtures("machine")
def test_the_command_exits_0_when_everything_is_in_order() -> None:
    result = cli.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    assert "all checks passed" in result.stdout
    assert "PROBLEM" not in result.stdout


def test_the_command_exits_4_with_a_fix_per_problem(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor_cli, "real_probes", lambda environ: probes(daemon=None, free=0))
    result = cli.invoke(app, ["doctor"])
    assert result.exit_code == 4
    assert result.stdout.count("PROBLEM") == 2
    assert result.stdout.count("fix: ") == 2
    assert "2 problem(s) found" in result.stdout


def test_the_command_json_matches_the_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor_cli, "real_probes", lambda environ: probes(docker=None))
    result = cli.invoke(app, ["doctor", "--json"])
    assert result.exit_code == 4
    document = json.loads(result.stdout)
    assert DoctorReport.model_validate(document).ok is False
    assert document["format"] == "assay-doctor/1"


@pytest.mark.usefixtures("machine")
def test_the_command_never_prints_a_variable_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ASSAY_LLM_API_KEY", SECRET)
    monkeypatch.setenv("ASSAY_LLM_MODEL", "private-model-name")
    for options in ([], ["--json"]):
        result = cli.invoke(app, ["doctor", *options])
        assert SECRET not in result.output
        assert "private-model-name" not in result.output
        assert "ASSAY_LLM_API_KEY SET" in result.output


@pytest.mark.usefixtures("machine")
def test_the_output_has_no_color_when_it_is_not_a_terminal() -> None:
    assert "\x1b" not in cli.invoke(app, ["doctor"]).output


def test_color_needs_a_terminal_and_no_no_color() -> None:
    class Stream:
        def __init__(self, tty: bool) -> None:
            self.tty = tty

        def isatty(self) -> bool:
            return self.tty

    assert color_enabled(Stream(True), {})  # type: ignore[arg-type]
    assert not color_enabled(Stream(False), {})  # type: ignore[arg-type]
    assert not color_enabled(Stream(True), {"NO_COLOR": "1"})  # type: ignore[arg-type]
    assert color_enabled(Stream(True), {"NO_COLOR": ""})  # type: ignore[arg-type]


def test_a_colored_render_keeps_the_text_and_uses_escape_codes_only_for_labels() -> None:
    report = run_doctor(probes(docker=None))
    plain = doctor_cli.render(report)
    colored = doctor_cli.render(report, color=True)
    assert "\x1b" not in plain
    assert re.sub(r"\x1b\[[0-9;]*m", "", colored) == plain


def test_untrusted_text_in_a_detail_is_escaped() -> None:
    report = DoctorReport(
        ok=False,
        checks=(Check(id="x", title="t", status="problem", detail="a\x1b[31mb", fix="f\x07"),),
    )
    text = doctor_cli.render(report)
    assert "\x1b" not in text
    assert "\x07" not in text


def test_the_sandbox_runner_reads_the_platforms_from_docker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess

    calls: list[list[str]] = []

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[1] == "version":
            return subprocess.CompletedProcess(args, 0, "linux/arm64\n", "")
        if args[1:3] == ["image", "inspect"]:
            return subprocess.CompletedProcess(args, 0, "linux/amd64\n", "")
        raise AssertionError(args)

    monkeypatch.setattr("assay.sandbox.runner.subprocess.run", fake_run)
    runner = SandboxRunner(docker="/usr/bin/docker")
    assert runner.daemon_platform() == "linux/arm64"
    assert runner.image_platform() == "linux/amd64"
    assert calls[0][1:] == ["version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"]
    assert calls[1][-1] == DEFAULT_IMAGE


def test_a_daemon_that_does_not_answer_raises_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, 1, "", "Cannot connect to the Docker daemon\n")

    monkeypatch.setattr("assay.sandbox.runner.subprocess.run", fake_run)
    runner = SandboxRunner(docker="/usr/bin/docker")
    with pytest.raises(SandboxUnavailable, match="not reachable"):
        runner.daemon_platform()
    with pytest.raises(SandboxUnavailable, match="make image"):
        runner.image_platform()
