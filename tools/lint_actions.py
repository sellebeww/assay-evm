"""Run a pinned actionlint over the workflows and the action (`make lint-actions`).

actionlint is downloaded once from its GitHub release into `build/actionlint/<version>/`, after
the sha256 of the archive is checked against `CHECKSUMS` below, and run on every file under
`.github/workflows/`. The version and the checksums are the pin; a new version needs new checksums
from the release's `actionlint_<version>_checksums.txt`.

actionlint reads workflows only, not action metadata files. Every `action.yml` (of the repository
root and of `.github/actions/*/`) is therefore checked in two ways: its structure (a composite
action with a description on every input and output, a `shell` on every `run` step), and its steps,
which are wrapped into a throwaway workflow with the same inputs, so that actionlint checks their
expressions, their contexts and, when shellcheck is installed, their scripts.

Exit status: the one of actionlint (0 without findings, 1 with findings), 2 when the binary
cannot be obtained or the platform has no pinned archive.
"""

import hashlib
import io
import platform
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Any, Final

import yaml

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
VERSION: Final = "1.7.12"
CHECKSUMS: Final = {
    "darwin_amd64": "5b44c3bc2255115c9b69e30efc0fecdf498fdb63c5d58e17084fd5f16324c644",
    "darwin_arm64": "aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f",
    "linux_amd64": "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
    "linux_arm64": "325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6",
}
URL: Final = (
    "https://github.com/rhysd/actionlint/releases/download/v{version}/"
    "actionlint_{version}_{platform}.tar.gz"
)
MAX_ARCHIVE_BYTES: Final = 32 * 1024 * 1024
TIMEOUT_S: Final = 60


class LintToolError(Exception):
    """actionlint cannot be obtained."""


def platform_key() -> str:
    system = {"Darwin": "darwin", "Linux": "linux"}.get(platform.system(), "")
    machine = {"x86_64": "amd64", "AMD64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(
        platform.machine(), ""
    )
    key = f"{system}_{machine}"
    if key not in CHECKSUMS:
        raise LintToolError(
            f"no pinned actionlint archive for {platform.system()} {platform.machine()}"
        )
    return key


def ensure_actionlint(root: Path = REPO_ROOT) -> Path:
    """The path of the pinned actionlint binary; downloads and verifies it when it is missing."""
    binary = root / "build" / "actionlint" / VERSION / "actionlint"
    if binary.is_file():
        return binary
    key = platform_key()
    url = URL.format(version=VERSION, platform=key)
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT_S) as response:
            data: bytes = response.read(MAX_ARCHIVE_BYTES + 1)
    except OSError as exc:
        raise LintToolError(f"cannot download {url}: {exc}") from exc
    if len(data) > MAX_ARCHIVE_BYTES:
        raise LintToolError("the actionlint archive is larger than expected")
    digest = hashlib.sha256(data).hexdigest()
    if digest != CHECKSUMS[key]:
        raise LintToolError(f"sha256 of the actionlint archive differs from the pin: {digest}")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        member = archive.getmember("actionlint")
        if not member.isfile():
            raise LintToolError("actionlint is not a regular file in its archive")
        handle = archive.extractfile(member)
        if handle is None:
            raise LintToolError("cannot read actionlint from its archive")
        content = handle.read()
    binary.parent.mkdir(parents=True, exist_ok=True)
    partial = binary.with_suffix(".partial")
    partial.write_bytes(content)
    partial.chmod(0o755)
    partial.replace(binary)
    return binary


def workflows(root: Path = REPO_ROOT) -> list[Path]:
    """The workflow files, relative to `root`."""
    directory = root / ".github" / "workflows"
    found = [*sorted(directory.glob("*.yml")), *sorted(directory.glob("*.yaml"))]
    return [path.relative_to(root) for path in found]


def actions(root: Path = REPO_ROOT) -> list[Path]:
    """The action metadata files, relative to `root`."""
    found = [
        *sorted(root.glob("action.y*ml")),
        *sorted((root / ".github" / "actions").glob("*/action.y*ml")),
    ]
    return [path.relative_to(root) for path in found]


def targets(root: Path = REPO_ROOT) -> list[Path]:
    return [*workflows(root), *actions(root)]


def structure_problems(document: Any) -> list[str]:
    """What is wrong with the structure of a composite action, one sentence each."""
    if not isinstance(document, dict):
        return ["the file is not a mapping"]
    problems: list[str] = []
    for key in ("name", "description"):
        if not document.get(key):
            problems.append(f"missing {key}")
    for section in ("inputs", "outputs"):
        for name, spec in (document.get(section) or {}).items():
            if not isinstance(spec, dict) or not spec.get("description"):
                problems.append(f"{section[:-1]} {name} has no description")
            if section == "outputs" and isinstance(spec, dict) and "value" not in spec:
                problems.append(f"output {name} has no value")
    runs = document.get("runs")
    if not isinstance(runs, dict) or runs.get("using") != "composite":
        problems.append("runs.using must be composite")
        return problems
    for number, step in enumerate(runs.get("steps") or [], start=1):
        if "run" in step and "shell" not in step:
            problems.append(f"step {number} has a run script and no shell")
        if "run" not in step and "uses" not in step:
            problems.append(f"step {number} has neither run nor uses")
    return problems


def wrap_as_workflow(document: dict[str, Any]) -> str:
    """The steps of a composite action as a workflow job with the same inputs."""
    inputs = {
        name: {
            "description": spec.get("description", ""),
            "required": bool(spec.get("required", False)),
            "type": "string",
        }
        for name, spec in (document.get("inputs") or {}).items()
    }
    workflow = {
        "name": "wrapped action",
        "on": {"workflow_dispatch": {"inputs": inputs}},
        "permissions": {},
        "jobs": {
            "composite": {
                "runs-on": "ubuntu-24.04",
                "steps": document["runs"]["steps"],
            }
        },
    }
    return yaml.safe_dump(workflow, sort_keys=False, width=10_000)


def _run(binary: Path, files: list[Path], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(binary), "-no-color", *map(str, files)],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def lint(root: Path = REPO_ROOT, binary: Path | None = None) -> tuple[int, str]:
    """Lint the workflows and the actions of `root`; returns the exit status and the report.

    Raises `LintToolError` when actionlint cannot be obtained.
    """
    binary = binary or ensure_actionlint()
    files, action_files = workflows(root), actions(root)
    if not files and not action_files:
        raise LintToolError("no workflow or action file found")
    report: list[str] = []
    status = 0
    if files:
        done = _run(binary, files, root)
        report.append(done.stdout + done.stderr)
        status = max(status, done.returncode)
    for action in action_files:
        document = yaml.safe_load((root / action).read_text(encoding="utf-8"))
        problems = structure_problems(document)
        report += [f"{action}: {problem}" for problem in problems]
        if problems:
            status = max(status, 1)
            continue
        with tempfile.TemporaryDirectory(prefix="lint-actions-") as tmp:
            wrapped = Path(tmp) / "wrapped.yml"
            wrapped.write_text(wrap_as_workflow(document), encoding="utf-8")
            done = _run(binary, [wrapped], Path(tmp))
        text = (done.stdout + done.stderr).replace("wrapped.yml", f"{action} (steps)")
        report.append(text)
        status = max(status, done.returncode)
    return status, "\n".join(item for item in report if item)


def main() -> int:
    try:
        status, report = lint()
    except LintToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if report:
        print(report)
    if status == 0:
        print(f"lint-actions: {len(targets())} files, actionlint {VERSION}: OK")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
