"""`assay replay`: re-check an evidence bundle offline.

1. Files. `manifest.json` is parsed strictly, then every other file of the bundle is hashed and
   compared with the manifest: a changed, missing or unexpected file, a symlink or a special file
   means the bundle was tampered with, and nothing runs.
2. Environment (ADR 0013). The runner image recorded in the bundle is used when it exists
   locally. Otherwise the default runner image is used when its tool versions and the
   `versions.lock` it is built from match the bundle, and the output says so. Otherwise the
   environment is missing: run `make image`.
3. Re-run. The oracles run again in the sandbox, without network, on `base/`, `patch.diff` and
   `poc/` of the bundle, with the harness, settings and patch policy recorded in it, into a
   temporary ledger.
4. Compare. Inputs, the status, verdict, reason codes and warning codes of every oracle, and the
   final verdict with its reasons must equal the manifest.

A bundle of a verification with the symbolic oracle also needs the symbolic runner image
(ADR 0018), chosen the same way as the runner image in step 2.
"""

import hashlib
import json
import os
import stat
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from pydantic import ValidationError

from assay.ingest.patch import PatchPolicy
from assay.ingest.paths import UnsafePathError, safe_relative_path
from assay.ledger import Ledger
from assay.oracles.runtree import load_harness
from assay.orchestrator.models import REPORT_ORDER, OracleRow, VerifyReport
from assay.orchestrator.verify import VerifyRequest, run_verification
from assay.report.bundle import (
    BASE_DIR,
    HARNESS_DIR,
    MANIFEST_FILE,
    MANIFEST_SCHEMA_VERSION,
    MAX_BUNDLE_FILES,
    PATCH_FILE,
    POC_DIR,
    Environment,
    Manifest,
    tool_versions,
)
from assay.sandbox import DEFAULT_IMAGE, DEFAULT_SYMBOLIC_IMAGE, SandboxRunner, SandboxUnavailable

MAX_MANIFEST_BYTES: Final = 64 * 1024 * 1024
MAX_BUNDLE_BYTES: Final = 2 * 1024 * 1024 * 1024
_READ_CHUNK: Final = 1024 * 1024
_SHOWN: Final = 10

ReplayProblem = Literal["tampered", "environment", "format"]


class ReplayError(Exception):
    """The bundle cannot be replayed: it was tampered with, or the environment is missing."""

    def __init__(self, kind: ReplayProblem, message: str, details: Sequence[str] = ()) -> None:
        super().__init__(message)
        self.kind: ReplayProblem = kind
        self.details = tuple(details)


@dataclass(frozen=True, slots=True)
class ReplayOutcome:
    manifest: Manifest
    report: VerifyReport
    differences: tuple[str, ...]
    notes: tuple[str, ...]

    @property
    def matches(self) -> bool:
        return not self.differences


def _tampered(message: str, details: Sequence[str] = ()) -> ReplayError:
    return ReplayError("tampered", message, details)


def _read_manifest(bundle: Path) -> Manifest:
    path = bundle / MANIFEST_FILE
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise _tampered(f"{MANIFEST_FILE} is missing or not a regular file") from exc
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise _tampered(f"{MANIFEST_FILE} is not a regular file")
        data = handle.read(MAX_MANIFEST_BYTES + 1)
    if len(data) > MAX_MANIFEST_BYTES:
        raise _tampered(f"{MANIFEST_FILE} is larger than {MAX_MANIFEST_BYTES} bytes")
    try:
        manifest = Manifest.model_validate_json(data, strict=True)
    except ValidationError as exc:
        version = _schema_version(data)
        if version is not None and version != MANIFEST_SCHEMA_VERSION:
            raise ReplayError(
                "format",
                f"{MANIFEST_FILE} has schema version {version}; this Assay replays version "
                f"{MANIFEST_SCHEMA_VERSION} only (verify the inputs again to get a new bundle)",
            ) from exc
        raise _tampered(f"{MANIFEST_FILE} does not match the bundle format") from exc
    listed = [item.path for item in manifest.files]
    if len(set(listed)) != len(listed) or MANIFEST_FILE in listed:
        raise _tampered(f"{MANIFEST_FILE} lists a file twice, or lists itself")
    for item in listed:
        try:
            safe_relative_path(item)
        except UnsafePathError as exc:
            raise _tampered(f"{MANIFEST_FILE} lists an unsafe path: {item!r}") from exc
    if PATCH_FILE not in listed or not any(path.startswith(f"{HARNESS_DIR}/") for path in listed):
        raise _tampered(f"{MANIFEST_FILE} does not list {PATCH_FILE} and the harness")
    return manifest


def _schema_version(data: bytes) -> int | None:
    """The `schema_version` of a manifest that does not parse, when it has a plain integer one."""
    try:
        document = json.loads(data)
    except ValueError:
        return None
    version = document.get("schema_version") if isinstance(document, dict) else None
    return version if type(version) is int else None


def _hash(path: Path) -> tuple[str, int]:
    hasher = hashlib.sha256()
    size = 0
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as handle:
        while chunk := handle.read(_READ_CHUNK):
            hasher.update(chunk)
            size += len(chunk)
    return hasher.hexdigest(), size


def _bundle_files(bundle: Path) -> dict[str, tuple[str, int]]:
    """sha256 and size of every regular file of the bundle except the manifest."""
    found: dict[str, tuple[str, int]] = {}
    total = 0
    pending = [""]
    while pending:
        relative_dir = pending.pop()
        with os.scandir(bundle / relative_dir if relative_dir else bundle) as listing:
            entries = sorted(listing, key=lambda entry: entry.name)
        for entry in entries:
            relative = f"{relative_dir}/{entry.name}" if relative_dir else entry.name
            mode = entry.stat(follow_symlinks=False).st_mode
            if stat.S_ISDIR(mode):
                pending.append(relative)
            elif stat.S_ISREG(mode):
                if relative == MANIFEST_FILE:
                    continue
                if len(found) >= MAX_BUNDLE_FILES:
                    raise _tampered(f"the bundle holds more than {MAX_BUNDLE_FILES} files")
                found[relative] = _hash(Path(entry.path))
                total += found[relative][1]
                if total > MAX_BUNDLE_BYTES:
                    raise _tampered(f"the bundle is larger than {MAX_BUNDLE_BYTES} bytes")
            elif stat.S_ISLNK(mode):
                raise _tampered(f"the bundle contains a symlink: {relative}")
            else:
                raise _tampered(f"the bundle contains a special file: {relative}")
    return found


def _shown(items: Sequence[str]) -> list[str]:
    more = len(items) - _SHOWN
    return list(items[:_SHOWN]) + ([f"... and {more} more"] if more > 0 else [])


def load_bundle(bundle: Path) -> Manifest:
    """Parse the manifest and check every file against it; raise `ReplayError` otherwise."""
    if not bundle.is_dir() or bundle.is_symlink():
        raise _tampered(f"not a bundle directory: {bundle}")
    manifest = _read_manifest(bundle)
    found = _bundle_files(bundle)
    listed = {item.path: (item.sha256, item.size) for item in manifest.files}
    problems = [f"missing: {path}" for path in sorted(listed.keys() - found.keys())]
    problems += [f"not in the manifest: {path}" for path in sorted(found.keys() - listed.keys())]
    problems += [
        f"changed: {path}"
        for path in sorted(listed.keys() & found.keys())
        if listed[path] != found[path]
    ]
    if problems:
        raise _tampered(
            f"the bundle does not match its manifest ({len(problems)} problem(s))",
            _shown(problems),
        )
    return manifest


def select_runner(
    manifest: Manifest,
    *,
    make_runner: Callable[[str], SandboxRunner],
    versions_lock: str | None,
) -> tuple[SandboxRunner, tuple[str, ...]]:
    """The runner for the replay and notes about the environment (ADR 0013)."""
    return _select(manifest.environment, DEFAULT_IMAGE, "runner", make_runner, versions_lock)


def select_symbolic_runner(
    manifest: Manifest,
    *,
    make_runner: Callable[[str], SandboxRunner],
    versions_lock: str | None,
) -> tuple[SandboxRunner | None, tuple[str, ...]]:
    """The symbolic runner for the replay of a bundle whose verification ran the symbolic
    oracle, chosen like the runner (ADR 0013, ADR 0018); `None` for any other bundle."""
    if not manifest.settings.symbolic:
        return None, ()
    environment = manifest.symbolic_environment
    if environment is None:
        raise _tampered(f"{MANIFEST_FILE} records a symbolic run without its environment")
    return _select(
        environment, DEFAULT_SYMBOLIC_IMAGE, "symbolic runner", make_runner, versions_lock
    )


def _select(
    environment: Environment,
    default_image: str,
    what: str,
    make_runner: Callable[[str], SandboxRunner],
    versions_lock: str | None,
) -> tuple[SandboxRunner, tuple[str, ...]]:
    recorded = environment.image_digest
    exact = make_runner(recorded)
    try:
        if exact.image_id() == recorded:
            return exact, ()
    except SandboxUnavailable as exc:
        if "docker CLI not found" in str(exc):
            raise ReplayError("environment", str(exc)) from exc
    current = make_runner(default_image)
    try:
        current_id = current.image_id()
        labels = current.image_labels()
    except SandboxUnavailable as exc:
        raise ReplayError(
            "environment",
            f"the {what} image recorded in the bundle ({recorded}) is not available, and "
            f"neither is {default_image}: run make image ({exc})",
        ) from exc
    if tool_versions(labels) == environment.tool_versions and versions_lock == (
        environment.versions_lock
    ):
        note = (
            f"note: the {what} image recorded in the bundle ({recorded}) is not available; "
            f"{default_image} ({current_id}) is used instead: its tool versions and "
            "versions.lock match the bundle"
        )
        return current, (note,)
    raise ReplayError(
        "environment",
        f"the {what} image recorded in the bundle ({recorded}) is not available, and "
        f"{default_image} has other tool versions or another versions.lock: run make image "
        "with the versions.lock recorded in the bundle",
    )


def _row_text(row: OracleRow | None) -> str:
    if row is None:
        return "absent"
    verdict = row.verdict.value if row.verdict is not None else "-"
    codes = ", ".join(row.codes()) or "-"
    warnings = ", ".join(row.warning_codes())
    text = f"{row.status} {verdict} ({codes})"
    return text + (f" warnings ({warnings})" if warnings else "")


def differences(manifest: Manifest, report: VerifyReport) -> tuple[str, ...]:
    """What the replay changed compared with the manifest, as readable lines."""
    found: list[str] = []
    recorded_inputs = manifest.inputs.model_dump()
    for name, value in report.inputs.model_dump().items():
        if recorded_inputs.get(name) != value:
            found.append(f"inputs.{name}: bundle {recorded_inputs.get(name)}, replay {value}")
    recorded = {row.oracle: row for row in manifest.oracles}
    replayed = {row.oracle: row for row in report.oracles}
    for oracle in REPORT_ORDER:
        before, after = recorded.get(oracle), replayed.get(oracle)
        if _row_text(before) != _row_text(after):
            found.append(f"{oracle.value}: bundle {_row_text(before)}, replay {_row_text(after)}")
    if manifest.final_verdict is not report.final_verdict:
        found.append(
            f"final verdict: bundle {manifest.final_verdict.value}, "
            f"replay {report.final_verdict.value}"
        )
    if manifest.reasons != report.reasons:
        found.append(
            f"final reasons: bundle {'; '.join(manifest.reasons) or '-'}, "
            f"replay {'; '.join(report.reasons) or '-'}"
        )
    if manifest.integrity_violation != report.integrity_violation:
        found.append(
            f"integrity violation: bundle {manifest.integrity_violation}, "
            f"replay {report.integrity_violation}"
        )
    if manifest.bounds != report.bounds:
        found.append("bounds: the replay ran with other bounds than the bundle records")
    if manifest.annotations != report.annotations:
        found.append("annotations: the symbolic statements of the replay differ from the bundle")
    return tuple(found)


def replay_bundle(
    bundle: Path,
    manifest: Manifest,
    *,
    runner: SandboxRunner,
    work_dir: Path,
    notes: Sequence[str] = (),
    symbolic_runner: SandboxRunner | None = None,
) -> ReplayOutcome:
    """Re-run every oracle on the bundle's inputs and compare with its manifest."""
    harness = load_harness(bundle / HARNESS_DIR)
    settings = manifest.settings
    verify_dir = work_dir / "verify"
    verify_dir.mkdir()
    with Ledger.open(work_dir / "ledger.db") as ledger:
        outcome = run_verification(
            VerifyRequest(base=bundle / BASE_DIR, patch=bundle / PATCH_FILE, poc=bundle / POC_DIR),
            runner=runner,
            ledger=ledger,
            work_dir=verify_dir,
            settings=settings.verify_settings(),
            harness=harness,
            policy=PatchPolicy(scope=settings.scope, protected=settings.protected),
            symbolic_runner=symbolic_runner,
        )
    return ReplayOutcome(
        manifest=manifest,
        report=outcome.report,
        differences=differences(manifest, outcome.report),
        notes=tuple(notes),
    )
