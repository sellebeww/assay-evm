"""Evidence bundle of a verification (`assay verify --bundle-out DIR`).

Layout (ADR 0013):

    manifest.json   sha256 of every other file, the environment, the settings, the verdict of
                    every oracle, the final verdict and the bounds statement
    base/           the vulnerable project as ingested: the snapshot without `.git`, `.assay`,
                    `out`, `cache` and the other left-out entries, with the project's own
                    `foundry.toml` and `remappings.txt` instead of the rewritten configuration
    poc/            the PoC directory, the same way
    harness/        the shared harness that ran (`solidity/*.sol`)
    patch.diff      the candidate patch, byte for byte
    evidence/       per oracle: `result.json` (verdict, reasons, executions, traces) and the
                    artifacts the oracle stored (forge results, counterexample, behavior diff,
                    interface comparison)
    fix/            only in the bundle of a fix loop (`assay fix`, `assay run`): `history.json`,
                    the attempt history (diff hashes, verdict per oracle, reasons) and the
                    limits that applied. It holds no prompt and no credential.

The manifest holds no timestamps, absolute host paths or user names: evidence and manifest text
pass through a sanitizer that replaces known host paths with placeholders. Every file is written
from deterministic data, so two verifications of the same inputs with the same runner image give
byte-identical manifests apart from the `timing` section, which records how long the oracles and
the variant campaigns took (ADR 0017). The manifest is written last; a bundle without one is
incomplete.
"""

import hashlib
import json
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StringConstraints

from assay import __version__
from assay.ingest import Snapshot
from assay.ingest.paths import safe_relative_path
from assay.ledger import FinalVerdict
from assay.oracles.base import OracleResult
from assay.oracles.runtree import CONFIG_FILE, Harness
from assay.oracles.variant import ProfileName
from assay.orchestrator.models import (
    Bounds,
    EvidenceLevel,
    Inputs,
    OracleRow,
    Timing,
    VerifyReport,
    VerifySettings,
)

MANIFEST_FILE: Final = "manifest.json"
BUNDLE_FORMAT: Final = "assay-evidence-bundle"
BASE_DIR: Final = "base"
POC_DIR: Final = "poc"
HARNESS_DIR: Final = "harness"
PATCH_FILE: Final = "patch.diff"
EVIDENCE_DIR: Final = "evidence"
FIX_DIR: Final = "fix"
HISTORY_FILE: Final = f"{FIX_DIR}/history.json"
RESULT_FILE: Final = "result.json"
LABEL_PREFIX: Final = "assay."
LABEL_SUFFIX: Final = ".version"
MAX_BUNDLE_FILES: Final = 100_000
MANIFEST_SCHEMA_VERSION: Final = 2
TIMING_KEY: Final = "timing"

_Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
_ImageId = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
_SLUG: Final = re.compile(r"[^a-z0-9]+")


class BundleError(Exception):
    """The bundle directory cannot be used."""


class EnvironmentUnavailable(Exception):
    """A part of the environment record (for example `versions.lock`) cannot be read."""


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Environment(_Model):
    """The runner environment of a verification.

    `image_digest` is the content-addressed id of the local runner image; `tool_versions` are
    the versions the image declares in its labels; `versions_lock` is the content of the
    `versions.lock` the image is built from.
    """

    image_digest: _ImageId
    tool_versions: dict[str, str]
    versions_lock: str
    versions_lock_sha256: _Sha256


class ManifestSettings(_Model):
    """The settings a verification ran with; a replay runs with the same ones.

    `fuzz_runs` is set only when it replaced the profile's runs per seed.
    """

    exploit_replays: int
    profile: ProfileName
    fuzz_seed: str
    fuzz_runs: int | None
    symbolic: bool = False
    scope: tuple[str, ...]
    protected: tuple[str, ...]

    def verify_settings(self) -> VerifySettings:
        return VerifySettings(
            replays=self.exploit_replays,
            profile=self.profile,
            fuzz_seed=self.fuzz_seed,
            fuzz_runs=self.fuzz_runs,
            symbolic=self.symbolic,
        )


class ManifestFile(_Model):
    path: Annotated[str, StringConstraints(min_length=1, max_length=4096)]
    sha256: _Sha256
    size: int = Field(ge=0)


class Manifest(_Model):
    """`manifest.json` of an evidence bundle.

    Everything except `timing` is deterministic: two verifications of the same inputs with the
    same runner image give the same manifest apart from the durations in `timing` (ADR 0017).
    """

    schema_version: Literal[2] = 2
    format: Literal["assay-evidence-bundle"] = BUNDLE_FORMAT
    assay_version: str
    environment: Environment
    symbolic_environment: Environment | None = None
    """The symbolic runner image (Halmos), when the symbolic oracle ran."""
    settings: ManifestSettings
    inputs: Inputs
    oracles: tuple[OracleRow, ...]
    final_verdict: FinalVerdict
    reasons: tuple[str, ...]
    integrity_violation: bool
    bounds: Bounds
    bounds_statement: str
    timing: Timing
    evidence_level: EvidenceLevel | None = None
    annotations: tuple[str, ...] = ()
    files: tuple[ManifestFile, ...] = Field(max_length=MAX_BUNDLE_FILES)


def default_versions_lock() -> Path:
    """`docker/runner/versions.lock` of the source checkout this package runs from, or, in an
    installed wheel, the copy that the wheel carries."""
    packaged = Path(__file__).resolve().parents[1] / "_data" / "versions.lock"
    if packaged.is_file():
        return packaged
    return Path(__file__).resolve().parents[3] / "docker" / "runner" / "versions.lock"


def read_versions_lock(path: Path | None = None) -> str:
    path = path if path is not None else default_versions_lock()
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise EnvironmentUnavailable(f"versions.lock cannot be read: {exc}") from exc


def tool_versions(labels: Mapping[str, str]) -> dict[str, str]:
    """Tool versions declared by the image labels `assay.<tool>.version`."""
    return {
        key[len(LABEL_PREFIX) : -len(LABEL_SUFFIX)]: value
        for key, value in sorted(labels.items())
        if key.startswith(LABEL_PREFIX) and key.endswith(LABEL_SUFFIX)
    }


def environment(image_digest: str, labels: Mapping[str, str], versions_lock: str) -> Environment:
    return Environment(
        image_digest=image_digest,
        tool_versions=tool_versions(labels),
        versions_lock=versions_lock,
        versions_lock_sha256=hashlib.sha256(versions_lock.encode("utf-8")).hexdigest(),
    )


class Sanitizer:
    """Replaces known host paths in text with placeholders such as `<work>`."""

    def __init__(self, paths: Iterable[tuple[Path, str]]) -> None:
        replacements: dict[str, str] = {}
        for path, placeholder in paths:
            for form in {str(path), os.path.realpath(path)}:
                if len(PurePosixPath(form).parts) >= 3 and form not in replacements:
                    replacements[form] = placeholder
        self._replacements = sorted(replacements.items(), key=lambda item: -len(item[0]))

    def text(self, value: str) -> str:
        for path, placeholder in self._replacements:
            value = value.replace(path, placeholder)
        return value

    def data(self, value: bytes) -> bytes:
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError:
            return value
        return self.text(text).encode("utf-8")


def check_bundle_dir(dest: Path, *, inputs: Sequence[Path] = ()) -> None:
    """Refuse a bundle directory that exists and is not empty, or that lies inside an input."""
    if dest.is_symlink():
        raise BundleError(f"the bundle directory must not be a symlink: {dest}")
    if dest.exists():
        if not dest.is_dir():
            raise BundleError(f"the bundle path exists and is not a directory: {dest}")
        if any(dest.iterdir()):
            raise BundleError(f"the bundle directory must be empty or absent: {dest}")
    resolved = dest.resolve()
    for item in inputs:
        source = item.resolve()
        if resolved == source or source in resolved.parents:
            raise BundleError(f"the bundle directory must not lie inside an input: {item}")


@dataclass(frozen=True, slots=True)
class BundleContents:
    base: Snapshot
    poc: Snapshot
    patch: bytes
    harness: Harness
    results: tuple[OracleResult, ...]
    report: VerifyReport
    environment: Environment
    settings: ManifestSettings
    symbolic_environment: Environment | None = None
    extra: tuple[tuple[str, bytes], ...] = ()
    """Further files `(path, data)` that the manifest lists, under `fix/` only."""


def _snapshot_files(snapshot: Snapshot, prefix: str) -> list[tuple[str, bytes]]:
    """The snapshot as ingested, with the project's own configuration files."""
    files = [
        (f"{prefix}/{item.path}", (snapshot.tree_dir / item.path).read_bytes())
        for item in snapshot.files
        if item.path != CONFIG_FILE
    ]
    files += [
        (f"{prefix}/{item.path}", (snapshot.evidence_dir / item.path).read_bytes())
        for item in snapshot.project_config
    ]
    return files


def _slug(text: str) -> str:
    return _SLUG.sub("-", text.lower()).strip("-")[:80] or "artifact"


def _extension(media_type: str) -> str:
    return {"application/json": ".json", "text/plain": ".txt"}.get(media_type, ".bin")


def _json_bytes(value: JsonValue) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


def _evidence_files(result: OracleResult, sanitizer: Sanitizer) -> list[tuple[str, bytes]]:
    """`result.json` and the artifacts of one oracle, under `evidence/<oracle>/`."""
    directory = f"{EVIDENCE_DIR}/{result.oracle.value}"
    files: list[tuple[str, bytes]] = []
    used: set[str] = {RESULT_FILE}
    executions: list[JsonValue] = []
    index = 0
    for execution in result.executions:
        listed: list[JsonValue] = []
        for item in execution.evidence:
            index += 1
            name = item.name
            if name is None or name in used:
                name = f"{index:02d}-{_slug(item.label)}{_extension(item.media_type)}"
            used.add(name)
            data = sanitizer.data(item.data)
            files.append((f"{directory}/{name}", data))
            listed.append(
                {
                    "label": item.label,
                    "media_type": item.media_type,
                    "file": name,
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
        executions.append(
            {
                "revision": execution.revision.value,
                "claim": execution.claim,
                "argv": list(execution.argv),
                "seed": execution.seed,
                "exit_code": execution.exit_code,
                "verdict": execution.verdict.value,
                "summary": execution.summary,
                "reasons": [item.model_dump(mode="json") for item in execution.reasons],
                "warnings": [item.model_dump(mode="json") for item in execution.warnings],
                "trace": execution.trace,
                "evidence": listed,
            }
        )
    document: JsonValue = {
        "oracle": result.oracle.value,
        "verdict": result.verdict.value,
        "summary": result.summary,
        "reasons": [item.model_dump(mode="json") for item in result.reasons],
        "warnings": [item.model_dump(mode="json") for item in result.warnings],
        "executions": executions,
    }
    files.append((f"{directory}/{RESULT_FILE}", sanitizer.data(_json_bytes(document))))
    return files


def bundle_files(contents: BundleContents, sanitizer: Sanitizer) -> list[tuple[str, bytes]]:
    """Every file of the bundle except the manifest, sorted by path."""
    files = _snapshot_files(contents.base, BASE_DIR)
    files += _snapshot_files(contents.poc, POC_DIR)
    files += [(f"{HARNESS_DIR}/{name}", data) for name, data in contents.harness.files]
    files.append((PATCH_FILE, contents.patch))
    for result in contents.results:
        files += _evidence_files(result, sanitizer)
    for path, data in contents.extra:
        if not path.startswith(f"{FIX_DIR}/"):
            raise BundleError(f"an extra bundle file must lie under {FIX_DIR}/: {path}")
        files.append((path, sanitizer.data(data)))
    paths = [path for path, _ in files]
    if len(set(paths)) != len(paths):
        raise BundleError("two bundle files have the same path")
    for path in paths:
        safe_relative_path(path)
    return sorted(files, key=lambda item: item[0].encode("utf-8"))


def without_timing(manifest_text: bytes) -> bytes:
    """The manifest with its `timing` section removed: the part that two verifications of the
    same inputs give byte for byte."""
    document = json.loads(manifest_text)
    document.pop(TIMING_KEY, None)
    return _json_bytes(document)


def manifest_bytes(manifest: Manifest, sanitizer: Sanitizer) -> bytes:
    text = json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=True)
    return (sanitizer.text(text) + "\n").encode("ascii")


def build_manifest(contents: BundleContents, files: Sequence[tuple[str, bytes]]) -> Manifest:
    report = contents.report
    return Manifest(
        assay_version=__version__,
        environment=contents.environment,
        symbolic_environment=contents.symbolic_environment,
        settings=contents.settings,
        inputs=report.inputs,
        oracles=report.oracles,
        final_verdict=report.final_verdict,
        reasons=report.reasons,
        integrity_violation=report.integrity_violation,
        bounds=report.bounds,
        bounds_statement=report.bounds_statement,
        timing=report.timing,
        evidence_level=report.evidence_level,
        annotations=report.annotations,
        files=tuple(
            ManifestFile(path=path, sha256=hashlib.sha256(data).hexdigest(), size=len(data))
            for path, data in files
        ),
    )


def write_bundle(dest: Path, contents: BundleContents, sanitizer: Sanitizer) -> str:
    """Write the bundle into `dest` (empty or absent); return the sha256 of the manifest."""
    check_bundle_dir(dest)
    files = bundle_files(contents, sanitizer)
    manifest = manifest_bytes(build_manifest(contents, files), sanitizer)
    dest.mkdir(parents=True, exist_ok=True)
    for path, data in files:
        target = dest.joinpath(*PurePosixPath(path).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as handle:
            handle.write(data)
    with (dest / MANIFEST_FILE).open("xb") as handle:
        handle.write(manifest)
    return hashlib.sha256(manifest).hexdigest()
