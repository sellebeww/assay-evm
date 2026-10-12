"""Ground truth for the fixtures (`make fixtures-check`).

For every fixture under `fixtures/<class>/<name>/`, the checker runs the vulnerable revision and
each labelled patch with plain Foundry inside the sandbox runner, and compares what it observes
with the fixture's `expected.json`. It imports no Assay oracle code and no Assay result parser:
it reads forge's JSON output itself, so that the oracles can later be tested against labels that
were established independently of them.

For each variant the checker

1. copies `src/`, `test/` and `poc/` of the fixture and, for a patch, applies it with
   `git apply` (fixtures are trusted test material; nothing else may use `git apply`); the
   symbolic properties in `poc/symbolic/` are Halmos input, not ground truth, and are left out
   of the run trees (their files are still checked against the authoring rules);
2. builds two run trees through the ingest snapshot step, which writes the fixed Foundry
   configuration: the benign tree (`src/`, `test/`) and the PoC tree (`src/`, with `poc/` in the
   place of `test/`). Both get the shared harness from `solidity/` under `assay/`, where test
   files import it as `assay/AssayExploit.sol`;
3. compiles both trees, runs the benign tests, reads the target's ABI and storage layout with
   `forge inspect`, and runs the PoC with a fixed fuzz seed and run count; a fixture invariant
   (`AssayInvariant`) in `poc/` runs too, with a fixed number of runs and depth, and must break
   on the vulnerable revision and hold under the `good` patch.

Fixtures are discovered, not listed: every directory `<root>/<class>/<name>/` is a fixture, where
the roots are `fixtures/` (the development split) and `bench/heldout/` (the held-out split, when
it exists); `--fixtures` names other roots. Fixtures of the held-out root are shown as
`heldout:<class>/<name>`. Any other visible entry at those two levels (a file, a symlink, a
directory not named after a class id, a class directory without fixtures) is reported and fails
the check, so that nothing placed there is skipped silently. The output ends with one summary
line per fixture.

Exit status: 0 when every row matches, 1 when a row does not match, a fixture is broken or the
fixtures root holds a foreign entry, 2 when the sandbox cannot be used or the arguments are
invalid.
"""

import argparse
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from assay.ingest import IngestError, create_snapshot
from assay.ingest.config import safe_foundry_toml
from assay.sandbox import (
    ArgvRejected,
    SandboxError,
    SandboxResult,
    SandboxRunner,
    check_argv,
    make_scratch_dir,
)

REPO_ROOT: Final = Path(__file__).resolve().parent.parent
FIXTURES_DIR: Final = REPO_ROOT / "fixtures"
HELDOUT_DIR: Final = REPO_ROOT / "bench" / "heldout"
HARNESS_DIR: Final = REPO_ROOT / "solidity"
VERSIONS_LOCK: Final = REPO_ROOT / "docker" / "runner" / "versions.lock"

HEADER: Final = "// INTENTIONALLY VULNERABLE: test fixture, do not deploy"
SPDX_PREFIX: Final = "// SPDX-License-Identifier:"
CLASS_IDS: Final = (
    "reentrancy",
    "access_control",
    "unchecked_call",
    "signature_replay",
    "delegatecall",
    "oracle_manipulation",
    "dos",
    "rounding",
)
PATCH_LABELS: Final = ("good", "overfit", "destructive", "regressing")
VARIANTS: Final = ("vulnerable", *PATCH_LABELS)
FIXTURE_ENTRIES: Final = frozenset(
    {"src", "test", "poc", "patches", "foundry.toml", "expected.json", "README.md"}
)
# Directory of the run trees where the harness is placed; a fixture must not use it.
HARNESS_MOUNT: Final = "assay"
INTEGRITY_REASONS: Final = frozenset(
    {
        "protected_path_modified",
        "out_of_scope",
        "path_traversal",
        "symlink",
        "binary_file",
        "vacuous_patch",
        "special_casing",
        "environment_sniffing",
    }
)
KIND_REASONS: Final[Mapping[str, str]] = {
    "layout": "layout_changed",
    "abi": "abi_changed",
    "events": "event_changed",
}
INTERFACE_KINDS: Final = ("layout", "abi", "events")

DEFAULT_FUZZ_SEED: Final = "0x1"
DEFAULT_FUZZ_RUNS: Final = 256

# Foundry deploys every test contract at this address (its default sender's first CREATE).
TEST_CONTRACT: Final = "0x7fa9385be102ac3eac297483dd6233d62b3e1496"
HARNESS_CONTRACT: Final = f"{HARNESS_MOUNT}/AssayExploit.sol:AssayExploit"
PREDICATE_EVENT: Final = "AssayPredicate(string,string)"
RECORD_EVENT: Final = "AssayRecord(bytes32,bytes)"
REPLAY_TEST: Final = "test_replay"
FUZZ_TEST: Final = "testFuzz_variants"
PREDICATE_MARKER: Final = "ASSAY_PREDICATE|"
VARIANT_MARKER: Final = "ASSAY_VARIANT_FOUND|"
INVARIANT_TEST: Final = "invariant_assay"
INVARIANT_MARKER: Final = "ASSAY_INVARIANT_BROKEN|"
DEFAULT_INVARIANT_RUNS: Final = 64
DEFAULT_INVARIANT_DEPTH: Final = 25

GIT_TIMEOUT_S: Final = 60

# Allowed imports per directory of a fixture. Relative imports must resolve into one of the
# listed directories; `src/` may import nothing else, so the target never sees forge-std.
_IMPORT: Final = re.compile(r"\bimport\b[^;\"']*[\"']([^\"']+)[\"']")
_IMPORT_ROOTS: Final[Mapping[str, frozenset[str]]] = {
    "src": frozenset({"src"}),
    "test": frozenset({"src", "test"}),
    "poc": frozenset({"src", "poc"}),
}
# Symbolic properties may also import the vulnerable revision, which the symbolic tree places
# under `baseline/`, and the symbolic harness.
_SYMBOLIC_DIR: Final = "poc/symbolic/"
_SYMBOLIC_ROOTS: Final = frozenset({"src", "poc", "baseline"})
_LIBRARY_IMPORT: Final = re.compile(r"forge-std/[A-Za-z0-9_./]+\.sol")
_HARNESS_IMPORTS: Final = frozenset(
    {f"{HARNESS_MOUNT}/AssayExploit.sol", f"{HARNESS_MOUNT}/AssayInvariant.sol"}
)
_SYMBOLIC_IMPORTS: Final = frozenset({f"{HARNESS_MOUNT}/AssayCheck.sol"})
_POC_CONTRACT: Final = re.compile(r"\bcontract\s+\w+\s+is\s+[^{]*\bAssayPoC\b")
_INVARIANT_CONTRACT: Final = re.compile(r"\bcontract\s+\w+\s+is\s+[^{]*\bAssayInvariant\b")

ERROR: Final = "ERROR"
NOT_RUN: Final = "-"


class CheckError(Exception):
    """A fixture or a run is broken; the observation is not usable."""


# ---------------------------------------------------------------------------------------------
# expected.json
# ---------------------------------------------------------------------------------------------

Outcome = Literal["EXPLOITED", "BLOCKED"]
BenignResult = Literal["pass", "FAIL"]
InterfaceKind = Literal["layout", "abi", "events"]
ClassId = Literal[
    "reentrancy",
    "access_control",
    "unchecked_call",
    "signature_replay",
    "delegatecall",
    "oracle_manipulation",
    "dos",
    "rounding",
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class InterfaceSpec(_Strict):
    status: Literal["baseline", "same", "changed"]
    kinds: tuple[InterfaceKind, ...]


class VulnerableSpec(_Strict):
    applies: bool
    replay: Outcome
    fuzz_variants: Outcome
    benign: BenignResult
    interface: InterfaceSpec


class PatchSpec(VulnerableSpec):
    verdict: Literal["VERIFIED_WITHIN_BOUNDS", "REJECTED"]
    reason: str | None


class VariantSpecs(_Strict):
    vulnerable: VulnerableSpec
    good: PatchSpec
    overfit: PatchSpec
    destructive: PatchSpec
    regressing: PatchSpec

    def get(self, variant: str) -> VulnerableSpec:
        spec = getattr(self, variant)
        assert isinstance(spec, VulnerableSpec)
        return spec


class ExpectedFile(_Strict):
    schema_version: Literal[1]
    fixture: str
    class_id: ClassId = Field(alias="class")
    solc: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    contract: str = Field(
        pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.\-]*(/[A-Za-z0-9_][A-Za-z0-9_.\-]*)*\.sol"
        r":[A-Za-z_$][A-Za-z0-9_$]*$"
    )
    variants: VariantSpecs


# Expected observations per label (docs/fixture-spec.md, section 4, consistency rules).
_OUTCOME_RULES: Final[Mapping[str, tuple[Outcome, Outcome, BenignResult]]] = {
    "vulnerable": ("EXPLOITED", "EXPLOITED", "pass"),
    "good": ("BLOCKED", "BLOCKED", "pass"),
    "overfit": ("BLOCKED", "EXPLOITED", "pass"),
    "destructive": ("BLOCKED", "BLOCKED", "FAIL"),
    "regressing": ("BLOCKED", "BLOCKED", "pass"),
}
_INTERFACE_RULES: Final[Mapping[str, frozenset[str]]] = {
    "vulnerable": frozenset({"baseline"}),
    "good": frozenset({"same"}),
    "overfit": frozenset({"same"}),
    "destructive": frozenset({"same", "changed"}),
    "regressing": frozenset({"changed"}),
}


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    keys = [key for key, _ in pairs]
    if duplicates := sorted({key for key in keys if keys.count(key) > 1}):
        raise CheckError(f"duplicate keys: {', '.join(duplicates)}")
    return dict(pairs)


def load_expected(path: Path) -> ExpectedFile:
    """Parse `expected.json` strictly; unknown fields and duplicate keys are rejected."""
    text = path.read_bytes()
    try:
        json.loads(text, object_pairs_hook=_reject_duplicates)
        return ExpectedFile.model_validate_json(text)
    except CheckError as exc:
        raise CheckError(f"{path.name}: {exc}") from exc
    except (ValueError, ValidationError) as exc:
        raise CheckError(f"{path.name} does not match the schema: {exc}") from exc


def expected_errors(expected: ExpectedFile, fixture_id: str, solc: str) -> list[str]:
    """Return the violations of the consistency rules of `expected.json`."""
    errors: list[str] = []
    if expected.fixture != fixture_id:
        errors.append(f"fixture is {expected.fixture!r}, expected {fixture_id!r}")
    if expected.class_id != fixture_id.split("/", 1)[0]:
        errors.append(f"class {expected.class_id!r} is not the first segment of {fixture_id!r}")
    if expected.solc != solc:
        errors.append(f"solc is {expected.solc!r}, the pinned version is {solc!r}")
    for variant in VARIANTS:
        spec = expected.variants.get(variant)
        prefix = f"variants.{variant}"
        replay, fuzz, benign = _OUTCOME_RULES[variant]
        if not spec.applies:
            errors.append(f"{prefix}.applies must be true")
        if (spec.replay, spec.fuzz_variants, spec.benign) != (replay, fuzz, benign):
            errors.append(
                f"{prefix}: replay, fuzz_variants, benign must be {replay}, {fuzz}, {benign}"
            )
        status, kinds = spec.interface.status, spec.interface.kinds
        if status not in _INTERFACE_RULES[variant]:
            allowed = " or ".join(sorted(_INTERFACE_RULES[variant]))
            errors.append(f"{prefix}.interface.status must be {allowed}")
        if len(set(kinds)) != len(kinds):
            errors.append(f"{prefix}.interface.kinds has duplicates")
        if (status == "changed") != bool(kinds):
            errors.append(f"{prefix}.interface.kinds must be non-empty exactly when changed")
        if isinstance(spec, PatchSpec):
            errors.extend(_verdict_errors(variant, spec))
    return errors


def _verdict_errors(variant: str, spec: PatchSpec) -> list[str]:
    prefix = f"variants.{variant}"
    errors: list[str] = []
    verdict = "VERIFIED_WITHIN_BOUNDS" if variant == "good" else "REJECTED"
    if spec.verdict != verdict:
        errors.append(f"{prefix}.verdict must be {verdict}")
    allowed: frozenset[str | None]
    if variant == "good":
        allowed = frozenset({None})
    elif variant == "overfit":
        allowed = frozenset({"variant_found"})
    elif variant == "destructive":
        allowed = frozenset({"benign_test_failed", *INTEGRITY_REASONS})
    else:
        allowed = frozenset(KIND_REASONS[kind] for kind in spec.interface.kinds)
    if spec.reason not in allowed:
        errors.append(f"{prefix}.reason {spec.reason!r} is not allowed for this label")
    return errors


# ---------------------------------------------------------------------------------------------
# Static checks (no Docker)
# ---------------------------------------------------------------------------------------------


def pinned_solc(lock: Path = VERSIONS_LOCK) -> str:
    """Return SOLC_VERSION from versions.lock."""
    for line in lock.read_text().splitlines():
        if line.startswith("SOLC_VERSION="):
            return line.split("=", 1)[1].strip()
    raise CheckError(f"SOLC_VERSION missing from {lock.name}")


def _visible(directory: Path) -> list[Path]:
    """Entries of `directory`, sorted, without hidden ones (names starting with `.`)."""
    return sorted(item for item in directory.iterdir() if not item.name.startswith("."))


def discover_fixtures(root: Path) -> list[str]:
    """Return the fixture ids (`<class>/<name>`) of every directory `root/*/*/`, sorted.

    Hidden entries are ignored. Anything else that is not a fixture directory at that depth is
    reported by `layout_errors`, never skipped silently.
    """
    found: list[str] = []
    for class_dir in _visible(root):
        if class_dir.is_dir() and not class_dir.is_symlink():
            found += [
                f"{class_dir.name}/{item.name}"
                for item in _visible(class_dir)
                if item.is_dir() and not item.is_symlink()
            ]
    return found


def layout_errors(root: Path) -> list[str]:
    """Check the fixtures root itself: `<class>/<name>/` directories and nothing else.

    Every visible entry of `root` must be a directory named after a class id that holds at least
    one fixture, and every visible entry of a class directory must be a fixture directory.
    Symlinks count as foreign entries.
    """
    errors: list[str] = []
    for class_dir in _visible(root):
        name = class_dir.name
        if class_dir.is_symlink() or not class_dir.is_dir():
            errors.append(f"{name}: not a class directory")
            continue
        if name not in CLASS_IDS:
            errors.append(f"{name}/: not a class id ({', '.join(CLASS_IDS)})")
        entries = _visible(class_dir)
        if not entries:
            errors.append(f"{name}/: holds no fixture")
        errors += [
            f"{name}/{item.name}: not a fixture directory"
            for item in entries
            if item.is_symlink() or not item.is_dir()
        ]
    return errors


def static_errors(fixture_dir: Path, fixture_id: str, solc: str) -> list[str]:
    """Check the fixture's files against the specification without running anything."""
    errors: list[str] = []
    entries = {item.name for item in fixture_dir.iterdir()}
    if missing := sorted(FIXTURE_ENTRIES - entries):
        errors.append(f"missing: {', '.join(missing)}")
    if unexpected := sorted(entries - FIXTURE_ENTRIES):
        errors.append(f"unexpected entries: {', '.join(unexpected)}")
    if missing:
        return errors
    sources: dict[str, str] = {}
    for directory in ("src", "test", "poc"):
        files = sorted((fixture_dir / directory).rglob("*"))
        if not any(path.suffix == ".sol" for path in files):
            errors.append(f"{directory}/ contains no Solidity file")
        for path in files:
            relative = path.relative_to(fixture_dir).as_posix()
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                errors.append(f"{relative}: not a regular file or directory")
            elif path.suffix == ".sol":
                sources[relative] = path.read_text()
                errors += solidity_errors(relative, sources[relative], solc)
    errors += directory_role_errors(sources)
    for label in PATCH_LABELS:
        if not (fixture_dir / "patches" / f"{label}.diff").is_file():
            errors.append(f"patches/{label}.diff missing")
    errors += foundry_toml_errors(fixture_dir / "foundry.toml", solc)
    readme = (fixture_dir / "README.md").read_text()
    if "intentionally vulnerable" not in readme[:600].lower():
        errors.append("README.md does not open with the intentionally-vulnerable notice")
    try:
        expected = load_expected(fixture_dir / "expected.json")
    except CheckError as exc:
        errors.append(str(exc))
    else:
        errors += [
            f"expected.json: {error}" for error in expected_errors(expected, fixture_id, solc)
        ]
        contract_path = expected.contract.split(":", 1)[0]
        if not (fixture_dir / "src" / contract_path).is_file():
            errors.append(f"expected.json: contract file src/{contract_path} not found")
    return errors


def solidity_errors(relative: str, text: str, solc: str) -> list[str]:
    """Header, pragma and inline-configuration rules for one Solidity file of a fixture."""
    errors: list[str] = []
    lines = text.splitlines()
    pragma = f"pragma solidity {solc};"
    if relative.startswith("src/"):
        if lines[:1] != [HEADER]:
            errors.append(f"{relative}: first line must be the intentionally-vulnerable header")
        if len(lines) < 3 or not lines[1].startswith(SPDX_PREFIX) or lines[2] != pragma:
            errors.append(f"{relative}: lines 2 and 3 must be the SPDX identifier and the pragma")
    pragmas = [line.strip() for line in lines if line.strip().startswith("pragma solidity")]
    if pragmas != [pragma]:
        errors.append(f"{relative}: needs exactly one pragma, `{pragma}`")
    if "forge-config" in text.lower():
        errors.append(f"{relative}: contains inline Foundry configuration")
    errors += [f"{relative}: import not allowed: {item}" for item in import_errors(relative, text)]
    return errors


def import_errors(relative: str, text: str) -> list[str]:
    """Imports of a fixture file that leave the directories it may use (`_IMPORT_ROOTS`)."""
    roots = _IMPORT_ROOTS.get(relative.split("/", 1)[0])
    if roots is None:
        return []
    harness = _HARNESS_IMPORTS
    if relative.startswith(_SYMBOLIC_DIR):
        roots, harness = _SYMBOLIC_ROOTS, _HARNESS_IMPORTS | _SYMBOLIC_IMPORTS
    bad: list[str] = []
    for target in _IMPORT.findall(text):
        if target.startswith(("./", "../")):
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(relative), target))
            if resolved.split("/", 1)[0] not in roots:
                bad.append(target)
        elif relative.startswith("src/"):
            bad.append(target)  # the target imports only its own files
        elif target not in harness and _LIBRARY_IMPORT.fullmatch(target) is None:
            bad.append(target)
    return bad


def directory_role_errors(sources: Mapping[str, str]) -> list[str]:
    """One PoC contract under poc/; benign tests under test/ that record behavior."""
    errors: list[str] = []
    pocs = sum(
        len(_POC_CONTRACT.findall(text))
        for path, text in sources.items()
        if path.startswith("poc/")
    )
    if pocs != 1:
        errors.append(
            f"poc/ must contain exactly one contract deriving from AssayPoC, found {pocs}"
        )
    invariants = sum(
        len(_INVARIANT_CONTRACT.findall(text))
        for path, text in sources.items()
        if path.startswith("poc/")
    )
    if invariants > 1:
        errors.append(
            "poc/ may contain at most one contract deriving from AssayInvariant, "
            f"found {invariants}"
        )
    tests = {path: text for path, text in sources.items() if path.startswith("test/")}
    if any(_POC_CONTRACT.search(text) for text in tests.values()):
        errors.append("test/ must not contain a contract deriving from AssayPoC")
    if any(_INVARIANT_CONTRACT.search(text) for text in tests.values()):
        errors.append("test/ must not contain a contract deriving from AssayInvariant")
    if tests and not any("recordBehavior(" in text for text in tests.values()):
        errors.append("the benign tests in test/ never call recordBehavior")
    return errors


def foundry_toml_errors(path: Path, solc: str) -> list[str]:
    try:
        config = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as exc:
        return [f"foundry.toml: {exc}"]
    profile = config.get("profile", {}).get("default", {})
    errors: list[str] = []
    if set(config) - {"profile"} or set(config.get("profile", {})) - {"default"}:
        errors.append("foundry.toml: only [profile.default] is allowed")
    if profile.get("solc") != solc:
        errors.append(f"foundry.toml: solc must be {solc!r}")
    if profile.get("ffi") is not False:
        errors.append("foundry.toml: ffi must be false")
    for key in ("fs_permissions", "rpc_endpoints", "etherscan", "via_ir", "eth_rpc_url"):
        if key in profile:
            errors.append(f"foundry.toml: {key} is not allowed")
    for remapping in profile.get("remappings", []):
        target = str(remapping).split("=", 1)[-1]
        if target.startswith("/") or ".." in PurePosixPath(target).parts:
            errors.append(f"foundry.toml: remapping outside the fixture: {remapping!r}")
    return errors


def harness_errors(solc: str) -> list[str]:
    """Pragma and inline-configuration rules for the files of the shared harness."""
    errors: list[str] = []
    files = sorted(HARNESS_DIR.glob("*.sol"))
    if not files:
        errors.append("solidity/ contains no harness file")
    for path in files:
        errors += solidity_errors(f"solidity/{path.name}", path.read_text(), solc)
    return errors


# ---------------------------------------------------------------------------------------------
# Patches
# ---------------------------------------------------------------------------------------------


def patch_scope_errors(numstat: str) -> list[str]:
    """Paths of `git apply --numstat` output that a fixture patch may not touch."""
    errors: list[str] = []
    for line in numstat.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            errors.append(f"unexpected numstat line: {line!r}")
            continue
        path = parts[2]
        pure = PurePosixPath(path)
        if parts[0] == "-" or parts[1] == "-":
            errors.append(f"binary changes are not allowed: {path}")
        elif " => " in path or "{" in path:
            errors.append(f"renames are not allowed: {path}")
        elif pure.is_absolute() or ".." in pure.parts or pure.parts[:1] != ("src",):
            errors.append(f"patch touches a path outside src/: {path}")
    return errors


def _git(work: Path, args: Sequence[str], patch: bytes) -> subprocess.CompletedProcess[str]:
    git = shutil.which("git")
    if git is None:
        raise CheckError("git not found on PATH")
    # A fixed environment: the ceiling keeps git from treating an enclosing repository as the
    # target of the patch, and no system or user configuration (for example a stricter
    # `apply.whitespace`) changes the outcome.
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": str(work.parent),
        "LC_ALL": "C",
        "GIT_CEILING_DIRECTORIES": str(work.parent),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }
    return subprocess.run(
        [git, "apply", *args, "-"],
        cwd=work,
        input=patch.decode("utf-8"),
        capture_output=True,
        text=True,
        env=env,
        timeout=GIT_TIMEOUT_S,
        check=False,
    )


def apply_patch(work: Path, patch: bytes) -> bool:
    """Apply `patch` to the copy in `work`; return False if it does not apply cleanly."""
    numstat = _git(work, ["--numstat"], patch)
    if numstat.returncode != 0:
        return False
    if errors := patch_scope_errors(numstat.stdout):
        raise CheckError("; ".join(errors))
    if _git(work, ["--check"], patch).returncode != 0:
        return False
    applied = _git(work, [], patch)
    if applied.returncode != 0:
        raise CheckError(f"git apply failed after --check passed: {applied.stderr.strip()}")
    return True


# ---------------------------------------------------------------------------------------------
# forge output
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class RawLog:
    address: str
    topics: tuple[str, ...]
    data: str


@dataclass(frozen=True)
class ForgeCase:
    """One test function of a `forge test --json` run."""

    suite: str
    signature: str
    status: str
    reason: str
    counterexample: bool
    decoded_logs: tuple[str, ...]
    logs: tuple[RawLog, ...]
    fuzz_runs: int | None
    invariant_runs: int | None = None
    invariant_reasons: tuple[str, ...] = ()

    @property
    def name(self) -> str:
        return self.signature.split("(", 1)[0]

    def emitted(self, topic: str) -> list[RawLog]:
        """Logs with event `topic` emitted by the test contract itself."""
        return [
            log
            for log in self.logs
            if log.address.lower() == TEST_CONTRACT and log.topics[:1] == (topic,)
        ]


def _dict(value: object, what: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise CheckError(f"unexpected forge output: {what} is not an object")
    return value


def _list(value: object, what: str) -> list[object]:
    if not isinstance(value, list):
        raise CheckError(f"unexpected forge output: {what} is not a list")
    return value


def _str(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise CheckError(f"unexpected forge output: {what} is not a string")
    return value


def _json(text: str, what: str) -> object:
    try:
        parsed: object = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CheckError(f"{what}: output is not JSON ({exc})") from exc
    return parsed


def parse_test_output(stdout: str) -> list[ForgeCase]:
    """Parse the JSON printed by `forge test --json -vv`."""
    cases: list[ForgeCase] = []
    for suite, body in _dict(_json(stdout, "forge test"), "test output").items():
        results = _dict(_dict(body, suite).get("test_results"), f"{suite}.test_results")
        for signature, raw in results.items():
            result = _dict(raw, signature)
            logs = tuple(
                RawLog(
                    address=_str(log.get("address"), "log address").lower(),
                    topics=tuple(
                        _str(topic, "log topic").lower()
                        for topic in _list(log.get("topics"), "log topics")
                    ),
                    data=_str(log.get("data"), "log data").lower(),
                )
                for log in (_dict(item, "log") for item in _list(result.get("logs", []), "logs"))
            )
            kind = _dict(result.get("kind"), "kind")
            fuzz = kind.get("Fuzz")
            runs = _dict(fuzz, "fuzz kind").get("runs") if fuzz is not None else None
            invariant = kind.get("Invariant")
            sequences = (
                _dict(invariant, "invariant kind").get("runs") if invariant is not None else None
            )
            broken = tuple(
                str(_dict(item, "invariant failure").get("reason") or "")
                for item in _list(result.get("invariant_failures") or [], "invariant failures")
            )
            cases.append(
                ForgeCase(
                    suite=suite,
                    signature=signature,
                    status=_str(result.get("status"), "status"),
                    reason=str(result.get("reason") or ""),
                    counterexample=result.get("counterexample") is not None,
                    decoded_logs=tuple(
                        _str(line, "decoded log")
                        for line in _list(result.get("decoded_logs") or [], "decoded logs")
                    ),
                    logs=logs,
                    fuzz_runs=runs if isinstance(runs, int) else None,
                    invariant_runs=sequences if isinstance(sequences, int) else None,
                    invariant_reasons=broken,
                )
            )
    return cases


@dataclass(frozen=True)
class Cell:
    """One observation of the table: a value and a short explanation."""

    value: str
    detail: str = ""


def _setup_failure(cases: Sequence[ForgeCase]) -> Cell | None:
    for case in cases:
        if case.name == "setUp" and case.status != "Success":
            return Cell(ERROR, f"setUp() failed in {case.suite}: {case.reason}")
    return None


def _single(cases: Sequence[ForgeCase], name: str) -> ForgeCase | Cell:
    matching = [case for case in cases if case.name == name]
    if len(matching) != 1:
        failure = _setup_failure(cases)
        if failure is not None:
            return failure
        return Cell(ERROR, f"expected one {name} test, found {len(matching)}")
    return matching[0]


def replay_cell(cases: Sequence[ForgeCase], predicate_topic: str) -> Cell:
    """EXPLOITED when test_replay passes and the test contract emitted a predicate."""
    case = _single(cases, REPLAY_TEST)
    if isinstance(case, Cell):
        return case
    if case.status == "Failure":
        return Cell("BLOCKED", f"test_replay reverted: {case.reason or 'no reason'}")
    if case.status != "Success":
        return Cell(ERROR, f"test_replay status {case.status}")
    markers = [line for line in case.decoded_logs if line.startswith(PREDICATE_MARKER)]
    if not case.emitted(predicate_topic) or not markers:
        return Cell(ERROR, "test_replay passed without a predicate")
    return Cell("EXPLOITED", markers[0])


def fuzz_cell(cases: Sequence[ForgeCase], predicate_topic: str, runs: int) -> Cell:
    """EXPLOITED when the variant search found an input that reaches a predicate."""
    case = _single(cases, FUZZ_TEST)
    if isinstance(case, Cell):
        return case
    if case.status == "Success":
        if case.fuzz_runs is None or case.fuzz_runs < runs:
            return Cell(ERROR, f"variant search ran {case.fuzz_runs} of {runs} runs")
        return Cell("BLOCKED", f"no variant in {case.fuzz_runs} runs")
    found = case.reason.startswith(VARIANT_MARKER)
    if case.status == "Failure" and found and case.counterexample and case.emitted(predicate_topic):
        return Cell("EXPLOITED", case.reason)
    return Cell(ERROR, f"variant search failed without a variant: {case.reason or case.status}")


def invariant_cell(cases: Sequence[ForgeCase], runs: int) -> Cell:
    """BROKEN when the fixture invariant broke, `holds` when it held for every run, `-` when the
    PoC directory has no invariant."""
    matching = [case for case in cases if case.name == INVARIANT_TEST]
    if not matching:
        return Cell(NOT_RUN, "no invariant in poc/")
    if len(matching) > 1:
        return Cell(ERROR, f"expected one {INVARIANT_TEST} test, found {len(matching)}")
    case = matching[0]
    if case.status == "Success":
        if case.invariant_runs is None or case.invariant_runs < runs:
            return Cell(ERROR, f"the invariant ran {case.invariant_runs} of {runs} runs")
        return Cell("holds", f"held in {case.invariant_runs} runs")
    reasons = [item for item in case.invariant_reasons if item.startswith(INVARIANT_MARKER)]
    if case.status == "Failure" and reasons:
        return Cell("BROKEN", reasons[0])
    detail = "; ".join(case.invariant_reasons) or case.reason or case.status
    return Cell(ERROR, f"the invariant test failed without breaking: {detail}")


Records = Mapping[str, tuple[tuple[str, str], ...]]


def benign_cell(cases: Sequence[ForgeCase]) -> Cell:
    """`pass` when every benign test passes, `FAIL` when at least one fails."""
    if failure := _setup_failure(cases):
        return failure
    tests = [case for case in cases if case.name != "setUp"]
    if not tests:
        return Cell(ERROR, "no benign tests found")
    if skipped := [case.signature for case in tests if case.status not in {"Success", "Failure"}]:
        return Cell(ERROR, f"tests neither passed nor failed: {', '.join(skipped)}")
    failed = sorted(case.signature for case in tests if case.status == "Failure")
    if failed:
        return Cell("FAIL", f"{len(failed)} of {len(tests)} failed: {', '.join(failed)}")
    return Cell("pass", f"{len(tests)} passed")


def records_of(cases: Sequence[ForgeCase], record_topic: str) -> Records:
    """Behavior records (`AssayRecord` events of the test contract) of the passing tests."""
    return {
        f"{case.suite}.{case.signature}": tuple(
            (",".join(log.topics[1:]), log.data) for log in case.emitted(record_topic)
        )
        for case in cases
        if case.status == "Success" and case.name != "setUp"
    }


# ---------------------------------------------------------------------------------------------
# Interface: storage layout, ABI and events
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Slot:
    label: str
    slot: int
    offset: int
    type: str
    size: int

    @property
    def last_slot(self) -> int:
        return self.slot + (self.offset + self.size - 1) // 32


@dataclass(frozen=True)
class Interface:
    layout: tuple[Slot, ...]
    functions: Mapping[str, str]
    events: Mapping[str, str]


@dataclass(frozen=True)
class InterfaceDiff:
    kinds: tuple[str, ...]
    additions: tuple[str, ...]

    @property
    def status(self) -> str:
        return "changed" if self.kinds else "same"


def parse_layout(text: str) -> tuple[Slot, ...]:
    """Parse `forge inspect <contract> storageLayout --json`."""
    layout = _dict(_json(text, "storageLayout"), "storage layout")
    types = _dict(layout.get("types") or {}, "layout types")
    slots: list[Slot] = []
    for raw in _list(layout.get("storage"), "layout storage"):
        item = _dict(raw, "layout entry")
        type_info = _dict(types.get(_str(item.get("type"), "entry type")), "type info")
        offset = item.get("offset")
        if not isinstance(offset, int):
            raise CheckError("unexpected forge output: layout offset is not an integer")
        slots.append(
            Slot(
                label=_str(item.get("label"), "entry label"),
                slot=int(_str(item.get("slot"), "entry slot")),
                offset=offset,
                type=_str(type_info.get("label"), "type label"),
                size=int(_str(type_info.get("numberOfBytes"), "type size")),
            )
        )
    return tuple(slots)


def _canonical_type(param: dict[str, object]) -> str:
    kind = _str(param.get("type"), "parameter type")
    if kind.startswith("tuple"):
        components = [_dict(item, "component") for item in _list(param.get("components"), "tuple")]
        return "(" + ",".join(_canonical_type(item) for item in components) + ")" + kind[5:]
    return kind


def _types(item: dict[str, object], key: str) -> list[dict[str, object]]:
    return [_dict(param, key) for param in _list(item.get(key, []), key)]


def parse_abi(text: str) -> tuple[dict[str, str], dict[str, str]]:
    """Parse `forge inspect <contract> abi --json` into functions and events.

    Functions (including the constructor, `receive` and `fallback`) map their signature to their
    return types and state mutability; events map their signature to their indexed flags.
    Custom errors are not part of the compared interface.
    """
    functions: dict[str, str] = {}
    events: dict[str, str] = {}
    for raw in _list(_json(text, "abi"), "abi"):
        item = _dict(raw, "abi entry")
        kind = _str(item.get("type"), "abi entry type")
        inputs = _types(item, "inputs")
        arguments = ",".join(_canonical_type(param) for param in inputs)
        if kind == "error":
            continue
        if kind == "event":
            name = _str(item.get("name"), "event name")
            flags = ",".join("indexed" if param.get("indexed") is True else "-" for param in inputs)
            anonymous = " anonymous" if item.get("anonymous") is True else ""
            events[f"{name}({arguments})"] = f"[{flags}]{anonymous}"
            continue
        if kind == "function":
            name = _str(item.get("name"), "function name")
        elif kind in {"constructor", "receive", "fallback"}:
            name = kind
        else:
            raise CheckError(f"unexpected forge output: abi entry of type {kind!r}")
        outputs = ",".join(_canonical_type(param) for param in _types(item, "outputs"))
        mutability = _str(item.get("stateMutability"), "state mutability")
        functions[f"{name}({arguments})"] = f"returns ({outputs}) {mutability}"
    return functions, events


def _map_change(base: Mapping[str, str], new: Mapping[str, str]) -> tuple[bool, list[str]]:
    breaking = any(new.get(key) != value for key, value in base.items())
    return breaking, sorted(key for key in new if key not in base)


def compare_interface(base: Interface, new: Interface) -> InterfaceDiff:
    """Breaking changes give a kind; additive changes are listed as additions."""
    kinds: list[str] = []
    additions: list[str] = []
    prefix = new.layout[: len(base.layout)]
    extra = new.layout[len(base.layout) :]
    last = max((item.last_slot for item in base.layout), default=-1)
    if prefix != base.layout or any(item.slot <= last for item in extra):
        kinds.append("layout")
    else:
        additions += [f"storage {item.label} (slot {item.slot})" for item in extra]
    breaking, added = _map_change(base.functions, new.functions)
    if breaking:
        kinds.append("abi")
    additions += [f"function {name}" for name in added]
    breaking, added = _map_change(base.events, new.events)
    if breaking:
        kinds.append("events")
    additions += [f"event {name}" for name in added]
    return InterfaceDiff(kinds=tuple(kinds), additions=tuple(additions))


# ---------------------------------------------------------------------------------------------
# Running one variant
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Settings:
    fuzz_seed: str
    fuzz_runs: int
    invariant_runs: int = DEFAULT_INVARIANT_RUNS
    invariant_depth: int = DEFAULT_INVARIANT_DEPTH


@dataclass
class Observation:
    applies: bool
    replay: Cell = Cell(NOT_RUN)
    fuzz: Cell = Cell(NOT_RUN)
    benign: Cell = Cell(NOT_RUN)
    invariant: Cell = Cell(NOT_RUN)
    interface: Interface | None = None
    records: Records | None = None


class Checker:
    """Runs fixture variants through the sandbox runner."""

    def __init__(self, runner: SandboxRunner, settings: Settings) -> None:
        self.runner = runner
        self.settings = settings
        self._topics: dict[str, str] | None = None

    def _run(self, argv: Sequence[str], tree: Path, scratch: Path) -> SandboxResult:
        result = self.runner.run(argv, project_dir=tree, scratch_dir=scratch)
        command = " ".join(argv[:3])
        if result.timed_out:
            raise CheckError(f"{command}: wall-clock limit reached")
        if result.oom_killed:
            raise CheckError(f"{command}: memory limit reached")
        if result.truncated:
            raise CheckError(f"{command}: output exceeded the size limit")
        return result

    def _build(self, tree: Path, scratch: Path, what: str) -> None:
        result = self._run(("forge", "build", "--json"), tree, scratch)
        if result.exit_code != 0:
            lines = (result.stderr.strip() or result.stdout.strip()).splitlines()
            raise CheckError(f"{what} does not compile: {' | '.join(lines[:6])}")

    def _test(self, tree: Path, scratch: Path) -> list[ForgeCase]:
        argv = (
            "forge",
            "test",
            "--json",
            "-vv",
            "--threads",
            "1",
            "--fuzz-seed",
            self.settings.fuzz_seed,
            "--fuzz-runs",
            str(self.settings.fuzz_runs),
        )
        result = self._run(argv, tree, scratch)
        if not result.stdout.strip():
            raise CheckError(f"forge test printed no results (exit {result.exit_code})")
        return parse_test_output(result.stdout)

    def _inspect(self, tree: Path, scratch: Path, contract: str, field_name: str) -> str:
        result = self._run(("forge", "inspect", contract, field_name, "--json"), tree, scratch)
        if result.exit_code != 0:
            raise CheckError(f"forge inspect {contract} {field_name}: {result.stderr.strip()}")
        return result.stdout

    def topics(self, tree: Path, scratch: Path) -> dict[str, str]:
        """Event topics of the harness, read once from a compiled tree."""
        if self._topics is None:
            events = _dict(
                _json(self._inspect(tree, scratch, HARNESS_CONTRACT, "events"), "events"), "events"
            )
            self._topics = {name: _str(topic, name).lower() for name, topic in events.items()}
            for name in (PREDICATE_EVENT, RECORD_EVENT):
                if name not in self._topics:
                    raise CheckError(f"the harness does not declare the event {name}")
        return self._topics

    def observe(
        self, fixture_dir: Path, patch: Path | None, contract: str, workdir: Path
    ) -> Observation:
        work = workdir / "work"
        for directory in ("src", "test", "poc"):
            shutil.copytree(
                fixture_dir / directory,
                work / directory,
                ignore=_without_symbolic if directory == "poc" else None,
            )
        if patch is not None:
            if not apply_patch(work, patch.read_bytes()):
                return Observation(applies=False)
            solc = pinned_solc()
            for path in sorted((work / "src").rglob("*.sol")):
                relative = path.relative_to(work).as_posix()
                if errors := solidity_errors(relative, path.read_text(), solc):
                    raise CheckError(f"the patched source breaks the fixture rules: {errors[0]}")

        benign_tree, benign_scratch = _run_tree(work, "test", workdir / "benign")
        poc_config = safe_foundry_toml(
            invariant_runs=self.settings.invariant_runs,
            invariant_depth=self.settings.invariant_depth,
        )
        poc_tree, poc_scratch = _run_tree(work, "poc", workdir / "poc", poc_config)

        self._build(benign_tree, benign_scratch, "the revision with its benign tests")
        topics = self.topics(benign_tree, benign_scratch)
        benign_cases = self._test(benign_tree, benign_scratch)
        target = f"src/{contract}"
        layout = parse_layout(self._inspect(benign_tree, benign_scratch, target, "storageLayout"))
        functions, events = parse_abi(self._inspect(benign_tree, benign_scratch, target, "abi"))
        interface = Interface(layout=layout, functions=functions, events=events)
        self._build(poc_tree, poc_scratch, "the revision with its PoC")
        poc_cases = self._test(poc_tree, poc_scratch)
        predicate = topics[PREDICATE_EVENT]
        return Observation(
            applies=True,
            replay=replay_cell(poc_cases, predicate),
            fuzz=fuzz_cell(poc_cases, predicate, self.settings.fuzz_runs),
            benign=benign_cell(benign_cases),
            invariant=invariant_cell(poc_cases, self.settings.invariant_runs),
            interface=interface,
            records=records_of(benign_cases, topics[RECORD_EVENT]),
        )


def _without_symbolic(directory: str, names: list[str]) -> set[str]:
    """`shutil.copytree` filter: leave out `symbolic/` at the top of the PoC directory."""
    return {"symbolic"} if Path(directory).name == "poc" and "symbolic" in names else set()


def _run_tree(
    work: Path, tests_from: str, base: Path, config: bytes | None = None
) -> tuple[Path, Path]:
    """Snapshot `src/`, `<tests_from>/` as `test/` and the harness; return tree and scratch."""
    staging = base / "staging"
    shutil.copytree(work / "src", staging / "src")
    shutil.copytree(work / tests_from, staging / "test")
    (staging / HARNESS_MOUNT).mkdir()
    for path in sorted(HARNESS_DIR.glob("*.sol")):
        shutil.copyfile(path, staging / HARNESS_MOUNT / path.name)
    try:
        snapshot = create_snapshot(staging, base / "snapshot", foundry_toml=config)
    except IngestError as exc:
        raise CheckError(f"ingest rejected the run tree: {exc}") from exc
    return snapshot.tree_dir, make_scratch_dir(base)


# ---------------------------------------------------------------------------------------------
# Rows
# ---------------------------------------------------------------------------------------------


@dataclass
class Row:
    variant: str
    applies: str = NOT_RUN
    replay: Cell = Cell(NOT_RUN)
    fuzz: Cell = Cell(NOT_RUN)
    benign: Cell = Cell(NOT_RUN)
    invariant: Cell = Cell(NOT_RUN)
    interface: str = NOT_RUN
    records: str = NOT_RUN
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def matches(self) -> bool:
        return not self.problems


def build_row(
    variant: str,
    spec: VulnerableSpec,
    observed: Observation | CheckError,
    baseline: Observation | None,
) -> Row:
    """Compare one observation with its expected.json entry."""
    row = Row(variant=variant)
    if isinstance(observed, CheckError):
        row.applies = ERROR
        row.problems.append(f"broken: {observed}")
        return row
    row.applies = "yes" if observed.applies else "no"
    if observed.applies != spec.applies:
        row.problems.append(f"applies: expected {'yes' if spec.applies else 'no'}")
    if not observed.applies:
        return row
    row.replay, row.fuzz, row.benign = observed.replay, observed.fuzz, observed.benign
    row.invariant = observed.invariant
    required = {"vulnerable": "BROKEN", "good": "holds"}.get(variant)
    if observed.invariant.value == ERROR:
        row.problems.append(f"invariant: {observed.invariant.detail}")
    elif required and observed.invariant.value not in (NOT_RUN, required):
        row.problems.append(
            f"invariant: expected {required}, observed {observed.invariant.value} "
            f"({observed.invariant.detail})"
        )
    for name, cell, wanted in (
        ("replay", observed.replay, spec.replay),
        ("fuzz_variants", observed.fuzz, spec.fuzz_variants),
        ("benign", observed.benign, spec.benign),
    ):
        if cell.value != wanted:
            detail = f" ({cell.detail})" if cell.detail else ""
            row.problems.append(f"{name}: expected {wanted}, observed {cell.value}{detail}")

    if variant == "vulnerable":
        row.interface = row.records = "baseline"
        silent = sorted(name for name, items in (observed.records or {}).items() if not items)
        if silent:
            row.problems.append(f"benign tests that record nothing: {', '.join(silent)}")
        return row
    if baseline is None or baseline.interface is None or baseline.records is None:
        row.interface = row.records = ERROR
        row.problems.append("no baseline: the vulnerable revision could not be observed")
        return row
    assert observed.interface is not None
    assert observed.records is not None
    diff = compare_interface(baseline.interface, observed.interface)
    row.interface = diff.status + (f"({','.join(diff.kinds)})" if diff.kinds else "")
    row.notes += [f"additive change: {item}" for item in diff.additions]
    expected_kinds = set(spec.interface.kinds)
    if diff.status != spec.interface.status or set(diff.kinds) != expected_kinds:
        kinds = f"({','.join(spec.interface.kinds)})" if spec.interface.kinds else ""
        row.problems.append(
            f"interface: expected {spec.interface.status}{kinds}, observed {row.interface}"
        )

    if observed.benign.value == "pass":
        row.records = "same" if observed.records == baseline.records else "changed"
        verified = isinstance(spec, PatchSpec) and spec.verdict == "VERIFIED_WITHIN_BOUNDS"
        if row.records == "changed" and verified:
            # A verified patch keeps benign behavior: the records must equal the baseline.
            row.problems.append("records: benign behavior differs from the vulnerable revision")
    return row


@dataclass
class FixtureReport:
    fixture_id: str
    rows: list[Row]
    errors: list[str]

    @property
    def matched(self) -> int:
        return sum(row.matches for row in self.rows)


def fixture_label(root: Path, fixture_id: str) -> str:
    """How a fixture is named in the output: its id, prefixed with the name of its root (for
    example `heldout:dos/payout_loop`) unless it lives in the development fixtures root."""
    return fixture_id if root.resolve() == FIXTURES_DIR.resolve() else f"{root.name}:{fixture_id}"


def check_fixture(
    checker: Checker, fixtures_root: Path, fixture_id: str, solc: str
) -> FixtureReport:
    fixture_dir = fixtures_root / fixture_id
    label = fixture_label(fixtures_root, fixture_id)
    errors = static_errors(fixture_dir, fixture_id, solc)
    if errors:
        rows = [
            Row(variant=variant, problems=["fixture failed the static checks"])
            for variant in VARIANTS
        ]
        return FixtureReport(label, rows, errors)
    expected = load_expected(fixture_dir / "expected.json")
    observations: dict[str, Observation | CheckError] = {}
    with tempfile.TemporaryDirectory(
        prefix="assay-fixture-check-", ignore_cleanup_errors=True
    ) as tmp:
        for variant in VARIANTS:
            patch = None if variant == "vulnerable" else fixture_dir / "patches" / f"{variant}.diff"
            workdir = Path(tmp) / variant
            workdir.mkdir()
            try:
                observations[variant] = checker.observe(
                    fixture_dir, patch, expected.contract, workdir
                )
            except CheckError as exc:
                observations[variant] = exc
    vulnerable = observations["vulnerable"]
    baseline = vulnerable if isinstance(vulnerable, Observation) else None
    rows = [
        build_row(variant, expected.variants.get(variant), observations[variant], baseline)
        for variant in VARIANTS
    ]
    return FixtureReport(label, rows, [])


# ---------------------------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------------------------

COLUMNS: Final = (
    "variant",
    "applies",
    "replay",
    "fuzz_variants",
    "benign",
    "invariant",
    "interface",
    "records",
    "result",
)


def render(report: FixtureReport, settings: Settings, *, verbose: bool) -> list[str]:
    lines = [
        f"{report.fixture_id}  (fuzz seed {settings.fuzz_seed}, {settings.fuzz_runs} runs; "
        f"invariant {settings.invariant_runs} runs of depth {settings.invariant_depth})"
    ]
    lines += [f"  static check: {error}" for error in report.errors]
    table = [list(COLUMNS)] + [
        [
            row.variant,
            row.applies,
            row.replay.value,
            row.fuzz.value,
            row.benign.value,
            row.invariant.value,
            row.interface,
            row.records,
            "match" if row.matches else "MISMATCH",
        ]
        for row in report.rows
    ]
    widths = [max(len(line[index]) for line in table) for index in range(len(COLUMNS))]
    lines += [
        "  "
        + "  ".join(cell.ljust(width) for cell, width in zip(line, widths, strict=True)).rstrip()
        for line in table
    ]
    for row in report.rows:
        details = list(row.problems) + row.notes
        if verbose:
            details += [
                f"{name}: {cell.detail}"
                for name, cell in (
                    ("replay", row.replay),
                    ("fuzz_variants", row.fuzz),
                    ("benign", row.benign),
                    ("invariant", row.invariant),
                )
                if cell.detail
            ]
        lines += [f"  {row.variant}: {detail}" for detail in details]
    return lines


def render_summary(reports: Sequence[FixtureReport]) -> list[str]:
    """One line per fixture with its matching rows, so that a mismatch is easy to spot."""
    if not reports:
        return []
    width = max(len(report.fixture_id) for report in reports)
    lines = ["summary"]
    for report in reports:
        status = "match" if report.matched == len(VARIANTS) else "MISMATCH"
        lines.append(
            f"  {report.fixture_id.ljust(width)}  {report.matched}/{len(VARIANTS)} rows  {status}"
        )
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fixture_check.py",
        description="Establish the fixture labels with plain Foundry in the sandbox runner.",
    )
    parser.add_argument(
        "--fixtures",
        type=Path,
        action="append",
        default=None,
        help="fixtures root, may be repeated (default: fixtures/ and bench/heldout/ if it exists)",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="CLASS/NAME",
        help="restrict the run; fixtures of another root are named ROOT:CLASS/NAME",
    )
    parser.add_argument("--fuzz-seed", default=DEFAULT_FUZZ_SEED)
    parser.add_argument("--fuzz-runs", type=int, default=DEFAULT_FUZZ_RUNS)
    parser.add_argument("--invariant-runs", type=int, default=DEFAULT_INVARIANT_RUNS)
    parser.add_argument("--invariant-depth", type=int, default=DEFAULT_INVARIANT_DEPTH)
    parser.add_argument("--image", default=None, help="runner image (default assay-runner:dev)")
    parser.add_argument("--verbose", action="store_true", help="explain every observation")
    args = parser.parse_args(argv)

    roots: list[Path] = [item.resolve() for item in args.fixtures or []]
    if not roots:
        roots = [FIXTURES_DIR] + ([HELDOUT_DIR] if HELDOUT_DIR.is_dir() else [])
    layout: list[str] = []
    entries: list[tuple[Path, str]] = []
    for root in roots:
        if not root.is_dir():
            print(f"error: not a directory: {root.name}", file=sys.stderr)
            return 2
        prefix = "" if len(roots) == 1 else f"{root.name}: "
        layout += [f"{prefix}{error}" for error in layout_errors(root)]
        entries += [(root, item) for item in discover_fixtures(root)]
    labels = [fixture_label(root, item) for root, item in entries]
    if unknown := [item for item in args.only if item not in labels]:
        print(f"error: unknown fixture: {', '.join(unknown)}", file=sys.stderr)
        return 2
    selected = [
        entry
        for entry, label in zip(entries, labels, strict=True)
        if not args.only or label in args.only
    ]
    if not selected:
        print("error: no fixtures found", file=sys.stderr)
        return 2

    settings = Settings(
        fuzz_seed=args.fuzz_seed,
        fuzz_runs=args.fuzz_runs,
        invariant_runs=args.invariant_runs,
        invariant_depth=args.invariant_depth,
    )
    try:
        safe_foundry_toml(
            invariant_runs=settings.invariant_runs, invariant_depth=settings.invariant_depth
        )
    except ValueError as exc:
        print(f"error: invalid invariant settings: {exc}", file=sys.stderr)
        return 2
    try:
        check_argv(
            [
                "forge",
                "test",
                "--fuzz-seed",
                settings.fuzz_seed,
                "--fuzz-runs",
                str(settings.fuzz_runs),
            ]
        )
    except ArgvRejected as exc:
        print(f"error: invalid fuzz settings: {exc}", file=sys.stderr)
        return 2
    solc = pinned_solc()
    runner = SandboxRunner() if args.image is None else SandboxRunner(image=args.image)
    harness = harness_errors(solc)
    try:
        runner.image_id()
        checker = Checker(runner, settings)
        reports = (
            [] if harness else [check_fixture(checker, root, item, solc) for root, item in selected]
        )
    except SandboxError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for error in layout:
        print(f"fixtures: {error}")
    for error in harness:
        print(f"harness: {error}")
    for report in reports:
        print("\n".join(render(report, settings, verbose=args.verbose)))
        print()
    if summary := render_summary(reports):
        print("\n".join(summary))
        print()
    total = len(selected) * len(VARIANTS)
    matched = sum(report.matched for report in reports)
    print(f"FIXTURES CHECK: {len(selected)} fixtures, {matched}/{total} rows match")
    return 0 if matched == total and not harness and not layout else 1


if __name__ == "__main__":
    sys.exit(main())
