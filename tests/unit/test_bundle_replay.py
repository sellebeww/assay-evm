"""Evidence bundles and `assay replay` with a stand-in runner (no Docker)."""

import getpass
import hashlib
import json
import os
import re
import shutil
from pathlib import Path

import pytest
from fake_forge import IMAGE_ID, FakeForge
from schema_support import assert_valid
from typer.testing import CliRunner, Result
from vault_scenario import FIXTURE, ROOT, vault_forge

from assay.cli.main import app
from assay.oracles.variant import derive_seeds
from assay.report.bundle import (
    Manifest,
    Sanitizer,
    check_bundle_dir,
    tool_versions,
    without_timing,
)
from assay.sandbox import SandboxUnavailable

FORBIDDEN = re.compile(r"\b(safe|proven|guaranteed|unhackable)\b", re.IGNORECASE)
ORACLES = ["integrity", "exploit", "variant", "behavior", "regression"]

cli = CliRunner()


@pytest.fixture
def forge(monkeypatch: pytest.MonkeyPatch) -> FakeForge:
    fake = vault_forge()
    monkeypatch.setattr("assay.cli.verify.SandboxRunner", lambda: fake)
    monkeypatch.setattr("assay.cli.replay._runner", lambda image: fake)
    return fake


def verify(tmp_path: Path, patch: str | bytes, bundle: Path, *options: str) -> Result:
    if isinstance(patch, bytes):
        patch_file = tmp_path / "patch.diff"
        patch_file.write_bytes(patch)
    else:
        patch_file = FIXTURE / "patches" / f"{patch}.diff"
    return cli.invoke(
        app,
        [
            "verify",
            "--base",
            str(FIXTURE),
            "--patch",
            str(patch_file),
            "--poc",
            str(FIXTURE / "poc"),
            "--ledger",
            str(tmp_path / ".assay" / "ledger.db"),
            "--bundle-out",
            str(bundle),
            *options,
        ],
    )


def replay(bundle: Path, *options: str) -> Result:
    return cli.invoke(app, ["replay", str(bundle), *options])


def files_of(bundle: Path) -> dict[str, bytes]:
    return {
        path.relative_to(bundle).as_posix(): path.read_bytes()
        for path in sorted(bundle.rglob("*"))
        if path.is_file()
    }


def assert_clean(text: str) -> None:
    assert "secure" not in text.lower()
    assert FORBIDDEN.search(text) is None, text


# -- the bundle -------------------------------------------------------------------------------


def test_the_bundle_holds_inputs_evidence_and_a_manifest(tmp_path: Path, forge: FakeForge) -> None:
    bundle = tmp_path / "bundle"
    result = verify(tmp_path, "good", bundle)
    assert result.exit_code == 0, result.output
    files = files_of(bundle)
    manifest = Manifest.model_validate_json(files["manifest.json"])
    assert {item.path for item in manifest.files} == set(files) - {"manifest.json"}
    for item in manifest.files:
        assert hashlib.sha256(files[item.path]).hexdigest() == item.sha256
        assert len(files[item.path]) == item.size
    assert files["patch.diff"] == (FIXTURE / "patches" / "good.diff").read_bytes()
    assert files["base/src/Vault.sol"] == (FIXTURE / "src" / "Vault.sol").read_bytes()
    assert files["base/foundry.toml"] == (FIXTURE / "foundry.toml").read_bytes()
    assert (
        files["poc/VaultReentrancy.t.sol"]
        == (FIXTURE / "poc" / "VaultReentrancy.t.sol").read_bytes()
    )
    assert (
        files["harness/AssayExploit.sol"] == (ROOT / "solidity" / "AssayExploit.sol").read_bytes()
    )
    for oracle in ORACLES:
        document = json.loads(files[f"evidence/{oracle}/result.json"])
        assert document["oracle"] == oracle
        assert document["verdict"] == "PASS"
        for execution in document["executions"]:
            for item in execution["evidence"]:
                data = files[f"evidence/{oracle}/{item['file']}"]
                assert hashlib.sha256(data).hexdigest() == item["sha256"]
    assert "evidence/variant/sanity-counterexample.json" in files
    assert "evidence/regression/interface-vulnerable.json" in files

    assert manifest.final_verdict == "VERIFIED_WITHIN_BOUNDS"
    assert [row.verdict for row in manifest.oracles] == ["PASS"] * 5
    assert manifest.environment.image_digest == IMAGE_ID
    assert manifest.environment.tool_versions == {
        "forge-std": "v1.17.0",
        "foundry": "v1.8.4",
        "solc": "0.8.36",
    }
    lock = (ROOT / "docker" / "runner" / "versions.lock").read_text()
    assert manifest.environment.versions_lock == lock
    assert manifest.settings.fuzz_seed == "0x1"
    assert manifest.settings.fuzz_runs is None
    assert manifest.settings.profile == "standard"
    assert manifest.settings.exploit_replays == 3
    assert manifest.bounds.fuzz_runs == 256
    assert manifest.bounds.variant is not None
    assert manifest.bounds.variant.seeds == derive_seeds("0x1", 3)
    assert "fuzz: 3 of 3 seeds of 256 runs (768 runs), no variant found" in (
        manifest.bounds_statement
    )
    assert "this is not a proof of absence" in manifest.bounds_statement
    assert manifest.timing.total_s >= 0
    assert manifest.timing.variant is not None
    assert manifest.bounds.interface_contracts == ("src/Vault.sol:Vault",)
    digest = hashlib.sha256(files["manifest.json"]).hexdigest()
    assert f"manifest sha256 {digest}" in result.stdout


def test_verify_and_replay_json_match_their_schemas(tmp_path: Path, forge: FakeForge) -> None:
    bundle = tmp_path / "bundle"
    verified = verify(tmp_path, "good", bundle, "--json")
    assert verified.exit_code == 0, verified.output
    document = json.loads(verified.stdout)
    assert document["final_verdict"] == "VERIFIED_WITHIN_BOUNDS"
    assert_valid("verify", document)
    replayed = replay(bundle, "--json")
    assert replayed.exit_code == 0, replayed.output
    as_json = json.loads(replayed.stdout)
    assert as_json["format"] == "assay-replay/1"
    assert_valid("replay", as_json)


def test_the_base_snapshot_leaves_out_vcs_data_and_build_output(
    tmp_path: Path, forge: FakeForge
) -> None:
    base = tmp_path / "project"
    shutil.copytree(FIXTURE, base)
    for name in (".git/HEAD", ".assay/ledger.db", "out/Vault.sol/Vault.json", "cache/files.json"):
        (base / name).parent.mkdir(parents=True, exist_ok=True)
        (base / name).write_text("left out\n")
    bundle = tmp_path / "bundle"
    result = cli.invoke(
        app,
        [
            "verify",
            "--base",
            str(base),
            "--patch",
            str(FIXTURE / "patches" / "good.diff"),
            "--poc",
            str(base / "poc"),
            "--ledger",
            str(tmp_path / "ledger" / "ledger.db"),
            "--bundle-out",
            str(bundle),
        ],
    )
    assert result.exit_code == 0, result.output
    files = files_of(bundle)
    assert "base/src/Vault.sol" in files
    for name in (".git", ".assay", "out", "cache"):
        assert not any(path.startswith(f"base/{name}/") for path in files), name


def test_the_manifest_has_no_host_paths_user_names_or_timestamps(
    tmp_path: Path, forge: FakeForge
) -> None:
    bundle = tmp_path / "bundle"
    assert verify(tmp_path, "overfit", bundle).exit_code == 1
    text = (bundle / "manifest.json").read_text()
    evidence = "".join(
        data.decode() for path, data in files_of(bundle).items() if path.startswith("evidence/")
    )
    for value in (str(tmp_path), os.path.realpath(tmp_path), str(ROOT), str(Path.home())):
        assert value not in text
        assert value not in evidence
    assert re.search(rf"\b{re.escape(getpass.getuser())}\b", text) is None
    assert re.search(r"\b20\d\d-\d\d-\d\d", text) is None
    assert_clean(text)


def test_two_verifications_give_byte_identical_manifests_apart_from_timing(
    tmp_path: Path, forge: FakeForge
) -> None:
    """ADR 0017: only the `timing` section, which holds durations and nothing else, may differ."""
    first, second = tmp_path / "one" / "bundle", tmp_path / "two" / "elsewhere"
    (tmp_path / "one").mkdir()
    (tmp_path / "two").mkdir()
    assert verify(tmp_path / "one", "overfit", first).exit_code == 1
    assert verify(tmp_path / "two", "overfit", second).exit_code == 1
    manifests = [(item / "manifest.json").read_bytes() for item in (first, second)]
    assert without_timing(manifests[0]) == without_timing(manifests[1])
    for data in manifests:
        timing = json.loads(data)["timing"]
        assert set(timing) == {"total_s", "oracles", "variant", "symbolic"}
        assert timing["symbolic"] is None
        assert isinstance(timing["total_s"], int | float)
        assert all(isinstance(value, int | float) for value in timing["oracles"].values())
        assert set(timing["variant"]) == {"total_s", "campaigns"}
        for entry in timing["variant"]["campaigns"]:
            assert set(entry) == {"revision", "mode", "seed_index", "seconds"}
    # The manifest was compared above without its durations; every other file is byte-identical.
    one, two = files_of(first), files_of(second)
    assert one.keys() == two.keys()
    assert {n: d for n, d in one.items() if n != "manifest.json"} == {
        n: d for n, d in two.items() if n != "manifest.json"
    }


def test_the_counterexample_of_a_variant_is_in_the_bundle(tmp_path: Path, forge: FakeForge) -> None:
    bundle = tmp_path / "bundle"
    assert verify(tmp_path, "overfit", bundle).exit_code == 1
    document = json.loads((bundle / "evidence" / "variant" / "counterexample.json").read_text())
    assert document["revision"] == "patched"
    assert document["knobs"] == ["7886", "3", "0", "0"]
    assert document["confirmation"]["status"] == "confirmed"
    assert document["confirmation"]["reproduced"] == 3
    source = (bundle / "evidence" / "variant" / "variant_poc.t.sol").read_text()
    assert "contract AssayVariantPoC is ExploitPoC" in source
    assert "assayReplayVariant(" in source


@pytest.mark.parametrize("kind", ["file", "non-empty", "inside-base", "symlink"])
def test_an_unusable_bundle_directory_is_refused_before_anything_runs(
    tmp_path: Path, forge: FakeForge, kind: str
) -> None:
    if kind == "file":
        bundle = tmp_path / "bundle"
        bundle.write_text("x")
    elif kind == "non-empty":
        bundle = tmp_path / "bundle"
        bundle.mkdir()
        (bundle / "old.txt").write_text("x")
    elif kind == "inside-base":
        bundle = FIXTURE / "bundle-out"
    else:
        (tmp_path / "target").mkdir()
        bundle = tmp_path / "bundle"
        bundle.symlink_to(tmp_path / "target")
    result = verify(tmp_path, "good", bundle)
    assert result.exit_code == 2, result.output
    assert forge.calls == []
    assert not (FIXTURE / "bundle-out").exists()


def test_an_empty_existing_directory_is_accepted(tmp_path: Path, forge: FakeForge) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    assert verify(tmp_path, "good", bundle).exit_code == 0
    assert (bundle / "manifest.json").is_file()


def test_a_bundle_records_an_integrity_violation_and_replays_it(
    tmp_path: Path, forge: FakeForge
) -> None:
    bundle = tmp_path / "bundle"
    patch = b"--- a/../../etc/x\n+++ b/../../etc/x\n@@ -1 +1 @@\n-a\n+b\n"
    result = verify(tmp_path, patch, bundle)
    assert result.exit_code == 5, result.output
    assert forge.calls == []
    manifest = Manifest.model_validate_json((bundle / "manifest.json").read_bytes())
    assert manifest.integrity_violation is True
    assert [row.status for row in manifest.oracles] == ["ran"] + ["skipped"] * 4
    replayed = replay(bundle)
    assert replayed.exit_code == 0, replayed.output
    assert "REPLAY MATCH" in replayed.stdout
    assert forge.calls == []


def test_sanitizer_replaces_known_host_paths(tmp_path: Path) -> None:
    sanitizer = Sanitizer([(tmp_path / "work", "<work>"), (Path("/"), "<root>")])
    text = f"error in {tmp_path}/work/a.sol and {os.path.realpath(tmp_path)}/work/b.sol at /"
    assert sanitizer.text(text) == "error in <work>/a.sol and <work>/b.sol at /"
    assert sanitizer.data(b"\xff\xfe") == b"\xff\xfe"


def test_check_bundle_dir_accepts_an_absent_directory(tmp_path: Path) -> None:
    check_bundle_dir(tmp_path / "new" / "bundle", inputs=(FIXTURE,))


def test_tool_versions_come_from_the_image_labels() -> None:
    labels = {"assay.solc.version": "0.8.36", "assay.role": "x", "other.version": "1"}
    assert tool_versions(labels) == {"solc": "0.8.36"}


# -- replay -----------------------------------------------------------------------------------


@pytest.fixture
def good_bundle(tmp_path: Path, forge: FakeForge) -> Path:
    bundle = tmp_path / "bundle"
    assert verify(tmp_path, "good", bundle).exit_code == 0
    forge.calls.clear()
    return bundle


def test_an_intact_bundle_replays_to_a_match(good_bundle: Path, forge: FakeForge) -> None:
    result = replay(good_bundle)
    assert result.exit_code == 0, result.output
    lines = result.stdout.splitlines()
    assert lines[0] == "REPLAY MATCH"
    assert "final verdict: VERIFIED_WITHIN_BOUNDS (recorded and replayed)" in lines
    assert forge.tests("^testFuzz_variants[(]"), "the oracles ran again"
    assert_clean(result.output)
    as_json = json.loads(replay(good_bundle, "--json").stdout)
    assert as_json["match"] is True
    assert as_json["differences"] == []


def flip_byte(path: Path) -> None:
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0x01
    path.write_bytes(bytes(data))


@pytest.mark.parametrize(
    "tamper",
    [
        "base/src/Vault.sol",
        "patch.diff",
        "poc/VaultReentrancy.t.sol",
        "harness/AssayExploit.sol",
        "evidence/variant/result.json",
        "manifest.json",
        "extra",
        "missing",
        "symlink",
    ],
)
def test_a_tampered_bundle_exits_5_and_runs_nothing(
    good_bundle: Path, forge: FakeForge, tamper: str
) -> None:
    if tamper == "extra":
        (good_bundle / "base" / "src" / "Extra.sol").write_text("contract Extra {}\n")
    elif tamper == "missing":
        (good_bundle / "evidence" / "exploit" / "result.json").unlink()
    elif tamper == "symlink":
        target = good_bundle / "base" / "src" / "Vault.sol"
        moved = good_bundle.parent / "Vault.sol"
        shutil.move(target, moved)
        target.symlink_to(moved)
    else:
        flip_byte(good_bundle / tamper)
    result = replay(good_bundle)
    assert result.exit_code == 5, result.output
    assert "nothing was run" in result.stderr
    assert "REPLAY MATCH" not in result.stdout
    assert forge.calls == []


class MissingImage(FakeForge):
    def image_id(self) -> str:
        raise SandboxUnavailable("runner image is not available (build it with `make image`)")


def test_a_missing_image_exits_4_with_a_hint(
    good_bundle: Path, forge: FakeForge, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = MissingImage(lambda tree, number: "blocked")
    monkeypatch.setattr("assay.cli.replay._runner", lambda image: missing)
    result = replay(good_bundle)
    assert result.exit_code == 4, result.output
    assert "run make image" in result.stderr
    assert missing.calls == []


class OtherImage(FakeForge):
    def __init__(self, base: FakeForge, image: str, labels: dict[str, str]) -> None:
        super().__init__(
            base.decide,
            variant=base.variant,
            benign=base.benign,
            interface=base.interface,
            labels=labels,
        )
        self.image = image

    def image_id(self) -> str:
        if self.image.startswith("sha256:"):
            raise SandboxUnavailable("No such image")
        return "sha256:" + "01" * 32


def test_another_image_with_the_same_tool_versions_is_used_with_a_note(
    good_bundle: Path, forge: FakeForge, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "assay.cli.replay._runner", lambda image: OtherImage(forge, image, forge.labels)
    )
    result = replay(good_bundle)
    assert result.exit_code == 0, result.output
    assert result.stdout.startswith("note: the runner image recorded in the bundle")
    assert "REPLAY MATCH" in result.stdout


def test_another_image_with_other_tool_versions_exits_4(
    good_bundle: Path, forge: FakeForge, monkeypatch: pytest.MonkeyPatch
) -> None:
    labels = {**forge.labels, "assay.solc.version": "0.8.37"}
    monkeypatch.setattr("assay.cli.replay._runner", lambda image: OtherImage(forge, image, labels))
    result = replay(good_bundle)
    assert result.exit_code == 4, result.output
    assert "run make image" in result.stderr


def test_a_different_verdict_on_replay_exits_1_and_shows_the_difference(
    good_bundle: Path, forge: FakeForge
) -> None:
    forge.variant = lambda tree: "found"
    result = replay(good_bundle)
    assert result.exit_code == 1, result.output
    lines = result.stdout.splitlines()
    assert lines[0] == "REPLAY MISMATCH: the replay differs from the bundle"
    assert "  variant: bundle ran PASS (-), replay ran FAIL (variant_found)" in lines
    assert "  final verdict: bundle VERIFIED_WITHIN_BOUNDS, replay REJECTED" in lines
    assert_clean(result.output)


def test_replay_needs_an_existing_bundle(tmp_path: Path) -> None:
    assert replay(tmp_path / "absent").exit_code == 2
    empty = tmp_path / "empty"
    empty.mkdir()
    result = replay(empty)
    assert result.exit_code == 5
    assert "manifest.json is missing" in result.stderr


def rewrite_manifest(bundle: Path, change: dict[str, object]) -> None:
    path = bundle / "manifest.json"
    document = json.loads(path.read_text())
    document.update(change)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


def test_a_manifest_without_the_harness_is_refused(good_bundle: Path, forge: FakeForge) -> None:
    files = json.loads((good_bundle / "manifest.json").read_text())["files"]
    shutil.rmtree(good_bundle / "harness")
    rewrite_manifest(
        good_bundle, {"files": [item for item in files if not item["path"].startswith("harness/")]}
    )
    result = replay(good_bundle)
    assert result.exit_code == 5, result.output
    assert forge.calls == []


def test_a_manifest_with_wrong_types_is_refused(good_bundle: Path, forge: FakeForge) -> None:
    document = json.loads((good_bundle / "manifest.json").read_text())
    rewrite_manifest(good_bundle, {"settings": {**document["settings"], "fuzz_runs": "256"}})
    assert replay(good_bundle).exit_code == 5
    assert forge.calls == []


def test_a_manifest_that_claims_another_verdict_does_not_match(
    good_bundle: Path, forge: FakeForge
) -> None:
    rewrite_manifest(good_bundle, {"final_verdict": "REJECTED", "reasons": ["variant_found"]})
    result = replay(good_bundle)
    assert result.exit_code == 1, result.output
    assert "  final verdict: bundle REJECTED, replay VERIFIED_WITHIN_BOUNDS" in result.stdout


def test_a_bundle_of_an_older_format_is_refused_as_such(
    good_bundle: Path, forge: FakeForge
) -> None:
    rewrite_manifest(good_bundle, {"schema_version": 1, "timing": None})
    result = replay(good_bundle)
    assert result.exit_code == 2, result.output
    assert "schema version 1" in result.stderr
    assert "nothing was run" in result.stderr
    assert forge.commands("test") == []


def test_a_replay_compares_the_variant_campaigns_but_not_the_durations(
    good_bundle: Path, forge: FakeForge
) -> None:
    path = good_bundle / "manifest.json"
    document = json.loads(path.read_text())
    document["timing"]["total_s"] = 12345.6
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    # The manifest itself is not hashed, so a changed duration is not tampering.
    result = replay(good_bundle)
    assert result.exit_code == 0, result.output
    assert "REPLAY MATCH" in result.stdout
    assert "recorded run 12345.6 s" in result.stdout
