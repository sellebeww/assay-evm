import tomllib
from pathlib import Path
from typing import Any

from assay.ingest import SAFE_FOUNDRY_TOML, safe_foundry_toml
from assay.sandbox.layout import FORGE_STD_SRC, SCRATCH_MOUNT, SOLC_PATH

REPO = Path(__file__).resolve().parents[2]


def load() -> dict[str, Any]:
    return tomllib.loads(SAFE_FOUNDRY_TOML)


def test_only_the_default_profile_and_test_settings_exist() -> None:
    config = load()
    assert set(config) == {"profile", "fuzz", "invariant"}
    assert set(config["profile"]) == {"default"}


def test_ffi_is_off_and_no_file_access_is_granted() -> None:
    profile = load()["profile"]["default"]
    assert profile["ffi"] is False
    assert profile["fs_permissions"] == []
    assert profile["allow_paths"] == []
    assert profile["include_paths"] == []


def test_solc_is_fixed_to_the_image_compiler() -> None:
    profile = load()["profile"]["default"]
    assert profile["solc"] == SOLC_PATH == "/opt/assay/bin/solc"
    assert profile["auto_detect_solc"] is False
    assert profile["offline"] is True


def test_no_network_endpoints_are_configured() -> None:
    config = load()
    keys = set(config["profile"]["default"]) | set(config["fuzz"]) | set(config["invariant"])
    for forbidden in ("rpc_endpoints", "eth_rpc_url", "etherscan", "etherscan_api_key", "fork"):
        assert not any(key.startswith(forbidden) for key in keys)
    assert "rpc_endpoints" not in config
    assert "etherscan" not in config


def test_the_only_remapping_points_at_forge_std_in_the_image() -> None:
    profile = load()["profile"]["default"]
    assert profile["remappings"] == [f"forge-std/={FORGE_STD_SRC}"]
    assert FORGE_STD_SRC == "/opt/assay/lib/forge-std/src/"
    assert profile["auto_detect_remappings"] is False
    assert profile["libs"] == []


def test_everything_forge_writes_goes_to_the_scratch_directory() -> None:
    config = load()
    profile = config["profile"]["default"]
    written = [
        profile["out"],
        profile["cache_path"],
        profile["snapshots"],
        config["fuzz"]["failure_persist_dir"],
        config["invariant"]["failure_persist_dir"],
    ]
    assert all(path.startswith(f"{SCRATCH_MOUNT}/") for path in written)


def test_fuzz_seed_is_fixed() -> None:
    assert load()["fuzz"]["seed"] == "0x1"


def test_bytes_match_the_text() -> None:
    assert safe_foundry_toml() == SAFE_FOUNDRY_TOML.encode("utf-8")


def test_image_paths_match_the_runner_image() -> None:
    dockerfile = (REPO / "docker" / "runner" / "Dockerfile").read_text()
    assert f"/rootfs{SOLC_PATH}" in dockerfile
    assert f"FOUNDRY_SOLC={SOLC_PATH}" in dockerfile
    assert f"/rootfs{FORGE_STD_SRC.removesuffix('/src/')} " in dockerfile
