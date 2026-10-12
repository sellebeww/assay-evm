"""Stand-in forge behavior for the reentrancy fixture, decided from the vault's source.

The decisions follow what the fixture's labels describe, so that `assay verify` can be tested
end to end without Docker:

- the PoC replay reproduces only while the vault's code (comments aside) is unchanged;
- the variant search finds a variant while the code is unchanged or carries the overfit
  re-check;
- the benign tests fail when the transfer to the caller is gone (destructive);
- the storage layout gains a leading `locked` flag when the patch adds one (regressing).
"""

from pathlib import Path

from fake_forge import (
    DEFAULT_BENIGN,
    VAULT_ABI,
    VAULT_LAYOUT,
    BenignTests,
    FakeForge,
    layout_json,
)

from assay.oracles.integrity.solidity import mask

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures" / "reentrancy" / "single_function"
ORIGINAL_VAULT = (FIXTURE / "src" / "Vault.sol").read_text()
OVERFIT_CHECK = "uint256 current = balanceOf[msg.sender];"
TRANSFER = "msg.sender.call{value: amount}"
LOCK = "bool private locked;"


def code_of(source: str) -> list[str]:
    return mask(source).split()


def vault_source(tree: Path) -> str:
    return (tree / "src" / "Vault.sol").read_text()


def unchanged(tree: Path) -> bool:
    return code_of(vault_source(tree)) == code_of(ORIGINAL_VAULT)


def vault_decide(tree: Path, number: int) -> str:
    """The PoC reproduces only while the vault's code, comments aside, is unchanged."""
    return "exploited" if unchanged(tree) else "blocked"


def vault_variant(tree: Path) -> str:
    return "found" if unchanged(tree) or OVERFIT_CHECK in vault_source(tree) else "none"


def vault_benign(tree: Path) -> BenignTests:
    if TRANSFER in vault_source(tree):
        return DEFAULT_BENIGN
    return {**DEFAULT_BENIGN, "test_withdraw()": ("Failure", [])}


LOCKED_LAYOUT = layout_json(
    ("locked", 0, 0, "t_bool"),
    ("balanceOf", 1, 0, "t_mapping(t_address,t_uint256)"),
    ("totalDeposits", 2, 0, "t_uint256"),
)


def vault_interface(tree: Path, contract: str, field: str) -> str:
    if field == "abi":
        return VAULT_ABI
    return LOCKED_LAYOUT if LOCK in vault_source(tree) else VAULT_LAYOUT


def vault_forge() -> FakeForge:
    return FakeForge(
        vault_decide, variant=vault_variant, benign=vault_benign, interface=vault_interface
    )
