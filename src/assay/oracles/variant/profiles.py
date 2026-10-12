"""Campaign profiles of the VariantOracle and the derivation of their seeds.

The profiles live in `profiles.toml` next to this module. Every seed of a campaign is derived
from one recorded base seed: seed `i` of family `f` is the first 16 hex digits of
sha256("assay-variant-seed-v1", f, base seed, i). The same base seed always gives the same
seeds, on every machine, so a campaign can be repeated exactly. Families keep seed sets apart
(for example a held-out family for a final decision after a fix loop).
"""

import hashlib
import tomllib
from functools import cache
from importlib import resources
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

ProfileName = Literal["quick", "standard", "thorough"]
PROFILE_NAMES: Final[tuple[ProfileName, ...]] = ("quick", "standard", "thorough")
DEFAULT_PROFILE: Final[ProfileName] = "standard"
DEFAULT_BASE_SEED: Final = "0x1"
SEED_SCHEME: Final = "assay-variant-seed-v1"
SEARCH_FAMILY: Final = "search"
PROFILES_RESOURCE: Final = "profiles.toml"
MAX_SEEDS: Final = 64

BaseSeed = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{1,16}$")]
_Family = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,31}$")]


class ProfileError(ValueError):
    """The profiles file is malformed, or a profile does not exist."""


class Profile(BaseModel):
    """The bounds of one campaign profile."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: ProfileName
    seeds: int = Field(ge=1, le=MAX_SEEDS)
    runs_per_seed: int = Field(ge=1, le=1_000_000)
    invariant_runs: int = Field(ge=1, le=100_000)
    invariant_depth: int = Field(ge=1, le=10_000)
    campaign_timeout_s: int = Field(ge=10, le=86_400)


class _Values(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    seeds: int
    runs_per_seed: int
    invariant_runs: int
    invariant_depth: int
    campaign_timeout_s: int


class _ProfilesFile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1]
    default: ProfileName
    profiles: dict[ProfileName, _Values]


def parse_profiles(text: str) -> dict[ProfileName, Profile]:
    """Parse and check a profiles file, or raise `ProfileError`."""
    try:
        data = _ProfilesFile.model_validate(tomllib.loads(text))
        profiles = {
            name: Profile(name=name, **values.model_dump())
            for name, values in data.profiles.items()
        }
    except (tomllib.TOMLDecodeError, ValidationError) as exc:
        raise ProfileError(f"malformed profiles file: {exc}") from exc
    if set(profiles) != set(PROFILE_NAMES):
        raise ProfileError(f"the profiles file must define exactly {', '.join(PROFILE_NAMES)}")
    if data.default != DEFAULT_PROFILE:
        raise ProfileError(f"the default profile must be {DEFAULT_PROFILE}")
    return profiles


@cache
def _shipped() -> dict[ProfileName, Profile]:
    text = resources.files("assay.oracles.variant").joinpath(PROFILES_RESOURCE).read_text("utf-8")
    return parse_profiles(text)


def profile(name: str = DEFAULT_PROFILE) -> Profile:
    """The shipped profile `name`, or `ProfileError`."""
    for known, value in _shipped().items():
        if known == name:
            return value
    raise ProfileError(f"unknown profile {name!r}; known: {', '.join(PROFILE_NAMES)}")


def derive_seeds(base_seed: str, count: int, family: str = SEARCH_FAMILY) -> tuple[str, ...]:
    """The first `count` seeds of `family` derived from `base_seed`, as 16-digit hex strings."""
    try:
        base = int(_check_base(base_seed), 16)
        _check_family(family)
    except ValidationError as exc:
        raise ProfileError(str(exc)) from exc
    if not 1 <= count <= MAX_SEEDS:
        raise ProfileError(f"the number of seeds must be in [1, {MAX_SEEDS}]")
    return tuple(
        "0x"
        + hashlib.sha256(f"{SEED_SCHEME}\n{family}\n{base:x}\n{index}".encode("ascii")).hexdigest()[
            :16
        ]
        for index in range(1, count + 1)
    )


class _BaseSeed(BaseModel):
    value: BaseSeed


class _FamilyName(BaseModel):
    value: _Family


def _check_base(base_seed: str) -> str:
    return _BaseSeed(value=base_seed).value


def _check_family(family: str) -> str:
    return _FamilyName(value=family).value
