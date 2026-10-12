"""The Foundry configuration written into every snapshot.

A project's own `foundry.toml` and `remappings.txt` are never used: forge reads
`remappings.txt` from the project root even when `foundry.toml` lists remappings, so both are
removed from the snapshot and kept only as evidence. The configuration below replaces them.
"""

from typing import Final

from assay.sandbox.layout import FORGE_STD_SRC, SCRATCH_MOUNT, SOLC_PATH

# Fuzz seed used when a run does not pass `--fuzz-seed`, so that fuzz and invariant results are
# reproducible by default.
DEFAULT_FUZZ_SEED: Final = "0x1"

SAFE_FOUNDRY_TOML: Final = f"""\
# Foundry configuration of an Assay snapshot. The project's own foundry.toml is not used.
[profile.default]
src = "src"
test = "test"
script = "script"
libs = []
# The only library is forge-std from the runner image, mounted read-only.
remappings = ["forge-std/={FORGE_STD_SRC}"]
auto_detect_remappings = false
solc = "{SOLC_PATH}"
auto_detect_solc = false
offline = true
ffi = false
fs_permissions = []
allow_paths = []
include_paths = []
# Everything forge writes goes to the scratch directory; the project mount is read-only.
out = "{SCRATCH_MOUNT}/out"
cache_path = "{SCRATCH_MOUNT}/cache"
snapshots = "{SCRATCH_MOUNT}/snapshots"

[fuzz]
seed = "{DEFAULT_FUZZ_SEED}"
failure_persist_dir = "{SCRATCH_MOUNT}/fuzz"

[invariant]
failure_persist_dir = "{SCRATCH_MOUNT}/invariant"
"""

MAX_INVARIANT_RUNS: Final = 100_000
MAX_INVARIANT_DEPTH: Final = 10_000


DYNAMIC_TEST_LINKING_OFF: Final = (
    "# Halmos reads the compiled tests; dynamic test linking would rewrite `new C()` in them into\n"
    "# a cheat code that Halmos does not support.\n"
    "dynamic_test_linking = false\n"
)


def safe_foundry_toml(
    *,
    invariant_runs: int | None = None,
    invariant_depth: int | None = None,
    for_halmos: bool = False,
) -> bytes:
    """Return the bytes of the configuration written into every snapshot.

    `invariant_runs` and `invariant_depth` set the bounds of Foundry's invariant campaigns (the
    number of call sequences and the calls per sequence); they are added to `[invariant]` for the
    run trees of the variant search and are absent otherwise. Reverting calls never fail a
    campaign. `for_halmos` switches dynamic test linking off, for the symbolic trees.
    """
    text = SAFE_FOUNDRY_TOML
    if for_halmos:
        head, separator, rest = text.partition("\n[fuzz]\n")
        text = head + DYNAMIC_TEST_LINKING_OFF + separator + rest
    if invariant_runs is not None or invariant_depth is not None:
        if invariant_runs is None or invariant_depth is None:
            raise ValueError("invariant_runs and invariant_depth are set together")
        if not (1 <= invariant_runs <= MAX_INVARIANT_RUNS):
            raise ValueError(f"invariant_runs must be in [1, {MAX_INVARIANT_RUNS}]")
        if not (1 <= invariant_depth <= MAX_INVARIANT_DEPTH):
            raise ValueError(f"invariant_depth must be in [1, {MAX_INVARIANT_DEPTH}]")
        text += f"runs = {invariant_runs:d}\ndepth = {invariant_depth:d}\nfail_on_revert = false\n"
    return text.encode("utf-8")
