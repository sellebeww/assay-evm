"""Fixed paths inside the runner container and the runner image."""

from typing import Final

# Mount points. The project snapshot is mounted read-only; the scratch directory is the only
# writable host directory and receives forge's build output and cache.
PROJECT_MOUNT: Final = "/work/project"
SCRATCH_MOUNT: Final = "/work/scratch"

# Toolchain locations baked into the runner image (docker/runner/Dockerfile).
SOLC_PATH: Final = "/opt/assay/bin/solc"
FORGE_STD_SRC: Final = "/opt/assay/lib/forge-std/src/"

# Non-root user of the runner image.
CONTAINER_USER: Final = "10001:10001"
