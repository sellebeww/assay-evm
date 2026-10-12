"""S8 for patches: a patch with path traversal, a symlink or a binary file stops `assay verify`
before anything runs in the sandbox, and nothing outside the working copy is written.

Docker calls are recorded on the real runner (`docker_calls`): the runner image is looked up
(its digest goes into the ledger), but no container is started.
"""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from assay.cli.main import app

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("runner")]

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures" / "reentrancy" / "single_function"
MARKER = "outside-marker-2b7c"

PATCHES = {
    "traversal": b"--- a/src/../../../outside/Target.sol\n+++ b/src/../../../outside/Target.sol\n"
    b"@@ -1 +1 @@\n-// " + MARKER.encode() + b"\n+// replaced\n",
    "absolute": b"--- {outside}/Target.sol\n+++ {outside}/Target.sol\n"
    b"@@ -1 +1 @@\n-// " + MARKER.encode() + b"\n+// replaced\n",
    "symlink": b"diff --git a/src/Link.sol b/src/Link.sol\nnew file mode 120000\n"
    b"--- /dev/null\n+++ b/src/Link.sol\n@@ -0,0 +1 @@\n+{outside}/Target.sol\n",
    "binary": b"diff --git a/src/blob.bin b/src/blob.bin\nnew file mode 100644\n"
    b"GIT binary patch\nliteral 4\nLcmZ?wbN~PV\n",
    "protected": b"--- a/poc/VaultReentrancy.t.sol\n+++ b/poc/VaultReentrancy.t.sol\n"
    b"@@ -1 +1 @@\n-// SPDX-License-Identifier: MIT\n+// replaced\n",
}
CODES = {
    "traversal": "path_traversal",
    "absolute": "path_traversal",
    "symlink": "symlink",
    "binary": "binary_file",
    "protected": "protected_path_modified",
}


@pytest.mark.parametrize("name", sorted(PATCHES))
def test_a_hostile_patch_stops_before_any_container_starts(
    name: str, tmp_path: Path, docker_calls: list[str]
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "Target.sol"
    target.write_text(f"// {MARKER}\n")
    patch = tmp_path / "hostile.diff"
    patch.write_bytes(PATCHES[name].replace(b"{outside}", str(outside).encode()))

    result = CliRunner().invoke(
        app,
        [
            "verify",
            "--base",
            str(FIXTURE),
            "--patch",
            str(patch),
            "--poc",
            str(FIXTURE / "poc"),
            "--ledger",
            str(tmp_path / ".assay" / "ledger.db"),
        ],
    )

    assert result.exit_code == 5, result.output
    assert CODES[name] in result.stdout
    assert "run" not in docker_calls, docker_calls
    assert docker_calls == ["image"]
    assert target.read_text() == f"// {MARKER}\n"
    assert sorted(path.name for path in outside.iterdir()) == ["Target.sol"]
