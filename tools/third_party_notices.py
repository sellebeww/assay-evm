"""Write the license of every Python package bundled in the runner images.

Reads the `dist-info/METADATA` of each package from an exported image filesystem and records its
version and license (`License-Expression`, then the `License:` field, then the license
classifiers). Output: `build/audit/python-licenses.json`, sorted by package name. The tool is
used to keep `THIRD_PARTY_NOTICES.md` honest; it reads the real images, not a hard-coded list.

Usage:
    python tools/third_party_notices.py --runner-fs <tar> --symbolic-fs <tar> [--out <json>]

Each `<tar>` is the output of `docker export` of the matching image. The Makefile target
`third-party-notices` creates them and runs this tool.
"""

import argparse
import json
import re
import sys
import tarfile
from pathlib import Path
from typing import Final

REPO_ROOT: Final = Path(__file__).resolve().parent.parent
DEFAULT_OUT: Final = REPO_ROOT / "build" / "audit" / "python-licenses.json"
_AGPL: Final = re.compile(r"Affero|AGPL", re.IGNORECASE)
_GPL: Final = re.compile(r"GNU General Public|GPLv3|GPL-3|(^|[^A-Za-z])GPL([^A-Za-z]|$)")
_LGPL: Final = re.compile(r"LGPL|Lesser General Public", re.IGNORECASE)
_MPL: Final = re.compile(r"Mozilla|MPL", re.IGNORECASE)


def _normalize(expression: str, free_text: str, classifiers: list[str]) -> str:
    blob = f"{expression} {free_text} {' '.join(classifiers)}"
    if _AGPL.search(blob):
        return "AGPL-3.0"
    if _LGPL.search(blob):
        return "LGPL"
    if _GPL.search(blob):
        return "GPL-3.0"
    if _MPL.search(blob):
        return "MPL-2.0"
    if expression:
        return expression
    if "Apache" in blob:
        return "Apache-2.0"
    if "BSD" in blob:
        return "BSD"
    if "MIT" in blob:
        return "MIT"
    if "Python Software" in blob or free_text.strip() == "PSFL":
        return "PSF"
    if "Public Domain" in blob or "CC0" in blob:
        return "Public Domain"
    if "ISC" in blob:
        return "ISC"
    return free_text or (classifiers[0] if classifiers else "unknown")


def _packages(tar_path: Path, env: str) -> dict[str, tuple[str, str]]:
    marker = f"/{env}/lib/python3.12/site-packages/"
    found: dict[str, tuple[str, str]] = {}
    with tarfile.open(tar_path) as archive:
        for member in archive.getmembers():
            if not (member.isfile() and marker in member.name):
                continue
            if not member.name.endswith(".dist-info/METADATA"):
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            text = handle.read().decode("utf-8", "replace")
            stem = member.name.split("site-packages/", 1)[1].split(".dist-info", 1)[0]
            name, version = stem.rsplit("-", 1)
            expression = _field(text, "License-Expression")
            free_text = _field(text, "License")
            classifiers = [
                line.split("License :: ", 1)[-1].strip()
                for line in text.splitlines()
                if line.startswith("Classifier: License")
            ]
            found[name] = (version, _normalize(expression, free_text, classifiers))
    return found


def _field(text: str, key: str) -> str:
    prefix = f"{key}:"
    for line in text.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :].strip()
    return ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="third_party_notices.py", description=__doc__)
    parser.add_argument("--runner-fs", type=Path, required=True, help="docker export of the runner")
    parser.add_argument(
        "--symbolic-fs", type=Path, required=True, help="docker export of the symbolic runner"
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)

    merged: dict[str, dict[str, object]] = {}
    for tar_path, env in ((args.runner_fs, "slither"), (args.symbolic_fs, "halmos")):
        try:
            packages = _packages(tar_path, env)
        except (OSError, tarfile.TarError) as exc:
            print(f"error: cannot read {tar_path}: {exc}", file=sys.stderr)
            return 2
        for name, (version, license_id) in packages.items():
            row = merged.setdefault(name, {"version": version, "license": license_id, "images": []})
            images = row["images"]
            assert isinstance(images, list)
            if env not in images:
                images.append(env)
    for row in merged.values():
        images = row["images"]
        assert isinstance(images, list)
        images.sort()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    copyleft = sorted(
        name
        for name, row in merged.items()
        if row["license"] in ("AGPL-3.0", "GPL-3.0", "LGPL", "MPL-2.0")
    )
    print(f"wrote {args.out} ({len(merged)} packages)")
    print(f"copyleft packages: {', '.join(copyleft) or 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
