"""Export the JSON Schemas of the `--json` output of every command (`make schemas`).

Writes `docs/schemas/<command>.schema.json` from the Pydantic models in
`assay.cli.documents`, so the schemas are never written by hand. With `--check` nothing is
written: the exit status is 1 when a file differs from what the models give, or is missing or
unexpected. The files hold no timestamps or host paths.

Exit status: 0 up to date (or written), 1 out of date with `--check`.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from assay.cli.documents import SCHEMAS

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
DEFAULT_DIR: Final = REPO_ROOT / "docs" / "schemas"
SCHEMA_DIALECT: Final = "https://json-schema.org/draft/2020-12/schema"


def schema_files() -> dict[str, str]:
    """File name to content, for every command."""
    files: dict[str, str] = {}
    for command, model in sorted(SCHEMAS.items()):
        schema = model.model_json_schema(mode="serialization")
        schema = {"$schema": SCHEMA_DIALECT, "title": f"assay {command} --json", **schema}
        files[f"{command}.schema.json"] = json.dumps(schema, indent=2, sort_keys=True) + "\n"
    return files


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_DIR, help="Directory of the schemas.")
    parser.add_argument("--check", action="store_true", help="Compare instead of writing.")
    args = parser.parse_args(argv)
    out: Path = args.out
    wanted = schema_files()
    if args.check:
        problems = [
            f"differs or missing: {name}"
            for name, text in wanted.items()
            if not (out / name).is_file() or (out / name).read_text(encoding="utf-8") != text
        ]
        if out.is_dir():
            problems += [
                f"unexpected: {path.name}"
                for path in sorted(out.glob("*.json"))
                if path.name not in wanted
            ]
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1 if problems else 0
    out.mkdir(parents=True, exist_ok=True)
    for name, text in wanted.items():
        (out / name).write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {len(wanted)} schemas to {out.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
