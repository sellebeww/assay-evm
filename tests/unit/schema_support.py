"""Check a `--json` document of a command against its exported JSON Schema."""

import json
from pathlib import Path

import jsonschema

SCHEMAS = Path(__file__).resolve().parents[2] / "docs" / "schemas"


def assert_valid(command: str, document: object) -> None:
    schema = json.loads((SCHEMAS / f"{command}.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(document, schema, cls=jsonschema.Draft202012Validator)
