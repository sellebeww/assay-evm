# Assay report viewer

A static page that opens the JSON of `assay verify --json` and shows the verdict, one card per
oracle with its reasons, the bounds that ran, and the input hashes. There is no backend: the file
is read in the browser and never leaves it. Text from a report is rendered as text only, and the
page ships a Content Security Policy.

```sh
cd web
npm ci
npm run dev        # development server
npm test           # vitest (jsdom)
npm run build      # type check, then the static site in dist/
```

Create the input with `assay verify ... --json > report.json`, or `assay replay BUNDLE --json`.
The summary `result.json` of `assay ci verify` is not a report; open the report of one PoC.

The three files in `public/samples/` are **synthetic**: they are generated from the Python model
with the helper of the unit tests (`tests/unit/ci_support.py::make_report`) and show the layout.
They are not results of real runs. A unit test keeps them equal to that helper and valid against
`docs/schemas/verify.schema.json`. To regenerate them, run from `tests/unit`:

```sh
../../.venv/bin/python - <<'PY'
import json, sys
sys.path.insert(0, ".")
from ci_support import make_report
for name, v in [("rejected", "REJECTED"), ("verified", "VERIFIED_WITHIN_BOUNDS"),
                ("inconclusive", "INCONCLUSIVE")]:
    r = make_report(verdict=v)
    open(f"../../web/public/samples/{name}.json", "w").write(
        json.dumps(r.model_dump(mode="json"), indent=2, sort_keys=True) + "\n")
PY
```
