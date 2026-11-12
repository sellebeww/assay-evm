# Report viewer

`web/` holds a static page (Vite, React, TypeScript) that opens the JSON of `assay verify --json`
and shows the verdict, one card per oracle with its reasons and locations, the bounds that ran and
the input hashes. There is no backend: the file is read in the browser and never uploaded. Text
from a report is shown as text, and the page sets a Content Security Policy.

```sh
cd web && npm ci && npm run dev
```

Produce a report with `assay verify ... --json > report.json` (or `assay replay BUNDLE --json`)
and drop it on the page. The summary `result.json` of `assay ci verify` is not a report; open the
report of one PoC. The three examples on the page are synthetic and say so. See `web/README.md`
for the tests and the build.
