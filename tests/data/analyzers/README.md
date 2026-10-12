# Recorded analyzer output

Golden files for the unit tests of `assay.analysis`: the raw JSON that Slither and Aderyn wrote
inside the runner image, byte for byte, so that parsing is tested without Docker.

| File | Tool | Project |
|---|---|---|
| `slither/reentrancy-single_function.json` | Slither 0.11.6 | `fixtures/reentrancy/single_function` |
| `slither/oracle_manipulation-spot_price.json` | Slither 0.11.6 | `fixtures/oracle_manipulation/spot_price` |
| `aderyn/reentrancy-single_function.json` | Aderyn 0.6.8 | `fixtures/reentrancy/single_function` |
| `aderyn/oracle_manipulation-spot_price.json` | Aderyn 0.6.8 | `fixtures/oracle_manipulation/spot_price` |

Each file was recorded once with the runner image built from `docker/runner/versions.lock`, by
running the adapter on an ingested snapshot of the fixture (the same command as
`assay dev analyze <tool> <fixture>`) and writing `RawAnalysis.output` unchanged. Paths in the
files are container paths under `/work/project`; no host path occurs. When a pinned tool version
changes, the files are recorded again and the expected values in
`tests/unit/test_analysis_adapters.py` are checked by hand.
