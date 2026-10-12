# Captured forge output

Inputs for the unit tests of the forge output parser. Both files were produced by the pinned
toolchain (Foundry v1.8.4, solc 0.8.36, forge-std v1.17.0) through the sandbox runner, on a
snapshot made by ingest (so with the rewritten `foundry.toml` and its fixed fuzz seed).

| File | Project | Command |
|---|---|---|
| `probe-test.json` | `probe/` | `forge test --json -vv --threads 1` |
| `broken-build.json` | `broken/` | `forge build --json` |

`probe/` covers every test kind (unit, fuzz, table, invariant) and status (success, failure,
skipped) that the parser normalizes, plus a `console.log` line. `broken/` does not compile.

Edit made after capture, to a field the parser does not read: every `traces` array in
`probe-test.json` was replaced by an empty array to keep the file small (the invariant test alone
produced about 300 KB of traces). The `counterexample` of the failing fuzz test is kept as
captured; the parser reads its calldata, arguments and run index.

The integration tests run both projects again and compare the normalized results with these
files, so a toolchain change that alters the output shows up as a failing test. To refresh the
files after such a change, rerun the two commands above on snapshots of `probe/` and `broken/`
and repeat the edit.
