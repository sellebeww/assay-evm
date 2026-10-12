# Runner sandbox

All untrusted code (target projects, PoCs, patches, the static analyzers Slither and Aderyn, and
Halmos) runs inside the runner image, or, for Halmos, inside the symbolic runner image, which is
the runner plus Halmos. This document describes the runner at its current stage, the
properties that tests check against the real image, and what the sandbox does not cover.

## Current stage

Implemented:

- the runner image (`docker/runner/`) and its smoke check (`make image-check`);
- `SandboxRunner` (`src/assay/sandbox/`): one allowlisted command per container, under the
  container policy below;
- ingest (`src/assay/ingest/`): snapshot, `tree_sha256`, `foundry.toml` rewrite, rejection of
  symlinks out of the tree, path traversal, special files and inline Foundry configuration,
  size and file-count limits;
- the Foundry adapter (`src/assay/analyzers/foundry/`) and the hidden developer command
  `assay dev forge-test <dir>`;
- the static analyzers Slither and Aderyn in the image, their adapters (`src/assay/analysis/`)
  and the hidden developer command `assay dev analyze <slither|aderyn> <dir>`
  ([Static analyzers](#static-analyzers));
- the symbolic runner image with Halmos and its solver z3, built for linux/amd64 only, and the
  symbolic oracle's adapter (`src/assay/oracles/symbolic/`) ([Halmos](#halmos));
- integration tests against the real image (`make test-integration`), including the
  determinism test;
- the security suite (`make test-security`, `tests/security/`) for the claims S1 to S9;
- the CI job `integration`, which builds the image and runs both suites on every pull request.

The [table of claims](#security-claims) names the test of each claim.

## Image contents

Every input is pinned in `docker/runner/versions.lock`. The build reads it as its only source of
versions and checksums.

| Component | Pin | Location in the image |
|---|---|---|
| Foundry | v1.8.4, sha256 per platform; only `forge` is installed | `/usr/local/bin/forge` |
| solc | 0.8.36, official static build, sha256 per platform | `/opt/assay/bin/solc` |
| forge-std | v1.17.0, commit `f3dae6e`, sha256 of the source archive | `/opt/assay/lib/forge-std` |
| Python | CPython 3.12.15 from python-build-standalone (release 20261001), sha256 per platform; without pip, `ensurepip`, IDLE, Tkinter and the standard library's tests | `/opt/assay/python` |
| Slither | 0.11.6 with its dependencies, every distribution pinned by sha256 in `docker/runner/slither-requirements.txt` (wheels only); the sha256 of that file is in `versions.lock` | virtual environment `/opt/assay/slither`, command `/usr/local/bin/slither` |
| `solc_select` stand-in | `docker/runner/solc_select/`: reports no installed compiler and refuses every download; solc-select itself is not installed | in the Slither environment |
| Aderyn | v0.6.8, official release archive, sha256 per platform | `/usr/local/bin/aderyn` |
| The pinned solc as Aderyn's one installed compiler | a symlink to `/opt/assay/bin/solc` in svm-rs's layout | `/opt/assay/share/svm/0.8.36/solc-0.8.36` |
| Dynamic loader and the libraries that forge, Aderyn, Python and its extension modules link against | copied from `debian:trixie-slim`, pinned by index digest | `/lib/...`, `/usr/lib/...` |
| Dockerfile frontend | `docker/dockerfile:1.27.1`, digest | build time only |

The symbolic runner image (`assay-runner-symbolic:dev`, Dockerfile target `runner-symbolic`) is
the runner image above plus:

| Component | Pin | Location in the image |
|---|---|---|
| Halmos | 0.3.3 with its dependencies, every distribution pinned by sha256 in `docker/runner/halmos-requirements.txt` (wheels only); the sha256 of that file is in `versions.lock` | virtual environment `/opt/assay/halmos`, command `/usr/local/bin/halmos` |
| z3 | 4.12.6.0, from the pinned `z3-solver` wheel: the Python binding Halmos builds its queries with and the `z3` binary that answers them | `/opt/assay/halmos/bin/z3` |

It is built for linux/amd64 only, because the z3-solver release that Halmos pins has no
linux/arm64 wheel; on an arm64 host it runs under emulation. Yices, Halmos's default solver, is
not installed: its binary stops with an illegal-instruction signal under that emulation
([ADR 0018](adr/0018-halmos-in-a-linux-amd64-image.md)).

The runtime image is assembled from scratch. Besides the components above it contains only
`/etc/passwd`, `/etc/group`, `/etc/ld.so.cache` and the empty directories `/tmp` and `/work`.
There is no shell, no package manager and no compiler other than solc. The one interpreter is
the Python that runs Slither ([ADR 0015](adr/0015-static-analyzers-in-the-runner-image.md)).

Build-time properties:

- Every download is verified with `ADD --checksum`; a mismatch aborts the build.
- No system package manager runs during the build. pip runs in two build stages, to install the
  wheels listed in `slither-requirements.txt` and in `halmos-requirements.txt`, with
  `--require-hashes --no-deps --only-binary :all:` (no dependency resolution, no source builds);
  the build checks the sha256 of each file against `versions.lock`. pip does not reach the
  runtime images.
- Build arguments have no defaults. A build without the values from `versions.lock` fails.
- The build fails if the runtime filesystem contains a set-uid or set-gid file.
- The image runs as uid and gid 10001 by default.

Settings fixed by the image for every run:

| Variable | Value | Effect |
|---|---|---|
| `FOUNDRY_OFFLINE` | `true` | forge never tries to download a compiler or dependency; overrides `offline` in a project's `foundry.toml` |
| `FOUNDRY_SOLC` | `/opt/assay/bin/solc` | the baked-in compiler is used; overrides `solc` and `solc_version` in a project's `foundry.toml` |
| `HOME` | `/tmp` | per-user state lives on the tmpfs and disappears with the container |
| `XDG_DATA_HOME` | `/opt/assay/share` | Aderyn's compiler lookup (svm-rs) finds the pinned solc as its one installed version and downloads nothing |
| `PYTHONSAFEPATH`, `PYTHONNOUSERSITE`, `PYTHONDONTWRITEBYTECODE` | `1` | Python never imports a module from the working directory (the project) or a user directory, and writes no byte code |
| `PYTHONHASHSEED` | `0` | the order of Slither's results repeats from run to run |

Foundry v1.8.4 does not read `ffi` or `fs_permissions` from the environment, so the image cannot
force them. The controls for these settings are in ingest: the project's `foundry.toml` is
replaced, and projects with inline configuration are rejected (see [Ingest](#ingest)).

The platform choice (native linux/arm64 or linux/amd64, no emulation by default) is recorded in
[ADR 0008](adr/0008-runner-platform.md); the exception for the symbolic image in
[ADR 0018](adr/0018-halmos-in-a-linux-amd64-image.md).

## Container policy

`SandboxRunner` starts every container with these flags; `make image-check` uses the same
policy:

| Flag | Purpose |
|---|---|
| `--network none` | no network connectivity: only the loopback interface is configured, and there are no routes |
| `--read-only` | the root filesystem cannot be written |
| `--tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m` | small writable scratch space, no executables |
| `--cap-drop ALL` | no Linux capabilities |
| `--security-opt no-new-privileges` | no privilege gain through set-uid binaries |
| `--user 10001:10001` | non-root user |
| `--pids-limit 256`, `--memory 2g`, `--memory-swap 2g`, `--cpus 2` | resource limits; equal memory and memory-swap values mean no swap |
| `--pull never` | a missing image is an error; Docker never contacts a registry |
| `--log-driver none` | output is streamed to the runner only, never stored by the Docker daemon |
| `--rm`, `--name assay-…`, `--label assay.role=…` | removal after exit and identification for cleanup |

With `--network none`, the kernel's fallback tunnel devices (`gre0`, `sit0` and similar) may be
listed inside the container. They are down and have no addresses.

Mounts: the project snapshot is mounted read-only at `/work/project`, which is also the working
directory. One scratch directory is mounted writable at `/work/scratch` and receives forge's
build output, cache and fuzz failure records. Nothing else from the host is visible. Mount paths
that contain a comma, a double quote or a control character are refused, and the project and
scratch directories must not contain each other.

Environment: Docker passes nothing from the host environment to the container. The container
sees only the image's environment (the table above and `NO_COLOR=1`), and the runner sets these
values again explicitly. The docker CLI itself runs with a reduced host environment: `HOME`, a
fixed `PATH`, and the `DOCKER_*` connection variables.

Each container runs exactly one command, passed as an argument vector. No shell is involved.

## SandboxRunner

Argument allowlist. Before Docker is called, the argument vector must match:

| Command | Switches | Options (value in the next item) |
|---|---|---|
| `forge build` | `--json`, `--force` | none |
| `forge test` | `--json`, `--force`, one of `-v`, `-vv`, `-vvv` | `--match-test`, `--no-match-test`, `--match-contract`, `--no-match-contract` (regular expressions over letters, digits and `_$.*+?\|()[]^`); `--match-path`, `--no-match-path` (globs without `..`); `--fuzz-seed` (decimal or `0x` hex); `--fuzz-runs` (1 to 9999999); `--threads` (only `1`, see ADR 0014) |
| `forge inspect <contract> <field>` | `--json`, `--force`, after the two arguments | none; `<contract>` is `[<path>.sol:]<Name>` with a relative path whose segments start with a letter, digit or `_`; `<field>` is one of `abi`, `events`, `methodIdentifiers`, `storageLayout` |
| `slither <target>` | `--fail-none`, `--disable-color` | `--json` with the value `-` only (the report goes to standard output); `<target>` is `.` or a relative path inside the project whose segments start with a letter, digit or `_` |
| `aderyn <target>` | none | `--output` with a `.json` file directly in `/work/scratch`; `<target>` as for Slither |
| `halmos` | `--no-status` | required: `--root /work/project`, `--forge-build-out /work/scratch/out`, `--json-output` with a `.json` file directly in `/work/scratch`; optional: `--function` (`check_` or `check_<word>_`), `--loop` (1 to 99), `--solver` (only `z3`), `--solver-timeout-assertion` (1 to 9999 seconds, written `<n>s`), `--solver-threads` (1 to 4) |

Everything else is rejected: other programs (`python3`, `crytic-compile`, `solc-select`, `z3`
among them) and subcommands, Halmos's `--ffi`, `--config`, `--solver-command` and query dumps, positional arguments (except the two of `forge inspect` and the target
of an analyzer), other `forge inspect` fields such as `bytecode` or `standardJson`, the
`--flag=value` form, repeated flags, values that start with `-`, and items that contain
whitespace or control characters. At most 32 items, each at most 256 characters.

Default limits (`SandboxLimits`):

| Limit | Default |
|---|---|
| Wall-clock time | 600 s |
| Memory (no swap) | 2048 MiB |
| CPUs | 2 |
| Processes | 256 |
| `/tmp` tmpfs | 64 MiB |
| Captured output | 16 MiB for stdout and 16 MiB for stderr |

Run sequence:

1. Check the argument vector and the mount paths.
2. Resolve the image tag to its content-addressed id and start the container by that id, so the
   reported `image_id` is the image that ran.
3. Read stdout and stderr concurrently. Output beyond the limit is read and discarded, and the
   result is flagged `truncated`.
4. At the wall-clock limit, kill the container (`docker kill --signal KILL`) and flag the result
   `timed_out`.
5. After every run, confirm that no container with the run's name exists, force-removing it if
   necessary. A container that cannot be removed is an error.
6. Read the Docker daemon's event log for an `oom` event of the container and set `oom_killed`.
   (`--rm` removes the container before its state could be inspected.)

Result (`SandboxResult`): `argv`, `exit_code`, `stdout`, `stderr`, `truncated`, `timed_out`,
`oom_killed`, `duration_s`, `image_id`. `SandboxRunner.remove_containers()` removes every
container with the label `assay.role=sandbox`, for cleanup after an interrupted session.
`SandboxRunner.image_labels()` reads the labels of the image (`docker image inspect`); the
`assay.<tool>.version` labels name the pinned tool versions, which an evidence bundle records.

## Ingest

`create_snapshot(source, dest)` turns a project directory into:

```
<dest>/tree/       the snapshot, mounted read-only into the container
<dest>/evidence/   the project's own configuration files, never used by a tool
```

It works in two passes. The first pass walks the tree, applies the rules below and checks the
limits, without writing anything. The second pass copies the files, opening each one without
following symlinks and re-checking its type and size; a tree that changes during the copy is
rejected. The snapshot contains only directories (mode 0755) and regular files (mode 0644).

Entries left out:

| Entry | Where |
|---|---|
| `.git`, `node_modules`, `.assay` | anywhere |
| `out`, `cache` (Foundry build output) | project root |
| `foundry.toml`, `remappings.txt`, `slither.config.json`, `aderyn.toml`, `halmos.toml` in any letter case (kept in `evidence/` instead) | project root |
| names starting with `.env`; names ending in `.pem`, `.key`, `.p12`, `.pfx`, `.jks`, `.keystore`; names starting with `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519` | anywhere |
| files that contain a PEM private key block | anywhere |

A left-out entry is never read, so a left-out symlink is never followed. Every left-out path is
listed in the result with its reason.

Rejections (the whole project is refused; `assay dev forge-test` exits with code 5):

| Code | Cause |
|---|---|
| `symlink_outside_tree` | a symlink resolves outside the project directory |
| `symlink_unresolvable` | a symlink is dangling or part of a loop |
| `symlink_to_directory` | a symlink resolves to a directory (symlinks to regular files inside the tree are copied as regular files) |
| `symlink_to_excluded_path` | a symlink resolves into a left-out entry, such as `.env` |
| `special_file` | a FIFO, socket or device file |
| `unsafe_path` | a path that is not valid UTF-8 or contains a control character |
| `inline_config` | a `.sol` file contains `forge-config` ([ADR 0009](adr/0009-reject-inline-foundry-config.md)) |
| `too_many_files`, `too_many_directories`, `file_too_large`, `tree_too_large` | a limit is exceeded |
| `changed_during_copy`, `unreadable` | the tree changed between the passes, or a file cannot be read |

Default limits (`IngestLimits`): 20,000 files, 10,000 directories, 16 MiB per file, 256 MiB in
total. Left-out entries do not count.

`tree_sha256` is computed over the snapshot as written, including the rewritten `foundry.toml`:
the sha256 of the concatenation, over all regular files sorted by the UTF-8 bytes of their
relative POSIX path, of `<path> NUL <sha256 hex of the content> LF`. File modes, timestamps and
empty directories do not take part. The same tree gives the same hash on every machine, and two
projects that differ only in their own `foundry.toml` have the same hash.

The rewritten `foundry.toml`:

- `ffi = false`, `fs_permissions = []`, no `allow_paths` or `include_paths`;
- `solc` fixed to `/opt/assay/bin/solc`, `auto_detect_solc = false`, `offline = true`;
- no RPC endpoints and no Etherscan settings;
- sources in `src/`, tests in `test/`, scripts in `script/`, `libs = []`,
  `auto_detect_remappings = false`, and one remapping, `forge-std/` to the read-only forge-std
  inside the image;
- `out`, `cache_path`, `snapshots` and the fuzz and invariant failure directories under
  `/work/scratch`;
- fuzz seed `0x1`, so fuzz and invariant results repeat unless a run passes `--fuzz-seed`.

The project's `remappings.txt` is removed because forge reads it even when `foundry.toml` lists
remappings. Both configuration files are matched in any letter case: on a case-insensitive
filesystem (the macOS default, shared into Docker Desktop), forge opens `Remappings.txt` when it
looks for `remappings.txt`. Inline configuration is rejected because forge applies it on top of `foundry.toml`;
with the pinned Foundry it can widen `fs_permissions` (ADR 0009).

Patches are applied by ingest's own parser, never by `git apply`: every path is checked before
anything is written, symlinks in the tree are never followed, and either every file applies or
nothing is written. The accepted format and the refused paths are described in
[the oracle documentation](oracles.md#patch-format).

## Foundry adapter

`build()` runs `forge build --json`. On success it reports nothing else; on failure it returns
the compiler errors (type, code, message, file, offsets). Warnings are not reported.

`test()` runs `forge test --json -vv --threads 1` (`-vv` adds the `console.log` lines; one thread
keeps fuzz campaigns deterministic, [ADR 0014](adr/0014-single-threaded-forge-test-runs.md)) and
normalizes the output: suites sorted by name, tests sorted by name, and per test the status (`success`,
`failure`, `skipped`), the reason, the kind (`unit`, `fuzz`, `table`, `invariant`), gas figures,
runs, invariant calls and reverts, the log lines, the raw logs as events (emitting address,
topics and data in lowercase hex), so that a consumer can check which contract emitted an event,
and for a failing fuzz or invariant test its counterexample (the calldata of each call, forge's
rendering of the arguments, and the index of the failing fuzz run).
Durations, traces and labels are dropped, so the same snapshot and image give byte-identical
results. Forge output is parsed with
strict models and limits on counts and string lengths; malformed output is a structured error.

A failing test is a result. No usable result is an error: a timeout (never a pass), an
out-of-memory kill, output that exceeded the limit or did not parse, or forge exiting with an
error before any result (for example a compilation error).

`assay dev forge-test <dir>` snapshots the directory, runs `test()` and prints the normalized
results and `tree_sha256` as JSON. Exit codes: 0 every test passed; 1 a test failed or forge
failed before producing results; 2 usage error; 3 inconclusive (timeout, unusable output, or no
test passed); 4 Docker, the image or memory; 5 the project was rejected at ingest.

## Static analyzers

Slither and Aderyn run like forge: one allowlisted command per container, on an ingested
snapshot mounted read-only, with one writable scratch directory, no network, the limits above
and the same container policy. The adapters are in `src/assay/analysis/`
([ADR 0015](adr/0015-static-analyzers-in-the-runner-image.md)).

| Tool | Command | Report | Exit code |
|---|---|---|---|
| Slither | `slither . --json - --fail-none --disable-color` | JSON on standard output | 0 with or without results; anything else is a failure |
| Aderyn | `aderyn . --output /work/scratch/aderyn.json` | JSON file in the scratch directory | 0 with or without results; anything else is a failure |

Slither compiles the project through crytic-compile, which runs `forge build --build-info`
inside the same container, offline and with the pinned solc. Aderyn compiles with the same solc,
found as svm-rs's one installed version. Neither tool downloads anything. The project's
`slither.config.json` and `aderyn.toml` never reach them: ingest leaves both out (see
[Ingest](#ingest)).

Analyzer output is untrusted input (threat T13):

- The raw report is read as bytes: Slither's from standard output (16 MiB limit of the runner);
  Aderyn's file from the host side of the scratch directory, opened without following a
  symlink, accepted only as a regular file and only up to the size limit.
- Before Python's JSON parser sees it, one iterative pass checks the size (16 MiB), the nesting
  depth (64), the length of every string (100,000 characters as written) and the number of
  values (2,000,000). The parser then rejects duplicate keys, `NaN`, `Infinity` and integers of
  more than 100 digits.
- Strict models read only the fields that Assay uses (detector, severity as reported, message,
  locations); the rest is ignored and never interpreted. At most 10,000 results per report.
- A reported path must lie in the project: a path under `/work/project` becomes relative, and
  any other absolute path, `..` component or backslash is an error. Slither elements in
  dependencies (forge-std in the image) are left out of the locations.
- Every violation is an `AnalyzerOutputError` with a stable code (`output_too_large`,
  `too_deep`, `string_too_long`, `too_many_values`, `malformed_json`, `duplicate_key`,
  `not_utf8`, `schema_mismatch`, `path_outside_project`, `too_many_results`), never a crash and
  never an action.

`assay dev analyze <slither|aderyn> <dir>` snapshots the directory, runs the tool, stores the raw
report as a content-addressed blob in the ledger, parses it and records a `scan` with one
`observation` per result (ledger migration 2). Results are candidate (unverified) hints:
recording them creates no finding and no claim and changes no status. The command prints the
tool and version, the exit code, the duration, the number of results, the tree hash and the
hash of the raw report. Exit codes: 0 recorded; 1 the tool failed; 2 usage error; 3 time limit
or unusable output (the raw report is still stored); 4 Docker, the image, the ledger or memory;
5 the project was rejected at ingest.

## Halmos

The symbolic oracle runs Halmos like the other tools: one allowlisted command per container, on
a run tree mounted read-only, with one writable scratch directory, no network and the container
policy above, in the symbolic runner image. Its limits differ: 900 s of wall-clock time, 4096 MiB
of memory and a 256 MiB `/tmp` tmpfs, where Halmos writes its solver queries.

| Tool | Command | Report | Exit code |
|---|---|---|---|
| Halmos | `halmos --root /work/project --forge-build-out /work/scratch/out --function <prefix> --loop 3 --solver z3 --solver-timeout-assertion 60s --solver-threads 1 --json-output /work/scratch/halmos.json --no-status` | JSON file in the scratch directory | 0 or 1 with a report; anything without a report is a failure |

Halmos compiles the run tree itself with `forge build` inside the same container, offline and
with the pinned solc. The run tree's configuration switches Foundry's dynamic test linking off,
because it rewrites `new C()` in tests into a cheat code that Halmos does not support. Halmos
finds z3 in its own virtual environment and never downloads a solver. A project cannot change
its options: ingest leaves `halmos.toml` out, the allowlist has no `--ffi` or `--config`, and the
symbolic oracle refuses sources that contain a Halmos option annotation (`custom:halmos`) before
Halmos runs.

The report is untrusted input, read like Aderyn's (no symlink, a regular file, at most 16 MiB),
bounded before parsing, and validated by strict models; see
[the SymbolicOracle](oracles.md#symbolicoracle).

## Security claims

The security suite (`make test-security`, files in `tests/security/`, marker `integration`)
checks each claim against the real runner image under the container policy above. The CI job
`integration` builds the image from `versions.lock` and runs the suite on every pull request.

| Id | Claim | Checked by |
|---|---|---|
| S1 | A hostile `foundry.toml` (FFI on, read-write access to `/`, `allow_paths = ["/"]`), also when named in another letter case, has no effect: `vm.ffi` fails with "FFI is disabled"; `vm.readFile("/etc/passwd")`, reading a project file and writing to the scratch directory fail as not allowed. A project's `remappings.txt`, in any letter case, does not replace forge-std. Inline configuration is rejected at ingest, before Docker is called. A hostile `slither.config.json` or `aderyn.toml` (detectors switched off, paths filtered, another framework or compiler, environment variables) changes no result, and Python files in the project (a module named like Slither's, `sitecustomize`, `usercustomize`) are never imported; a control shows that the same configuration inside the snapshot would change the results. A hostile `halmos.toml` (FFI on, loop bound 1, a solver command) changes neither the bounds nor the result; a Halmos option annotation is refused before any Halmos container starts; a property that calls `vm.ffi` gets no output from it | `test_s1_project_config.py`, `test_s1_analyzer_config.py`, `test_s1_halmos_config.py` |
| S2 | A `foundry.toml` that names another compiler (a file in the project, by relative or absolute path, or another solc version) is ignored: the build succeeds and the artifacts record the solc pinned in `versions.lock`. This holds after ingest and also with the project mounted directly, where only the runner's `FOUNDRY_SOLC` applies | `test_s2_compiler.py` |
| S3 | Enormous output is truncated and the runner does not run out of memory: 64 MiB on each of standard output and standard error are cut at the limit, and the runner's peak memory grows by far less than what went through the pipes | `test_s3_s6_container_policy.py` (`test_s3_…`); integration test `test_output_is_truncated_at_the_limit` for forge output |
| S4 | An endless loop ends with `timed_out = true` and the container is gone | `test_s3_s6_container_policy.py` (`test_s4_…`); integration test `test_timeout_kills_and_removes_the_container` for a forge run |
| S5 | A fork bomb is contained by the pids limit: forking stops with `EAGAIN` below the limit, and the forked processes end with the container | `test_s3_s6_container_policy.py` (`test_s5_…`) |
| S6 | The container has no network beyond loopback: no route, only `lo` is up, TCP and UDP to the internet (IPv4 and IPv6), to the Docker Desktop host and to the default bridge gateway fail, names do not resolve; a connection to a loopback listener works | `test_s3_s6_container_policy.py` (`test_s6_…`) |
| S7 | The root filesystem and the project mount are read-only; only `/work/scratch` and the `/tmp` tmpfs accept writes. With forge's file access opened to `/` (project mounted directly, bypassing ingest), creating or removing files and directories in `/`, `/etc`, `/work`, `/opt/assay` and `/work/project` fails with "Read-only file system", and overwriting `solc`, `forge` or `/etc/passwd` fails | `test_s7_read_only_root.py` |
| S8 | Symlinks out of the tree (absolute, relative, to a directory, through a chain of links, dangling) and into a left-out entry such as `.env` are rejected at ingest: `assay dev forge-test` exits with code 5, calls no Docker command and prints nothing of the target. Paths with `..` components, absolute paths and backslashes are rejected. An argument vector outside the allowlist raises `ArgvRejected` before any Docker command runs. A patch with path traversal (relative or absolute), a symlink, a binary file or a protected path stops `assay verify` with exit code 5 before any container starts, and nothing outside the working copy is written | `test_s8_ingest_and_argv.py`, `test_s8_patches.py`; unit tests |
| S9 | The process policy: the container sees no variable of the host environment (a sentinel and a model API key set in the runner's environment do not reach it), runs as uid and gid 10001, holds no capability (effective, permitted and bounding sets are empty) and has `NoNewPrivs` set | `test_s3_s6_container_policy.py` (`test_s9_…`) |

Two methods recur in the suite. Where a claim depends on a single layer, the test removes the
layers in front of it: S7 and the second half of S2 mount the project directly with a permissive
`foundry.toml`, so a denial can only come from the container or the runner environment. S3 to S6
and S9 run the Python that the image carries for Slither with exactly the container arguments of
`SandboxRunner`; only the argv allowlist, which would refuse that program, is skipped, so every
limit they observe is enforced by the container. Where a
claim says that Docker is not called (S1 inline configuration, S8), the test records every
command the runner sends to the real Docker CLI; a control test shows that an allowed run is
recorded in full.

Determinism is checked by the integration test `tests/integration/test_determinism.py`: the
smoke project and the probe project (unit, fuzz, table and invariant tests) run three times
each, from fresh snapshots in different directories, and the sha256 of the normalized JSON must
be the same for all three runs. The CLI output of `assay dev forge-test` for the smoke project is
compared the same way.

Across platforms: on 2026-10-03, `tools/fixture_check.py --verbose` printed byte-identical
output for the fixture `reentrancy/single_function` with the linux/arm64 image and with the
linux/amd64 image under emulation, including the counterexample values found by fuzzing. This is
a manual check, not a test; it is repeated when fixtures are added.

## What the sandbox does not cover

The tests check the properties listed above for the pinned image and the documented container
policy. Passing them does not make the sandbox a complete barrier. Not covered:

- Kernel vulnerabilities, including unknown ones. Every container shares the kernel of the host
  or of the Docker Desktop virtual machine, and a kernel flaw can lead to a container escape.
- Flaws in the Docker Desktop virtual machine and its file sharing, in the Docker Engine, or in
  the container runtime.
- Hardware side channels, such as speculative execution or cache timing.
- Access to the Docker daemon. Whoever can use the Docker socket controls the daemon; on Linux,
  membership in the `docker` group is equivalent to root. Assay needs this access and does not
  restrict it.
- Denial of service of the local run. Within the limits (2 CPUs, 2 GiB, 600 s, 256 processes), a
  hostile project can keep the machine busy and make a run end without a result.
- Writes during a run. The project's tests can write to `/tmp` (a 64 MiB tmpfs) and to the
  scratch directory while the run lasts. The scratch directory lives on the host and holds build
  output; Assay does not execute anything from it.
- The pinned releases themselves. The checksums in `versions.lock` detect a changed download, not
  a release that was already hostile when it was pinned.
- Correctness of forge, solc, Slither, Aderyn, Halmos and z3. A bug in any of them can change a result
  without crossing the sandbox boundary; analyzer results are unverified hints in any case.
- Other container setups. The suite runs on the native platform with Docker Engine or Docker
  Desktop (ADR 0008); rootless Docker, Podman and other runtimes are not tested.

A container escape cannot be fully excluded. The defenses are layered (no network, read-only
root, no capabilities, non-root user, resource limits, minimal image) to make one harder.

## Known limitations at this stage

- The image ID is not reproducible across builds or platforms, because layer timestamps are not
  normalized and each platform uses different binaries. See ADR 0008. `assay replay` therefore
  accepts another image when its tool versions and `versions.lock` match the bundle, and says so
  (ADR 0013).
- The symbolic image is linux/amd64 only and runs under emulation on arm64 hosts: slower, and
  with an emulator inside the trust boundary for Halmos runs (ADR 0018). Every other run stays
  native.
- Halmos's contract addresses differ from Foundry's. A counterexample that names a deployed
  contract's address cannot be replayed with Foundry; it is reported as `flaky_counterexample`,
  never as a variant.
- The analyzers compile with the single pinned solc. A project whose pragma excludes 0.8.36
  cannot be analyzed; Aderyn then fails instead of downloading another compiler.
- The Python interpreter in the image is there for Slither only, but any program inside the
  container could start it. The container policy limits what it can do, as for forge.
- `PYTHONHASHSEED` is fixed so that Slither's output repeats; hash randomization does not protect
  Slither's dictionaries against crafted collisions. Within the limits, this is at worst a
  denial of service of the local run.
- The snapshot layout is fixed: `src/`, `test/` and `script/`, with forge-std from the image as
  the only remapped library. Libraries vendored under `lib/` are copied but can be imported only
  by relative path.
- The inline-configuration check is textual: a Solidity file that only mentions `forge-config`
  is rejected too.
- `oom_killed` comes from the Docker daemon's event log, queried with host timestamps and a
  margin of a few seconds. A larger clock difference between the host and the Docker virtual
  machine could hide the event.
- On Linux hosts, files that the container user (uid 10001) writes into the scratch directory
  belong to that user, so the host user may be unable to delete them and temporary scratch
  directories can remain after a run. Docker Desktop on macOS maps ownership to the host user.
- With `-vv`, forge includes traces of invariant runs in its JSON output (about 300 KB for one
  invariant test at 256 runs). The parser drops them, but they count toward the output limit.
- Overwriting an existing file of the image is denied by file permissions (the non-root user)
  before the read-only mount is consulted. The read-only mount itself shows when entries are
  created or removed (S7).
