"""Allowlist of commands that the sandbox runner may execute.

Only argument vectors accepted by `check_argv` reach Docker. Everything else is rejected before
any process starts. The allowlist is deliberately small and grows one tested entry at a time.
"""

import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final

MAX_ARGV_ITEMS: Final = 32
MAX_ARG_LENGTH: Final = 256

# Test and contract filters are regular expressions evaluated by forge (Rust `regex`, linear
# time). The character set excludes whitespace, quotes, backslashes and anything shell-like.
_NAME_FILTER: Final = re.compile(r"[A-Za-z0-9_$.*+?|()\[\]^]{1,200}")
# Path filters are globs relative to the project root.
_PATH_FILTER: Final = re.compile(r"[A-Za-z0-9_.*?/\-]{1,200}")
_FUZZ_SEED: Final = re.compile(r"0x[0-9a-fA-F]{1,64}|[0-9]{1,78}")
_FUZZ_RUNS: Final = re.compile(r"[1-9][0-9]{0,6}")
# One thread only: with more, forge splits a fuzz campaign over parallel workers and the
# reported runs, gas figures and counterexamples depend on scheduling.
_THREADS: Final = re.compile(r"1")

_VERBOSITY: Final = frozenset({"-v", "-vv", "-vvv"})

# `forge inspect <contract> <field>`: the contract is `[<relative path>.sol:]<Name>`. Path
# segments start with a letter, digit or `_`, so `.` and `..` segments and absolute paths are
# impossible. Only fields that describe the interface of a contract are allowed.
_INSPECT_CONTRACT: Final = re.compile(
    r"(?:[A-Za-z0-9_][A-Za-z0-9_.\-]*(?:/[A-Za-z0-9_][A-Za-z0-9_.\-]*)*\.sol:)?"
    r"[A-Za-z_$][A-Za-z0-9_$]*"
)
_INSPECT_FIELDS: Final = frozenset({"abi", "events", "methodIdentifiers", "storageLayout"})
_INSPECT_SWITCHES: Final = frozenset({"--json", "--force"})

# Static analyzers take one target: `.` (the project root, the working directory) or a relative
# path inside the project whose segments start with a letter, digit or `_`, so that `..`
# segments and absolute paths are impossible.
_ANALYZER_TARGET: Final = re.compile(
    r"\.|[A-Za-z0-9_][A-Za-z0-9_.\-]*(?:/[A-Za-z0-9_][A-Za-z0-9_.\-]*)*"
)
# Slither prints its JSON report to standard output and nowhere else.
_STDOUT: Final = re.compile(r"-")
# Aderyn writes its report to a plain JSON file directly in the scratch mount.
_SCRATCH_REPORT: Final = re.compile(r"/work/scratch/[A-Za-z0-9_][A-Za-z0-9_.\-]{0,63}\.json")

# Halmos (ADR 0018) reads the project at its root and forge's build output from the scratch mount,
# runs the properties whose names start with one fixed prefix, with explicit bounds and the one
# pinned solver, and writes its JSON report to the scratch mount. Options that would widen what
# it does (`--ffi`, `--config`, `--solver-command`, query dumps) are not on the list.
_HALMOS_ROOT: Final = re.compile(r"/work/project")
_HALMOS_BUILD_OUT: Final = re.compile(r"/work/scratch/out")
_HALMOS_FUNCTION: Final = re.compile(r"check_(?:[a-z]{1,16}_)?")
_HALMOS_LOOP: Final = re.compile(r"[1-9][0-9]?")
_HALMOS_SOLVER: Final = re.compile(r"z3")
_HALMOS_TIMEOUT: Final = re.compile(r"[1-9][0-9]{0,3}s")
_HALMOS_THREADS: Final = re.compile(r"[1-4]")
_HALMOS_REQUIRED: Final = ("--root", "--forge-build-out", "--json-output")


class ArgvRejected(ValueError):
    """An argument vector is not on the allowlist."""


@dataclass(frozen=True)
class _CommandSpec:
    switches: frozenset[str]
    options: Mapping[str, re.Pattern[str]] = field(default_factory=dict)


_FORGE_COMMANDS: Final[Mapping[str, _CommandSpec]] = {
    "build": _CommandSpec(switches=frozenset({"--force", "--json"})),
    "test": _CommandSpec(
        switches=frozenset({"--force", "--json"}) | _VERBOSITY,
        options={
            "--match-test": _NAME_FILTER,
            "--no-match-test": _NAME_FILTER,
            "--match-contract": _NAME_FILTER,
            "--no-match-contract": _NAME_FILTER,
            "--match-path": _PATH_FILTER,
            "--no-match-path": _PATH_FILTER,
            "--fuzz-seed": _FUZZ_SEED,
            "--fuzz-runs": _FUZZ_RUNS,
            "--threads": _THREADS,
        },
    ),
}


_ANALYZERS: Final[Mapping[str, _CommandSpec]] = {
    "slither": _CommandSpec(
        switches=frozenset({"--fail-none", "--disable-color"}),
        options={"--json": _STDOUT},
    ),
    "aderyn": _CommandSpec(switches=frozenset(), options={"--output": _SCRATCH_REPORT}),
}


_HALMOS: Final = _CommandSpec(
    switches=frozenset({"--no-status"}),
    options={
        "--root": _HALMOS_ROOT,
        "--forge-build-out": _HALMOS_BUILD_OUT,
        "--function": _HALMOS_FUNCTION,
        "--loop": _HALMOS_LOOP,
        "--solver": _HALMOS_SOLVER,
        "--solver-timeout-assertion": _HALMOS_TIMEOUT,
        "--solver-threads": _HALMOS_THREADS,
        "--json-output": _SCRATCH_REPORT,
    },
)


def _check_item(item: object) -> str:
    if not isinstance(item, str):
        raise ArgvRejected("argv items must be strings")
    if not item:
        raise ArgvRejected("empty argv item")
    if len(item) > MAX_ARG_LENGTH:
        raise ArgvRejected(f"argv item longer than {MAX_ARG_LENGTH} characters")
    if any(unicodedata.category(ch).startswith(("C", "Z")) for ch in item):
        raise ArgvRejected(f"argv item contains whitespace or control characters: {item!r}")
    return item


def _check_inspect(items: tuple[str, ...]) -> tuple[str, ...]:
    rest = items[2:]
    if len(rest) < 2:
        raise ArgvRejected("forge inspect needs a contract and a field")
    contract, field_name, switches = rest[0], rest[1], rest[2:]
    if _INSPECT_CONTRACT.fullmatch(contract) is None:
        raise ArgvRejected(f"contract not allowed for forge inspect: {contract!r}")
    if field_name not in _INSPECT_FIELDS:
        raise ArgvRejected(f"field not allowed for forge inspect: {field_name!r}")
    seen: set[str] = set()
    for switch in switches:
        if switch not in _INSPECT_SWITCHES:
            raise ArgvRejected(f"argument not allowed for forge inspect: {switch!r}")
        if switch in seen:
            raise ArgvRejected(f"repeated flag: {switch!r}")
        seen.add(switch)
    return items


def _check_options(
    command: str, spec: _CommandSpec, rest: tuple[str, ...], *, dash_values: bool = False
) -> None:
    """Check `--switch` and `--option value` items; each flag at most once."""
    seen: set[str] = set()
    index = 0
    while index < len(rest):
        flag = rest[index]
        if flag in seen:
            raise ArgvRejected(f"repeated flag: {flag!r}")
        seen.add(flag)
        if flag in spec.switches:
            index += 1
            continue
        pattern = spec.options.get(flag)
        if pattern is None:
            raise ArgvRejected(f"argument not allowed for {command}: {flag!r}")
        if index + 1 >= len(rest):
            raise ArgvRejected(f"missing value for {flag}")
        value = rest[index + 1]
        if (value.startswith("-") and not dash_values) or pattern.fullmatch(value) is None:
            raise ArgvRejected(f"value not allowed for {flag}: {value!r}")
        if flag.endswith("-path") and ".." in value.split("/"):
            raise ArgvRejected(f"value not allowed for {flag}: {value!r}")
        index += 2


def _check_analyzer(items: tuple[str, ...]) -> tuple[str, ...]:
    if len(items) < 2:
        raise ArgvRejected(f"{items[0]} needs a target")
    target = items[1]
    if _ANALYZER_TARGET.fullmatch(target) is None:
        raise ArgvRejected(f"target not allowed for {items[0]}: {target!r}")
    # The value patterns are exact, so `-` (standard output) is the only value that starts with
    # a dash and can pass.
    _check_options(items[0], _ANALYZERS[items[0]], items[2:], dash_values=True)
    return items


def _check_halmos(items: tuple[str, ...]) -> tuple[str, ...]:
    rest = items[1:]
    _check_options("halmos", _HALMOS, rest)
    missing = [flag for flag in _HALMOS_REQUIRED if flag not in rest]
    if missing:
        raise ArgvRejected(f"halmos needs {', '.join(missing)}")
    return items


def check_argv(argv: Sequence[str]) -> tuple[str, ...]:
    """Return `argv` as a tuple if it is allowed, otherwise raise `ArgvRejected`.

    Accepted: `forge build` and `forge test` with the switches and options listed in
    `_FORGE_COMMANDS`. Options take their value as the next item (`--flag value`); the
    `--flag=value` form, positional arguments and repeated flags are rejected.

    Also accepted: `forge inspect <contract> <field>` followed by `--json` and `--force` at
    most once each, where `<field>` is one of `_INSPECT_FIELDS`.

    Also accepted: `slither <target>` and `aderyn <target>` with the switches and options in
    `_ANALYZERS`, where `<target>` is `.` or a relative path inside the project. Slither's
    `--json` takes only `-` (standard output); Aderyn's `--output` only a `.json` file directly
    in the scratch mount.

    Also accepted: `halmos` with `--root /work/project`, `--forge-build-out /work/scratch/out` and
    `--json-output` (a `.json` file directly in the scratch mount), and optionally the options
    and switch in `_HALMOS`: a property prefix `check_` or `check_<word>_`, a loop bound of 1 to
    99, the solver `z3`, an assertion timeout of 1 to 9999 seconds, 1 to 4 solver threads.
    """
    if isinstance(argv, str):
        raise ArgvRejected("argv must be a sequence of strings, not a string")
    items = tuple(_check_item(item) for item in argv)
    if not items:
        raise ArgvRejected("empty argv")
    if len(items) > MAX_ARGV_ITEMS:
        raise ArgvRejected(f"argv has more than {MAX_ARGV_ITEMS} items")
    if items[0] in _ANALYZERS:
        return _check_analyzer(items)
    if items[0] == "halmos":
        return _check_halmos(items)
    if items[0] != "forge":
        raise ArgvRejected(f"program not allowed: {items[0]!r}")
    if len(items) > 1 and items[1] == "inspect":
        return _check_inspect(items)
    if len(items) < 2 or items[1] not in _FORGE_COMMANDS:
        subcommand = items[1] if len(items) > 1 else ""
        raise ArgvRejected(f"forge subcommand not allowed: {subcommand!r}")

    subcommand = items[1]
    rest = items[2:]
    _check_options(f"forge {subcommand}", _FORGE_COMMANDS[subcommand], rest)
    if len(set(rest) & _VERBOSITY) > 1:
        raise ArgvRejected("more than one verbosity flag")
    return items
