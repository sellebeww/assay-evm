import pytest

from assay.sandbox import ArgvRejected, check_argv
from assay.sandbox.allowlist import MAX_ARGV_ITEMS


@pytest.mark.parametrize(
    "argv",
    [
        ["forge", "build"],
        ["forge", "build", "--json", "--force"],
        ["forge", "test"],
        ["forge", "test", "--json", "-vv"],
        ["forge", "test", "--match-test", "test_Increment.*", "--match-contract", "CounterTest"],
        ["forge", "test", "--no-match-test", "testFuzz_(A|B)$"],
        ["forge", "test", "--match-path", "test/Counter.t.sol"],
        ["forge", "test", "--no-match-path", "test/*/Slow*.sol"],
        ["forge", "test", "--fuzz-seed", "0x1f", "--fuzz-runs", "1000"],
        ["forge", "test", "--fuzz-seed", "42"],
        ["forge", "test", "--json", "-vv", "--threads", "1"],
        ["forge", "inspect", "Counter", "abi"],
        ["forge", "inspect", "src/Counter.sol:Counter", "storageLayout", "--json"],
        ["forge", "inspect", "lib/a-b/C_1.sol:C$", "events", "--force", "--json"],
        ["forge", "inspect", "Counter", "methodIdentifiers"],
    ],
)
def test_allowed_argv_is_returned_unchanged(argv: list[str]) -> None:
    assert check_argv(argv) == tuple(argv)


@pytest.mark.parametrize(
    "argv",
    [
        pytest.param([], id="empty"),
        pytest.param(["sh", "-c", "forge test"], id="shell"),
        pytest.param(["bash", "-c", "forge test"], id="bash"),
        pytest.param(["/usr/local/bin/forge", "test"], id="absolute-program"),
        pytest.param(["cast", "call"], id="other-program"),
        pytest.param(["forge"], id="no-subcommand"),
        pytest.param(["forge", "script", "Deploy"], id="script"),
        pytest.param(["forge", "install"], id="install"),
        pytest.param(["forge", "create", "Counter"], id="create"),
        pytest.param(["forge", "inspect"], id="inspect-without-arguments"),
        pytest.param(["forge", "inspect", "Counter"], id="inspect-without-field"),
        pytest.param(["forge", "inspect", "Counter", "bytecode"], id="inspect-bytecode"),
        pytest.param(["forge", "inspect", "Counter", "standardJson"], id="inspect-standard-json"),
        pytest.param(["forge", "inspect", "Counter", "abi", "abi"], id="inspect-extra-positional"),
        pytest.param(["forge", "inspect", "--json", "Counter", "abi"], id="inspect-flag-first"),
        pytest.param(["forge", "inspect", "C", "abi", "--json", "--json"], id="inspect-repeat"),
        pytest.param(["forge", "inspect", "Counter", "abi", "--root", "/"], id="inspect-root"),
        pytest.param(["forge", "inspect", "Counter", "abi", "--out", "/tmp"], id="inspect-out"),
        pytest.param(["forge", "inspect", "../x/C.sol:C", "abi"], id="inspect-traversal"),
        pytest.param(["forge", "inspect", "src/../C.sol:C", "abi"], id="inspect-inner-traversal"),
        pytest.param(["forge", "inspect", "/etc/C.sol:C", "abi"], id="inspect-absolute-path"),
        pytest.param(["forge", "inspect", "src/C.txt:C", "abi"], id="inspect-not-solidity"),
        pytest.param(["forge", "inspect", "-C", "abi"], id="inspect-flag-as-contract"),
        pytest.param(["forge", "inspect", "1Counter", "abi"], id="inspect-bad-name"),
        pytest.param(["forge", "inspect", "C;id", "abi"], id="inspect-semicolon"),
        pytest.param(["forge", "test", "--ffi"], id="ffi"),
        pytest.param(["forge", "test", "--fork-url", "http://127.0.0.1:8545"], id="fork-url"),
        pytest.param(["forge", "test", "--rpc-url", "local"], id="rpc-url"),
        pytest.param(["forge", "test", "--root", "/"], id="root"),
        pytest.param(["forge", "test", "--config-path", "/tmp/foundry.toml"], id="config-path"),
        pytest.param(["forge", "build", "--out", "/tmp/out"], id="out"),
        pytest.param(["forge", "build", "--cache-path", "/tmp/cache"], id="cache-path"),
        pytest.param(["forge", "build", "--remappings", "x/=/etc/"], id="remappings"),
        pytest.param(["forge", "build", "--use", "/tmp/solc"], id="custom-solc"),
        pytest.param(["forge", "build", "src/Counter.sol"], id="positional-path"),
        pytest.param(["forge", "test", "--match-test=foo"], id="equals-form"),
        pytest.param(["forge", "test", "--match-test"], id="missing-value"),
        pytest.param(["forge", "test", "--match-test", "--ffi"], id="flag-as-value"),
        pytest.param(["forge", "test", "--match-test", "a b"], id="space-in-value"),
        pytest.param(["forge", "test", "--match-test", "a;b"], id="semicolon-in-value"),
        pytest.param(["forge", "test", "--match-test", "a`b"], id="backtick-in-value"),
        pytest.param(["forge", "test", "--match-path", "../outside/*.sol"], id="path-traversal"),
        pytest.param(["forge", "test", "--match-path", "test/../../x.sol"], id="inner-traversal"),
        pytest.param(["forge", "test", "--fuzz-runs", "0"], id="zero-runs"),
        pytest.param(["forge", "test", "--fuzz-runs", "100000000"], id="too-many-runs"),
        pytest.param(["forge", "test", "--fuzz-seed", "seed"], id="bad-seed"),
        pytest.param(["forge", "test", "--json", "--json"], id="repeated-flag"),
        pytest.param(["forge", "test", "-v", "-vv"], id="two-verbosity-flags"),
        pytest.param(["forge", "test", "-vvvv"], id="trace-verbosity"),
        pytest.param(["forge", "build", "-vv"], id="verbosity-on-build"),
        pytest.param(["forge", "test", "--json\n"], id="newline"),
        pytest.param(["forge\x00", "test"], id="nul"),
        pytest.param(["forge", "test", "--match-test", "x" * 300], id="too-long"),
        pytest.param(["forge", "test", ""], id="empty-item"),
    ],
)
def test_disallowed_argv_is_rejected(argv: list[str]) -> None:
    with pytest.raises(ArgvRejected):
        check_argv(argv)


def test_string_instead_of_sequence_is_rejected() -> None:
    with pytest.raises(ArgvRejected, match="not a string"):
        check_argv("forge test")


def test_non_string_item_is_rejected() -> None:
    with pytest.raises(ArgvRejected, match="must be strings"):
        check_argv(["forge", "test", 1])  # type: ignore[list-item]


def test_too_many_items_are_rejected() -> None:
    argv = ["forge", "test", *(["--match-test", "a"] * MAX_ARGV_ITEMS)]
    with pytest.raises(ArgvRejected, match="more than"):
        check_argv(argv)


def test_the_oracle_commands_are_allowed() -> None:
    for argv in (
        ("forge", "build", "--json"),
        (
            "forge",
            "test",
            "--json",
            "-vv",
            "--match-test",
            "^test_replay[(][)]$",
            "--fuzz-seed",
            "0x1",
        ),
        ("forge", "inspect", "assay/AssayExploit.sol:AssayExploit", "events", "--json"),
    ):
        assert check_argv(argv) == argv


@pytest.mark.parametrize("value", ["0", "2", "16", "01", "auto", "-1", "1.0"])
def test_only_one_thread_is_allowed(value: str) -> None:
    with pytest.raises(ArgvRejected):
        check_argv(["forge", "test", "--threads", value])


@pytest.mark.parametrize(
    "argv",
    [
        ["forge", "build", "--threads", "1"],
        ["forge", "test", "-j", "1"],
        ["forge", "test", "--jobs", "1"],
        ["forge", "test", "--threads", "1", "--threads", "1"],
        ["forge", "test", "--threads=1"],
    ],
)
def test_other_thread_options_are_rejected(argv: list[str]) -> None:
    with pytest.raises(ArgvRejected):
        check_argv(argv)


HALMOS_ARGV = [
    "halmos",
    "--root",
    "/work/project",
    "--forge-build-out",
    "/work/scratch/out",
    "--function",
    "check_variant_",
    "--loop",
    "3",
    "--solver",
    "z3",
    "--solver-timeout-assertion",
    "60s",
    "--solver-threads",
    "1",
    "--json-output",
    "/work/scratch/halmos.json",
    "--no-status",
]


def _halmos(**changes: str | None) -> list[str]:
    """`HALMOS_ARGV` with options replaced (a value) or removed (`None`)."""
    argv = list(HALMOS_ARGV)
    for flag, value in changes.items():
        option = "--" + flag.replace("_", "-")
        index = argv.index(option)
        if value is None:
            del argv[index : index + (1 if option == "--no-status" else 2)]
        else:
            argv[index + 1] = value
    return argv


@pytest.mark.parametrize(
    "argv",
    [
        HALMOS_ARGV,
        _halmos(function="check_"),
        _halmos(function="check_equiv_"),
        _halmos(loop="12", solver_threads="4", solver_timeout_assertion="300s"),
        _halmos(no_status=None, loop=None, solver_threads=None),
    ],
)
def test_halmos_argv_is_allowed(argv: list[str]) -> None:
    assert check_argv(argv) == tuple(argv)


@pytest.mark.parametrize(
    "argv",
    [
        pytest.param(["halmos"], id="bare"),
        pytest.param(_halmos(root=None), id="no-root"),
        pytest.param(_halmos(forge_build_out=None), id="no-build-out"),
        pytest.param(_halmos(json_output=None), id="no-json-output"),
        pytest.param(_halmos(root="/"), id="other-root"),
        pytest.param(_halmos(root="/work/scratch"), id="scratch-root"),
        pytest.param(_halmos(forge_build_out="out"), id="relative-build-out"),
        pytest.param(_halmos(json_output="/tmp/h.json"), id="json-outside-scratch"),
        pytest.param(_halmos(json_output="/work/scratch/../h.json"), id="json-traversal"),
        pytest.param(_halmos(function="test_"), id="other-prefix"),
        pytest.param(_halmos(function="check_.*"), id="regex-function"),
        pytest.param(_halmos(loop="0"), id="zero-loop"),
        pytest.param(_halmos(loop="100"), id="huge-loop"),
        pytest.param(_halmos(solver="yices"), id="other-solver"),
        pytest.param(_halmos(solver="/bin/sh"), id="solver-path"),
        pytest.param(_halmos(solver_threads="0"), id="zero-threads"),
        pytest.param(_halmos(solver_threads="8"), id="many-threads"),
        pytest.param(_halmos(solver_timeout_assertion="0"), id="no-timeout"),
        pytest.param(_halmos(solver_timeout_assertion="1h"), id="hour-timeout"),
        pytest.param([*HALMOS_ARGV, "--ffi"], id="ffi"),
        pytest.param([*HALMOS_ARGV, "--config", "/work/project/x.toml"], id="config"),
        pytest.param([*HALMOS_ARGV, "--solver-command", "/bin/sh"], id="solver-command"),
        pytest.param([*HALMOS_ARGV, "--coverage-output", "/work/scratch/c"], id="coverage"),
        pytest.param([*HALMOS_ARGV, "--dump-smt-queries"], id="dump-queries"),
        pytest.param([*HALMOS_ARGV, "--no-status"], id="repeated-switch"),
        pytest.param([*HALMOS_ARGV, "--loop=3"], id="equals-form"),
        pytest.param([*HALMOS_ARGV, "check_x"], id="positional"),
        pytest.param(["halmos", "--version"], id="version"),
    ],
)
def test_disallowed_halmos_argv_is_rejected(argv: list[str]) -> None:
    with pytest.raises(ArgvRejected):
        check_argv(argv)
