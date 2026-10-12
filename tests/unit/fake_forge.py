"""A stand-in for the sandbox runner that answers forge commands without Docker.

Every argv still goes through the real allowlist. Answers come from decision functions that see
the run tree, so a test can make the vulnerable and the patched revision behave differently:

- `decide(tree, number)`: the outcome of replay `number` (from 1) of `test_replay`;
- `variant(tree)`: the outcome of the variant search (`testFuzz_variants`);
- `benign(tree)`: the benign tests of a benign tree, with their status and records;
- `interface(tree, contract, field)`: the output of `forge inspect` for `storageLayout`/`abi`;
- `invariant(tree)`: the outcome of an invariant campaign (`invariant_assay`), by default
  `missing` (the PoC directory has no invariant);
- `confirm(tree, number)`: the outcome of replay `number` of a generated `variant_poc.t.sol`,
  by default `reproduced` when the tree's variant search finds a variant.
"""

import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from assay.oracles.exploit import PREDICATE_EVENT, RECORD_EVENT, REPLAY_FILTER, TEST_CONTRACT
from assay.oracles.variant import INVARIANT_FILTER, REPLAY_CONTRACT_FILTER, VARIANT_FILTER
from assay.sandbox import SandboxResult, SandboxRunner, check_argv

IMAGE_ID = "sha256:" + "ef" * 32
TOPIC = "0x" + "ab" * 32
RECORD_TOPIC = "0x" + "cd" * 32
OTHER_ADDRESS = "0x" + "12" * 20
LABELS = {
    "assay.forge-std.version": "v1.17.0",
    "assay.foundry.version": "v1.8.4",
    "assay.solc.version": "0.8.36",
    "org.opencontainers.image.title": "assay-runner",
}
VARIANT_REASON = (
    "ASSAY_VARIANT_FOUND|attacker=0x3d96494F5a7D013d27e61277B78875cADbEA63A0"
    "|balance=3126453882223813690|knobs=7886,3,0,0"
)
VARIANT_CALLDATA = "0xa167c778" + "".join(f"{value:064x}" for value in (11, 22, 3, 4, 5, 6))
INVARIANT_REASON = "ASSAY_INVARIANT_BROKEN|vault_solvent"
HANDLER = "0x2e234dae75c793f67a35089c9d99245e1c58470b"
INVARIANT_CALLS = [
    {
        "warp": None,
        "roll": None,
        "sender": "0xa9c8315a196e6df8be3aed79927636eebfd2bf56",
        "addr": HANDLER,
        "calldata": "0x76fcc654" + f"{63:064x}",
        "contract_name": "test/Solvency.t.sol:VaultHandler",
        "func_name": "attackerDeposit",
        "signature": "attackerDeposit(uint256)",
        "args": "63",
        "raw_args": "63",
    },
    {
        "warp": None,
        "roll": None,
        "sender": "0x0000000000000000000000000000000000001e22",
        "addr": HANDLER,
        "calldata": "0x133eebca" + f"{4515:064x}" + f"{401:064x}",
        "contract_name": "test/Solvency.t.sol:VaultHandler",
        "func_name": "attackerWithdraw",
        "signature": "attackerWithdraw(uint256,uint256)",
        "args": "4515, 401",
        "raw_args": "4515, 401",
    },
]

Decide = Callable[[Path, int], str]
"""Returns the outcome of replay `number` (from 1) in a run tree: `exploited`, `blocked`,
`reverted` (or `reverted:<revert message>`), `foreign`, `marker_only`, `setup`, `missing`,
`timeout` or `oom`."""

Variant = Callable[[Path], str]
"""Returns the outcome of the variant search: `found`, `none`, `incomplete`, `unconfirmed`,
`other`, `setup`, `missing`, `timeout` or `oom`."""

BenignTests = Mapping[str, tuple[str, Sequence[tuple[str, str]]]]
"""Test signature to (forge status, [(record key, record payload in hex)]). A status can carry
the failure message: `Failure: <message>`."""

Invariant = Callable[[Path], str]
"""Returns the outcome of an invariant campaign: `found`, `none`, `incomplete`, `unconfirmed`,
`other`, `setup`, `missing`, `timeout` or `oom`."""

Confirm = Callable[[Path, int], str]
"""Returns the outcome of replay `number` of a generated test: `reproduced`, `blocked`,
`timeout` or `oom`."""

Benign = Callable[[Path], BenignTests | str]
"""Returns the benign tests of a tree, or `timeout` or `oom`."""
Inspect = Callable[[Path, str, str], str]


def abi_strings(*values: str) -> str:
    head = b""
    tail = b""
    offset = 32 * len(values)
    for value in values:
        raw = value.encode()
        encoded = len(raw).to_bytes(32, "big") + raw + b"\0" * (-len(raw) % 32)
        head += offset.to_bytes(32, "big")
        tail += encoded
        offset += len(encoded)
    return "0x" + (head + tail).hex()


def abi_bytes(payload_hex: str) -> str:
    """ABI encoding of one `bytes` value (the data of an `AssayRecord` event)."""
    raw = bytes.fromhex(payload_hex.removeprefix("0x"))
    padded = raw + b"\0" * (-len(raw) % 32)
    return "0x" + ((32).to_bytes(32, "big") + len(raw).to_bytes(32, "big") + padded).hex()


def key_topic(key: str) -> str:
    return "0x" + key.encode().ljust(32, b"\0").hex()


def _case(
    status: str,
    reason: str | None,
    logs: list[Any],
    decoded: list[str],
    *,
    kind: Any = None,
    counterexample: Any = None,
) -> Any:
    return {
        "status": status,
        "reason": reason,
        "counterexample": counterexample,
        "logs": logs,
        "decoded_logs": decoded,
        "kind": kind if kind is not None else {"Unit": {"gas": 1000}},
        "traces": [],
        "duration": "1ms",
    }


def predicate_log(address: str = TEST_CONTRACT, topic: str = TOPIC) -> dict[str, Any]:
    return {
        "address": address,
        "topics": [topic],
        "data": abi_strings("attacker_profit", "eth:1->2"),
    }


def record_log(key: str, payload: str, address: str = TEST_CONTRACT) -> dict[str, Any]:
    return {
        "address": address,
        "topics": [RECORD_TOPIC, key_topic(key)],
        "data": abi_bytes(payload),
    }


MARKER = "ASSAY_PREDICATE|attacker_profit|eth:1->2"


def _output(suite: str, results: dict[str, Any]) -> tuple[int, str]:
    stdout = json.dumps({suite: {"test_results": results}})
    status = 0 if all(item["status"] == "Success" for item in results.values()) else 1
    return status, stdout


def replay_output(outcome: str) -> tuple[int, str]:
    """Exit code and stdout of `forge test --json` for one replay outcome."""
    results: dict[str, Any]
    if outcome == "exploited":
        results = {"test_replay()": _case("Success", None, [predicate_log()], [MARKER])}
    elif outcome == "foreign":
        results = {
            "test_replay()": _case("Success", None, [predicate_log(OTHER_ADDRESS)], [MARKER])
        }
    elif outcome == "marker_only":
        results = {"test_replay()": _case("Success", None, [], [MARKER])}
    elif outcome == "blocked":
        results = {"test_replay()": _case("Failure", "AssayNoPredicate()", [], [])}
    elif outcome == "reverted" or outcome.startswith("reverted:"):
        text = outcome.partition(":")[2] or "InsufficientBalance(2, 1)"
        results = {"test_replay()": _case("Failure", text, [], [])}
    elif outcome == "setup":
        results = {"setUp()": _case("Failure", "revert: setup broke", [], [])}
    elif outcome == "missing":
        return 0, ""
    else:
        raise ValueError(outcome)
    return _output("test/Exploit.t.sol:ExploitPoC", results)


VARIANT_SIGNATURE = "testFuzz_variants(uint256,uint256,uint256,uint256,uint256,uint256)"


def _fuzz(runs: int) -> dict[str, Any]:
    return {"Fuzz": {"runs": runs, "mean_gas": 7, "median_gas": 7}}


def variant_output(outcome: str, runs: int) -> tuple[int, str]:
    """Exit code and stdout of `forge test --json` for one variant search outcome."""
    single = {
        "Single": {
            "calldata": VARIANT_CALLDATA,
            "raw_args": "1, 2, 3, 4, 5, 6",
            "fuzz_run": 3,
        }
    }
    if outcome == "found":
        case = _case(
            "Failure",
            VARIANT_REASON,
            [predicate_log()],
            [MARKER],
            kind=_fuzz(3),
            counterexample=single,
        )
    elif outcome == "unconfirmed":
        case = _case("Failure", VARIANT_REASON, [], [MARKER], kind=_fuzz(3), counterexample=single)
    elif outcome == "none":
        case = _case("Success", None, [], [], kind=_fuzz(runs))
    elif outcome == "incomplete":
        case = _case("Success", None, [], [], kind=_fuzz(runs - 1))
    elif outcome == "other":
        case = _case("Failure", "panic: arithmetic underflow", [], [], kind=_fuzz(2))
    elif outcome == "setup":
        return _output(
            "test/Exploit.t.sol:ExploitPoC",
            {"setUp()": _case("Failure", "revert: setup broke", [], [])},
        )
    elif outcome == "missing":
        return 0, ""
    else:
        raise ValueError(outcome)
    return _output("test/Exploit.t.sol:ExploitPoC", {VARIANT_SIGNATURE: case})


INVARIANT_SIGNATURE = "invariant_assay()"


def _invariant(runs: int, calls: int) -> dict[str, Any]:
    return {"Invariant": {"runs": runs, "calls": calls, "reverts": 0, "workers": 1}}


def invariant_output(outcome: str, runs: int) -> tuple[int, str]:
    """Exit code and stdout of `forge test --json` for one invariant campaign outcome."""
    suite = "test/Solvency.t.sol:SolvencyInvariant"
    if outcome == "found":
        case = _case("Failure", None, [], [], kind=_invariant(4, 53))
        case["invariant_failures"] = [
            {
                "kind": "predicate",
                "name": "invariant_assay",
                "reason": INVARIANT_REASON,
                "counterexample": {"Sequence": [8, INVARIANT_CALLS]},
                "persisted_path": "/work/scratch/invariant/failures/x",
                "is_anchor": True,
            }
        ]
    elif outcome == "unconfirmed":
        case = _case("Failure", None, [], [], kind=_invariant(4, 53))
        case["invariant_failures"] = [
            {"kind": "predicate", "name": "invariant_assay", "reason": INVARIANT_REASON}
        ]
    elif outcome == "none":
        case = _case("Success", None, [], [], kind=_invariant(runs, runs * 10))
    elif outcome == "incomplete":
        case = _case("Success", None, [], [], kind=_invariant(runs - 1, 10))
    elif outcome == "other":
        case = _case("Failure", "panic: arithmetic underflow", [], [], kind=_invariant(2, 3))
    elif outcome == "setup":
        return _output(suite, {"setUp()": _case("Failure", "revert: setup broke", [], [])})
    elif outcome == "missing":
        return 0, ""
    else:
        raise ValueError(outcome)
    return _output(suite, {INVARIANT_SIGNATURE: case})


def confirm_output(outcome: str) -> tuple[int, str]:
    """Exit code and stdout of `forge test --json` for one replay of a generated test."""
    if outcome == "reproduced":
        case = _case("Success", None, [predicate_log()], [MARKER])
    elif outcome == "blocked":
        case = _case("Failure", "AssayNoPredicate()", [], [])
    else:
        raise ValueError(outcome)
    return _output("test/AssayVariantPoC.t.sol:AssayVariantPoC", {"test_variant()": case})


def benign_output(tests: BenignTests) -> tuple[int, str]:
    """Exit code and stdout of `forge test --json` for benign tests."""
    if not tests:
        return 0, ""
    results = {
        name: _case(
            status.partition(":")[0],
            None
            if status == "Success"
            else (status.partition(":")[2].strip() or "assertion failed"),
            [record_log(key, payload) for key, payload in records],
            [],
        )
        for name, (status, records) in tests.items()
    }
    return _output("test/Vault.t.sol:VaultBenignTest", results)


def layout_json(*variables: tuple[str, int, int, str]) -> str:
    """`forge inspect ... storageLayout --json` for (label, slot, offset, type id) entries."""
    types = {
        "t_bool": {"encoding": "inplace", "label": "bool", "numberOfBytes": "1"},
        "t_address": {"encoding": "inplace", "label": "address", "numberOfBytes": "20"},
        "t_uint256": {"encoding": "inplace", "label": "uint256", "numberOfBytes": "32"},
        "t_uint128": {"encoding": "inplace", "label": "uint128", "numberOfBytes": "16"},
        "t_mapping(t_address,t_uint256)": {
            "encoding": "mapping",
            "key": "t_address",
            "label": "mapping(address => uint256)",
            "numberOfBytes": "32",
            "value": "t_uint256",
        },
    }
    storage = [
        {
            "astId": 3 + index,
            "contract": "src/Vault.sol:Vault",
            "label": label,
            "offset": offset,
            "slot": str(slot),
            "type": type_id,
        }
        for index, (label, slot, offset, type_id) in enumerate(variables)
    ]
    return json.dumps({"storage": storage, "types": types})


VAULT_LAYOUT = layout_json(
    ("balanceOf", 0, 0, "t_mapping(t_address,t_uint256)"), ("totalDeposits", 1, 0, "t_uint256")
)


def function(name: str, inputs: Sequence[str], outputs: Sequence[str], mutability: str) -> Any:
    return {
        "type": "function",
        "name": name,
        "inputs": [{"name": "", "type": item, "internalType": item} for item in inputs],
        "outputs": [{"name": "", "type": item, "internalType": item} for item in outputs],
        "stateMutability": mutability,
    }


def event(name: str, *params: tuple[str, bool], anonymous: bool = False) -> Any:
    return {
        "type": "event",
        "name": name,
        "inputs": [
            {"name": f"p{index}", "type": kind, "indexed": indexed, "internalType": kind}
            for index, (kind, indexed) in enumerate(params)
        ],
        "anonymous": anonymous,
    }


VAULT_ABI_ENTRIES: list[Any] = [
    function("balanceOf", ["address"], ["uint256"], "view"),
    function("deposit", [], [], "payable"),
    function("totalDeposits", [], ["uint256"], "view"),
    function("withdraw", ["uint256"], [], "nonpayable"),
    event("Deposited", ("address", True), ("uint256", False)),
    event("Withdrawn", ("address", True), ("uint256", False)),
    {"type": "error", "name": "ZeroAmount", "inputs": []},
]
VAULT_ABI = json.dumps(VAULT_ABI_ENTRIES)
DEFAULT_BENIGN: BenignTests = {
    "test_deposit()": ("Success", [("deposit", "0x01")]),
    "test_withdraw()": ("Success", [("withdraw", "0x02")]),
}


def marker_decide(
    marker: str, *, vulnerable: str = "exploited", patched: str = "blocked"
) -> Decide:
    """Outcome `vulnerable` when `marker` occurs in the tree's sources, else `patched`."""

    def decide(tree: Path, number: int) -> str:
        sources = "".join(path.read_text() for path in sorted((tree / "src").rglob("*.sol")))
        return vulnerable if marker in sources else patched

    return decide


class FakeForge(SandboxRunner):
    def __init__(
        self,
        decide: Decide,
        *,
        variant: Variant | None = None,
        invariant: Invariant | None = None,
        confirm: Confirm | None = None,
        benign: Benign | None = None,
        interface: Inspect | None = None,
        build_fails: Callable[[Path], bool] = lambda tree: False,
        events_output: str | None = None,
        labels: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(docker="unused")
        self.decide = decide
        self.variant = variant if variant is not None else self._variant_from_decide
        self.invariant: Invariant = invariant if invariant is not None else (lambda tree: "missing")
        self.confirm: Confirm = confirm if confirm is not None else self._confirm_from_variant
        self.timeouts: list[float | None] = []
        self.benign: Benign = benign if benign is not None else (lambda tree: DEFAULT_BENIGN)
        self.interface: Inspect = (
            interface
            if interface is not None
            else (
                lambda tree, contract, field: (
                    VAULT_LAYOUT if field == "storageLayout" else VAULT_ABI
                )
            )
        )
        self.build_fails = build_fails
        self.events_output = (
            events_output
            if events_output is not None
            else json.dumps({PREDICATE_EVENT: TOPIC, RECORD_EVENT: RECORD_TOPIC})
        )
        self.labels = dict(labels if labels is not None else LABELS)
        self.calls: list[tuple[str, ...]] = []
        self._replays: dict[Path, int] = {}

    def _variant_from_decide(self, tree: Path) -> str:
        return "found" if self.decide(tree, 1) == "exploited" else "none"

    def _confirm_from_variant(self, tree: Path, number: int) -> str:
        found = self.variant(tree) == "found" or self.invariant(tree) == "found"
        return "reproduced" if found else "blocked"

    def image_id(self) -> str:
        return IMAGE_ID

    def image_labels(self) -> dict[str, str]:
        return dict(self.labels)

    def run(
        self,
        argv: Sequence[str],
        *,
        project_dir: Path,
        scratch_dir: Path,
        timeout_s: float | None = None,
    ) -> SandboxResult:
        command = check_argv(argv)
        self.calls.append(command)
        self.timeouts.append(timeout_s)
        fields: dict[str, Any] = {
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "truncated": False,
            "timed_out": False,
            "oom_killed": False,
            "duration_s": 1.0,
            "image_id": IMAGE_ID,
        }
        if command[1] == "build":
            if self.build_fails(project_dir):
                error = {
                    "severity": "error",
                    "type": "TypeError",
                    "errorCode": "9582",
                    "message": "Member not found.",
                    "sourceLocation": {"file": "test/Exploit.t.sol", "start": 1, "end": 2},
                }
                fields.update(exit_code=1, stdout=json.dumps({"errors": [error]}))
        elif command[1] == "inspect":
            contract, field = command[2], command[3]
            if field == "events":
                fields.update(stdout=self.events_output)
            else:
                fields.update(stdout=self.interface(project_dir, contract, field))
        elif command[1] == "test":
            fields.update(self._test(command, project_dir))
        return SandboxResult(argv=command, **fields)

    def _test(self, command: tuple[str, ...], tree: Path) -> dict[str, Any]:
        options = dict(zip(command[4::2], command[5::2], strict=False))
        match = options.get("--match-test")
        confirming = options.get("--match-contract") == REPLAY_CONTRACT_FILTER
        if confirming:
            number = self._replays.get(tree, 0) + 1
            self._replays[tree] = number
            outcome = self.confirm(tree, number)
        elif match == REPLAY_FILTER:
            number = self._replays.get(tree, 0) + 1
            self._replays[tree] = number
            outcome = self.decide(tree, number)
        elif match == VARIANT_FILTER:
            outcome = self.variant(tree)
        elif match == INVARIANT_FILTER:
            outcome = self.invariant(tree)
        else:
            answer = self.benign(tree)
            outcome = answer if isinstance(answer, str) else "benign"
        if outcome == "timeout":
            return {"exit_code": -9, "timed_out": True}
        if outcome == "oom":
            return {"exit_code": 137, "oom_killed": True}
        if confirming:
            exit_code, stdout = confirm_output(outcome)
        elif match == REPLAY_FILTER:
            exit_code, stdout = replay_output(outcome)
        elif match == INVARIANT_FILTER:
            exit_code, stdout = invariant_output(outcome, 64)
        elif match == VARIANT_FILTER:
            exit_code, stdout = variant_output(outcome, int(options.get("--fuzz-runs", "256")))
        else:
            tests = self.benign(tree)
            assert not isinstance(tests, str)
            exit_code, stdout = benign_output(tests)
        return {"exit_code": exit_code, "stdout": stdout}

    def commands(self, subcommand: str) -> list[tuple[str, ...]]:
        return [call for call in self.calls if call[1] == subcommand]

    def tests(self, match: str | None) -> list[tuple[str, ...]]:
        """`forge test` commands with the given `--match-test` value (None: no filter)."""
        found = []
        for call in self.commands("test"):
            options = dict(zip(call[4::2], call[5::2], strict=False))
            if options.get("--match-test") == match:
                found.append(call)
        return found
