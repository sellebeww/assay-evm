"""Concrete tests (`variant_poc.t.sol`) that replay a variant the search reported.

A variant found by a fuzz or invariant campaign is replayed through a test with fixed values,
written from a template. Two kinds of data enter the Solidity source, and nothing else:

- numbers: every value is a Python integer in [0, 2**256) taken from strictly validated hex
  (the calldata of the failing input, sender and target addresses) and printed as a hex literal
  of fixed width; a 40-digit literal is never written, so no address checksum rule applies;
- the name and file of the contract the test derives from (the PoC or the fixture invariant),
  which must match strict identifier and path patterns, and the solc version of the harness.

Revert reasons, decoded arguments, labels and any other text from the run never reach the
source. Input that does not fit (wrong calldata length, a time shift in a sequence, a name that
is not a plain identifier) raises `PocRejected`; it is never written.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final

from assay.analyzers.foundry import ForgeCall

VARIANT_POC_FILE: Final = "variant_poc.t.sol"
VARIANT_POC_PATH: Final = "AssayVariantPoC.t.sol"
"""Where the generated test goes in a PoC run tree, relative to `test/`."""
VARIANT_POC_CONTRACT: Final = "AssayVariantPoC"
VARIANT_POC_TEST: Final = "test_variant"
FUZZ_ARGUMENTS: Final = 6
KNOB_COUNT: Final = 4
MAX_CALLS: Final = 256
MAX_WORDS_PER_CALL: Final = 64
WORD_BYTES: Final = 32
SELECTOR_BYTES: Final = 4

_HEX: Final = re.compile(r"0x(?:[0-9a-f]{2})*")
_ADDRESS: Final = re.compile(r"0x[0-9a-f]{40}")
_IDENTIFIER: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_SEGMENT: Final = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.\-]{0,99}")
_CHECK_FUNCTION: Final = re.compile(r"check_[A-Za-z0-9_]{1,64}")
_SOLC: Final = re.compile(r"[0-9]{1,2}\.[0-9]{1,3}\.[0-9]{1,3}")
_PRAGMA: Final = re.compile(rb"^pragma solidity ([0-9]{1,2}\.[0-9]{1,3}\.[0-9]{1,3});$", re.M)


class PocRejected(ValueError):
    """A counterexample or a contract name cannot be written into a test safely."""


@dataclass(frozen=True, slots=True)
class BaseContract:
    """The contract a generated test derives from, and its file relative to `test/`."""

    name: str
    path: str


@dataclass(frozen=True, slots=True)
class FuzzInput:
    """The six arguments of a failing `testFuzz_variants` call (the raw fuzzer seeds)."""

    attacker_seed: int
    balance_seed: int
    knob_seeds: tuple[int, int, int, int]


@dataclass(frozen=True, slots=True)
class ReplayCall:
    """One call of an invariant sequence: sender, target, selector and argument words."""

    sender: int
    target: int
    selector: int
    words: tuple[int, ...]


def base_contract(suite: str) -> BaseContract:
    """The contract of a forge suite name `test/<path>.sol:<Name>`, checked strictly."""
    path, separator, name = suite.rpartition(":")
    if not separator or _IDENTIFIER.fullmatch(name) is None or name == VARIANT_POC_CONTRACT:
        raise PocRejected("the test contract name is not a plain identifier")
    parts = PurePosixPath(path).parts
    if len(parts) < 2 or parts[0] != "test" or not path.endswith(".sol"):
        raise PocRejected("the test contract does not lie in a .sol file under test/")
    relative = parts[1:]
    if any(_SEGMENT.fullmatch(part) is None or part in (".", "..") for part in relative):
        raise PocRejected("the test contract file has an unexpected path")
    joined = "/".join(relative)
    if joined == VARIANT_POC_PATH:
        raise PocRejected("the test contract file uses the name reserved for generated tests")
    return BaseContract(name=name, path=joined)


def solc_version(harness_file: bytes) -> str:
    """The exact solc version of the harness pragma (`pragma solidity X.Y.Z;`)."""
    found = _PRAGMA.findall(harness_file)
    if len(found) != 1:
        raise PocRejected("the harness does not declare exactly one exact pragma")
    return str(found[0].decode("ascii"))


def _bytes(text: str, what: str) -> bytes:
    if not isinstance(text, str) or _HEX.fullmatch(text) is None:
        raise PocRejected(f"{what} is not lowercase hex")
    return bytes.fromhex(text[2:])


def _address(text: str | None, what: str) -> int:
    if text is None or _ADDRESS.fullmatch(text) is None:
        raise PocRejected(f"{what} is not an address")
    return int(text[2:], 16)


def _words(data: bytes) -> tuple[int, ...]:
    return tuple(
        int.from_bytes(data[index : index + WORD_BYTES], "big")
        for index in range(0, len(data), WORD_BYTES)
    )


def fuzz_input(calldata: str) -> FuzzInput:
    """The arguments of a `testFuzz_variants` call from its calldata (selector and 6 words)."""
    data = _bytes(calldata, "the calldata")
    if len(data) != SELECTOR_BYTES + FUZZ_ARGUMENTS * WORD_BYTES:
        raise PocRejected("the calldata does not hold the six arguments of testFuzz_variants")
    words = _words(data[SELECTOR_BYTES:])
    return FuzzInput(
        attacker_seed=words[0],
        balance_seed=words[1],
        knob_seeds=(words[2], words[3], words[4], words[5]),
    )


def replay_calls(calls: Sequence[ForgeCall]) -> tuple[ReplayCall, ...]:
    """The calls of an invariant sequence, or `PocRejected` if one cannot be replayed."""
    if not calls:
        raise PocRejected("the sequence has no calls")
    if len(calls) > MAX_CALLS:
        raise PocRejected(f"the sequence has more than {MAX_CALLS} calls")
    found: list[ReplayCall] = []
    for index, call in enumerate(calls, start=1):
        if call.warp is not None or call.roll is not None:
            raise PocRejected(f"call {index} shifts time or block number")
        data = _bytes(call.calldata, f"the calldata of call {index}")
        body = data[SELECTOR_BYTES:]
        if len(data) < SELECTOR_BYTES or len(body) % WORD_BYTES:
            raise PocRejected(f"the calldata of call {index} is not a selector and whole words")
        if len(body) // WORD_BYTES > MAX_WORDS_PER_CALL:
            raise PocRejected(f"call {index} has more than {MAX_WORDS_PER_CALL} argument words")
        found.append(
            ReplayCall(
                sender=_address(call.sender, f"the sender of call {index}"),
                target=_address(call.target, f"the target of call {index}"),
                selector=int.from_bytes(data[:SELECTOR_BYTES], "big"),
                words=_words(body),
            )
        )
    return tuple(found)


def _word(value: int) -> str:
    """A 64-digit hex literal; the only way a value enters the source."""
    if type(value) is not int or not 0 <= value < 2**256:
        raise PocRejected("a value is not an unsigned 256-bit integer")
    return f"0x{value:064x}"


def _selector(value: int) -> str:
    if type(value) is not int or not 0 <= value < 2**32:
        raise PocRejected("a selector is not a 4-byte value")
    return f"0x{value:08x}"


def _header(
    base: BaseContract,
    solc: str,
    purpose: str,
    origin: str = "the variant search",
) -> list[str]:
    if _IDENTIFIER.fullmatch(base.name) is None or base.name == VARIANT_POC_CONTRACT:
        raise PocRejected("the base contract name is not a plain identifier")
    parts = base.path.split("/")
    if not base.path.endswith(".sol") or any(
        _SEGMENT.fullmatch(part) is None or part in (".", "..") for part in parts
    ):
        raise PocRejected("the base contract file has an unexpected path")
    if _SOLC.fullmatch(solc) is None:
        raise PocRejected("the solc version is not X.Y.Z")
    return [
        "// SPDX-License-Identifier: MIT",
        f"pragma solidity {solc};",
        "",
        f'import {{{base.name}}} from "./{base.path}";',
        "",
        f"/// @notice {purpose}",
        f"/// @dev The values are those of the counterexample that {origin} reported.",
        f"contract {VARIANT_POC_CONTRACT} is {base.name} {{",
        f"    function {VARIANT_POC_TEST}() public {{",
    ]


def render_fuzz(base: BaseContract, item: FuzzInput, solc: str) -> str:
    """A test that replays one input of `testFuzz_variants`; it passes only if a predicate holds."""
    if len(item.knob_seeds) != KNOB_COUNT:
        raise PocRejected("a fuzz input has four knob seeds")
    knobs = ", ".join(f"uint256({_word(value)})" for value in item.knob_seeds)
    lines = _header(base, solc, "Replays one variant of the exploit with fixed inputs.")
    lines += [
        "        assayReplayVariant(",
        f"            {_word(item.attacker_seed)},",
        f"            {_word(item.balance_seed)},",
        f"            [{knobs}]",
        "        );",
        "    }",
        "}",
        "",
    ]
    return "\n".join(lines)


def render_invariant(base: BaseContract, calls: Sequence[ReplayCall], solc: str) -> str:
    """A test that replays an invariant sequence; it passes only if the invariant is broken."""
    if not calls or len(calls) > MAX_CALLS:
        raise PocRejected("a sequence has 1 to 256 calls")
    lines = _header(base, solc, "Replays a sequence of calls that breaks the fixture invariant.")
    for call in calls:
        if len(call.words) > MAX_WORDS_PER_CALL:
            raise PocRejected("a call has too many argument words")
        arguments = [f"bytes4(uint32({_selector(call.selector)}))"]
        arguments += [f"uint256({_word(word)})" for word in call.words]
        lines += [
            "        assayReplayCall(",
            f"            address(uint160(uint256({_word(call.sender)}))),",
            f"            address(uint160(uint256({_word(call.target)}))),",
            "            abi.encodePacked(",
            *(
                f"                {argument}{',' if index < len(arguments) - 1 else ''}"
                for index, argument in enumerate(arguments)
            ),
            "            )",
            "        );",
        ]
    lines += ["        assayCheckInvariant();", "    }", "}", ""]
    return "\n".join(lines)


def render_check(base: BaseContract, function: str, words: Sequence[int], solc: str) -> str:
    """A test that replays a counterexample of a symbolic property (`check_*`) through
    `assayReplayCheck`; it passes only if a predicate holds. `words` are the property's
    arguments in order, one 32-byte word each (static types only)."""
    if _CHECK_FUNCTION.fullmatch(function) is None:
        raise PocRejected("the property name is not a plain check_ identifier")
    if len(words) > MAX_WORDS_PER_CALL:
        raise PocRejected("a property has too many arguments")
    lines = _header(base, solc, "Replays a counterexample of a symbolic property.", "Halmos")
    arguments = [f"{base.name}.{function}.selector", *(f"uint256({_word(word)})" for word in words)]
    lines += [
        "        assayReplayCheck(",
        "            abi.encodePacked(",
        *(
            f"                {argument}{',' if index < len(arguments) - 1 else ''}"
            for index, argument in enumerate(arguments)
        ),
        "            )",
        "        );",
        "    }",
        "}",
        "",
    ]
    return "\n".join(lines)
