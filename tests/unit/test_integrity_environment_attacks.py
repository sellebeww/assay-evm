"""Attacks on the evidence from the code under test: a target or a patch that reaches for the
test environment is refused by the IntegrityOracle (threat T7), whichever way it does it."""

from pathlib import Path

import pytest
from test_oracle_integrity import BANK, check, details

from assay.ledger import Verdict

CHEATCODE = "0x7109709ECfa91a80626fF3989D68f67F5b1DD12D"
IMPORTS = [
    'import "forge-std/Test.sol";',
    'import {Test, console} from "forge-std/Test.sol";',
    'import "forge-std/Vm.sol";',
    'import "forge-std/console2.sol";',
    'import "ds-test/test.sol";',
    'import {console} from "./lib/Console.sol";',
]
ADDRESS_FORMS = [
    f"address vm = {CHEATCODE};",
    f"address vm = {CHEATCODE.lower()};",
    f"address vm = address(uint160({CHEATCODE.lower()}));",
    "address console = 0x000000000000000000636F6e736F6c652e6c6f67;",
]


def with_import(line: str) -> str:
    return BANK.replace("pragma solidity 0.8.36;\n", f"pragma solidity 0.8.36;\n{line}\n")


@pytest.mark.parametrize("line", IMPORTS)
def test_a_patch_that_imports_a_test_library_fails(tmp_path: Path, line: str) -> None:
    result = check(tmp_path, with_import(line))
    assert result.verdict is Verdict.FAIL
    assert "imports the test library file" in " ".join(details(result, "environment_sniffing"))


@pytest.mark.parametrize("line", IMPORTS)
def test_a_target_that_imports_a_test_library_is_still_flagged_after_a_patch(
    tmp_path: Path, line: str
) -> None:
    base = with_import(line)
    patched = base.replace("function total()", "function total2()")
    result = check(tmp_path, patched, base=base)
    assert "environment_sniffing" in result.codes()


@pytest.mark.parametrize("statement", ADDRESS_FORMS)
def test_a_patch_that_names_a_cheatcode_or_console_address_fails(
    tmp_path: Path, statement: str
) -> None:
    anchor = 'require(sent, "send");'
    result = check(tmp_path, BANK.replace(anchor, f"{anchor}\n        {statement}"))
    assert result.verdict is Verdict.FAIL
    assert "environment_sniffing" in result.codes()


def test_a_cheatcode_name_in_a_comment_or_a_string_is_not_an_attack(tmp_path: Path) -> None:
    anchor = 'require(sent, "send");'
    harmless = f'// forge-std/Test.sol {CHEATCODE}\n        string memory s = "forge-std/Test.sol";'
    result = check(tmp_path, BANK.replace(anchor, f"{anchor}\n        {harmless}"))
    assert "environment_sniffing" not in result.codes()
