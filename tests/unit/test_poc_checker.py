"""The static PoC checker: default deny, calibrated on the fixtures, strict on hostile sources."""

import glob
import re
from pathlib import Path

import pytest
from hostile_pocs import GOOD, HOSTILE, INSTRUCTIONS, benign_mentions, inject
from prove_support import ROOT

from assay.llm.errors import LlmError
from assay.llm.poc_checker import ALLOWED_CHEATCODES, MAX_POC_BYTES, check_poc
from assay.llm.poc_writer import POC_FILE, PocRejected, example_poc, write_poc

FIXTURE_POCS = sorted(
    path
    for path in glob.glob(str(ROOT / "fixtures" / "*" / "*" / "poc" / "*.t.sol"))
    if "is AssayPoC" in Path(path).read_text()
)


def test_every_fixture_poc_passes() -> None:
    assert len(FIXTURE_POCS) == 8
    for path in FIXTURE_POCS:
        result = check_poc(Path(path).read_text())
        assert result.ok, (path, result.violations)


def test_the_example_in_the_prompt_passes_and_is_a_fixture_poc() -> None:
    assert check_poc(example_poc()).ok
    fixture = ROOT / "fixtures" / "reentrancy" / "single_function" / "poc" / "VaultReentrancy.t.sol"
    assert example_poc() == fixture.read_text()


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_a_hostile_poc_is_rejected_with_a_structured_reason(name: str) -> None:
    source, expected = HOSTILE[name]
    result = check_poc(source)
    assert not result.ok, name
    assert expected in result.codes(), (name, result.violations)
    for item in result.violations:
        assert re.fullmatch(r"[a-z_]+", item.code)
        assert item.detail


def test_hostile_text_in_comments_and_strings_is_data_not_code() -> None:
    assert check_poc(benign_mentions()).ok


def test_every_allowed_cheatcode_is_accepted_and_the_list_is_small() -> None:
    assert len(ALLOWED_CHEATCODES) <= 12
    for name in ALLOWED_CHEATCODES:
        assert check_poc(inject(f"vm.{name}(address(0));")).ok, name


def test_a_cheatcode_through_whitespace_or_a_comment_is_still_checked() -> None:
    for text in ("vm . ffi(c);", "vm/* x */.ffi(c);", "vm\n.\nreadFile('x');"):
        assert not check_poc(inject(text)).ok, text


def test_the_size_limit_is_exact() -> None:
    padding = "\n// " + "x" * (MAX_POC_BYTES - len(GOOD.encode()) - 4)
    assert check_poc(GOOD + padding).ok
    assert "too_large" in check_poc(GOOD + padding + "xx").codes()


def test_a_violation_names_a_line_when_it_can() -> None:
    result = check_poc(inject('vm.readFile("x");'))
    lines = [item.line for item in result.violations if item.code == "cheatcode_not_allowed"]
    assert lines
    assert all(isinstance(line, int) and line > 1 for line in lines)


def test_the_checker_reports_at_most_twenty_violations() -> None:
    noisy = inject(" ".join(f'vm.read{index}("x");' for index in range(100)))
    assert len(check_poc(noisy).violations) <= 20


def test_the_corpus_phrases_are_in_the_instruction_list() -> None:
    assert all(isinstance(text, str) and text for text in INSTRUCTIONS)


# Writing


def test_write_poc_saves_one_fixed_file_after_the_checker_accepted(tmp_path: Path) -> None:
    path = write_poc(tmp_path, GOOD)
    assert path == tmp_path / POC_FILE
    assert path.read_text().strip() == GOOD.strip()
    assert [p.name for p in tmp_path.iterdir()] == [POC_FILE]


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_write_poc_writes_nothing_for_a_rejected_poc(tmp_path: Path, name: str) -> None:
    with pytest.raises(PocRejected) as caught:
        write_poc(tmp_path, HOSTILE[name][0])
    assert HOSTILE[name][1] in caught.value.check.codes()
    assert list(tmp_path.iterdir()) == []


def test_write_poc_refuses_links_and_missing_directories(tmp_path: Path) -> None:
    with pytest.raises(LlmError):
        write_poc(tmp_path / "missing", GOOD)
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(LlmError):
        write_poc(link, GOOD)
    (real / POC_FILE).symlink_to(tmp_path / "elsewhere.txt")
    with pytest.raises(LlmError):
        write_poc(real, GOOD)
    assert not (tmp_path / "elsewhere.txt").exists()
