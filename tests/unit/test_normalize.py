"""The normalizer: class mapping, placement, stable ids and deduplication across tools."""

import ast
import hashlib
import os
import random
import time
import tomllib
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import fixture_check
from assay.analysis import Aderyn, AnalyzerName, Location, Observation, Slither
from assay.analysis.normalize import (
    ID_SCHEME,
    OTHER,
    ClassMapError,
    Finding,
    ToolObservations,
    default_class_map,
    normalize,
    parse_class_map,
    severity_word,
    stable_id,
)
from assay.analysis.source_map import MAX_SOURCE_BYTES, SourceReader, Span, function_spans
from assay.ledger import EvidenceLevel, FindingState

ROOT = Path(__file__).resolve().parents[2]
ANALYSIS = ROOT / "src" / "assay" / "analysis"
CLASS_MAP = ANALYSIS / "class_map.toml"
GOLDEN = ROOT / "tests" / "data" / "analyzers"
REENTRANCY = ROOT / "fixtures" / "reentrancy" / "single_function"
SLITHER, ADERYN = AnalyzerName.SLITHER, AnalyzerName.ADERYN

BANK = [
    "// SPDX-License-Identifier: MIT",  # 1
    "pragma solidity 0.8.36;",  # 2
    "",  # 3
    "contract Bank {",  # 4
    "    mapping(address => uint256) public balance;",  # 5
    "",  # 6
    "    function deposit() external payable {",  # 7
    "        balance[msg.sender] += msg.value;",  # 8
    "    }",  # 9
    "",  # 10
    "    function withdraw(uint256 amount) external {",  # 11
    '        (bool ok,) = msg.sender.call{value: amount}("");',  # 12
    "        require(ok);",  # 13
    "        balance[msg.sender] -= amount;",  # 14
    "    }",  # 15
    "}",  # 16
]
BANK_PATH = "src/Bank.sol"


def write_project(root: Path, lines: list[str] = BANK, path: str = BANK_PATH) -> Path:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n")
    return root


def observation(
    rule: str,
    *ranges: tuple[int, int],
    path: str = BANK_PATH,
    severity: str = "High",
    message: str = "a message",
) -> Observation:
    return Observation(
        rule_id=rule,
        severity_reported=severity,
        message=message,
        locations=tuple(Location(path=path, start_line=a, end_line=b) for a, b in ranges),
    )


def run(
    root: Path, slither: list[Observation] | None = None, aderyn: list[Observation] | None = None
) -> tuple[Finding, ...]:
    results = []
    if slither is not None:
        results.append(ToolObservations(SLITHER, "0.11.6", tuple(slither)))
    if aderyn is not None:
        results.append(ToolObservations(ADERYN, "v0.6.8", tuple(aderyn)))
    return normalize(results, SourceReader(root))


@pytest.fixture
def bank(tmp_path: Path) -> Path:
    return write_project(tmp_path / "bank")


# -- the mapping file ------------------------------------------------------------------------


def test_the_mapping_file_lists_exactly_the_eight_fixture_classes() -> None:
    data = tomllib.loads(CLASS_MAP.read_text())
    assert tuple(data["classes"]) == fixture_check.CLASS_IDS
    mapping = default_class_map()
    assert mapping.classes == fixture_check.CLASS_IDS
    for tool, table in mapping.detectors.items():
        assert set(table.values()) <= {*mapping.classes, OTHER}, tool


def test_known_detectors_map_to_their_class_and_unknown_ones_to_other() -> None:
    mapping = default_class_map()
    assert mapping.vuln_class(SLITHER, "reentrancy-eth") == "reentrancy"
    assert mapping.vuln_class(ADERYN, "reentrancy-state-change") == "reentrancy"
    assert mapping.vuln_class(SLITHER, "controlled-delegatecall") == "delegatecall"
    assert mapping.vuln_class(SLITHER, "low-level-calls") == OTHER
    assert mapping.vuln_class(SLITHER, "a-detector-of-a-later-version") == OTHER
    # The same id means different things per tool; the table is per tool.
    assert mapping.vuln_class(ADERYN, "reentrancy-eth") == OTHER


def test_detector_names_live_only_in_the_mapping_file() -> None:
    """No Python module of the analysis layer, the scan orchestrator or the scan command names
    a detector of the mapping: the table in class_map.toml is the only place."""
    data = tomllib.loads(CLASS_MAP.read_text())
    detectors = {name for table in data["detectors"].values() for name in table}
    modules = [
        *sorted(ANALYSIS.glob("*.py")),
        ROOT / "src" / "assay" / "orchestrator" / "scan.py",
        ROOT / "src" / "assay" / "cli" / "scan.py",
    ]
    for module in modules:
        strings = {
            node.value
            for node in ast.walk(ast.parse(module.read_text()))
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        assert not strings & detectors, (module.name, sorted(strings & detectors))


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (('classes = [\n    "reentrancy",', 'classes = [\n    "other",'), "other"),
        (('classes = [\n    "reentrancy",', 'classes = [\n    "dos",'), "unique"),
        (('reentrancy-eth = "reentrancy"', 'reentrancy-eth = "reentrancyy"'), "unknown classes"),
        (('high = "error"', 'high = "fatal"'), "malformed"),
        (('high = "error"', 'critical = "error"'), "same words"),
        (("schema_version = 1", "schema_version = 2"), "malformed"),
        (("[detectors.aderyn]", "[detectors.mythril]"), "malformed"),
    ],
)
def test_a_malformed_mapping_is_refused(change: tuple[str, str], message: str) -> None:
    text = CLASS_MAP.read_text()
    assert change[0] in text
    with pytest.raises(ClassMapError, match=message):
        parse_class_map(text.replace(change[0], change[1], 1))


def test_severities_keep_their_order_and_unknown_ones_meet_every_threshold() -> None:
    mapping = default_class_map()
    assert severity_word("High (confidence Low)") == "high"
    assert severity_word("Low") == "low"
    assert mapping.sarif_level("High (confidence Medium)") == "error"
    assert mapping.sarif_level("Medium (confidence High)") == "warning"
    assert mapping.sarif_level("Informational (confidence High)") == "note"
    assert mapping.sarif_level("Critical") == "warning"
    assert mapping.meets("High", "high")
    assert mapping.meets("Medium (confidence Low)", "low")
    assert not mapping.meets("Low", "medium")
    assert not mapping.meets("Optimization (confidence High)", "informational")
    assert mapping.meets("Critical", "high")


# -- function spans and source reading ------------------------------------------------------


def test_function_spans_cover_every_function_like_body() -> None:
    text = "\n".join(
        [
            "contract A is B, C(1) {",  # 1
            "    modifier only() { _; }",  # 2
            "    constructor() { x = 1; }",  # 3
            "    receive() external payable {}",  # 4
            "    fallback() external {",  # 5
            "        if (x > 0) { x = 0; }",  # 6
            "    }",  # 7
            "    function f(function (uint) external g) internal returns (uint) {",  # 8
            '        string memory s = "} function fake() {";',  # 9
            "        // function commented() {",  # 10
            "        /* } */ return 1;",  # 11
            "    }",  # 12
            "    struct S { uint a; }",  # 13
            "    function (uint) external pointer;",  # 14
            "}",  # 15
            "interface I { function g() external; }",  # 16
            "function free(uint a) pure returns (uint) {",  # 17
            "    return a;",  # 18
            "}",  # 19
            "abstract contract D { function h() public virtual; function k() public {} }",  # 20
        ]
    )
    assert function_spans(text) == (
        Span("A.only", 2, 2),
        Span("A.constructor", 3, 3),
        Span("A.receive", 4, 4),
        Span("A.fallback", 5, 7),
        Span("A.f", 8, 12),
        Span("free", 17, 19),
        Span("D.k", 20, 20),
    )


@pytest.mark.parametrize(
    "text",
    [
        "/*" * 200_000,
        '"\\"' * 200_000,
        "{" * 300_000,
        "contract X { function f() { " * 50_000,
    ],
)
def test_hostile_sources_are_scanned_in_linear_time(text: str) -> None:
    started = time.monotonic()
    function_spans(text)
    assert time.monotonic() - started < 5


def test_the_reader_refuses_symlinks_oversized_files_and_paths_outside(tmp_path: Path) -> None:
    root = write_project(tmp_path / "p")
    secret = tmp_path / "secret.sol"
    secret.write_text("contract Secret { function s() public {} }\n")
    os.symlink(secret, root / "src" / "Link.sol")
    (root / "src" / "Big.sol").write_bytes(b"a" * (MAX_SOURCE_BYTES + 1))
    reader = SourceReader(root)
    assert reader.get(BANK_PATH) is not None
    assert reader.get("src/Link.sol") is None
    assert reader.get("src/Big.sol") is None
    assert reader.get("../secret.sol") is None
    assert reader.get("src/Missing.sol") is None


# -- placement -------------------------------------------------------------------------------


def test_a_result_becomes_an_unverified_candidate_with_what_the_tool_reported(bank: Path) -> None:
    (finding,) = run(
        bank,
        slither=[
            observation("reentrancy-eth", (11, 15), (12, 12), severity="High (confidence Medium)")
        ],
    )
    assert finding.vuln_class == "reentrancy"
    assert finding.state == FindingState.CANDIDATE.value
    assert finding.evidence_level == EvidenceLevel.E0.value
    assert (finding.location.path, finding.location.start_line, finding.location.end_line) == (
        BANK_PATH,
        11,
        15,
    )
    assert finding.location.function == "Bank.withdraw"
    (source,) = finding.sources
    assert (source.tool, source.tool_version, source.rule_id) == (
        SLITHER,
        "0.11.6",
        "reentrancy-eth",
    )
    assert source.severity_reported == "High (confidence Medium)"
    assert source.message == finding.message == "a message"
    assert [(loc.start_line, loc.end_line) for loc in source.locations] == [(11, 15), (12, 12)]


def test_a_reversed_line_range_is_ordered(bank: Path) -> None:
    (finding,) = run(bank, aderyn=[observation("reentrancy-state-change", (14, 12))])
    assert (finding.location.start_line, finding.location.end_line) == (12, 14)
    assert finding.location.function == "Bank.withdraw"


def test_results_without_a_project_location_give_no_finding(bank: Path) -> None:
    assert run(bank, slither=[observation("solc-version")]) == ()


def test_a_location_outside_every_function_has_no_function(bank: Path) -> None:
    (whole, state) = run(
        bank,
        slither=[observation("unused-state", (5, 5)), observation("unprotected-upgrade", (4, 16))],
    )
    assert (whole.location.start_line, whole.location.end_line) == (4, 16)
    assert state.location.function is None
    assert whole.location.function is None


# -- stable ids ------------------------------------------------------------------------------


def test_the_stable_id_is_the_sha256_of_class_path_range_and_snippet_hash(bank: Path) -> None:
    (finding,) = run(bank, aderyn=[observation("reentrancy-state-change", (12, 14))])
    snippet = "\n".join(line.strip() for line in BANK[11:14])
    snippet_hash = hashlib.sha256(snippet.encode()).hexdigest()
    material = f"{ID_SCHEME}\nreentrancy\n{BANK_PATH}\n12:14\n{snippet_hash}"
    assert finding.snippet_sha256 == snippet_hash
    assert finding.id == hashlib.sha256(material.encode()).hexdigest()
    assert finding.id == stable_id("reentrancy", BANK_PATH, 12, 14, snippet_hash)


def test_the_id_does_not_depend_on_where_the_project_lives(tmp_path: Path) -> None:
    first = write_project(tmp_path / "one")
    second = write_project(tmp_path / "elsewhere" / "two")
    items = [observation("reentrancy-eth", (11, 15)), observation("calls-loop", (7, 9))]
    assert run(first, slither=items) == run(second, slither=items)


def test_the_id_follows_the_code_in_its_range_only(tmp_path: Path) -> None:
    items = [observation("reentrancy-eth", (11, 15))]
    (base,) = run(write_project(tmp_path / "base"), slither=items)
    reindented = [line.replace("    ", "\t") for line in BANK]
    (same,) = run(write_project(tmp_path / "indent", reindented), slither=items)
    elsewhere = [*BANK[:7], "        balance[msg.sender] += msg.value + 0;", *BANK[8:]]
    (unchanged,) = run(write_project(tmp_path / "other", elsewhere), slither=items)
    inside = [*BANK[:13], "        balance[msg.sender] = 0;", *BANK[14:]]
    (changed,) = run(write_project(tmp_path / "changed", inside), slither=items)
    assert base.id == same.id == unchanged.id
    assert changed.id != base.id


def test_the_id_depends_on_the_class(bank: Path) -> None:
    findings = run(
        bank,
        slither=[observation("reentrancy-eth", (11, 15)), observation("low-level-calls", (11, 15))],
    )
    assert len({finding.id for finding in findings}) == 2


_RULES = ["reentrancy-eth", "calls-loop", "low-level-calls", "unchecked-lowlevel"]
_items = st.lists(
    st.tuples(
        st.sampled_from([SLITHER, ADERYN]),
        st.sampled_from(_RULES),
        st.integers(1, 16),
        st.integers(0, 6),
    ),
    max_size=12,
)


@settings(max_examples=60, deadline=None)
@given(items=_items, seed=st.integers(0, 2**32))
def test_findings_do_not_depend_on_the_order_of_the_results(
    tmp_path_factory: pytest.TempPathFactory,
    items: list[tuple[AnalyzerName, str, int, int]],
    seed: int,
) -> None:
    root = write_project(tmp_path_factory.mktemp("order"))

    def observations(
        tool: AnalyzerName, chosen: list[tuple[AnalyzerName, str, int, int]]
    ) -> list[Observation]:
        return [
            observation(rule, (start, min(start + length, 16)), message=f"{rule}@{start}+{length}")
            for item_tool, rule, start, length in chosen
            if item_tool is tool
        ]

    shuffled = list(items)
    random.Random(seed).shuffle(shuffled)
    first = run(root, observations(SLITHER, items), observations(ADERYN, items))
    second = normalize(
        [
            ToolObservations(ADERYN, "v0.6.8", tuple(observations(ADERYN, shuffled))),
            ToolObservations(SLITHER, "0.11.6", tuple(observations(SLITHER, shuffled))),
        ],
        SourceReader(root),
    )
    assert [item.model_dump() for item in first] == [item.model_dump() for item in second]
    assert len({item.id for item in first}) == len(first)


# -- deduplication ---------------------------------------------------------------------------


def test_results_of_both_tools_in_one_function_merge_into_one_finding(bank: Path) -> None:
    (finding,) = run(
        bank,
        slither=[observation("reentrancy-eth", (11, 15), severity="High (confidence Medium)")],
        aderyn=[observation("reentrancy-state-change", (12, 12), severity="High")],
    )
    assert [(source.tool, source.rule_id) for source in finding.sources] == [
        (SLITHER, "reentrancy-eth"),
        (ADERYN, "reentrancy-state-change"),
    ]
    assert (finding.location.start_line, finding.location.end_line) == (11, 15)
    assert finding.location.function == "Bank.withdraw"


def test_the_same_function_merges_even_without_overlapping_lines(bank: Path) -> None:
    (finding,) = run(
        bank,
        slither=[observation("reentrancy-eth", (12, 12))],
        aderyn=[observation("reentrancy-state-change", (14, 14))],
    )
    assert len(finding.sources) == 2
    assert (finding.location.start_line, finding.location.end_line) == (12, 14)


def test_different_classes_or_functions_do_not_merge(bank: Path) -> None:
    findings = run(
        bank,
        slither=[
            observation("reentrancy-eth", (11, 15)),
            observation("unchecked-lowlevel", (12, 12)),
            observation("reentrancy-benign", (7, 9)),
        ],
    )
    assert sorted((item.vuln_class, item.location.function) for item in findings) == [
        ("reentrancy", "Bank.deposit"),
        ("reentrancy", "Bank.withdraw"),
        ("unchecked_call", "Bank.withdraw"),
    ]


def test_locations_outside_functions_merge_when_their_lines_overlap(bank: Path) -> None:
    findings = run(
        bank,
        slither=[observation("unused-state", (5, 5)), observation("events-access", (5, 6))],
        aderyn=[observation("state-no-address-check", (6, 6)), observation("todo", (10, 10))],
    )
    assert [(item.location.start_line, item.location.end_line) for item in findings] == [
        (5, 6),
        (10, 10),
    ]
    assert len(findings[0].sources) == 3


def test_a_whole_contract_location_does_not_absorb_findings_inside_functions(bank: Path) -> None:
    findings = run(
        bank,
        slither=[observation("unprotected-upgrade", (4, 16))],
        aderyn=[observation("tx-origin-used-for-auth", (12, 12))],
    )
    assert len(findings) == 2


def test_the_merged_finding_does_not_depend_on_which_tool_reported_first(bank: Path) -> None:
    slither = [observation("reentrancy-eth", (11, 15))]
    aderyn = [observation("reentrancy-state-change", (12, 12))]
    both = run(bank, slither=slither, aderyn=aderyn)
    swapped = normalize(
        [
            ToolObservations(ADERYN, "v0.6.8", tuple(aderyn)),
            ToolObservations(SLITHER, "0.11.6", tuple(slither)),
        ],
        SourceReader(bank),
    )
    assert both == swapped
    (only_slither,) = run(bank, slither=slither)
    assert only_slither.id == both[0].id


# -- recorded analyzer output ----------------------------------------------------------------


def test_the_recorded_reentrancy_output_gives_one_merged_reentrancy_finding() -> None:
    slither = Slither().parse((GOLDEN / "slither" / "reentrancy-single_function.json").read_bytes())
    aderyn = Aderyn().parse((GOLDEN / "aderyn" / "reentrancy-single_function.json").read_bytes())
    findings = run(REENTRANCY, slither=list(slither), aderyn=list(aderyn))

    reentrancy = [item for item in findings if item.vuln_class == "reentrancy"]
    assert len(reentrancy) == 1
    (finding,) = reentrancy
    assert finding.location.function == "Vault.withdraw"
    assert {source.tool for source in finding.sources} == {SLITHER, ADERYN}
    assert "reentrancy-eth" in {source.rule_id for source in finding.sources}
    placed = sum(1 for item in [*slither, *aderyn] if item.locations)
    assert sum(len(item.sources) for item in findings) == placed
    assert all(item.state == "CANDIDATE" and item.evidence_level == "E0" for item in findings)
