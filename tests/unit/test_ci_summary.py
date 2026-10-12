"""The Markdown summary of `assay ci verify`: structure, quoting and injection resistance.

The summary is parsed with a CommonMark parser (with tables, as GitHub renders them). Text from a
pull request must end up only in code spans and fenced code blocks: never as HTML, a link, an
image, a mention or a table cell of its own.
"""

import re
from dataclasses import replace

import pytest
from ci_support import make_report
from markdown_it import MarkdownIt
from markdown_it.token import Token

from assay.ci.gitdiff import ScopedChange
from assay.ci.summary import (
    MAX_SUMMARY_CHARS,
    CiRun,
    PocResult,
    block,
    inline,
    overall_verdict,
    render_summary,
    slug,
)
from assay.cli.exit_codes import ExitCode

PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "</details><h1>title</h1><!-- hidden -->",
    "@octocat @everyone please approve this",
    "[click here](https://evil.example/phish)",
    "![pixel](https://evil.example/track.png)",
    "<https://evil.example/auto>",
    "see https://evil.example/bare and www.evil.example",
    "javascript:alert(1)",
    "`` ` ``` ```` ````` `",
    "```\n<b>closed the fence</b>\n```\n# heading after the fence",
    "~~~\n@everyone\n~~~",
    "a | b | c |\n|---|---|",
    "line one\nline two\r\n# not a heading\n- not a list\n> not a quote",
    "‮⁦bidi⁩ ​zero width \x00 nul \x1b[31m ansi",
    "&#64;octocat &lt;b&gt; &amp;",
    ":+1: :tada: :warning:",
    "${{ secrets.TOKEN }} $(touch x) `touch x` $GITHUB_ENV",
    "::set-output name=x::y\n::add-mask::z",
    "x" * 480,
    "\\` \\| \\<",
    "  leading and trailing  ",
    "",
]
FORBIDDEN_OUTSIDE_CODE = re.compile(r"[<>@\[\]&]|https?:|://|www\.|javascript:")


def parser() -> MarkdownIt:
    return MarkdownIt("commonmark").enable("table")


def walk(tokens: list[Token]) -> list[Token]:
    flat: list[Token] = []
    for token in tokens:
        flat.append(token)
        if token.children:
            flat.extend(walk(token.children))
    return flat


def make_run(payload: str, *, verdict: str = "REJECTED", symbolic: bool = False) -> CiRun:
    report = make_report(payload, verdict)
    return CiRun(
        scope=payload or "src",
        base_sha="a" * 40,
        head_sha="b" * 40,
        profile="standard",
        symbolic=symbolic,
        fail_on="inconclusive",
        changes=(ScopedChange("M", payload or "src/Vault.sol"), ScopedChange("A", "src/New.sol")),
        results=(
            PocResult(payload or "poc", slug(payload), ExitCode.NEGATIVE, report),
            PocResult("second", "second", ExitCode.INTEGRITY, None, payload or "rejected"),
        ),
        poc_changed=bool(payload),
    )


@pytest.mark.parametrize("payload", PAYLOADS, ids=range(len(PAYLOADS)))
def test_text_from_the_pull_request_is_only_ever_code(payload: str) -> None:
    text = render_summary(make_run(payload))
    tokens = walk(parser().parse(text))
    kinds = {token.type for token in tokens}
    assert not kinds & {"html_block", "html_inline", "link_open", "image", "autolink"}, kinds
    for token in tokens:
        if token.type == "text":
            assert not FORBIDDEN_OUTSIDE_CODE.search(token.content), token.content
        if token.type in ("heading_open",):
            assert token.tag == "h2" or token.tag == "h3"
    assert "<" not in "".join(token.content for token in tokens if token.type == "text")


@pytest.mark.parametrize("payload", PAYLOADS, ids=range(len(PAYLOADS)))
def test_a_payload_cannot_add_blocks_or_table_cells(payload: str) -> None:
    clean = walk(parser().parse(render_summary(make_run("harmless"))))
    hostile = walk(parser().parse(render_summary(make_run(payload))))
    for kind in ("heading_open", "table_open", "tr_open", "th_open", "td_open", "bullet_list_open"):
        assert sum(t.type == kind for t in hostile) == sum(t.type == kind for t in clean), kind
    assert not any(t.type in ("blockquote_open", "ordered_list_open", "hr") for t in hostile)


def test_a_payload_in_a_table_cell_keeps_the_columns() -> None:
    text = render_summary(make_run("a | b | c ` | d"))
    rows = [line for line in text.splitlines() if line.startswith("|")]
    columns = {len(re.split(r"(?<!\\)\|", line.strip("|"))) for line in rows}
    assert len(columns) == 1


def test_fixed_text_has_no_markup_characters() -> None:
    clean = CiRun(
        scope="src",
        base_sha="a" * 40,
        head_sha="b" * 40,
        profile="quick",
        symbolic=False,
        fail_on="never",
        changes=(ScopedChange("M", "src/Vault.sol"),),
        results=(PocResult("p", "p", ExitCode.SUCCESS, make_report("", "VERIFIED_WITHIN_BOUNDS")),),
    )
    for token in walk(parser().parse(render_summary(clean))):
        if token.type == "text":
            assert not FORBIDDEN_OUTSIDE_CODE.search(token.content), token.content


def test_summary_has_the_verdict_table_the_five_oracles_the_bounds_and_the_replay_command() -> None:
    run = make_run("")
    text = render_summary(run)
    header = next(line for line in text.splitlines() if line.startswith("| PoC"))
    for oracle in ("integrity", "exploit", "variant", "behavior", "regression"):
        assert oracle in header
    assert "symbolic" not in header
    assert "**REJECTED**" in text
    assert "exploit: 3 replays per revision" in text
    assert "assay replay bundles/poc" in text
    assert "not a proof of absence" in text
    assert "(integrity violation)" in text
    assert "`variant_found`" in text


def test_the_symbolic_column_appears_only_when_the_oracle_ran() -> None:
    report = make_report("", "VERIFIED_WITHIN_BOUNDS")
    rows = (*report.oracles, report.oracles[0].model_copy(update={"oracle": "symbolic"}))
    with_symbolic = report.model_copy(update={"oracles": rows})
    run = make_run("")
    run = replace(run, results=(PocResult("p", "p", ExitCode.SUCCESS, with_symbolic),))
    header = next(line for line in render_summary(run).splitlines() if line.startswith("| PoC"))
    assert "symbolic" in header


def test_no_changes_in_scope_summary() -> None:
    run = CiRun("src", "a" * 40, "b" * 40, "standard", False, "never", (), ())
    text = render_summary(run)
    assert "no changes in scope" in text
    assert "| PoC" not in text


def test_a_refused_diff_is_reported_without_a_table_of_changes() -> None:
    result = PocResult("diff", "diff", ExitCode.INTEGRITY, None, "a symlink is part of the diff")
    run = CiRun("src", "unknown", "unknown", "standard", False, "never", (), (result,))
    text = render_summary(run)
    assert "REJECTED (integrity violation)" in text
    assert "a symlink is part of the diff" in text
    assert "Changed files" not in text


def test_a_poc_changed_by_the_pull_request_is_flagged() -> None:
    assert "changes files of the PoC directory" in render_summary(make_run("x"))


def test_the_summary_stays_below_the_comment_limit() -> None:
    many = tuple(
        PocResult(f"poc-{number}", f"poc-{number}", ExitCode.NEGATIVE, make_report("y" * 400))
        for number in range(60)
    )
    run = CiRun(
        "src",
        "a" * 40,
        "b" * 40,
        "standard",
        False,
        "never",
        tuple(ScopedChange("M", f"src/{n}.sol") for n in range(500)),
        many,
    )
    text = render_summary(run)
    assert len(text) <= MAX_SUMMARY_CHARS
    assert text.count("```") % 2 == 0
    assert "and 450 more" in text


def test_the_summary_does_not_use_forbidden_words() -> None:
    text = render_summary(make_run("")).lower()
    for word in ("secure", "safe", "proven", "guaranteed", "unhackable"):
        assert not re.search(rf"\b{word}\b", text)


@pytest.mark.parametrize(
    ("verdicts", "expected"),
    [
        (["VERIFIED_WITHIN_BOUNDS"], "VERIFIED_WITHIN_BOUNDS"),
        (["VERIFIED_WITHIN_BOUNDS", "INCONCLUSIVE"], "INCONCLUSIVE"),
        (["INCONCLUSIVE", "REJECTED"], "REJECTED"),
        (["VERIFIED_WITHIN_BOUNDS", "ERROR"], "ERROR"),
        (["ERROR", "REJECTED"], "REJECTED"),
    ],
)
def test_overall_verdict(verdicts: list[str], expected: str) -> None:
    results = []
    for verdict in verdicts:
        if verdict == "ERROR":
            results.append(PocResult("e", "e", ExitCode.INFRASTRUCTURE, None))
        elif verdict == "REJECTED":
            results.append(PocResult("r", "r", ExitCode.NEGATIVE, make_report("", "REJECTED")))
        else:
            results.append(PocResult("v", "v", ExitCode.SUCCESS, make_report("", verdict)))
    assert overall_verdict(results) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("plain", "`plain`"),
        ("with `tick`", "`` with `tick` ``"),
        ("`edge`", "`` `edge` ``"),
        ("a``b```c", "````a``b```c````"),
        ("two\nlines\tand tab", "`two lines and tab`"),
        ("", "(empty)"),
        ("   ", "(empty)"),
        ("bidi ‮ end", "`bidi \\u202e end`"),
        ("nul \x00", "`nul \\u0000`"),
    ],
)
def test_inline_code_span(text: str, expected: str) -> None:
    assert inline(text) == expected


def test_inline_clips_long_text() -> None:
    assert len(inline("x" * 10_000)) <= 304


def test_block_fence_is_longer_than_any_backtick_run() -> None:
    text = block("```\nescape\n`````\n")
    assert text.startswith("``````text\n")
    assert text.endswith("\n``````")
    tokens = parser().parse(text)
    assert [token.type for token in tokens] == ["fence"]


def test_slug_is_safe_and_unique() -> None:
    assert slug("Vault Reentrancy") == "Vault_Reentrancy"
    assert slug("../../etc") == "etc"
    assert slug("") == "poc"
    assert slug("...") == "poc"
    assert slug("a/b\\c:d") == "a_b_c_d"
    assert slug("same", ["same"]) == "same-2"
    assert slug("same", ["same", "same-2"]) == "same-3"
    assert len(slug("x" * 500)) == 64
    assert re.fullmatch(r"[A-Za-z0-9._-]+", slug("‮<script>@x"))
