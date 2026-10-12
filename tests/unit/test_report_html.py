"""The HTML report: golden output, determinism, inert untrusted text, vocabulary, the command."""

import os
import re
import shutil
from html.parser import HTMLParser
from pathlib import Path

import pytest
from report_support import build_bundle, rewrite_manifest_files
from typer.testing import CliRunner

from assay.cli.main import app
from assay.ledger import FinalVerdict
from assay.report.html import CSP, render_diff, render_report
from assay.report.replay import load_bundle

GOLDEN = Path(__file__).parent / "golden"
FORBIDDEN = re.compile(r"\b(secure|safe|proven|guaranteed|unhackable)\b", re.IGNORECASE)
ALLOWED_TAGS = {
    "html", "head", "meta", "title", "style", "body", "main", "h1", "h2", "section", "div", "p",
    "strong", "ul", "ol", "li", "dl", "dt", "dd", "table", "thead", "tbody", "tr", "th", "td",
    "code", "pre", "span", "details", "summary",
}  # fmt: skip
ALLOWED_ATTRIBUTES = {
    "class", "id", "role", "lang", "charset", "name", "content", "http-equiv", "open"
}  # fmt: skip
PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "</style><script>alert(1)</script>",
    "</pre><script>alert(1)</script>",
    "javascript:alert(1)",
    '<a href="javascript:alert(1)">click</a>',
    "' onmouseover='alert(1)",
    "<svg/onload=alert(1)>",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "<!-- --><script>alert(1)</script>",
    "]]></code><iframe src=//evil></iframe>",
    "\u202e<b>reversed</b>\x1b[31m",
]
cli = CliRunner()


class Inspect(HTMLParser):
    """Records every tag and attribute the parser sees, and the text of the page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.attributes: list[tuple[str, str, str | None]] = []
        self.text: list[str] = []
        self.style: list[str] = []
        self.comments = 0
        self._in_style = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self._in_style = tag == "style"
        self.attributes += [(tag, name, value) for name, value in attrs]

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        self._in_style = False

    def handle_data(self, data: str) -> None:
        (self.style if self._in_style else self.text).append(data)

    def handle_comment(self, data: str) -> None:
        self.comments += 1


def inspect(page: str) -> Inspect:
    parser = Inspect()
    parser.feed(page)
    parser.close()
    return parser


def render(tmp_path: Path, name: str = "bundle", **options: object) -> str:
    bundle = build_bundle(tmp_path / name, **options)  # type: ignore[arg-type]
    return render_report(bundle, load_bundle(bundle))


def check_golden(name: str, page: str) -> None:
    path = GOLDEN / name
    if os.environ.get("ASSAY_UPDATE_GOLDEN") == "1":
        path.write_text(page, encoding="utf-8")
    assert page == path.read_text(encoding="utf-8"), (
        f"{name} differs; if the change is intended, run with ASSAY_UPDATE_GOLDEN=1"
    )


# -- golden and determinism ---------------------------------------------------------------------


def test_golden_report_of_a_rejected_patch(tmp_path: Path) -> None:
    check_golden("report_rejected.html", render(tmp_path, verdict=FinalVerdict.REJECTED))


def test_golden_report_of_a_verified_fix_loop(tmp_path: Path) -> None:
    page = render(
        tmp_path, verdict=FinalVerdict.VERIFIED_WITHIN_BOUNDS, fix_loop=True, variant_poc=False
    )
    check_golden("report_verified_fix_loop.html", page)


def test_the_same_bundle_gives_the_same_bytes_wherever_it_lies(tmp_path: Path) -> None:
    first = build_bundle(tmp_path / "one" / "bundle", fix_loop=True)
    copy = tmp_path / "two" / "elsewhere" / "bundle"
    copy.parent.mkdir(parents=True)
    shutil.copytree(first, copy)
    page = render_report(first, load_bundle(first))
    assert page == render_report(first, load_bundle(first))
    assert page == render_report(copy, load_bundle(copy))
    assert str(tmp_path) not in page
    assert os.path.expanduser("~") not in page


def test_the_page_holds_no_time_and_no_user_name(tmp_path: Path) -> None:
    page = render(tmp_path, fix_loop=True)
    assert not re.search(r"\b20\d\d-\d\d-\d\d\b", page)
    assert not re.search(r"\d\d:\d\d:\d\d", page)
    assert os.environ.get("USER", "\0") not in page


# -- structure ----------------------------------------------------------------------------------


@pytest.mark.parametrize("verdict", list(FinalVerdict))
def test_the_banner_uses_the_exact_verdict_words(tmp_path: Path, verdict: FinalVerdict) -> None:
    page = render(tmp_path, verdict=verdict)
    parsed = inspect(page)
    assert verdict.value in parsed.text
    assert f"Assay report: {verdict.value}" in parsed.text


def test_the_page_is_self_contained_and_has_no_script(tmp_path: Path) -> None:
    page = render(tmp_path, fix_loop=True)
    parsed = inspect(page)
    assert set(parsed.tags) <= ALLOWED_TAGS
    assert {name for _, name, _ in parsed.attributes} <= ALLOWED_ATTRIBUTES
    csp = [
        value
        for tag, name, value in parsed.attributes
        if tag == "meta" and name == "content" and value is not None and "default-src" in value
    ]
    assert csp == [CSP]
    assert CSP == "default-src 'none'; style-src 'unsafe-inline'; img-src data:"
    assert 'http-equiv="Content-Security-Policy"' in page
    css = "".join(parsed.style)
    for needle in ("@import", "url(", "http:", "https:", "expression("):
        assert needle not in css
    assert "<script" not in page.lower()
    assert "http://" not in page
    assert "https://" not in page
    assert parsed.tags.count("style") == 1


def test_the_page_says_what_the_result_means_and_what_it_does_not(tmp_path: Path) -> None:
    text = " ".join(inspect(render(tmp_path, verdict=FinalVerdict.VERIFIED_WITHIN_BOUNDS)).text)
    assert "What this result means, and what it does not" in text
    assert "It is not a proof of absence" in text
    assert "Bounds that ran" in text
    assert "assay replay <bundle>" in text


def test_the_page_shows_the_poc_the_variant_poc_the_patch_and_the_oracles(tmp_path: Path) -> None:
    parsed = inspect(render(tmp_path, fix_loop=True))
    text = "\n".join(parsed.text)
    assert "poc/VaultReentrancy.t.sol" in text
    assert "evidence/variant/variant_poc.t.sol" in text
    assert "guard the external call" in text
    for oracle in ("integrity", "exploit", "variant", "behavior", "regression"):
        assert oracle in parsed.text or any(oracle in item for item in parsed.text)
    assert "Attempt history" in text
    assert "variant_found" in text


def test_a_bundle_without_a_variant_says_so(tmp_path: Path) -> None:
    text = " ".join(inspect(render(tmp_path, variant_poc=False)).text)
    assert "so there is no variant_poc" in text


def test_a_bundle_of_a_plain_verification_has_no_attempt_history(tmp_path: Path) -> None:
    text = " ".join(inspect(render(tmp_path, fix_loop=False)).text)
    assert "one patch, no attempt history" in text


def test_an_unreadable_attempt_history_is_reported_not_guessed(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path / "bundle", fix_loop=True)
    (bundle / "fix" / "history.json").write_text("{}\n")
    rewrite_manifest_files(bundle)
    text = " ".join(inspect(render_report(bundle, load_bundle(bundle))).text)
    assert "could not be read" in text


def test_a_large_file_is_cut_with_a_note(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path / "bundle")
    (bundle / "poc" / "VaultReentrancy.t.sol").write_text("// x\n" * 200_000)
    rewrite_manifest_files(bundle)
    page = render_report(bundle, load_bundle(bundle))
    assert "the rest is in the bundle" in page
    assert len(page) < 1_000_000


def test_the_report_never_uses_the_forbidden_words(tmp_path: Path) -> None:
    for index, verdict in enumerate(FinalVerdict):
        page = render(tmp_path, name=f"b{index}", verdict=verdict, fix_loop=True)
        text = " ".join(inspect(page).text)
        assert FORBIDDEN.search(text) is None, FORBIDDEN.search(text)
        assert FORBIDDEN.search(page) is None
        assert "secure" not in page.lower()


# -- the diff -----------------------------------------------------------------------------------


def lines_of(rendered: str) -> list[tuple[str, str]]:
    return re.findall(r'<span class="ln (\w+)">(.*?)</span>', rendered)


def test_the_diff_colours_added_removed_hunk_and_header_lines() -> None:
    diff = "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@ ctx\n keep\n-old\n+new\n"
    assert [kind for kind, _ in lines_of(render_diff(diff))] == [
        "meta", "meta", "meta", "hunk", "ctx", "del", "add"
    ]  # fmt: skip


def test_a_removed_line_that_starts_with_dashes_is_still_a_removed_line() -> None:
    diff = "--- a/x\n+++ b/x\n@@ -1,2 +1,1 @@\n--- not a header\n kept\n"
    kinds = [kind for kind, _ in lines_of(render_diff(diff))]
    assert kinds == ["meta", "meta", "hunk", "del", "ctx"]


def test_a_diff_line_with_markup_is_escaped_in_every_kind_of_line() -> None:
    payload = "<script>x</script>"
    diff = f"--- a/{payload}\n+++ b/{payload}\n@@ -1 +1 @@\n-{payload}\n+{payload}\n {payload}\n"
    rendered = render_diff(diff)
    assert "<script>" not in rendered
    assert rendered.count("&lt;script&gt;") == 5


# -- untrusted text is inert --------------------------------------------------------------------


@pytest.mark.parametrize("payload", PAYLOADS)
def test_untrusted_text_never_becomes_markup(tmp_path: Path, payload: str) -> None:
    page = render(
        tmp_path,
        payload=payload,
        fix_loop=True,
        verdict=FinalVerdict.REJECTED,
        tool_name=payload,
    )
    benign = inspect(
        render(
            tmp_path,
            name="benign",
            payload="plain text",
            fix_loop=True,
            verdict=FinalVerdict.REJECTED,
            tool_name="plain text",
        )
    )
    parsed = inspect(page)
    assert set(parsed.tags) <= ALLOWED_TAGS
    assert parsed.tags.count("style") == 1
    assert parsed.tags.count("script") == 0
    assert parsed.tags == benign.tags, "the payload changed the element structure"
    assert {name for _, name, _ in parsed.attributes} <= ALLOWED_ATTRIBUTES
    assert parsed.attributes == benign.attributes, "the payload changed an attribute"
    for _, name, value in parsed.attributes:
        assert not name.startswith("on")
        assert value is None or "javascript:" not in value.lower()
    assert parsed.comments == 0
    assert "".join(parsed.style) == "".join(benign.style)
    # The payload is shown, as text, in the places that carry it.
    visible = printable_form(payload)
    assert visible in "\n".join(parsed.text)


def printable_form(payload: str) -> str:
    from assay.cli.text import printable

    return printable(payload)


@pytest.mark.parametrize(
    "where",
    ["patch.diff", "poc/VaultReentrancy.t.sol", "evidence/variant/variant_poc.t.sol"],
)
def test_hostile_file_contents_stay_text(tmp_path: Path, where: str) -> None:
    payload = "</pre></details></section><script>alert(1)</script><img src=x onerror=alert(1)>"
    bundle = build_bundle(tmp_path / "bundle")
    (bundle / where).write_text(
        f"// function {payload}\n+// {payload}\n-// {payload}\n@@ -1 +1 @@ {payload}\n"
    )
    rewrite_manifest_files(bundle)
    parsed = inspect(render_report(bundle, load_bundle(bundle)))
    assert "script" not in parsed.tags
    assert "img" not in parsed.tags
    assert all(not name.startswith("on") for _, name, _ in parsed.attributes)
    assert any(payload in item for item in parsed.text)


def test_a_hostile_file_name_in_the_manifest_cannot_become_markup(tmp_path: Path) -> None:
    name = "poc/<img src=x onerror=alert(1)>.t.sol"
    bundle = build_bundle(tmp_path / "bundle")
    (bundle / "poc" / "<img src=x onerror=alert(1)>.t.sol").write_text("// poc\n")
    document = (bundle / "manifest.json").read_text()
    (bundle / "manifest.json").write_text(
        document.replace(
            '"files": [', '"files": [\n    {"path": "' + name + '", "sha256": "0", "size": 0},', 1
        )
    )
    rewrite_manifest_files(bundle)
    parsed = inspect(render_report(bundle, load_bundle(bundle)))
    assert "img" not in parsed.tags
    assert any(name in item for item in parsed.text)


# -- the command --------------------------------------------------------------------------------


def report(bundle: Path, out: Path, *options: str):  # type: ignore[no-untyped-def]
    return cli.invoke(app, ["report", str(bundle), "--out", str(out), *options])


def test_the_command_writes_the_report_and_is_deterministic(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path / "bundle", fix_loop=True)
    first, second = tmp_path / "a.html", tmp_path / "b.html"
    result = report(bundle, first)
    assert result.exit_code == 0, result.output
    assert report(bundle, second).exit_code == 0
    assert first.read_bytes() == second.read_bytes()
    assert first.read_text() == render_report(bundle, load_bundle(bundle))
    assert "REJECTED" in result.stdout


def test_the_command_replaces_an_existing_report(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path / "bundle")
    out = tmp_path / "r.html"
    out.write_text("old")
    assert report(bundle, out).exit_code == 0
    assert out.read_text().startswith("<!doctype html>")


def test_a_tampered_bundle_gets_no_report_and_exit_5(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path / "bundle")
    (bundle / "patch.diff").write_text("changed\n")
    out = tmp_path / "r.html"
    result = report(bundle, out)
    assert result.exit_code == 5
    assert "no report was written" in result.stderr
    assert not out.exists()


def test_an_extra_file_in_the_bundle_is_a_tamper_too(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path / "bundle")
    (bundle / "extra.txt").write_text("x")
    assert report(bundle, tmp_path / "r.html").exit_code == 5


def test_usage_errors_exit_2(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path / "bundle")
    assert report(tmp_path / "missing", tmp_path / "r.html").exit_code == 2
    assert report(bundle, tmp_path / "no" / "such" / "r.html").exit_code == 2
    assert report(bundle, tmp_path).exit_code == 2
    inside = report(bundle, bundle / "r.html")
    assert inside.exit_code == 2
    assert not (bundle / "r.html").exists()
    assert cli.invoke(app, ["report", str(bundle)]).exit_code == 2


def test_a_bundle_of_another_format_version_is_a_usage_error(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path / "bundle")
    text = (
        (bundle / "manifest.json").read_text().replace('"schema_version": 2', '"schema_version": 1')
    )
    (bundle / "manifest.json").write_text(text)
    result = report(bundle, tmp_path / "r.html")
    assert result.exit_code == 2
    assert "schema version" in result.stderr


def test_the_command_output_has_no_color_codes(tmp_path: Path) -> None:
    bundle = build_bundle(tmp_path / "bundle")
    result = report(bundle, tmp_path / "r.html")
    assert "\x1b" not in result.output
