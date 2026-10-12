"""Check the public documentation (`make docs-check`, part of `make check`).

1. Every relative link in `README.md` and in `docs/**/*.md` points to a file or directory that
   exists, and a `#fragment` names a heading of the target Markdown file. Links inside code
   fences and code spans are not links.
2. The words that the project never uses for a result do not appear in those files, except in a
   sentence that denies them ("is not a proof", "never says ..."). The words are listed in
   `FORBIDDEN`; a sentence is a denial when it holds a negation from `NEGATION`.

Images that are announced in the text but not committed yet are listed in `PENDING`; the check
prints a note for each and removes the entry's effect as soon as the file exists, so the list
cannot hide a link that was forgotten.

Exit status: 0 no problem, 1 at least one problem (each is printed with file and line), 2 bad
arguments.
"""

import argparse
import re
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Final
from urllib.parse import unquote

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
FORBIDDEN: Final = re.compile(
    r"(?<![\w-])(secure|safe|safely|proven|guarantee|guarantees|guaranteed|unhackable)(?![\w-])",
    re.IGNORECASE,
)
NEGATION: Final = re.compile(
    r"\b(not|never|no|cannot|without|nor|neither|denies|deny|denied|forbidden|rejects?|"
    r"refuses?|avoids?|unlike)\b|n't",
    re.IGNORECASE,
)
PENDING: Final = frozenset({"docs/img/report.png"})
"""Repository paths of images that the text announces and that are added by hand."""

_FENCE: Final = re.compile(r"^(\s*)(```|~~~)")
_CODE_SPAN: Final = re.compile(r"(`+)(.+?)\1")
_LINK: Final = re.compile(
    r"!?\[(?:[^\]\\]|\\.)*\]\(\s*(<[^>]*>|[^)\s]+)(?:\s+(?:\"[^\"]*\"|'[^']*'))?\s*\)"
)
_HEADING: Final = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_SENTENCE: Final = re.compile(r"(?<=[.!?;:])\s+")
_SCHEME: Final = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def markdown_files(root: Path) -> list[Path]:
    files = [root / "README.md", *sorted((root / "docs").rglob("*.md"))]
    return [path for path in files if path.is_file()]


def prose_lines(text: str, *, blank_code: bool = True) -> Iterable[tuple[int, str]]:
    """(line number, line) outside code fences; inline code spans are blanked out unless asked."""
    fence: str | None = None
    for number, line in enumerate(text.splitlines(), start=1):
        marker = _FENCE.match(line)
        if marker is not None:
            if fence is None:
                fence = marker.group(2)
            elif marker.group(2) == fence:
                fence = None
            continue
        if fence is None:
            yield (
                number,
                (_CODE_SPAN.sub(lambda m: " " * len(m.group(0)), line) if blank_code else line),
            )


def slug(heading: str) -> str:
    """The anchor GitHub gives a heading."""
    text = _CODE_SPAN.sub(lambda m: m.group(2), heading)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text).lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    found: dict[str, int] = {}
    result: set[str] = set()
    for _, line in prose_lines(path.read_text(encoding="utf-8"), blank_code=False):
        heading = _HEADING.match(line)
        if heading is None:
            continue
        base = slug(heading.group(2))
        count = found.get(base, 0)
        found[base] = count + 1
        result.add(base if count == 0 else f"{base}-{count}")
    return result


def check_links(path: Path, root: Path, notes: list[str]) -> list[str]:
    problems: list[str] = []
    text = path.read_text(encoding="utf-8")
    for number, line in prose_lines(text):
        for match in _LINK.finditer(line):
            target = match.group(1).strip("<>")
            if not target or _SCHEME.match(target):
                continue
            where = f"{path.relative_to(root)}:{number}"
            file_part, _, fragment = target.partition("#")
            file_part = unquote(file_part)
            destination = path if not file_part else (path.parent / file_part).resolve()
            try:
                relative = destination.relative_to(root.resolve()).as_posix()
            except ValueError:
                problems.append(f"{where}: link leaves the repository: {target}")
                continue
            if not destination.exists():
                if relative in PENDING:
                    notes.append(f"{where}: {relative} is announced and not committed yet")
                    continue
                problems.append(f"{where}: broken link: {target}")
                continue
            if (
                fragment
                and destination.suffix == ".md"
                and unquote(fragment) not in anchors(destination)
            ):
                problems.append(f"{where}: no heading for #{fragment} in {relative}")
    return problems


def check_words(path: Path, root: Path) -> list[str]:
    problems: list[str] = []
    text = path.read_text(encoding="utf-8")
    lines = list(prose_lines(text))
    # A sentence may span lines: join consecutive prose lines of a paragraph.
    paragraphs: list[list[tuple[int, str]]] = []
    for number, line in lines:
        if not line.strip():
            paragraphs.append([])
            continue
        if not paragraphs:
            paragraphs.append([])
        paragraphs[-1].append((number, line))
    for paragraph in paragraphs:
        for number, line in paragraph:
            for match in FORBIDDEN.finditer(line):
                if not _denied(paragraph, number, match.start()):
                    problems.append(
                        f"{path.relative_to(root)}:{number}: the word '{match.group(0)}' is only "
                        "allowed in a sentence that denies it"
                    )
    return problems


def _denied(paragraph: Sequence[tuple[int, str]], number: int, column: int) -> bool:
    """True when the sentence that holds the match has a negation."""
    joined = ""
    offset = 0
    for line_number, line in paragraph:
        if line_number == number:
            offset = len(joined) + column
        joined += line + " "
    start = 0
    for boundary in _SENTENCE.finditer(joined):
        if boundary.end() > offset:
            sentence = joined[start : boundary.start()]
            return NEGATION.search(sentence) is not None
        start = boundary.end()
    return NEGATION.search(joined[start:]) is not None


def run(root: Path) -> tuple[list[str], list[str]]:
    problems: list[str] = []
    notes: list[str] = []
    for path in markdown_files(root):
        problems += check_links(path, root, notes)
        problems += check_words(path, root)
    return problems, notes


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="Repository root.")
    args = parser.parse_args(argv)
    root: Path = args.root.resolve()
    if not (root / "README.md").is_file():
        print(f"error: no README.md in {root}", file=sys.stderr)
        return 2
    problems, notes = run(root)
    for note in notes:
        print(f"note: {note}")
    for problem in problems:
        print(problem, file=sys.stderr)
    checked = len(markdown_files(root))
    if problems:
        print(f"docs-check: {len(problems)} problem(s) in {checked} files", file=sys.stderr)
        return 1
    print(f"docs-check: OK ({checked} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
