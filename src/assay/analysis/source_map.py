"""Function spans and code snippets of project sources, for the normalizer.

The normalizer needs two facts about a reported location that the tools do not report in the
same way: the function it lies in (to merge results of different tools in one function) and a
hash of the code it covers (part of the stable finding id). Both are computed here from the
snapshot, the same way for every tool.

The text of a project file is untrusted data. It is read from the snapshot without following a
symlink, as a regular file and only up to `MAX_SOURCE_BYTES`, and scanned in one linear pass
over tokens: comments and string literals are skipped, braces are counted, nothing is evaluated.
A file that cannot be read gives no function spans and the hash of an empty snippet, so the
result stays deterministic.
"""

import bisect
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from assay.analysis.base import read_report
from assay.analysis.limits import AnalyzerOutputError
from assay.ingest.paths import UnsafePathError, safe_relative_path

MAX_SOURCE_BYTES: Final = 2 * 1024 * 1024

# Comments and strings run to their end or, when unterminated, to the end of the text or line,
# so every token is consumed once and the scan stays linear.
_TOKEN: Final = re.compile(
    r"""
    (?P<comment>//[^\n]*|/\*(?:[^*]|\*(?!/))*(?:\*/|\Z))
    |(?P<string>"(?:[^"\\\n]|\\.)*(?:"|(?=\n)|\Z)|'(?:[^'\\\n]|\\.)*(?:'|(?=\n)|\Z))
    |(?P<word>[A-Za-z_$][A-Za-z0-9_$]*)
    |(?P<punct>[{};(])
    """,
    re.VERBOSE | re.DOTALL,
)
_CONTAINERS: Final = frozenset({"contract", "library", "interface"})
_NAMED_CALLABLES: Final = frozenset({"function", "modifier"})
_UNNAMED_CALLABLES: Final = frozenset({"constructor", "fallback", "receive"})


@dataclass(frozen=True, slots=True)
class Span:
    """The body of a function-like declaration: its qualified name and its line range."""

    name: str
    start_line: int
    end_line: int

    def contains(self, start_line: int, end_line: int) -> bool:
        return self.start_line <= start_line and end_line <= self.end_line


@dataclass(slots=True)
class _Frame:
    kind: str  # "container", "callable" or "block"
    name: str
    start_line: int


def function_spans(text: str) -> tuple[Span, ...]:
    """Return the spans of every function, modifier, constructor, fallback and receive body.

    Names are qualified by their contract (`Vault.withdraw`); a free function keeps its plain
    name. A declaration without a body (in an interface, or an abstract function) has no span.
    """
    newlines = [index for index, char in enumerate(text) if char == "\n"]

    def line_of(offset: int) -> int:
        return bisect.bisect_right(newlines, offset - 1) + 1

    spans: list[Span] = []
    stack: list[_Frame] = []
    pending_container: str | None = None
    expect_container_name = False
    pending_callable: tuple[str, int] | None = None
    expect_callable_name: int | None = None  # line of a `function` or `modifier` keyword

    for token in _TOKEN.finditer(text):
        kind = token.lastgroup
        if kind in ("comment", "string"):
            continue
        value = token.group()
        line = line_of(token.start())
        at_declaration_level = not stack or stack[-1].kind == "container"
        if kind == "word":
            if expect_container_name:
                pending_container, expect_container_name = value, False
            elif expect_callable_name is not None:
                pending_callable, expect_callable_name = (value, expect_callable_name), None
            elif pending_callable is None and pending_container is None and at_declaration_level:
                if value in _CONTAINERS:
                    expect_container_name = True
                elif value in _NAMED_CALLABLES:
                    expect_callable_name = line
                elif value in _UNNAMED_CALLABLES:
                    pending_callable = (value, line)
            continue
        expect_callable_name = None  # `function (` starts a function type, not a declaration
        if value == "{":
            if pending_container is not None:
                stack.append(_Frame("container", pending_container, line))
                pending_container = None
            elif pending_callable is not None:
                stack.append(_Frame("callable", pending_callable[0], pending_callable[1]))
                pending_callable = None
            else:
                stack.append(_Frame("block", "", line))
        elif value == "}":
            if not stack:
                continue
            frame = stack.pop()
            if frame.kind == "callable":
                owners = [item.name for item in stack if item.kind == "container"]
                name = ".".join([*owners[-1:], frame.name])
                spans.append(Span(name, frame.start_line, line))
        elif value == ";":
            pending_callable = None
            pending_container = None
            expect_container_name = False
    return tuple(sorted(spans, key=lambda span: (span.start_line, span.end_line, span.name)))


@dataclass(frozen=True, slots=True)
class SourceFile:
    """The lines of one project file and its function spans."""

    lines: tuple[str, ...]
    functions: tuple[Span, ...]

    def function_at(self, start_line: int, end_line: int) -> Span | None:
        """The function whose body contains the whole line range, if any."""
        for span in self.functions:
            if span.contains(start_line, end_line):
                return span
        return None

    def snippet(self, start_line: int, end_line: int) -> str:
        """The lines of the range, each stripped of surrounding whitespace."""
        return "\n".join(line.strip() for line in self.lines[start_line - 1 : end_line])


def snippet_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class SourceReader:
    """Reads project files from a snapshot directory, each at most once."""

    root: Path
    max_bytes: int = MAX_SOURCE_BYTES
    _cache: dict[str, SourceFile | None] = field(default_factory=dict)

    def get(self, path: str) -> SourceFile | None:
        """The file at the project-relative `path`, or `None` if it cannot be read."""
        if path not in self._cache:
            self._cache[path] = self._load(path)
        return self._cache[path]

    def _load(self, path: str) -> SourceFile | None:
        try:
            relative = safe_relative_path(path)
            data = read_report(self.root / relative, self.max_bytes)
        except (UnsafePathError, AnalyzerOutputError):
            return None
        text = data.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
        return SourceFile(lines=tuple(text.split("\n")), functions=function_spans(text))
