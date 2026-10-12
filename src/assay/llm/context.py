"""Code context for a prompt: the function a finding points at, not the whole repository."""

import re
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Final

from assay.llm.errors import SourceNotAllowed
from assay.llm.redact import (
    DEFAULT_SCOPE,
    SourceFile,
    read_allowed_text,
    redact_text,
)
from assay.oracles.integrity.solidity import line_of, mask

MAX_CONTEXT_LINES: Final = 120
_WINDOW: Final = 6
_DECLARATION: Final = re.compile(r"(?<![\w$])(function|modifier|constructor|receive|fallback)\b")


def _spans(masked: str) -> list[tuple[int, int]]:
    """`(first line, last line)` of each function-like declaration that has a body."""
    spans: list[tuple[int, int]] = []
    for match in _DECLARATION.finditer(masked):
        paren = 0
        index = match.end()
        while index < len(masked):
            char = masked[index]
            if char == "(":
                paren += 1
            elif char == ")":
                paren -= 1
            elif paren == 0 and char in "{;":
                break
            index += 1
        if index >= len(masked) or masked[index] != "{":
            continue
        depth = 0
        end = index
        while end < len(masked):
            if masked[end] == "{":
                depth += 1
            elif masked[end] == "}":
                depth -= 1
                if depth == 0:
                    break
            end += 1
        spans.append((line_of(masked, match.start()), line_of(masked, min(end, len(masked) - 1))))
    return spans


def function_lines(text: str, start: int, end: int) -> tuple[int, int]:
    """The smallest function that holds lines `start` to `end`, else a small window around them."""
    containing = [(a, b) for a, b in _spans(mask(text)) if a <= start and end <= b]
    if containing:
        first, last = min(containing, key=lambda span: span[1] - span[0])
    else:
        first, last = max(1, start - _WINDOW), end + _WINDOW
    return first, min(last, first + MAX_CONTEXT_LINES - 1)


def related_code(
    root: Path,
    locations: Iterable[tuple[str, int, int]],
    *,
    scope: Sequence[str] = DEFAULT_SCOPE,
    usernames: Iterable[str] | None = None,
    max_files: int = 3,
) -> tuple[SourceFile, ...]:
    """Redacted source of the functions at `locations` (`path`, first line, last line).

    Only allowlisted files are read; a location that is not allowed or cannot be read is
    skipped. At most `max_files` distinct functions are returned.
    """
    chosen: list[SourceFile] = []
    seen: set[tuple[str, int]] = set()
    for path, start, end in locations:
        try:
            text = read_allowed_text(root, path, scope)
        except SourceNotAllowed:
            continue
        first, last = function_lines(text, start, end)
        if (path, first) in seen:
            continue
        seen.add((path, first))
        chunk = "\n".join(text.splitlines()[first - 1 : last])
        redaction = redact_text(chunk, usernames=usernames)
        chosen.append(SourceFile(path=path, text=redaction.text, counts=redaction.counts))
        if len(chosen) >= max_files:
            break
    return tuple(chosen)
