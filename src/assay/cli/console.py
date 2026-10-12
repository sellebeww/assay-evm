"""Color policy of the command line: plain text unless a terminal wants color."""

import os
from collections.abc import Mapping
from typing import TextIO

import typer


def color_enabled(stream: TextIO, environ: Mapping[str, str] | None = None) -> bool:
    """True only when `stream` is a terminal and `NO_COLOR` is unset or empty (no-color.org)."""
    env = os.environ if environ is None else environ
    if env.get("NO_COLOR"):
        return False
    try:
        return stream.isatty()
    except (AttributeError, ValueError):
        return False


def paint(
    text: str, color: str, *, stream: TextIO, environ: Mapping[str, str] | None = None
) -> str:
    """`text` in `color` when color is enabled for `stream`, else unchanged."""
    return typer.style(text, fg=color) if color_enabled(stream, environ) else text
