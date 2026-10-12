"""Text helpers for command output."""

import unicodedata


def printable(text: str) -> str:
    """Escape control and invisible formatting characters in untrusted text."""
    return "".join(
        ch if ch in "\n\t" or unicodedata.category(ch) not in ("Cc", "Cf") else f"\\u{ord(ch):04x}"
        for ch in text
    )
