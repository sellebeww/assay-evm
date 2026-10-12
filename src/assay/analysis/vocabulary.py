"""Words that scan output never uses, and the neutralization of text that tools wrote.

Scan output states what is known: an analyzer result is a candidate (unverified) at evidence
level E0. It never calls code confirmed, vulnerable, secure or safe, and never uses the words
proven, guaranteed or unhackable. Assay's own text is written without them. Text that comes
from a tool (a detector message, the last line of an error stream) can contain them; before such
text appears in scan output, each of these words is replaced by `WITHHELD`. The ledger and the
stored raw output keep the tool's text unchanged.

Structured fields such as paths and Solidity identifiers are printed as found.
"""

import re
from typing import Final

FORBIDDEN_WORDS: Final = (
    "confirmed",
    "vulnerable",
    "secure",
    "safe",
    "proven",
    "guaranteed",
    "unhackable",
)
WITHHELD: Final = "[term withheld]"
FORBIDDEN_PATTERN: Final = re.compile(r"\b(?:" + "|".join(FORBIDDEN_WORDS) + r")\b", re.IGNORECASE)


def neutral(text: str) -> str:
    """Return `text` with every word of `FORBIDDEN_WORDS` replaced by `WITHHELD`."""
    return FORBIDDEN_PATTERN.sub(WITHHELD, text)
