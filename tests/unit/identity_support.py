"""The user names that a bundle or a report must not contain.

A CI runner is called `runner` or `root` and that is also an ordinary word of the text ("runner
image"), so the real name only counts when it is distinctive. The tests also install a synthetic
user name in the environment, which cannot occur by chance, so the check does not depend on the
machine that runs it.
"""

import contextlib
import getpass
import os

import pytest

SENTINEL = "assayleakprobe8472"
GENERIC = frozenset(
    {"runner", "root", "user", "admin", "ubuntu", "build", "builder", "github", "ci"}
)


def install_synthetic_user(monkeypatch: pytest.MonkeyPatch) -> None:
    for variable in ("USER", "LOGNAME", "USERNAME"):
        monkeypatch.setenv(variable, SENTINEL)


def _real_names() -> set[str]:
    """The names of the real user, read once at import, before a test replaces them."""
    found = {os.environ.get(v, "") for v in ("USER", "LOGNAME", "USERNAME")}
    with contextlib.suppress(KeyError, OSError):
        found.add(getpass.getuser())
    return {n for n in found if len(n) >= 4 and n.lower() not in GENERIC}


REAL_NAMES = _real_names()


def forbidden_user_names() -> list[str]:
    return sorted({SENTINEL} | REAL_NAMES)
