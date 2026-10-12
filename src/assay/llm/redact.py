"""Redaction and the allowlist: the single place that decides what may leave the machine.

Order of operations before anything is sent:

1. allowlist: only `.sol` files inside the project scope, and snippets of them (`read_source`,
   `read_snippet`); never `.env`, `foundry.toml`, hidden paths, symlinks or files outside scope;
2. secret patterns: private keys, mnemonics, common API-key formats, RPC URLs that embed a
   token;
3. absolute paths, e-mail addresses and the user names of the host.

Redaction is pattern based. It reduces the chance of a leak; it does not guarantee there is none.
`scrub_secrets` removes literal secrets (the configured API key) from any text, for example an
error message.
"""

import contextlib
import getpass
import json
import os
import re
import stat
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

from assay.llm.errors import SourceNotAllowed

DEFAULT_SCOPE: Final = ("src",)
MAX_SOURCE_BYTES: Final = 256 * 1024
MAX_SNIPPET_LINES: Final = 200
_MIN_USERNAME_CHARS: Final = 3
_DENIED_NAMES: Final = ("foundry.toml", "remappings.txt", ".env")


def _marker(kind: str) -> str:
    return f"[REDACTED:{kind}]"


@dataclass(frozen=True)
class Redaction:
    """Redacted text and how many values of each kind were replaced (never the values)."""

    text: str
    counts: Mapping[str, int]

    @property
    def total(self) -> int:
        return sum(self.counts.values())


_PEM = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----"
    r".*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|\Z)",
    re.DOTALL,
)
_URL = re.compile(r"""\b(?:https?|wss?|file)://[^\s"'<>)\]]+""", re.IGNORECASE)
_URL_SECRET_QUERY = re.compile(
    r"[?&;](?:key|apikey|api_key|api-key|token|access_token|auth|secret|sig|signature)=",
    re.IGNORECASE,
)
_URL_LONG_SEGMENT = re.compile(r"/[A-Za-z0-9_-]{20,}(?:[/?#]|$)")
_KEY_FORMATS: Final = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}"),
)
_QUOTED_SECRET = re.compile(
    r"""(?ix)\b[\w-]*(?:api[_-]?key|secret|token|passw(?:or)?d|private[_-]?key|auth)[\w-]*\b
        \s*[:=]\s*(["'])(?P<value>[A-Za-z0-9_\-+/=.]{16,})\1"""
)
_ENV_ASSIGNMENT = re.compile(
    r"(?m)^[ \t]*(?:export[ \t]+)?[A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|MNEMONIC)[A-Z0-9_]*"
    r"[ \t]*=[ \t]*(?P<value>\S+)"
)
_HEX = r"(?P<value>(?:0x)?[0-9a-fA-F]{64})\b"
_HEX_KEYS: Final = (
    re.compile(r"""(?i)(?:private[_-]?key|priv[_-]?key|\bpk\b|secret)\w*\s*[:=(]\s*["']?""" + _HEX),
    re.compile(r"(?:\.addr|\.sign|startBroadcast|\.broadcast|rememberKey|deriveKey)\(\s*" + _HEX),
)
_MNEMONIC_CONTEXT = re.compile(
    r"(?i)(?:mnemonic|seed[ _-]?phrase|recovery[ _-]?phrase)\W{0,6}"
    r"(?P<value>(?:[a-z]{3,8}[ ]+){11,23}[a-z]{3,8})"
)
_MNEMONIC_QUOTED = re.compile(
    r"""(["'])(?P<value>(?:[a-z]{3,8} ){11}(?:(?:[a-z]{3,8} ){3}){0,4}[a-z]{3,8})\1"""
)
_EMAIL = re.compile(r"\b[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")
_UNIX_PATH = re.compile(r"(?<![\w.:/~-])/(?:[\w.@+-]+/)+[\w.@+-]*")
_HOME_PATH = re.compile(r"(?<![\w.])~/[\w./@+-]*")
_WINDOWS_PATH = re.compile(r"\b[A-Za-z]:\\(?:[^\s\\\"'<>|]+\\?)+")


def _replace_group(text: str, pattern: re.Pattern[str], kind: str, counts: Counter[str]) -> str:
    """Replace the group named `value` of every match, keeping the rest of the match."""

    def replace(match: re.Match[str]) -> str:
        counts[kind] += 1
        offset = match.start()
        start, end = match.span("value")
        whole = match.group(0)
        return whole[: start - offset] + _marker(kind) + whole[end - offset :]

    return pattern.sub(replace, text)


def _replace_all(text: str, pattern: re.Pattern[str], kind: str, counts: Counter[str]) -> str:
    def replace(_: re.Match[str]) -> str:
        counts[kind] += 1
        return _marker(kind)

    return pattern.sub(replace, text)


def _redact_urls(text: str, counts: Counter[str]) -> str:
    def replace(match: re.Match[str]) -> str:
        url = match.group(0)
        authority = url.split("://", 1)[1].split("/", 1)[0]
        if (
            url.lower().startswith("file://")
            or "@" in authority
            or _URL_SECRET_QUERY.search(url)
            or _URL_LONG_SEGMENT.search(url.split("://", 1)[1])
        ):
            counts["rpc_url" if not url.lower().startswith("file://") else "path"] += 1
            return _marker("rpc_url" if not url.lower().startswith("file://") else "path")
        return url

    return _URL.sub(replace, text)


def host_usernames() -> tuple[str, ...]:
    """The user names of this host: login name, environment names and the home directory name."""
    names: set[str] = set()
    with contextlib.suppress(KeyError, OSError, ImportError):
        names.add(getpass.getuser())
    for variable in ("USER", "LOGNAME", "USERNAME"):
        names.add(os.environ.get(variable, ""))
    with contextlib.suppress(RuntimeError, OSError):
        names.add(Path.home().name)
    return tuple(sorted(name for name in names if len(name) >= _MIN_USERNAME_CHARS))


def redact_text(text: str, *, usernames: Iterable[str] | None = None) -> Redaction:
    """Remove secret patterns, absolute paths, e-mail addresses and user names from `text`."""
    counts: Counter[str] = Counter()
    out = _replace_all(text, _PEM, "private_key", counts)
    out = _redact_urls(out, counts)
    for pattern in _KEY_FORMATS:
        out = _replace_all(out, pattern, "api_key", counts)
    for pattern in _HEX_KEYS:
        out = _replace_group(out, pattern, "private_key", counts)
    out = _replace_group(out, _QUOTED_SECRET, "api_key", counts)
    out = _replace_group(out, _ENV_ASSIGNMENT, "api_key", counts)
    out = _replace_group(out, _MNEMONIC_CONTEXT, "mnemonic", counts)
    out = _replace_group(out, _MNEMONIC_QUOTED, "mnemonic", counts)
    out = _replace_all(out, _EMAIL, "email", counts)
    for pattern in (_UNIX_PATH, _HOME_PATH, _WINDOWS_PATH):
        out = _replace_all(out, pattern, "path", counts)
    names = host_usernames() if usernames is None else tuple(usernames)
    for name in names:
        if len(name) < _MIN_USERNAME_CHARS:
            continue
        pattern = re.compile(rf"(?<![\w]){re.escape(name)}(?![\w])")
        found = len(pattern.findall(out))
        if found:
            counts["username"] += found
            out = pattern.sub("<user>", out)
    return Redaction(text=out, counts=dict(sorted(counts.items())))


def _redact_value(value: object, usernames: Iterable[str] | None, counts: Counter[str]) -> object:
    if isinstance(value, str):
        result = redact_text(value, usernames=usernames)
        counts.update(result.counts)
        return result.text
    if isinstance(value, list):
        return [_redact_value(item, usernames, counts) for item in value]
    if isinstance(value, dict):
        return {
            str(_redact_value(key, usernames, counts)): _redact_value(item, usernames, counts)
            for key, item in value.items()
        }
    return value


def redact_message_text(text: str, *, usernames: Iterable[str] | None = None) -> Redaction:
    """Redact the text of one message.

    A message that is a JSON object (the prompts of the model layer are) is redacted value by
    value and written back in canonical form, so that the escapes of the JSON encoding are not
    taken for text (`a:\\n...` is a newline after `a:`, not a Windows path). Any other text is
    redacted as it is.
    """
    if text.lstrip().startswith("{"):
        try:
            document = json.loads(text)
        except ValueError:
            document = None
        if isinstance(document, dict):
            counts: Counter[str] = Counter()
            clean = _redact_value(document, usernames, counts)
            canonical = json.dumps(clean, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            return Redaction(text=canonical, counts=dict(sorted(counts.items())))
    return redact_text(text, usernames=usernames)


def scrub_secrets(text: str, secrets: Iterable[str]) -> str:
    """Replace every literal occurrence of each secret in `text`. Used on all error text."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, _marker("secret"))
    return text


# Allowlist


def check_relative_path(path: str, scope: Sequence[str] = DEFAULT_SCOPE) -> PurePosixPath:
    """Return `path` as a project-relative path when it may be sent, else raise."""
    if not path or "\x00" in path or "\\" in path or path.startswith(("/", "~")):
        raise SourceNotAllowed("a source path must be relative to the project")
    if any(part in ("", ".", "..") for part in path.split("/")):
        raise SourceNotAllowed("a source path must not contain '.' or '..' parts")
    pure = PurePosixPath(path)
    parts = pure.parts
    if any(part.startswith(".") for part in parts):
        raise SourceNotAllowed("hidden files and directories are never sent")
    if pure.name in _DENIED_NAMES or pure.name.startswith(".env"):
        raise SourceNotAllowed("configuration and environment files are never sent")
    if pure.suffix != ".sol":
        raise SourceNotAllowed("only .sol files are sent")
    scope_dirs = [PurePosixPath(item) for item in scope]
    if not any(len(parts) > len(s.parts) and parts[: len(s.parts)] == s.parts for s in scope_dirs):
        raise SourceNotAllowed("the file is outside the project scope")
    return pure


@dataclass(frozen=True)
class SourceFile:
    """A source file, or a line range of it, after redaction."""

    path: str
    text: str
    counts: Mapping[str, int]


def _read_checked(root: Path, relative: PurePosixPath) -> str:
    base = root.resolve(strict=True)
    candidate = base.joinpath(*relative.parts)
    current = base
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise SourceNotAllowed("symbolic links are never sent")
    try:
        info = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise SourceNotAllowed("the file cannot be read") from exc
    if not stat.S_ISREG(info.st_mode) or not resolved.is_relative_to(base):
        raise SourceNotAllowed("only regular files inside the project are sent")
    if info.st_size > MAX_SOURCE_BYTES:
        raise SourceNotAllowed(f"the file is larger than {MAX_SOURCE_BYTES} bytes")
    try:
        return resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise SourceNotAllowed("the file is not readable UTF-8 text") from exc


def read_allowed_text(root: Path, path: str, scope: Sequence[str] = DEFAULT_SCOPE) -> str:
    """Raw text of one allowed file. Callers must redact what they keep (see `redact_text`)."""
    return _read_checked(root, check_relative_path(path, scope))


def read_source(
    root: Path,
    path: str,
    *,
    scope: Sequence[str] = DEFAULT_SCOPE,
    usernames: Iterable[str] | None = None,
) -> SourceFile:
    """Read one allowed file and return its redacted text."""
    relative = check_relative_path(path, scope)
    redaction = redact_text(_read_checked(root, relative), usernames=usernames)
    return SourceFile(path=relative.as_posix(), text=redaction.text, counts=redaction.counts)


def read_snippet(
    root: Path,
    path: str,
    start_line: int,
    end_line: int,
    *,
    scope: Sequence[str] = DEFAULT_SCOPE,
    usernames: Iterable[str] | None = None,
) -> SourceFile:
    """Read lines `start_line` to `end_line` (1-based, inclusive) of an allowed file, redacted."""
    if not 1 <= start_line <= end_line or end_line - start_line + 1 > MAX_SNIPPET_LINES:
        raise SourceNotAllowed(f"a snippet is at most {MAX_SNIPPET_LINES} lines")
    relative = check_relative_path(path, scope)
    lines = _read_checked(root, relative).splitlines()
    chunk = "\n".join(lines[start_line - 1 : end_line])
    redaction = redact_text(chunk, usernames=usernames)
    return SourceFile(path=relative.as_posix(), text=redaction.text, counts=redaction.counts)
