"""A small, conservative reader of Solidity source for the IntegrityOracle.

This is not a parser. It masks comments and string contents, then finds contracts, functions,
modifiers, top-level statements and literals with brace and parenthesis matching. Source text
is untrusted data: it is only scanned, never evaluated, and every loop is bounded by its length.
Masking keeps every newline and every offset, so positions map to the original line numbers.
"""

import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation, localcontext
from typing import Final, Literal

_IDENT: Final = r"[A-Za-z_$][A-Za-z0-9_$]*"
_CONTRACT: Final = re.compile(rf"\b(abstract\s+contract|contract|library|interface)\s+({_IDENT})")
_CALLABLE: Final = re.compile(r"\b(function|modifier|constructor|receive|fallback)\b")
_NAME: Final = re.compile(rf"\s*({_IDENT})")
_TOKEN: Final = re.compile(rf"{_IDENT}|[()]")
_PRAGMA: Final = re.compile(r"\bpragma\b[^;]*;")
_IMPORT: Final = re.compile(r"\bimport\b[^;]*?([\"'])([^\"']*)\1")
_NUMBER: Final = re.compile(
    r"(?<![\w$.])(0[xX][0-9a-fA-F_]+|[0-9][0-9_]*(?:\.[0-9][0-9_]*)?(?:[eE]-?[0-9]{1,3})?)"
    r"(?:\s+(wei|gwei|ether|seconds|minutes|hours|days|weeks))?(?![\w$])"
)
_UNITS: Final = {
    None: 1,
    "wei": 1,
    "gwei": 10**9,
    "ether": 10**18,
    "seconds": 1,
    "minutes": 60,
    "hours": 3600,
    "days": 86400,
    "weeks": 604800,
}
_VISIBILITY: Final = frozenset({"external", "public", "internal", "private"})
_MUTABILITY: Final = frozenset({"pure", "view", "payable", "nonpayable"})
_HEADER_KEYWORDS: Final = _VISIBILITY | _MUTABILITY | {"virtual", "override", "returns"}
_LOCATIONS: Final = frozenset({"memory", "storage", "calldata"})
_TYPE_SUFFIXES: Final = frozenset({"payable"})
_EXTERNAL_CALL: Final = re.compile(
    r"\.\s*(?:call|delegatecall)\s*[({]|\.\s*(?:transfer|send)\s*\("
    r"|(?<![\w$.])(?:call|delegatecall|callcode)\s*\(\s*gas\b"
)
_REVERT: Final = re.compile(r"revert\b")
_FALSE_CHECK: Final = re.compile(r"(?:require|assert)\s*\(\s*false\s*[,)]")
_LITERAL_CHECK: Final = re.compile(
    r"(?:require|assert)\s*\(\s*([0-9]+)\s*(==|!=|<=|>=|<|>)\s*([0-9]+)\s*[,)]"
)
_NO_CALLER: Final = re.compile(
    r"require\s*\(\s*(?:msg\.sender\s*==\s*address\s*\(\s*0\s*\)"
    r"|address\s*\(\s*0\s*\)\s*==\s*msg\.sender)\s*[,)]"
    r"|if\s*\(\s*(?:msg\.sender\s*!=\s*address\s*\(\s*0\s*\)"
    r"|address\s*\(\s*0\s*\)\s*!=\s*msg\.sender)\s*\)\s*\{?\s*revert\b"
)
_PLACEHOLDER: Final = re.compile(r"(?<![\w$])_\s*;")
_RETURN: Final = re.compile(r"return\b")
_MAX_VALUE: Final = 2**256


def mask(text: str, *, keep_strings: bool = False) -> str:
    """Replace comments, and unless `keep_strings` the contents of string literals, by spaces.

    Quotes and newlines stay where they are, so offsets and line numbers do not move.
    """
    out = list(text)
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        pair = text[index : index + 2]
        if pair == "//":
            end = text.find("\n", index)
            end = length if end < 0 else end
            _blank(out, index, end)
            index = end
        elif pair == "/*":
            end = text.find("*/", index + 2)
            end = length if end < 0 else end + 2
            _blank(out, index, end)
            index = end
        elif char in "\"'":
            end = index + 1
            while end < length and text[end] != char and text[end] != "\n":
                end += 2 if text[end] == "\\" else 1
            end = min(end, length)
            if not keep_strings:
                _blank(out, index + 1, end)
            index = end + 1
        else:
            index += 1
    return "".join(out)


def _blank(out: list[str], start: int, end: int) -> None:
    for position in range(start, min(end, len(out))):
        if out[position] != "\n":
            out[position] = " "


def _closing(text: str, start: int, opening: str, closing: str) -> int:
    """Index of the bracket that closes the one at `start`, or `len(text)` if unbalanced."""
    depth = 0
    for position in range(start, len(text)):
        char = text[position]
        if char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return position
    return len(text)


def _depths(text: str) -> list[int]:
    """Brace depth before each character."""
    depths: list[int] = []
    depth = 0
    for char in text:
        depths.append(depth)
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(depth - 1, 0)
    return depths


def line_of(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


# ---------------------------------------------------------------------------------------------
# Declarations
# ---------------------------------------------------------------------------------------------

CallableKind = Literal["function", "modifier", "constructor", "receive", "fallback"]
_KINDS: Final[dict[str, CallableKind]] = {
    "function": "function",
    "modifier": "modifier",
    "constructor": "constructor",
    "receive": "receive",
    "fallback": "fallback",
}


@dataclass(frozen=True, slots=True)
class Callable:
    kind: CallableKind
    name: str
    params: tuple[str, ...]
    visibility: str | None
    mutability: str | None
    modifiers: tuple[str, ...]
    body: str | None
    """Masked text between the braces, or `None` for a declaration without a body."""
    line: int

    @property
    def signature(self) -> str:
        return f"{self.name}({','.join(self.params)})"

    @property
    def external(self) -> bool:
        """Part of the contract's external interface."""
        if self.kind in ("receive", "fallback"):
            return True
        return self.kind == "function" and self.visibility in ("external", "public")


@dataclass(frozen=True, slots=True)
class Contract:
    kind: str
    name: str
    line: int
    body: str
    functions: dict[str, Callable] = field(default_factory=dict)
    """External and internal functions, constructor, receive and fallback, by signature."""
    modifiers: dict[str, Callable] = field(default_factory=dict)

    @property
    def external_calls(self) -> int:
        """Low-level calls and value transfers in the contract's code."""
        return len(_EXTERNAL_CALL.findall(self.body))


def _param_type(param: str) -> str:
    tokens = [token for token in param.split() if token not in _LOCATIONS]
    if len(tokens) >= 2 and re.fullmatch(_IDENT, tokens[-1]) and tokens[-1] not in _TYPE_SUFFIXES:
        tokens = tokens[:-1]
    return " ".join(tokens)


def _split_top(text: str, separator: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for char in text:
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        if char == separator and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def _header(text: str) -> tuple[str | None, str | None, tuple[str, ...]]:
    """Visibility, state mutability and modifier names from a function header."""
    visibility = mutability = None
    modifiers: list[str] = []
    depth = 0
    after_returns = False
    for match in _TOKEN.finditer(text):
        token = match.group(0)
        if token == "(":
            depth += 1
            continue
        if token == ")":
            depth -= 1
            continue
        if depth > 0 or after_returns:
            continue
        if token == "returns":
            after_returns = True
        elif token in _VISIBILITY:
            visibility = token
        elif token in _MUTABILITY:
            mutability = token
        elif token not in _HEADER_KEYWORDS:
            modifiers.append(token)
    return visibility, mutability, tuple(modifiers)


def _callable(body: str, match: re.Match[str], offset_line: int) -> Callable | None:
    keyword = match.group(1)
    position = match.end()
    if keyword in ("function", "modifier"):
        name_match = _NAME.match(body, position)
        if name_match is None:
            return None  # a function type, not a declaration
        name = name_match.group(1)
        position = name_match.end()
    else:
        name = keyword
    while position < len(body) and body[position].isspace():
        position += 1
    params: tuple[str, ...] = ()
    if position < len(body) and body[position] == "(":
        close = _closing(body, position, "(", ")")
        raw = body[position + 1 : close]
        params = tuple(_param_type(item) for item in _split_top(raw, ",") if item.strip())
        position = close + 1
    elif keyword != "modifier":
        return None
    end = position
    depth = 0
    while end < len(body):
        char = body[end]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and char in "{;":
            break
        end += 1
    visibility, mutability, modifiers = _header(body[position:end])
    content: str | None = None
    if end < len(body) and body[end] == "{":
        content = body[end + 1 : _closing(body, end, "{", "}")]
    return Callable(
        kind=_KINDS[keyword],
        name=name,
        params=params,
        visibility=visibility,
        mutability=mutability,
        modifiers=modifiers,
        body=content,
        line=offset_line + body.count("\n", 0, match.start()),
    )


def contracts(source: str) -> list[Contract]:
    """Contracts, abstract contracts, libraries and interfaces declared at the top level."""
    text = mask(source)
    depths = _depths(text)
    found: list[Contract] = []
    for match in _CONTRACT.finditer(text):
        if depths[match.start()] != 0:
            continue
        open_brace = match.end()
        depth = 0
        while open_brace < len(text):
            char = text[open_brace]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            elif char == "{" and depth == 0:
                break
            elif char == ";" and depth == 0:
                open_brace = len(text)
                break
            open_brace += 1
        if open_brace >= len(text):
            continue
        close = _closing(text, open_brace, "{", "}")
        body = text[open_brace + 1 : close]
        body_line = line_of(text, open_brace + 1)
        contract = Contract(
            kind=" ".join(match.group(1).split()),
            name=match.group(2),
            line=line_of(text, match.start()),
            body=body,
        )
        body_depths = _depths(body)
        for item in _CALLABLE.finditer(body):
            if body_depths[item.start()] != 0:
                continue
            declared = _callable(body, item, body_line)
            if declared is None:
                continue
            if declared.kind == "modifier":
                contract.modifiers[declared.name] = declared
            else:
                contract.functions[declared.signature] = declared
        found.append(contract)
    return found


# ---------------------------------------------------------------------------------------------
# Statements
# ---------------------------------------------------------------------------------------------


def statements(body: str) -> list[str]:
    """Top-level statements of a masked function or modifier body, stripped.

    A statement ends at a `;` outside brackets, or at the `}` that closes a block opened by the
    statement (`if (...) { ... }`), unless `else` follows.
    """
    found: list[str] = []
    start = 0
    depth = 0
    index = 0
    while index < len(body):
        char = body[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if char == "}" and depth == 0:
                following = body[index + 1 :].lstrip()
                if not following.startswith("else") and not following.startswith(";"):
                    found.append(body[start : index + 1].strip())
                    start = index + 1
        elif char == ";" and depth == 0:
            found.append(body[start : index + 1].strip())
            start = index + 1
        index += 1
    rest = body[start:].strip()
    if rest:
        found.append(rest)
    return [item for item in found if item and item != ";"]


def always_reverts(body: str) -> bool:
    """True when a top-level statement reverts unconditionally before any top-level return."""
    for statement in statements(body):
        if _RETURN.match(statement):
            return False
        if _REVERT.match(statement) or _FALSE_CHECK.match(statement):
            return True
        literal = _LITERAL_CHECK.match(statement)
        if literal and not _compare(int(literal[1]), literal[2], int(literal[3])):
            return True
    return False


def _compare(left: int, operator: str, right: int) -> bool:
    return {
        "==": left == right,
        "!=": left != right,
        "<": left < right,
        ">": left > right,
        "<=": left <= right,
        ">=": left >= right,
    }[operator]


def only_returns(body: str) -> bool:
    """True when the body has no top-level statement other than `return`."""
    return all(_RETURN.match(statement) for statement in statements(body))


def modifier_bricks(body: str) -> str | None:
    """Why a modifier with this masked body makes every function using it revert, or `None`."""
    if _PLACEHOLDER.search(body) is None:
        return "it never runs the function body (no `_;`)"
    if always_reverts(body):
        return "it always reverts"
    for statement in statements(body):
        if _NO_CALLER.match(statement):
            return "it requires a caller at address(0), which no caller can be"
    return None


# ---------------------------------------------------------------------------------------------
# Literals and imports
# ---------------------------------------------------------------------------------------------

LiteralKind = Literal["address", "selector", "number"]


@dataclass(frozen=True, slots=True)
class SourceLiteral:
    kind: LiteralKind
    value: int
    text: str
    line: int


def literals(masked: str) -> list[SourceLiteral]:
    """Numeric, address and four-byte literals of masked source; pragmas are skipped."""
    text = _PRAGMA.sub(lambda match: re.sub(r"[^\n]", " ", match.group(0)), masked)
    found: list[SourceLiteral] = []
    for match in _NUMBER.finditer(text):
        raw, unit = match.group(1), match.group(2)
        kind: LiteralKind = "number"
        if raw[:2] in ("0x", "0X"):
            digits = raw[2:].replace("_", "")
            if not digits:
                continue
            value = int(digits, 16)
            if len(raw) == 42 and "_" not in raw:
                kind = "address"
            elif len(raw) == 10 and "_" not in raw:
                kind = "selector"
        else:
            parsed = _decimal(raw.replace("_", ""), unit)
            if parsed is None:
                continue
            value = parsed
        if value >= _MAX_VALUE:
            continue
        found.append(SourceLiteral(kind, value, match.group(0), line_of(text, match.start())))
    return found


def _decimal(digits: str, unit: str | None) -> int | None:
    try:
        with localcontext(prec=200):
            number = Decimal(digits) * _UNITS[unit]
    except (InvalidOperation, KeyError):
        return None
    if number != number.to_integral_value() or number < 0 or number >= _MAX_VALUE:
        return None
    return int(number)


def imports(source: str) -> list[tuple[str, int]]:
    """`(path, line)` of every import statement; comments are ignored."""
    text = mask(source, keep_strings=True)
    return [(match.group(2), line_of(text, match.start())) for match in _IMPORT.finditer(text)]
