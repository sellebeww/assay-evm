"""The interface of a contract (storage layout, ABI functions, events) and its comparison.

Input is the JSON printed by `forge inspect <contract> storageLayout --json` and
`forge inspect <contract> abi --json`. It is untrusted: it is parsed with strict models and
size limits, and anything unexpected raises `InterfaceError`.

Comparison rules (breaking changes fail, additive changes are warnings):

- Storage layout. Every variable of the vulnerable revision is compared in order: name, slot,
  offset, type and size. Any difference is breaking, including a new variable placed before or
  between existing ones, or packed into the free bytes of the last used slot. New variables after
  the existing ones that start in a slot after the last slot used by the vulnerable revision are
  additive. Types are compared by their full description (struct members, mapping key and value,
  array base), never by forge's type identifiers, which contain AST ids.
- ABI functions, including the constructor, `receive` and `fallback`, identified by name and
  parameter types (tuples in canonical form). A removed function (a changed parameter list
  counts as a removal) or changed return types or state mutability is breaking; a new function is
  additive.
- Events, identified by name and parameter types. A removed event or a change of its indexed
  parameters or anonymity is breaking; a new event is additive.

Parameter names and custom errors are not compared.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Annotated, Final, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    TypeAdapter,
    ValidationError,
)

MAX_ENTRIES: Final = 10_000
MAX_TYPE_DEPTH: Final = 32
_Name = Annotated[str, StringConstraints(max_length=1024)]
_TypeId = Annotated[str, StringConstraints(min_length=1, max_length=4096)]
_Digits = Annotated[str, StringConstraints(pattern=r"^[0-9]{1,78}$")]
_AbiType = Annotated[str, StringConstraints(pattern=r"^[a-z0-9]+(?:\[[0-9]*\])*$", max_length=200)]

ChangeKind = Literal["layout", "abi", "events"]


class InterfaceError(ValueError):
    """Output of `forge inspect` that does not have the expected shape."""


class _Raw(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="ignore")


class _RawVariable(_Raw):
    label: _Name
    offset: Annotated[int, Field(ge=0, le=31)]
    slot: _Digits
    type: _TypeId


class _RawType(_Raw):
    encoding: _Name
    label: _Name
    numberOfBytes: _Digits
    key: _TypeId | None = None
    value: _TypeId | None = None
    base: _TypeId | None = None
    members: Annotated[list[_RawVariable], Field(max_length=MAX_ENTRIES)] | None = None


class _RawLayout(_Raw):
    storage: Annotated[list[_RawVariable], Field(max_length=MAX_ENTRIES)]
    types: Annotated[dict[_TypeId, _RawType], Field(max_length=MAX_ENTRIES)] | None = None


class _RawParam(_Raw):
    type: _AbiType
    components: Annotated[list["_RawParam"], Field(max_length=MAX_ENTRIES)] | None = None
    indexed: bool | None = None


_RawParam.model_rebuild()


class _RawEntry(_Raw):
    type: Literal["function", "constructor", "receive", "fallback", "event", "error"]
    name: _Name | None = None
    inputs: Annotated[list[_RawParam], Field(max_length=MAX_ENTRIES)] = []
    outputs: Annotated[list[_RawParam], Field(max_length=MAX_ENTRIES)] = []
    stateMutability: Literal["pure", "view", "nonpayable", "payable"] | None = None
    anonymous: bool | None = None


_LAYOUT: Final = TypeAdapter(_RawLayout)
_ABI: Final[TypeAdapter[list[_RawEntry]]] = TypeAdapter(
    Annotated[list[_RawEntry], Field(max_length=MAX_ENTRIES)]
)


@dataclass(frozen=True, slots=True)
class StorageVariable:
    label: str
    slot: int
    offset: int
    type: str
    """Full description of the type (see the module documentation); compared."""
    size: int
    type_label: str
    """The type as Solidity writes it, for messages."""

    @property
    def last_slot(self) -> int:
        return self.slot + (self.offset + self.size - 1) // 32 if self.size else self.slot

    def describe(self) -> str:
        return f"`{self.label}` (slot {self.slot}, offset {self.offset}, {self.type_label})"


@dataclass(frozen=True, slots=True)
class Interface:
    layout: tuple[StorageVariable, ...]
    functions: Mapping[str, str]
    """Signature to `returns (<types>) <state mutability>`."""
    events: Mapping[str, str]
    """Signature to `[<indexed flags>]` and ` anonymous` for anonymous events."""


@dataclass(frozen=True, slots=True)
class Change:
    kind: ChangeKind
    breaking: bool
    detail: str


def _describe(exc: ValidationError) -> str:
    first = exc.errors(include_input=False, include_url=False)[0]
    location = ".".join(str(part) for part in first["loc"])
    return f"{exc.error_count()} validation error(s); first at {location[:200]}: {first['msg']}"


def _type_text(types: Mapping[str, _RawType], type_id: str, stack: tuple[str, ...]) -> str:
    info = types.get(type_id)
    if info is None:
        raise InterfaceError(f"storage layout refers to an undeclared type: {type_id[:100]!r}")
    if type_id in stack or len(stack) >= MAX_TYPE_DEPTH:
        return f"{info.label} (recursive)"
    inner = (*stack, type_id)
    text = f"{info.label} [{info.encoding}, {info.numberOfBytes} bytes]"
    if info.key is not None:
        text += f" key {_type_text(types, info.key, inner)}"
    if info.value is not None:
        text += f" value {_type_text(types, info.value, inner)}"
    if info.base is not None:
        text += f" base {_type_text(types, info.base, inner)}"
    if info.members is not None:
        members = "; ".join(
            f"{member.label} @{member.slot}+{member.offset}: "
            f"{_type_text(types, member.type, inner)}"
            for member in info.members
        )
        text += " {" + members + "}"
    return text


def parse_layout(text: str) -> tuple[StorageVariable, ...]:
    """Parse `forge inspect <contract> storageLayout --json`."""
    try:
        raw = _LAYOUT.validate_json(text, strict=True)
    except ValidationError as exc:
        raise InterfaceError(f"unexpected storage layout: {_describe(exc)}") from exc
    types = raw.types or {}
    variables: list[StorageVariable] = []
    for item in raw.storage:
        info = types.get(item.type)
        if info is None:
            raise InterfaceError(
                f"storage layout refers to an undeclared type: {item.type[:100]!r}"
            )
        variables.append(
            StorageVariable(
                label=item.label,
                slot=int(item.slot),
                offset=item.offset,
                type=_type_text(types, item.type, ()),
                size=int(info.numberOfBytes),
                type_label=info.label,
            )
        )
    return tuple(variables)


def _canonical(param: _RawParam, depth: int = 0) -> str:
    if depth > MAX_TYPE_DEPTH:
        raise InterfaceError("ABI tuple types are nested too deeply")
    if param.type.startswith("tuple"):
        if param.components is None:
            raise InterfaceError("ABI tuple type without components")
        inner = ",".join(_canonical(item, depth + 1) for item in param.components)
        return f"({inner}){param.type[len('tuple') :]}"
    return param.type


def _add(table: dict[str, str], key: str, value: str) -> None:
    if key in table:
        raise InterfaceError(f"ABI declares {key[:200]!r} twice")
    table[key] = value


def parse_abi(text: str) -> tuple[dict[str, str], dict[str, str]]:
    """Parse `forge inspect <contract> abi --json` into functions and events."""
    try:
        entries = _ABI.validate_json(text, strict=True)
    except ValidationError as exc:
        raise InterfaceError(f"unexpected ABI: {_describe(exc)}") from exc
    functions: dict[str, str] = {}
    events: dict[str, str] = {}
    for entry in entries:
        if entry.type == "error":
            continue
        arguments = ",".join(_canonical(param) for param in entry.inputs)
        if entry.type == "event":
            if not entry.name:
                raise InterfaceError("ABI event without a name")
            flags = ",".join("indexed" if param.indexed else "-" for param in entry.inputs)
            anonymous = " anonymous" if entry.anonymous else ""
            _add(events, f"{entry.name}({arguments})", f"[{flags}]{anonymous}")
            continue
        if entry.type == "function":
            if not entry.name:
                raise InterfaceError("ABI function without a name")
            name = entry.name
        else:
            name = entry.type
        if entry.stateMutability is None:
            raise InterfaceError(f"ABI entry {name[:100]!r} without a state mutability")
        outputs = ",".join(_canonical(param) for param in entry.outputs)
        _add(functions, f"{name}({arguments})", f"returns ({outputs}) {entry.stateMutability}")
    return functions, events


def parse_interface(layout_text: str, abi_text: str) -> Interface:
    functions, events = parse_abi(abi_text)
    return Interface(layout=parse_layout(layout_text), functions=functions, events=events)


def _now(before: StorageVariable, after: StorageVariable) -> str:
    text = after.describe()
    if before.type != after.type and before.type_label == after.type_label:
        text += " with a different type layout"
    return text


def compare_layout(
    base: tuple[StorageVariable, ...], new: tuple[StorageVariable, ...]
) -> list[Change]:
    changes: list[Change] = []
    for index, before in enumerate(base):
        if index >= len(new):
            changes.append(Change("layout", True, f"storage variable {before.describe()} removed"))
        elif new[index] != before:
            changes.append(
                Change(
                    "layout",
                    True,
                    f"storage variable #{index} {before.describe()} is now "
                    f"{_now(before, new[index])}",
                )
            )
    last = max((item.last_slot for item in base), default=-1)
    known = {item.label for item in base}
    for after in new[len(base) :]:
        if after.label in known:
            changes.append(
                Change(
                    "layout",
                    True,
                    f"storage variable {after.describe()} moved behind its old position",
                )
            )
        elif after.slot > last:
            changes.append(Change("layout", False, f"storage variable {after.describe()} appended"))
        else:
            changes.append(
                Change(
                    "layout",
                    True,
                    f"new storage variable {after.describe()} placed in a slot the vulnerable "
                    f"revision uses (last used slot {last})",
                )
            )
    return changes


def _compare_table(
    kind: ChangeKind, what: str, base: Mapping[str, str], new: Mapping[str, str]
) -> list[Change]:
    changes: list[Change] = []
    for key in sorted(base):
        if key not in new:
            detail = (
                f"function `{key}` removed (or its parameter types changed)"
                if what == "function"
                else f"event `{key}` removed (or its parameter types changed)"
            )
            changes.append(Change(kind, True, detail))
        elif new[key] != base[key]:
            changes.append(Change(kind, True, f"{what} `{key}` changed: {base[key]} -> {new[key]}"))
    changes += [
        Change(kind, False, f"new {what} `{key}`") for key in sorted(new) if key not in base
    ]
    return changes


def compare_interface(base: Interface, new: Interface) -> list[Change]:
    """Every difference between two interfaces, breaking ones flagged."""
    return [
        *compare_layout(base.layout, new.layout),
        *_compare_table("abi", "function", base.functions, new.functions),
        *_compare_table("events", "event", base.events, new.events),
    ]
