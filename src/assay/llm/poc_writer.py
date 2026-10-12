"""PoC writer: ask for ONE Solidity PoC file, check it, and save it only in the PoC directory.

The reply is untrusted text. `request_poc` returns it only after strict JSON validation; the
static checker (`poc_checker`) must accept it before `write_poc` writes anything, and nothing
here compiles or runs it. Running it is the job of the caller, through the sandbox and the
ExploitOracle. The file is written to one fixed name inside the directory the caller names.
"""

import os
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Annotated, Final

from pydantic import BaseModel, ConfigDict, StringConstraints

from assay.llm.errors import LlmError
from assay.llm.hypothesize import CandidateContext, Hypothesis, untrusted_candidate
from assay.llm.messages import Message
from assay.llm.output import Completer, Structured, ask_structured
from assay.llm.poc_checker import (
    ALLOWED_CHEATCODES,
    MAX_POC_BYTES,
    PREDICATE_HELPERS,
    PocCheck,
    check_poc,
)
from assay.llm.prompt import DATA_RULES, clean_text, document

POC_FILE: Final = "AssayModelPoc.t.sol"
MAX_ATTEMPT_FEEDBACK: Final = 3
EXAMPLE_RESOURCE: Final = "poc_example.txt"

SYSTEM_PROMPT: Final = (
    "You write one Solidity proof-of-concept file for a deterministic checker. The file is "
    "checked statically and then run in an isolated sandbox; it only needs to show the "
    "weakness described by the hypothesis. " + DATA_RULES
)
_API: Final = (
    "The file has one contract that inherits AssayPoC (import {AssayPoC} from "
    '"assay/AssayExploit.sol"; target files come from "../src/<File>.sol"). It implements '
    "only `function setUpTarget() internal override` (deploy and fund the target, then declare "
    "the attacker's starting balance with declareAttackerBalance(replay, min, max) and up to "
    "four knobs with declareKnob(index, name, replay, min, max)) and `function exploit() "
    "internal override` (act as `attacker`, read knobs with knob(index), and end by calling a "
    "predicate helper: " + ", ".join(PREDICATE_HELPERS) + "). Helper contracts may not inherit "
    "anything. Cheatcodes are limited to vm." + ", vm.".join(ALLOWED_CHEATCODES) + ". No file "
    "access, environment access, assembly, console output, events, or imports besides the two "
    "kinds above."
)
TASK: Final = (
    "Write the PoC file. Reply with a JSON object with the single field solidity, a string "
    "holding the whole file. format_example is a complete PoC of the right shape for another "
    "contract."
)


class PocAnswer(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    solidity: Annotated[str, StringConstraints(min_length=1, max_length=MAX_POC_BYTES)]


@dataclass(frozen=True, slots=True)
class Feedback:
    """What went wrong with an earlier attempt, as short structured items (untrusted text)."""

    attempt: int
    stage: str
    items: tuple[tuple[str, str], ...]
    """`(code, detail)` pairs; details may quote text from the project or from forge."""


def feedback_from_check(attempt: int, check: PocCheck) -> Feedback:
    return Feedback(
        attempt,
        "static_check",
        tuple((item.code, item.detail) for item in check.violations),
    )


def example_poc() -> str:
    return resources.files("assay.llm").joinpath(EXAMPLE_RESOURCE).read_text(encoding="utf-8")


def _feedback_json(items: Sequence[Feedback]) -> list[dict[str, object]]:
    return [
        {
            "attempt": item.attempt,
            "stage": item.stage,
            "problems": [
                {"code": clean_text(code, 64), "detail": clean_text(detail, 300)}
                for code, detail in item.items[:8]
            ],
        }
        for item in items[-MAX_ATTEMPT_FEEDBACK:]
    ]


def poc_messages(
    hypothesis: Hypothesis, context: CandidateContext, feedback: Sequence[Feedback] = ()
) -> list[Message]:
    untrusted = untrusted_candidate(context)
    untrusted["hypothesis"] = hypothesis.model_dump(mode="json")
    untrusted["feedback_on_earlier_attempts"] = _feedback_json(feedback)
    text = document(TASK, {"rules": _API, "format_example": example_poc()}, untrusted)
    return [Message(role="system", content=SYSTEM_PROMPT), Message(role="user", content=text)]


def request_poc(
    client: Completer,
    hypothesis: Hypothesis,
    context: CandidateContext,
    feedback: Sequence[Feedback] = (),
) -> Structured[PocAnswer]:
    """Ask for a PoC; raises `StructuredOutputError` when the reply never qualifies."""
    return ask_structured(client, poc_messages(hypothesis, context, feedback), PocAnswer)


class PocRejected(LlmError):
    """The static checker refused the PoC; nothing was written."""

    def __init__(self, check: PocCheck) -> None:
        super().__init__("the PoC was rejected by the static checker: " + ", ".join(check.codes()))
        self.check = check


def write_poc(poc_dir: Path, source: str) -> Path:
    """Write `source` as the one PoC file of `poc_dir`, after the static checker accepted it.

    The directory must exist and must not be a symbolic link; the file name is fixed, so
    nothing is written anywhere else.
    """
    check = check_poc(source)
    if not check.ok:
        raise PocRejected(check)
    if poc_dir.is_symlink() or not poc_dir.is_dir():
        raise LlmError("the PoC directory must be an existing directory, not a link")
    target = poc_dir / POC_FILE
    if target.is_symlink():
        raise LlmError("the PoC file is a symbolic link")
    fd, temp = tempfile.mkstemp(dir=poc_dir, prefix=".poc-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(source if source.endswith("\n") else source + "\n")
        os.replace(temp, target)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise
    return target
