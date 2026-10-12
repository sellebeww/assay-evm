"""Hypothesizer: from a candidate finding and redacted code, ask for a structured hypothesis.

The reply is untrusted. It must be one JSON object that `Hypothesis` accepts; a hypothesis is
a proposal at evidence level E0 and never changes a status by itself. Recording it and moving
the finding from CANDIDATE to HYPOTHESIZED is the job of the caller (`assay prove`).
"""

from dataclasses import dataclass
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from assay.llm.messages import Message
from assay.llm.output import Completer, Structured, ask_structured
from assay.llm.prompt import DATA_RULES, clean_text, document
from assay.llm.redact import SourceFile

PredicateKind = Literal[
    "attacker_profit", "victim_loss", "unauthorized_role_change", "invariant_broken"
]
_Short = Annotated[str, StringConstraints(min_length=1, max_length=300)]

SYSTEM_PROMPT: Final = (
    "You help to reproduce one suspected weakness in a Solidity contract with a proof of "
    "concept. You only propose a hypothesis; a deterministic checker decides whether it holds. "
    + DATA_RULES
)
TASK: Final = (
    "Propose one hypothesis for the candidate finding. Reply with a JSON object with the fields "
    "vuln_class (snake_case class of the weakness), target_function (name of the function to "
    "attack), attack_idea (at most 1000 characters), preconditions (list of at most 8 short "
    "statements) and predicate_kind (one of attacker_profit, victim_loss, "
    "unauthorized_role_change, invariant_broken: what an exploit would show)."
)


class Hypothesis(BaseModel):
    """A structured guess about how the candidate can be exploited. Never evidence."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    vuln_class: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
    target_function: Annotated[str, StringConstraints(pattern=r"^[A-Za-z_$][A-Za-z0-9_$.]{0,99}$")]
    attack_idea: Annotated[str, StringConstraints(min_length=1, max_length=1000)]
    preconditions: Annotated[list[_Short], Field(max_length=8)] = []
    predicate_kind: PredicateKind


@dataclass(frozen=True, slots=True)
class ObservationNote:
    """What an analyzer reported for the candidate (unverified)."""

    rule_id: str
    severity: str
    message: str
    path: str
    start_line: int
    end_line: int


@dataclass(frozen=True, slots=True)
class CandidateContext:
    vuln_class: str
    observations: tuple[ObservationNote, ...]
    code: tuple[SourceFile, ...]


def untrusted_candidate(context: CandidateContext) -> dict[str, object]:
    return {
        "analyzer_reports": [
            {
                "rule": clean_text(note.rule_id, 100),
                "severity": clean_text(note.severity, 60),
                "message": clean_text(note.message),
                "location": f"{clean_text(note.path, 200)}:{note.start_line}-{note.end_line}",
            }
            for note in context.observations[:10]
        ],
        "code": [
            {"path": clean_text(file.path, 200), "source": file.text} for file in context.code
        ],
    }


def hypothesis_messages(context: CandidateContext) -> list[Message]:
    text = document(
        TASK,
        {"candidate_class": context.vuln_class},
        untrusted_candidate(context),
    )
    return [Message(role="system", content=SYSTEM_PROMPT), Message(role="user", content=text)]


def propose_hypothesis(client: Completer, context: CandidateContext) -> Structured[Hypothesis]:
    """Ask for a hypothesis; raises `StructuredOutputError` when the reply never qualifies."""
    return ask_structured(client, hypothesis_messages(context), Hypothesis)
