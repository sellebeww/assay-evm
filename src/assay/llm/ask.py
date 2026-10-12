"""The neutral question used by `assay dev llm-ask` to exercise the whole LLM path."""

from typing import Annotated, Final

from pydantic import BaseModel, ConfigDict, StringConstraints

from assay.llm.messages import Message

ASK_SYSTEM_PROMPT: Final = (
    "You answer one short question. Reply with only a JSON object of the form "
    '{"answer": "<your answer, at most 500 characters>"} and nothing else.'
)


class AskAnswer(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    answer: Annotated[str, StringConstraints(min_length=1, max_length=500)]


def ask_messages(question: str) -> list[Message]:
    return [
        Message(role="system", content=ASK_SYSTEM_PROMPT),
        Message(role="user", content=question),
    ]
