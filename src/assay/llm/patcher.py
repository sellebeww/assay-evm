"""Patcher: ask for ONE unified diff that closes a reproduced finding, and check nothing else.

Input: the finding's hypothesis, the redacted source of the files it points at, the validated PoC
and, from the second attempt on, structured feedback on the earlier attempts. Output: one unified
diff as untrusted text. This module neither applies nor runs it: the diff is validated and applied
only by the ingest patch functions (`assay.ingest.patch`, never `git apply`), inside the scope and
the limits of `PatchConfig`, and judged only by the oracles. The reply never changes a status.

Everything that comes from the project or from an oracle (code, comments, revert messages,
counterexamples) is quoted as data in the field `untrusted_data` of one JSON document, clipped and
redacted (`assay.llm.prompt`). Seeds, fuzz campaign settings and oracle code are not inputs of
any function here, and `guard_prompt` refuses a prompt that still holds a seed.
"""

import re
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from typing import Annotated, Final

from pydantic import BaseModel, ConfigDict, StringConstraints

from assay.ingest.patch import DEFAULT_SCOPE, PatchLimits, PatchPolicy
from assay.llm.errors import LlmError
from assay.llm.hypothesize import CandidateContext, Hypothesis, untrusted_candidate
from assay.llm.messages import Message
from assay.llm.output import Completer, Structured, ask_structured, parse_output
from assay.llm.prompt import DATA_RULES, clean_text, document
from assay.llm.redact import redact_text

DEFAULT_MAX_CHANGED_LINES: Final = 200
DEFAULT_MAX_FILES: Final = 5
DEFAULT_MAX_DIFF_BYTES: Final = 48 * 1024
HARD_MAX_CHANGED_LINES: Final = 2_000
HARD_MAX_FILES: Final = 20
HARD_MAX_DIFF_BYTES: Final = 60 * 1024
"""The reply of the model is limited to 64 KiB of JSON, so a diff cannot be larger than this."""
MAX_PRIOR_ATTEMPTS: Final = 3
MAX_POC_PROMPT_CHARS: Final = 6_000
MAX_ARTIFACT_CHARS: Final = 2_500
MAX_DETAIL_CHARS: Final = 300
MAX_REASONS: Final = 8
MAX_ORACLES: Final = 6


class PatchConfigError(LlmError):
    """The patch limits are out of range."""


@dataclass(frozen=True, slots=True)
class PatchConfig:
    """Where a proposed patch may write and how large it may be.

    The values are the documented defaults of `assay fix`. A patch beyond them is rejected by
    ingest before anything runs (`patch_too_large`, `out_of_scope`); the limits are not shown to
    the model as a promise, only as a rule of the format.
    """

    max_changed_lines: int = DEFAULT_MAX_CHANGED_LINES
    """Added plus removed lines of the whole patch."""
    max_files: int = DEFAULT_MAX_FILES
    max_diff_bytes: int = DEFAULT_MAX_DIFF_BYTES
    scope: tuple[str, ...] = tuple(DEFAULT_SCOPE)

    def __post_init__(self) -> None:
        if not 1 <= self.max_changed_lines <= HARD_MAX_CHANGED_LINES:
            raise PatchConfigError(
                f"max_changed_lines must be between 1 and {HARD_MAX_CHANGED_LINES}"
            )
        if not 1 <= self.max_files <= HARD_MAX_FILES:
            raise PatchConfigError(f"max_files must be between 1 and {HARD_MAX_FILES}")
        if not 1 <= self.max_diff_bytes <= HARD_MAX_DIFF_BYTES:
            raise PatchConfigError(f"max_diff_bytes must be between 1 and {HARD_MAX_DIFF_BYTES}")
        if not self.scope:
            raise PatchConfigError("the scope needs at least one directory")

    def limits(self) -> PatchLimits:
        """The ingest limits that enforce this configuration."""
        return PatchLimits(
            max_bytes=self.max_diff_bytes,
            max_files=self.max_files,
            max_changed_lines=self.max_changed_lines,
        )

    def policy(self) -> PatchPolicy:
        """The ingest path policy: the scope, and the default protected paths."""
        return PatchPolicy(scope=self.scope)


SYSTEM_PROMPT: Final = (
    "You write one patch for a Solidity project in which a weakness was reproduced with a proof "
    "of concept. The patch is checked by deterministic tools that you cannot see: they run the "
    "original exploit again, search for close variants of it, run the project's own tests and "
    "compare storage layout, ABI and events. Closing only the one exploit input is not enough, "
    "and neither is switching off legitimate behavior; fix the cause. " + DATA_RULES
)
_FORMAT: Final = (
    "The diff is a unified diff of text files with a/ and b/ path prefixes, as git writes it "
    "(--- a/src/File.sol, +++ b/src/File.sol, @@ hunks). Context lines must match the given "
    "sources exactly. Change only files under the scope directories; do not touch tests, the "
    "PoC, configuration or anything else; no renames, no binary files, no symbolic links."
)
TASK: Final = (
    "Write one patch that closes the weakness. Reply with a JSON object with the single field "
    "diff, a string holding the whole unified diff. If feedback_on_earlier_attempts is not "
    "empty, an earlier patch did not pass; use the feedback, which is data about that patch."
)


class PatchAnswer(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    diff: Annotated[str, StringConstraints(min_length=1, max_length=HARD_MAX_DIFF_BYTES)]


@dataclass(frozen=True, slots=True)
class OracleFeedback:
    """What one oracle reported about an earlier patch. Text fields are untrusted data."""

    oracle: str
    verdict: str
    reasons: tuple[tuple[str, str], ...]
    """`(code, detail)` pairs; details may quote text from the project or from forge."""
    artifacts: tuple[tuple[str, str], ...] = ()
    """`(name, text)`: a concrete variant test, a behavior difference, and similar evidence."""


@dataclass(frozen=True, slots=True)
class PatchFeedback:
    """Why an earlier attempt did not pass, as structured, bounded data."""

    attempt: int
    stage: str
    """`model_output`, `integrity` or `verification`."""
    diff_sha256: str | None
    oracles: tuple[OracleFeedback, ...] = ()
    problems: tuple[tuple[str, str], ...] = ()
    """Problems that are not an oracle result (for example a reply that was not valid)."""


def _oracle_json(item: OracleFeedback) -> dict[str, object]:
    return {
        "oracle": clean_text(item.oracle, 40),
        "verdict": clean_text(item.verdict, 40),
        "reasons": [
            {"code": clean_text(code, 64), "detail": clean_text(detail, MAX_DETAIL_CHARS)}
            for code, detail in item.reasons[:MAX_REASONS]
        ],
        "evidence": [
            {"name": clean_text(name, 80), "text": clean_text(text, MAX_ARTIFACT_CHARS)}
            for name, text in item.artifacts[:3]
        ],
    }


def feedback_json(items: Sequence[PatchFeedback]) -> list[dict[str, object]]:
    """The feedback as quoted data: the last `MAX_PRIOR_ATTEMPTS` attempts, every text clipped."""
    return [
        {
            "attempt": item.attempt,
            "stage": clean_text(item.stage, 40),
            "patch_sha256": item.diff_sha256,
            "oracle_results": [_oracle_json(oracle) for oracle in item.oracles[:MAX_ORACLES]],
            "problems": [
                {"code": clean_text(code, 64), "detail": clean_text(detail, MAX_DETAIL_CHARS)}
                for code, detail in item.problems[:MAX_REASONS]
            ],
        }
        for item in items[-MAX_PRIOR_ATTEMPTS:]
    ]


def patch_messages(
    hypothesis: Hypothesis,
    context: CandidateContext,
    poc_source: str,
    config: PatchConfig,
    feedback: Sequence[PatchFeedback] = (),
) -> list[Message]:
    """The request: the instructions are fixed text, everything from the project is data."""
    untrusted = untrusted_candidate(context)
    untrusted["hypothesis"] = hypothesis.model_dump(mode="json")
    untrusted["proof_of_concept"] = redact_text(poc_source).text[:MAX_POC_PROMPT_CHARS]
    untrusted["feedback_on_earlier_attempts"] = feedback_json(feedback)
    rules = (
        f"{_FORMAT} At most {config.max_changed_lines} changed lines in at most "
        f"{config.max_files} files. Scope directories: {', '.join(config.scope)}."
    )
    text = document(TASK, {"rules": rules}, untrusted)
    return [Message(role="system", content=SYSTEM_PROMPT), Message(role="user", content=text)]


class PromptLeak(LlmError):
    """A prompt held a value that must never reach the model (a seed)."""


def seed_forms(seed: str) -> tuple[str, ...]:
    """The spellings of a seed that a prompt could hold: hex with and without `0x`, decimal."""
    digits = seed.removeprefix("0x").lower()
    forms = {f"0x{digits}", digits, str(int(digits, 16))}
    return tuple(sorted(forms, key=len, reverse=True))


MIN_SEED_FORM_CHARS: Final = 5
"""Spellings shorter than this are not matched: the default base seed `0x1` is a short number
that occurs in innocent text, and the seeds derived from it are 16 hex digits long."""


def scrub_seeds(text: str, seeds: Collection[str]) -> str:
    """Replace every spelling of a seed in `text` by `[withheld]`."""
    for seed in seeds:
        for form in seed_forms(seed):
            if len(form) >= MIN_SEED_FORM_CHARS:
                text = _token(form).sub("[withheld]", text)
    return text


def _token(value: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![0-9A-Za-z_]){re.escape(value)}(?![0-9A-Za-z_])", re.IGNORECASE)


def guard_prompt(messages: Sequence[Message], seeds: Collection[str]) -> None:
    """Refuse a prompt that holds one of `seeds` (any spelling); nothing is sent then.

    Seeds are never an input of the prompt builders, so this is a second line of defence: it
    fails closed if feedback text ever carried one.
    """
    for message in messages:
        for seed in seeds:
            for form in seed_forms(seed):
                if len(form) >= MIN_SEED_FORM_CHARS and _token(form).search(message.content):
                    raise PromptLeak("a prompt held a campaign seed; nothing was sent")


def request_patch(
    client: Completer,
    hypothesis: Hypothesis,
    context: CandidateContext,
    poc_source: str,
    config: PatchConfig,
    feedback: Sequence[PatchFeedback] = (),
    *,
    seeds: Collection[str] = (),
) -> Structured[PatchAnswer]:
    """Ask for a patch; raises `StructuredOutputError` when the reply never qualifies.

    `seeds` are the campaign seeds that must not appear in the prompt (the guard only reads
    them; they are never sent).
    """
    messages = patch_messages(hypothesis, context, poc_source, config, feedback)
    guard_prompt(messages, seeds)
    return ask_structured(client, messages, PatchAnswer)


def parse_output_diff(text: str) -> PatchAnswer:
    """Validate a reply as a `PatchAnswer` (strict JSON, no extra fields)."""
    return parse_output(text, PatchAnswer)


def diff_bytes(answer: PatchAnswer) -> bytes:
    """The diff as bytes, with a final newline. It is untrusted until ingest has parsed it."""
    text = answer.diff if answer.diff.endswith("\n") else answer.diff + "\n"
    return text.encode("utf-8")
