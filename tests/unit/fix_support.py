"""Scenarios for the `assay fix` tests: a reproduced finding, scripted model answers and the
stand-in forge, without Docker and without a model.

`reproduce` runs `assay prove` the way the prove tests do (the fixture's own PoC plays the model's
answer), so that the fix tests start from a REPRODUCED finding in a real ledger. `FixRun` runs the
fix loop against a scripted endpoint and keeps every request the endpoint saw.
"""

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from fake_forge import FakeForge
from llm_support import Endpoint, ok
from prove_support import REENTRANCY, Fixture, answer, good_poc, hypothesis, seed
from vault_scenario import vault_forge

from assay.ledger import CassetteMode, FindingId, FindingState, Ledger
from assay.llm import Budget, LlmClient, load_config
from assay.llm.client import Recorder
from assay.llm.hypothesize import Hypothesis
from assay.llm.patcher import PatchConfig
from assay.orchestrator.fix import FixOutcome, FixRequest, run_fix
from assay.orchestrator.models import VerifySettings
from assay.orchestrator.prove import ProveOutcome, ProveRequest, run_prove
from assay.orchestrator.verify import BundleRequest
from assay.report.bundle import Environment, Sanitizer, environment
from assay.sandbox import SandboxRunner

CONFIG: Final = load_config(
    {
        "ASSAY_LLM_BASE_URL": "https://synthetic.invalid/v1",
        "ASSAY_LLM_API_KEY": "synthetic-not-a-key",
        "ASSAY_LLM_MODEL": "synthetic-model-0",
    }
)
QUICK: Final = VerifySettings(profile="quick")
ENV_LABELS: Final = {"assay.forge.version": "1.0.0"}
IMAGE: Final = "sha256:" + "ef" * 32


def patch_text(fixture: Fixture, label: str) -> str:
    return (fixture.project / "patches" / f"{label}.diff").read_text()


def diff_reply(text: str) -> str:
    return json.dumps({"diff": text})


@dataclass
class Reproduced:
    ledger_path: Path
    finding_id: int
    poc_dir: Path
    hypothesis: Hypothesis
    fixture: Fixture


TARGETS: Final = {"reentrancy": "withdraw", "access_control": "payOutAll"}


def reproduce(
    tmp_path: Path, fixture: Fixture = REENTRANCY, vuln_class: str = "reentrancy"
) -> Reproduced:
    """Scan result seeded, then `run_prove` to REPRODUCED with the fixture PoC as the answer."""
    ledger_path = tmp_path / "ledger.db"
    poc_dir = tmp_path / "poc"
    work = tmp_path / "prove-work"
    work.mkdir()
    with Ledger.open(ledger_path) as ledger:
        ids = seed(ledger, fixture, tmp_path)
        classes = [f["vuln_class"] for f in json.loads(fixture.scan.read_text())["findings"]]
        index = classes.index(vuln_class)
        endpoint = Endpoint(
            ok(
                hypothesis(TARGETS[vuln_class], "attacker_profit", vuln_class),
                model="synthetic-model-0",
            ),
            ok(answer(good_poc(fixture)), model="synthetic-model-0"),
        )

        def make_client(recorder: Recorder) -> LlmClient:
            return LlmClient(
                mode=CassetteMode.RECORD,
                allow_llm=True,
                config=CONFIG,
                budget=Budget(max_calls=10, max_tokens=1_000_000),
                cassette_dir=tmp_path / "prove-cassettes",
                recorder=recorder,
                transport=endpoint.transport,
            )

        outcome = run_prove(
            ProveRequest(fixture.project, poc_dir, int(ids[index]), None, 3),
            ledger=ledger,
            make_client=make_client,
            runner=prove_forge(),
            work_dir=work,
        )
        assert isinstance(outcome, ProveOutcome)
        assert outcome.state is FindingState.REPRODUCED, outcome
        return Reproduced(ledger_path, int(ids[index]), poc_dir, outcome.hypothesis, fixture)


def prove_forge() -> FakeForge:
    return FakeForge(lambda tree, number: "exploited")


def bundle_request(dest: Path, work: Path) -> BundleRequest:
    def record_environment() -> Environment:
        return environment(IMAGE, ENV_LABELS, "FOUNDRY=1.0.0\n")

    return BundleRequest(
        dest=dest,
        environment=record_environment,
        sanitizer=Sanitizer([(work, "<work>")]),
    )


@dataclass
class FixRun:
    """One fix loop over a scripted endpoint."""

    reproduced: Reproduced
    tmp_path: Path
    replies: Sequence[str]
    forge: SandboxRunner = field(default_factory=vault_forge)
    settings: VerifySettings = QUICK
    max_attempts: int = 3
    patch: PatchConfig = field(default_factory=PatchConfig)
    bundle_dir: Path | None = None
    budget_calls: int = 30
    endpoint: Endpoint = field(init=False)
    outcome: FixOutcome | None = field(init=False, default=None)
    cassettes: Path = field(init=False)

    def __post_init__(self) -> None:
        self.endpoint = Endpoint(*(ok(reply, model="synthetic-model-0") for reply in self.replies))
        self.cassettes = self.tmp_path / "fix-cassettes"

    def client(self, recorder: Recorder, mode: CassetteMode = CassetteMode.RECORD) -> LlmClient:
        return LlmClient(
            mode=mode,
            allow_llm=True,
            config=CONFIG,
            budget=Budget(max_calls=self.budget_calls, max_tokens=5_000_000),
            cassette_dir=self.cassettes,
            recorder=recorder,
            transport=self.endpoint.transport,
        )

    def run(self) -> FixOutcome:
        work = self.tmp_path / "fix-work"
        work.mkdir(exist_ok=True)
        bundle = None
        if self.bundle_dir is not None:
            bundle = bundle_request(self.bundle_dir, work)
        with Ledger.open(self.reproduced.ledger_path) as ledger:
            result = run_fix(
                FixRequest(
                    self.reproduced.fixture.project,
                    self.reproduced.poc_dir,
                    self.reproduced.finding_id,
                    self.max_attempts,
                    settings=self.settings,
                    patch=self.patch,
                ),
                ledger=ledger,
                make_client=self.client,
                runner=self.forge,
                work_dir=work,
                bundle=bundle,
            )
        assert isinstance(result, FixOutcome)
        self.outcome = result
        return result

    def prompts(self) -> list[list[dict[str, Any]]]:
        """The messages of every request the endpoint received."""
        return [body["messages"] for body in self.endpoint.bodies()]

    def prompt_text(self) -> str:
        return "\n".join(m["content"] for messages in self.prompts() for m in messages)

    def user_documents(self) -> list[dict[str, Any]]:
        """The JSON document of the first user message of each request."""
        return [json.loads(messages[1]["content"]) for messages in self.prompts()]

    def finding_state(self) -> FindingState:
        with Ledger.open(self.reproduced.ledger_path, read_only=True) as ledger:
            return ledger.get_finding(FindingId(self.reproduced.finding_id)).state


Decider = Callable[[Path, int], str]


def diff_of(fixture: Fixture, path: str, change: Callable[[str], str]) -> str:
    """A unified diff (a/ and b/ prefixes) of `path` of the fixture after `change`."""
    import difflib

    old = (fixture.project / path).read_text()
    new = change(old)
    assert new != old
    lines = difflib.unified_diff(
        old.splitlines(keepends=True),
        new.splitlines(keepends=True),
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
    )
    return "".join(lines)
