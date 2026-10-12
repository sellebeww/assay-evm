"""Steps shared by the oracles that run forge: building a run tree, reading harness event
topics, and turning forge errors into structured reasons.

A forge timeout or unusable output becomes a reason for an INCONCLUSIVE verdict, never a pass.
An out-of-memory kill is not handled here: it is an infrastructure problem and propagates.
"""

import json
from typing import Final

from pydantic import JsonValue

from assay.analyzers import foundry
from assay.analyzers.foundry import ForgeBuildRun, ForgeTestCase, ForgeTestRun
from assay.oracles.base import Evidence, Reason, reason
from assay.oracles.exploit.events import HARNESS_CONTRACT, HarnessEventsError, event_topic
from assay.oracles.runtree import RunTree
from assay.sandbox import SandboxRunner

SETUP_PREFIX: Final = "setUp("


class Stop(Exception):
    """An observation cannot continue; `problem` says why."""

    def __init__(self, problem: Reason, exit_code: int | None = None) -> None:
        super().__init__(problem.detail)
        self.problem = problem
        self.exit_code = exit_code


def first_error(build: ForgeBuildRun) -> str:
    if not build.errors:
        return f"forge build exited with code {build.exit_code}"
    error = build.errors[0]
    where = f" in {error.file}" if error.file else ""
    return f"{error.type}{where}: {error.message}"


def build(runner: SandboxRunner, tree: RunTree) -> ForgeBuildRun:
    """Compile the run tree; the caller decides what a failed build means."""
    return foundry.build(runner, tree.tree, scratch_dir=tree.scratch)


def harness_topic(runner: SandboxRunner, tree: RunTree, event: str) -> str:
    """Topic of a harness event, read from the compiled harness of the tree."""
    try:
        output = foundry.inspect(
            runner, tree.tree, HARNESS_CONTRACT, "events", scratch_dir=tree.scratch
        )
        return event_topic(output, event)
    except (foundry.ForgeOutputError, HarnessEventsError) as exc:
        raise Stop(reason("harness_unreadable", str(exc))) from exc


def problem_of(exc: foundry.ForgeTimeout | foundry.ForgeOutputError) -> tuple[Reason, int | None]:
    """The reason and exit code for a forge run without a usable result."""
    if isinstance(exc, foundry.ForgeTimeout):
        return reason("timeout", f"{exc}; a timeout is never a pass"), None
    return reason("unusable_output", str(exc)), exc.result.exit_code


def cases(run: ForgeTestRun) -> list[tuple[str, ForgeTestCase]]:
    """`(<suite>.<signature>, case)` for every test case of a run, in the run's order."""
    return [(f"{suite.name}.{case.name}", case) for suite in run.suites for case in suite.tests]


def failed_setups(run: ForgeTestRun) -> list[tuple[str, ForgeTestCase]]:
    return [
        (name, case)
        for name, case in cases(run)
        if case.name.startswith(SETUP_PREFIX) and case.status != "success"
    ]


def results_evidence(label: str, run: ForgeTestRun) -> Evidence:
    """The normalized forge results of a run (no durations, no host paths)."""
    return Evidence(
        label=label, media_type="application/json", data=run.model_dump_json().encode("utf-8")
    )


def json_evidence(label: str, value: JsonValue, name: str | None = None) -> Evidence:
    """A JSON document with sorted keys, so that the same value gives the same bytes."""
    text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    return Evidence(
        label=label, media_type="application/json", data=text.encode("ascii"), name=name
    )
