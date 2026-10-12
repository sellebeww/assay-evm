"""Write the synthetic cassettes of `make demo` (`make demo-cassettes`).

`assay run` replays a recorded conversation with a model instead of calling one. The demo ships
such a conversation for the reentrancy fixture in `demo/cassettes/`: a hypothesis, the fixture's
own PoC as the "model's" PoC, an overfit patch, and then the good patch. No model produced any of
it, and every cassette says so (`synthetic: true`).

This script records the conversation by running the real `assay run` in record mode against a
scripted endpoint (an in-process stand-in for the HTTP transport, so nothing leaves the machine),
with the real scanner, sandbox and oracles, and then marks each cassette as synthetic. It needs
Docker and the runner image. Run it again after a change that alters the prompts (the cassette key
is a hash of the request); `make demo` then fails with a missing cassette until you do.

Exit status: 0 written, 1 the recorded run did not end VERIFIED_WITHIN_BOUNDS, 2 unusable setup.
"""

import argparse
import functools
import json
import shutil
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Final
from unittest import mock

import httpx
from typer.testing import CliRunner

from assay.cli.main import app
from assay.llm import LlmClient
from assay.llm.cassette import load_cassette, write_cassette

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
FIXTURE: Final = REPO_ROOT / "fixtures" / "reentrancy" / "single_function"
DEFAULT_OUT: Final = REPO_ROOT / "demo" / "cassettes"
MODEL: Final = "synthetic-model-0"
NOTE: Final = "SYNTHETIC: scripted answer for the demo. No model produced it."
ENVIRONMENT: Final = {
    "ASSAY_LLM_BASE_URL": "https://synthetic.invalid/v1",
    "ASSAY_LLM_API_KEY": "synthetic-not-a-key",
    "ASSAY_LLM_MODEL": MODEL,
}


def replies() -> list[str]:
    """The scripted answers, in the order in which `assay run` asks."""
    return [
        json.dumps(
            {
                "vuln_class": "reentrancy",
                "target_function": "withdraw",
                "attack_idea": "Call withdraw from a contract whose receive function calls "
                "withdraw again before the balance is updated, then keep the extra ether.",
                "preconditions": ["the vault holds ether of other accounts"],
                "predicate_kind": "attacker_profit",
            }
        ),
        json.dumps({"solidity": (FIXTURE / "poc" / "VaultReentrancy.t.sol").read_text()}),
        json.dumps({"diff": (FIXTURE / "patches" / "overfit.diff").read_text()}),
        json.dumps({"diff": (FIXTURE / "patches" / "good.diff").read_text()}),
    ]


def scripted_transport(answers: Sequence[str]) -> httpx.MockTransport:
    pending = list(answers)

    def handler(request: httpx.Request) -> httpx.Response:
        content = pending.pop(0) if len(pending) > 1 else pending[0]
        body = {
            "id": "scripted",
            "model": MODEL,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50},
        }
        return httpx.Response(200, json=body)

    return httpx.MockTransport(handler)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Cassette directory.")
    args = parser.parse_args(argv)
    out: Path = args.out
    transport = scripted_transport(replies())
    with tempfile.TemporaryDirectory(prefix="assay-demo-") as tmp:
        scratch = Path(tmp)
        recorded = scratch / "cassettes"
        patched = functools.partial(LlmClient, transport=transport)
        with mock.patch("assay.cli.fix.LlmClient", patched):
            result = CliRunner(env=ENVIRONMENT).invoke(
                app,
                [
                    "run",
                    str(FIXTURE),
                    "--class",
                    "reentrancy",
                    "--mode",
                    "record",
                    "--allow-llm",
                    "--profile",
                    "quick",
                    "--cassette-dir",
                    str(recorded),
                    "--ledger",
                    str(scratch / "ledger.db"),
                    "--poc-dir",
                    str(scratch / "poc"),
                ],
            )
        print(result.output)
        if result.exit_code != 0:
            print(f"error: the recorded run exited with {result.exit_code}", file=sys.stderr)
            return 1 if result.exit_code in (1, 3) else 2
        if out.exists():
            shutil.rmtree(out)
        out.mkdir(parents=True)
        for item in sorted(recorded.glob("*.json")):
            cassette = load_cassette(recorded, item.stem)
            synthetic = cassette.model_copy(update={"synthetic": True, "note": NOTE})
            write_cassette(out, synthetic)
        shown = out.relative_to(REPO_ROOT) if out.is_relative_to(REPO_ROOT) else out
        print(f"wrote {len(list(out.glob('*.json')))} cassettes to {shown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
