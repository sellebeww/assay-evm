"""`assay report` on real bundles and `assay doctor` against the real Docker and runner image."""

import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

import pytest
from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "unit"))
from schema_support import assert_valid

from assay.cli.main import app

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("runner")]

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures" / "reentrancy" / "single_function"
FORBIDDEN = re.compile(r"\b(secure|safe|proven|guaranteed|unhackable)\b", re.IGNORECASE)
cli = CliRunner()


class Tags(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: set[str] = set()
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.add(tag)

    def handle_data(self, data: str) -> None:
        self.text.append(data)


@pytest.fixture(scope="module")
def workspace(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("report")


def bundle_of(workspace: Path, label: str) -> Path:
    bundle = workspace / label
    result = cli.invoke(
        app,
        [
            "verify",
            "--base",
            str(FIXTURE),
            "--patch",
            str(FIXTURE / "patches" / f"{label}.diff"),
            "--poc",
            str(FIXTURE / "poc"),
            "--profile",
            "quick",
            "--ledger",
            str(workspace / ".assay" / "ledger.db"),
            "--bundle-out",
            str(bundle),
        ],
    )
    assert result.exit_code in (0, 1), result.output
    return bundle


@pytest.mark.parametrize(
    ("label", "verdict"), [("good", "VERIFIED_WITHIN_BOUNDS"), ("overfit", "REJECTED")]
)
def test_a_real_bundle_gives_a_deterministic_report_without_script(
    workspace: Path, label: str, verdict: str
) -> None:
    bundle = bundle_of(workspace, label)
    first, second = workspace / f"{label}-1.html", workspace / f"{label}-2.html"
    for out in (first, second):
        result = cli.invoke(app, ["report", str(bundle), "--out", str(out)])
        assert result.exit_code == 0, result.output
    assert first.read_bytes() == second.read_bytes()
    page = first.read_text()
    parsed = Tags()
    parsed.feed(page)
    assert "script" not in parsed.tags
    assert verdict in parsed.text
    assert FORBIDDEN.search(" ".join(parsed.text)) is None
    assert str(workspace) not in page
    assert "default-src &#x27;none&#x27;" in page
    if label == "overfit":
        assert "variant_poc.t.sol" in page
        assert "variant_found" in page


def test_the_real_doctor_finds_the_machine_in_order() -> None:
    result = cli.invoke(app, ["doctor", "--json"])
    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert_valid("doctor", document)
    statuses = {item["id"]: item["status"] for item in document["checks"]}
    assert statuses["runner"] == "ok"
    assert statuses["runner_tools"] == "ok"
    assert statuses["docker_daemon"] == "ok"
