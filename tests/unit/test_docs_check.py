"""`tools/docs_check.py`: relative links, anchors and the words the project never uses."""

from pathlib import Path

import pytest

import docs_check

ROOT = Path(__file__).resolve().parents[2]


def write(root: Path, name: str, text: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    write(tmp_path, "README.md", "# Title\n\nSee [docs](docs/a.md).\n")
    write(tmp_path, "docs/a.md", "# A\n\n## Part two\n\nText.\n")
    return tmp_path


def run(root: Path) -> list[str]:
    return docs_check.run(root)[0]


def test_the_repository_documentation_is_clean() -> None:
    problems, _ = docs_check.run(ROOT)
    assert problems == []


def test_a_valid_repository_has_no_problem(repo: Path) -> None:
    assert run(repo) == []


def test_a_broken_relative_link_is_reported(repo: Path) -> None:
    write(repo, "docs/a.md", "# A\n\n[gone](missing.md)\n")
    (problem,) = run(repo)
    assert "docs/a.md:3" in problem
    assert "broken link" in problem


def test_a_link_outside_the_repository_is_reported(repo: Path) -> None:
    write(repo, "docs/a.md", "# A\n\n[up](../../outside.md)\n")
    assert "leaves the repository" in run(repo)[0]


def test_external_and_mail_links_are_not_checked(repo: Path) -> None:
    write(repo, "docs/a.md", "# A\n\n[x](https://example.com/none) [m](mailto:a@b.c)\n")
    assert run(repo) == []


def test_anchors_must_name_a_heading(repo: Path) -> None:
    write(repo, "README.md", "# T\n\n[ok](docs/a.md#part-two) [bad](docs/a.md#nope) [self](#t)\n")
    problems = run(repo)
    assert len(problems) == 1
    assert "#nope" in problems[0]


def test_headings_with_code_and_duplicates_get_github_anchors(repo: Path) -> None:
    write(repo, "docs/a.md", "# A\n\n## `assay x`\n\n## Same\n\n## Same\n")
    write(repo, "README.md", "[a](docs/a.md#assay-x) [b](docs/a.md#same-1)\n")
    assert run(repo) == []


def test_links_in_code_are_not_links(repo: Path) -> None:
    write(repo, "docs/a.md", "# A\n\n`[x](missing.md)`\n\n```\n[y](missing.md)\n```\n")
    assert run(repo) == []


def test_images_are_checked_too(repo: Path) -> None:
    write(repo, "docs/a.md", "# A\n\n![x](img/none.png)\n")
    assert "broken link" in run(repo)[0]


def test_an_announced_image_is_a_note_not_a_problem(repo: Path) -> None:
    write(repo, "docs/img/.keep", "")
    write(repo, "README.md", "# T\n\n![r](docs/img/report.png)\n")
    problems, notes = docs_check.run(repo)
    assert problems == []
    assert len(notes) == 1
    assert "not committed yet" in notes[0]
    write(repo, "docs/img/report.png", "x")
    assert docs_check.run(repo) == ([], [])


@pytest.mark.parametrize(
    "word", ["secure", "safe", "proven", "guarantee", "guaranteed", "unhackable", "Secure"]
)
def test_a_forbidden_word_is_reported(repo: Path, word: str) -> None:
    write(repo, "docs/a.md", f"# A\n\nThis contract is {word} now.\n")
    (problem,) = run(repo)
    assert word.lower() in problem.lower()
    assert "docs/a.md:3" in problem


@pytest.mark.parametrize(
    "text",
    [
        "Assay never says that a contract is secure.",
        "This is not a proof that the code is safe.",
        "The result is not proven and not guaranteed.",
        "It cannot be called unhackable.",
        "Nothing here says the patch is\nsecure, safe or proven, and no claim is made.",
    ],
)
def test_the_word_in_a_sentence_that_denies_it_is_allowed(repo: Path, text: str) -> None:
    write(repo, "docs/a.md", f"# A\n\n{text}\n")
    assert run(repo) == []


def test_a_denial_in_another_sentence_does_not_excuse_the_word(repo: Path) -> None:
    write(repo, "docs/a.md", "# A\n\nThis is not a toy. The patch is safe.\n")
    assert len(run(repo)) == 1


def test_words_inside_other_words_and_code_are_ignored(repo: Path) -> None:
    write(
        repo,
        "docs/a.md",
        "# A\n\nThe policy is `unsafe-inline`; unsafe, safeguard and a memory-safe mode.\n\n"
        "```\nsecure\n```\n",
    )
    assert run(repo) == []


def test_the_command_exit_codes(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert docs_check.main(["--root", str(repo)]) == 0
    write(repo, "docs/a.md", "# A\n\n[gone](missing.md)\n")
    assert docs_check.main(["--root", str(repo)]) == 1
    assert "broken link" in capsys.readouterr().err
    assert docs_check.main(["--root", str(repo / "docs")]) == 2
