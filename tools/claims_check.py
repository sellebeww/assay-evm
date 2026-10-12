"""Check that every claim has evidence, and that the README's claims are in the claims table.

`docs/claims.md` holds one row per claim: an area, the claim, one or more evidence paths and a
status. This tool checks that

1. every evidence path in the table exists (a file, a directory, or `path::name`, where the file
   exists and contains `name`, for a specific test);
2. every status is one of the allowed values;
3. every area that the README marks with a claim anchor has at least one row in the table, so a
   claim cannot be added to the README without evidence;
4. the README links to `docs/claims.md`.

The table is parsed as GitHub-flavoured Markdown: a header row, a separator, then one row per
claim. The tool reads only the repository, never the network, and makes no change.

Exit status: 0 when every check passes, 1 when a claim lacks evidence or a README area has no
row, 2 when a file cannot be read or the table is malformed.
"""

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

REPO_ROOT: Final = Path(__file__).resolve().parent.parent
CLAIMS_PAGE: Final = REPO_ROOT / "docs" / "claims.md"
README: Final = REPO_ROOT / "README.md"
ALLOWED_STATUS: Final = frozenset({"met", "bounded", "partial", "not-covered"})
# A README line `<!-- claim: <area> -->` declares a claim area that the table must cover.
README_CLAIM: Final = re.compile(r"<!--\s*claim:\s*([a-z0-9-]+)\s*-->")
_EVIDENCE_SPLIT: Final = re.compile(r"[;,]\s*")
_CODE_SPAN: Final = re.compile(r"`([^`]+)`")


@dataclass(frozen=True, slots=True)
class Claim:
    area: str
    claim: str
    evidence: tuple[str, ...]
    status: str


class ClaimsError(Exception):
    """The claims table or the README cannot be read."""


def _split_row(line: str) -> list[str]:
    cells = line.strip().strip("|").split("|")
    return [cell.strip() for cell in cells]


def parse_claims(text: str) -> list[Claim]:
    """Parse the first Markdown table under a heading that has the four expected columns."""
    rows: list[list[str]] = []
    header: list[str] | None = None
    for line in text.splitlines():
        if not line.strip().startswith("|"):
            if header is not None and rows:
                break
            continue
        cells = _split_row(line)
        if header is None:
            if [c.lower() for c in cells] == ["area", "claim", "evidence", "status"]:
                header = cells
            continue
        if set("".join(cells)) <= {"-", ":"}:
            continue
        rows.append(cells)
    if header is None:
        raise ClaimsError("docs/claims.md has no table with columns area, claim, evidence, status")
    claims: list[Claim] = []
    for cells in rows:
        if len(cells) != 4:
            raise ClaimsError(f"claims row does not have four columns: {cells}")
        area, claim, evidence_cell, status = cells
        evidence = tuple(
            span
            for item in _EVIDENCE_SPLIT.split(evidence_cell)
            for span in _CODE_SPAN.findall(item)
        )
        claims.append(Claim(area=area, claim=claim, evidence=evidence, status=status))
    return claims


def evidence_problem(reference: str) -> str | None:
    """Return a problem description for one evidence reference, or `None` when it is sound."""
    path_part, _, name = reference.partition("::")
    path = REPO_ROOT / path_part
    if "::" in reference:
        if not path.is_file():
            return f"evidence file does not exist: {path_part}"
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return f"evidence file cannot be read: {path_part} ({exc})"
        if name not in text:
            return f"evidence {path_part} does not contain {name!r}"
        return None
    if not path.exists():
        return f"evidence path does not exist: {path_part}"
    return None


def readme_claim_areas(text: str) -> set[str]:
    return set(README_CLAIM.findall(text))


def check(claims_text: str, readme_text: str) -> list[str]:
    """Return a list of problems; an empty list means every check passed."""
    problems: list[str] = []
    claims = parse_claims(claims_text)
    if not claims:
        problems.append("the claims table has no rows")
    seen_areas = {claim.area for claim in claims}
    for claim in claims:
        if claim.status not in ALLOWED_STATUS:
            problems.append(
                f"{claim.area}: status {claim.status!r} is not one of "
                f"{', '.join(sorted(ALLOWED_STATUS))}"
            )
        if not claim.evidence:
            problems.append(f"{claim.area}: the claim {claim.claim!r} cites no evidence")
        for reference in claim.evidence:
            problem = evidence_problem(reference)
            if problem is not None:
                problems.append(f"{claim.area}: {problem}")
    for area in sorted(readme_claim_areas(readme_text)):
        if area not in seen_areas:
            problems.append(f"README marks the claim area {area!r} but docs/claims.md has no row")
    if "docs/claims.md" not in readme_text:
        problems.append("README.md does not link to docs/claims.md")
    return problems


def main(argv: list[str] | None = None) -> int:
    try:
        claims_text = CLAIMS_PAGE.read_text(encoding="utf-8")
        readme_text = README.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        problems = check(claims_text, readme_text)
    except ClaimsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if problems:
        for problem in problems:
            print(f"CLAIM PROBLEM: {problem}")
        print(f"claims-check: {len(problems)} problem(s)")
        return 1
    claims = parse_claims(claims_text)
    print(f"claims-check: OK ({len(claims)} claims, every evidence path exists)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
