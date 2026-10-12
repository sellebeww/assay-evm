"""The variant power page (`tools/variant_power.py`), rendered from results without Docker."""

import re
from pathlib import Path

import fixture_check
import variant_power as vp

FIXTURES = sorted(
    fixture_check.discover_fixtures(fixture_check.FIXTURES_DIR),
    key=lambda item: fixture_check.CLASS_IDS.index(item.split("/")[0]),
)
FORBIDDEN = re.compile(r"\b(secure|safe|proven|guaranteed|unhackable)\b", re.IGNORECASE)


def _result(fixture: str, label: str, name: str, found: bool, **fields: object) -> vp.SearchResult:
    values: dict[str, object] = {
        "fixture": fixture,
        "label": label,
        "profile": name,
        "verdict": "FAIL" if found else "PASS",
        "reasons": ("variant_found",) if found else (),
        "found": found,
        "mode": "fuzz" if found else None,
        "seed_index": 2 if found else None,
        "seeds": 1 if name == "quick" else 3,
        "seconds": 12.5,
    }
    values.update(fields)
    return vp.SearchResult.model_validate(values)


def results(good_variant: bool = False) -> vp.PowerResults:
    items = []
    for name in ("quick", "standard"):
        for fixture in FIXTURES:
            # The quick profile misses the rounding variant in this synthetic run.
            missed = name == "quick" and fixture.startswith("rounding/")
            items.append(_result(fixture, "overfit", name, not missed))
            found = good_variant and name == "standard" and fixture.startswith("dos/")
            items.append(_result(fixture, "good", name, found))
    return vp.PowerResults(
        assay_version="0.1.0",
        tool_versions={"foundry": "v1.8.4"},
        versions_lock_sha256="c" * 64,
        base_seed="0x1",
        profiles=tuple(
            vp.ProfileValues.model_validate(vp.profile(name).model_dump())
            for name in ("quick", "standard")
        ),
        total_seconds=400.0,
        results=tuple(items),
    )


def test_the_page_lists_every_patch_and_profile_with_seed_and_time() -> None:
    page = vp.render_markdown(results())
    rows = [line for line in page.splitlines() if line.startswith("| `") and "`overfit`" in line]
    rows += [line for line in page.splitlines() if line.startswith("| `") and "`good`" in line]
    assert len(rows) == 2 * len(FIXTURES) * 2
    assert (
        "| `reentrancy` | `single_function` | `overfit` | `standard` | FAIL | yes | fuzz | "
        "2 of 3 | 12 s |" in page
    )
    assert (
        "| `reentrancy` | `single_function` | `good` | `quick` | PASS | no | - | none of 1 | 12 s |"
        in page
    )
    assert "VARIANT POWER: quick: 7/8 overfit patches with a variant, 0/8 good patches" in page
    assert "standard: 8/8 overfit patches with a variant, 0/8 good patches" in page


def test_the_page_says_that_quick_can_miss_and_that_this_is_no_guarantee() -> None:
    page = vp.render_markdown(results())
    assert "It is not edited by hand." in page
    assert "the `quick` profile runs fewer seeds" in page
    assert "not a guarantee" in page
    assert "not a proof of absence" in page
    missed = page.split("## Overfit patches without a variant", 1)[1].split("##", 1)[0]
    assert "`rounding/share_inflation` with the `quick` profile" in missed
    assert FORBIDDEN.search(page.replace("not a guarantee", "")) is None


def test_a_good_patch_with_a_variant_is_a_finding(tmp_path: Path) -> None:
    saved = tmp_path / "results.json"
    saved.write_text(results(good_variant=True).model_dump_json())
    out = tmp_path / "page.md"
    assert vp.main(["--from-results", str(saved), "--out", str(out)]) == 1
    assert "1/8 good patches with a variant" in out.read_text()
    clean = tmp_path / "clean.json"
    clean.write_text(results().model_dump_json())
    assert vp.main(["--from-results", str(clean), "--out", str(out)]) == 0


def test_bad_arguments_and_unreadable_results_exit_with_2(tmp_path: Path) -> None:
    assert vp.main(["--profiles", "fast", "--out", str(tmp_path / "x")]) == 2
    assert vp.main(["--profiles", "quick quick", "--out", str(tmp_path / "x")]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema_version": 9}')
    assert vp.main(["--from-results", str(bad), "--out", str(tmp_path / "x")]) == 2
