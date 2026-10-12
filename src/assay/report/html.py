"""Self-contained HTML report of an evidence bundle (`assay report`).

The page is one file: inline CSS, no script, no external resource, and a `Content-Security-Policy`
meta tag that allows nothing but inline styles and `data:` images. It is a pure function of the
bundle: no clock, no host path and no random value enter it, so the same bundle gives the same
bytes.

Text that comes from the target code, the patch, the PoC or a model (identifiers, comments, revert
reasons, diff lines, reasons) is data. It is only ever placed in element content, never in an
attribute, a style, a URL or a script, and it passes through `_text` first: control and invisible
formatting characters are made visible, then `& < > " '` are escaped. Every attribute value on the
page is a fixed string of this module.
"""

import hashlib
import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from html import escape
from pathlib import Path, PurePosixPath
from typing import Final

from pydantic import ValidationError

from assay.cli.text import printable
from assay.ledger import FinalVerdict
from assay.oracles.base import Reason
from assay.oracles.variant import VARIANT_POC_FILE
from assay.orchestrator.fix import FixHistory, HistoryOracle
from assay.orchestrator.models import REPORT_ORDER, OracleRow
from assay.report.bundle import (
    EVIDENCE_DIR,
    HISTORY_FILE,
    MANIFEST_FILE,
    PATCH_FILE,
    POC_DIR,
    Manifest,
)

MAX_SHOWN_BYTES: Final = 256 * 1024
"""Most bytes of one file that the page shows; the rest is replaced by a note."""
MAX_SHOWN_FILES: Final = 40
CSP: Final = "default-src 'none'; style-src 'unsafe-inline'; img-src data:"
REPLAY_COMMAND: Final = "assay replay <bundle>"

_HUNK: Final = re.compile(r"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")
_META_PREFIXES: Final = (
    "diff ",
    "index ",
    "new file",
    "deleted file",
    "old mode",
    "new mode",
    "similarity",
    "rename ",
    "copy ",
    "Binary files",
    "GIT binary patch",
)

_BANNER_CLASS: Final = {
    FinalVerdict.VERIFIED_WITHIN_BOUNDS: "ok",
    FinalVerdict.REJECTED: "bad",
    FinalVerdict.INCONCLUSIVE: "unsure",
}
_BANNER_LEAD: Final = {
    FinalVerdict.VERIFIED_WITHIN_BOUNDS: (
        "No variant of the exploit was found within the recorded bounds."
    ),
    FinalVerdict.REJECTED: "At least one oracle failed for this patch.",
    FinalVerdict.INCONCLUSIVE: (
        "No oracle failed, but at least one was inconclusive or did not run."
    ),
}
_MEANING: Final = {
    FinalVerdict.VERIFIED_WITHIN_BOUNDS: (
        "All required oracles passed on the patched revision: the PoC no longer reproduces, the "
        "variant search found no variant within its bounds, benign behavior is unchanged, and "
        "storage layout, ABI and events have no breaking change."
    ),
    FinalVerdict.REJECTED: (
        "At least one oracle failed. The reasons in the oracle table say which check failed and "
        "why. A rejected patch is not a statement about the rest of the code."
    ),
    FinalVerdict.INCONCLUSIVE: (
        "No oracle failed, but at least one was inconclusive or did not run, so the checks that "
        "were required did not all pass. A timeout or an unknown result is never counted as a "
        "pass."
    ),
}
_NOT_MEANT: Final = (
    "It is not a proof of absence. It says nothing about inputs, call sequences, seeds, loop "
    "bounds or code that the listed checks did not cover, and it does not describe the project "
    "as a whole. It is not a replacement for an audit.",
    "Only deterministic oracles decide. A model may have proposed the patch or the PoC; its "
    "output never changed a verdict by itself.",
    "The bundle is tamper-evident, not signed: whoever can rewrite both the files and the "
    "manifest can forge one.",
)
_LEVELS: Final = {
    "E0": "unverified signal",
    "E1": "exploit reproduced on the vulnerable revision",
    "E2": "patch blocks the PoC without a detected regression; the variant search did not decide",
    "E3": "all required oracles passed within the recorded bounds",
}

_CSS: Final = """
:root{color-scheme:light dark;--bg:#fafaf8;--fg:#1c1d1f;--muted:#5d6166;--card:#fff;--line:#d9dad6;\
--ok:#1d6b3a;--okbg:#e4f3e9;--bad:#a12622;--badbg:#fbe7e5;--unsure:#8a5a00;--unsurebg:#fbf0d9;\
--add:#e1f4e4;--del:#fbe3e1;--hunk:#e6eefb;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#141516;--fg:#e8e8e6;--muted:#a0a4a8;--card:#1c1d1f;\
--line:#34363a;--ok:#7fd49b;--okbg:#14301f;--bad:#f09a94;--badbg:#3a1815;--unsure:#e6bb66;\
--unsurebg:#35290f;--add:#17301d;--del:#3a1b19;--hunk:#1a2840}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,\
"Segoe UI",Roboto,sans-serif}
main{max-width:70rem;margin:0 auto;padding:1.5rem 1rem 3rem}
h1{font-size:1.15rem;margin:0 0 1rem;color:var(--muted);font-weight:600}
h2{font-size:1.1rem;margin:2rem 0 .6rem}
section,.box{background:var(--card);border:1px solid var(--line);border-radius:6px;\
padding:.9rem 1.1rem}
section{margin-top:1rem}
section>h2{margin-top:0}
.banner{border-radius:6px;padding:1.2rem 1.4rem;border:1px solid var(--line)}
.banner .verdict{font:700 1.7rem/1.2 var(--mono);overflow-wrap:anywhere}
.banner p{margin:.4rem 0 0}
.ok{background:var(--okbg);color:var(--ok);border-color:var(--ok)}
.bad{background:var(--badbg);color:var(--bad);border-color:var(--bad)}
.unsure{background:var(--unsurebg);color:var(--unsure);border-color:var(--unsure)}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;vertical-align:top;padding:.35rem .6rem;border-bottom:1px solid var(--line)}
th{font-weight:600;color:var(--muted);white-space:nowrap}
.tablewrap{overflow-x:auto}
code,pre,.mono{font-family:var(--mono);font-size:.85rem}
pre{margin:.4rem 0 0;padding:.6rem .8rem;overflow-x:auto;border:1px solid var(--line);\
border-radius:4px;background:var(--bg);white-space:pre}
.ln{display:block;min-height:1.4em;white-space:pre}
.add{background:var(--add)}.del{background:var(--del)}.hunk{background:var(--hunk)}
.meta{color:var(--muted)}
.tag{display:inline-block;padding:0 .45rem;border-radius:3px;font:600 .8rem var(--mono);\
border:1px solid currentColor}
.muted{color:var(--muted)}
dl{display:grid;grid-template-columns:max-content 1fr;gap:.25rem 1rem;margin:0}
dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}
ol.timeline{margin:0;padding-left:1.3rem}
ol.timeline li{margin:.2rem 0}
ul{margin:.3rem 0;padding-left:1.3rem}
details{margin-top:.6rem}summary{cursor:pointer;color:var(--muted)}
"""


def _text(value: str) -> str:
    """Untrusted text for element content: invisible characters made visible, markup escaped."""
    return escape(printable(value.replace("\r\n", "\n")), quote=True)


def _code(value: str) -> str:
    return f"<code>{_text(value)}</code>"


def _tag(verdict: str) -> str:
    css = {"PASS": "ok", "FAIL": "bad", "INCONCLUSIVE": "unsure"}.get(verdict, "muted")
    return f'<span class="tag {css}">{_text(verdict)}</span>'


@dataclass(frozen=True, slots=True)
class _Shown:
    path: str
    text: str
    note: str | None


class BundleFiles:
    """Read access to the files the manifest lists, nothing else.

    The caller has checked every file against the manifest (`assay.report.replay.load_bundle`),
    so the listed paths are valid relative paths of regular files with the right content.
    """

    def __init__(self, root: Path, manifest: Manifest) -> None:
        self._root = root
        self.paths = tuple(sorted(item.path for item in manifest.files))

    def read(self, path: str) -> _Shown:
        target = self._root.joinpath(*PurePosixPath(path).parts)
        with target.open("rb") as handle:
            data = handle.read(MAX_SHOWN_BYTES + 1)
        note = None
        if len(data) > MAX_SHOWN_BYTES:
            data = data[:MAX_SHOWN_BYTES]
            note = f"shown up to {MAX_SHOWN_BYTES} bytes; the rest is in the bundle"
        return _Shown(path, data.decode("utf-8", errors="replace"), note)

    def bytes(self, path: str) -> bytes:
        return self._root.joinpath(*PurePosixPath(path).parts).read_bytes()


def _reason_items(reasons: Iterable[Reason]) -> str:
    items = []
    for item in reasons:
        where = ""
        if item.path is not None:
            where = f" [{_text(item.path)}{'' if item.line is None else f':{item.line}'}]"
        items.append(f"<li>{_code(item.code)}: {_text(item.detail)}{where}</li>")
    return f"<ul>{''.join(items)}</ul>" if items else ""


def render_diff(diff: str) -> str:
    """The diff as `<span>` lines with a class per kind of line.

    Hunk headers give the number of lines that follow, so a removed line that starts with `--`
    (shown as `---`) is still a content line, not a file header.
    """
    lines = diff.replace("\r\n", "\n").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    out: list[str] = []
    old_left = new_left = 0
    for line in lines:
        kind = "ctx"
        if old_left > 0 or new_left > 0:
            if line.startswith("+"):
                kind, new_left = "add", new_left - 1
            elif line.startswith("-"):
                kind, old_left = "del", old_left - 1
            elif line.startswith("\\"):
                kind = "meta"
            else:
                old_left, new_left = old_left - 1, new_left - 1
        else:
            hunk = _HUNK.match(line)
            if hunk is not None:
                kind = "hunk"
                old_left = int(hunk.group(1)) if hunk.group(1) is not None else 1
                new_left = int(hunk.group(2)) if hunk.group(2) is not None else 1
            elif line.startswith(("--- ", "+++ ", *_META_PREFIXES)):
                kind = "meta"
        out.append(f'<span class="ln {kind}">{_text(line)}</span>')
    return "".join(out)


def _diff_counts(diff: str) -> tuple[int, int]:
    rendered = render_diff(diff)
    return rendered.count('class="ln add"'), rendered.count('class="ln del"')


def _file_block(shown: _Shown) -> str:
    note = f'<p class="muted">{_text(shown.note)}</p>' if shown.note else ""
    return (
        f"<details open><summary>{_code(shown.path)}</summary>{note}"
        f"<pre>{_text(shown.text)}</pre></details>"
    )


def _banner(manifest: Manifest) -> str:
    verdict = manifest.final_verdict
    reasons = "; ".join(manifest.reasons) or "every required oracle passed"
    level = manifest.evidence_level
    level_text = "" if level is None else f" Evidence level {level}: {_LEVELS[level]}."
    violation = (
        "<p>Integrity violation: the patch or its inputs broke an integrity rule, and nothing "
        "from the patch ran.</p>"
        if manifest.integrity_violation
        else ""
    )
    return (
        f'<div class="banner {_BANNER_CLASS[verdict]}" role="status">'
        f'<div class="verdict">{_text(verdict.value)}</div>'
        f"<p>{_text(_BANNER_LEAD[verdict])}{_text(level_text)}</p>"
        f"<p>Reason: {_text(reasons)}</p>{violation}</div>"
    )


def _meaning(manifest: Manifest) -> str:
    ran = ", ".join(oracle.value for oracle in manifest.bounds.oracles_run) or "none"
    not_ran = ", ".join(oracle.value for oracle in manifest.bounds.oracles_not_run) or "none"
    bounds = json.dumps(manifest.bounds.model_dump(mode="json"), indent=2, sort_keys=True)
    annotations = "".join(f"<li>{_text(item)}</li>" for item in manifest.annotations)
    return (
        '<section id="meaning"><h2>What this result means, and what it does not</h2>'
        f"<p>{_text(_MEANING[manifest.final_verdict])}</p>"
        f"<p><strong>Bounds that ran.</strong> {_text(manifest.bounds_statement)}</p>"
        f"<p>Oracles run: {_text(ran)}. Oracles not run: {_text(not_ran)}.</p>"
        + (f"<ul>{annotations}</ul>" if annotations else "")
        + "<p><strong>What it is not.</strong></p><ul>"
        + "".join(f"<li>{_text(item)}</li>" for item in _NOT_MEANT)
        + f"</ul><details><summary>Bounds as recorded</summary><pre>{_text(bounds)}</pre>"
        "</details></section>"
    )


def _summary(manifest: Manifest, history: FixHistory | None) -> str:
    level = manifest.evidence_level
    rows = [
        ("final verdict", _code(manifest.final_verdict.value)),
        (
            "evidence level",
            "not set" if level is None else f"{_code(level)} {_text(_LEVELS[level])}",
        ),
        ("profile", _code(manifest.settings.profile)),
        ("fuzz seed", _code(manifest.settings.fuzz_seed)),
        ("symbolic oracle", "requested" if manifest.settings.symbolic else "not requested"),
        ("base tree sha256", _code(manifest.inputs.base_tree_sha256)),
        ("PoC tree sha256", _code(manifest.inputs.poc_tree_sha256)),
        ("patch sha256", _code(manifest.inputs.patch_sha256)),
        (
            "patched tree sha256",
            "not built"
            if manifest.inputs.patched_tree_sha256 is None
            else _code(manifest.inputs.patched_tree_sha256),
        ),
    ]
    if history is not None:
        rows.insert(1, ("vulnerability class", _code(history.vuln_class)))
        rows.insert(2, ("origin", "patch from the fix loop"))
    body = "".join(f"<dt>{label}</dt><dd>{value}</dd>" for label, value in rows)
    return f'<section id="finding"><h2>Finding summary</h2><dl>{body}</dl></section>'


def _timeline(manifest: Manifest, history: FixHistory | None) -> str:
    steps: list[str] = []
    if history is not None:
        for attempt in history.attempts:
            verdict = "no verdict" if attempt.in_loop_verdict is None else attempt.in_loop_verdict
            steps.append(f"attempt {attempt.number}: {attempt.outcome}, in-loop verdict {verdict}")
        steps.append(
            f"decision ({history.final.decision}): {history.final.verdict.value}"
            f" after {history.final.attempts_used} attempt(s)"
        )
    else:
        steps.append("patch proposed for verification")
    for row in sorted(manifest.oracles, key=lambda item: REPORT_ORDER.index(item.oracle)):
        verdict = row.verdict.value if row.verdict is not None else row.status
        steps.append(f"{row.oracle.value}: {verdict}")
    steps.append(f"final verdict: {manifest.final_verdict.value}")
    items = "".join(f"<li>{_text(step)}</li>" for step in steps)
    return (
        '<section id="timeline"><h2>Status timeline</h2>'
        '<p class="muted">Steps in the order in which they were decided. '
        "No clock time is recorded.</p>"
        f'<ol class="timeline">{items}</ol></section>'
    )


def _oracle_row(row: OracleRow) -> str:
    verdict = row.verdict.value if row.verdict is not None else row.status
    warnings = ""
    if row.warnings:
        warnings = "<p>Warnings (they do not change the verdict):</p>" + _reason_items(row.warnings)
    return (
        f"<tr><td>{_code(row.oracle.value)}</td><td>{_tag(verdict)}</td>"
        f"<td>{_text(row.summary)}{_reason_items(row.reasons)}{warnings}</td></tr>"
    )


def _oracles(manifest: Manifest) -> str:
    rows = sorted(manifest.oracles, key=lambda item: REPORT_ORDER.index(item.oracle))
    return (
        '<section id="oracles"><h2>Oracle verdicts</h2><div class="tablewrap"><table>'
        "<thead><tr><th>oracle</th><th>verdict</th><th>reason</th></tr></thead><tbody>"
        + "".join(_oracle_row(row) for row in rows)
        + "</tbody></table></div></section>"
    )


def _poc(files: BundleFiles) -> str:
    poc = [path for path in files.paths if path.startswith(f"{POC_DIR}/")]
    variant = [
        path
        for path in files.paths
        if path.startswith(f"{EVIDENCE_DIR}/") and PurePosixPath(path).name == VARIANT_POC_FILE
    ]
    parts = ['<section id="poc"><h2>PoC</h2>']
    parts += [_file_block(files.read(path)) for path in poc[:MAX_SHOWN_FILES]]
    if len(poc) > MAX_SHOWN_FILES:
        parts.append(
            f'<p class="muted">{len(poc) - MAX_SHOWN_FILES} more PoC file(s) not shown.</p>'
        )
    if not poc:
        parts.append('<p class="muted">The bundle holds no PoC file.</p>')
    parts.append("<h2>variant_poc</h2>")
    if variant:
        parts.append(
            '<p class="muted">Concrete test written from a variant the search reported; '
            "it is evidence of what was found.</p>"
        )
        parts += [_file_block(files.read(path)) for path in variant[:MAX_SHOWN_FILES]]
    else:
        parts.append('<p class="muted">No variant was reported, so there is no variant_poc.</p>')
    parts.append("</section>")
    return "".join(parts)


def _patch(files: BundleFiles) -> str:
    shown = files.read(PATCH_FILE)
    added, removed = _diff_counts(shown.text)
    note = f'<p class="muted">{_text(shown.note)}</p>' if shown.note else ""
    return (
        '<section id="patch"><h2>Patch</h2>'
        f'<p class="muted">{added} line(s) added, {removed} line(s) removed. '
        f"sha256 of the file: {_code(hashlib.sha256(files.bytes(PATCH_FILE)).hexdigest())}</p>"
        f'{note}<pre class="diff">{render_diff(shown.text)}</pre></section>'
    )


def _history(history: FixHistory | None, unreadable: bool) -> str:
    if unreadable:
        return (
            '<section id="attempts"><h2>Attempt history</h2><p>The attempt history of this '
            "bundle could not be read.</p></section>"
        )
    if history is None:
        return (
            '<section id="attempts"><h2>Attempt history</h2><p class="muted">This bundle comes '
            "from <code>assay verify</code>: one patch, no attempt history.</p></section>"
        )
    rows = []
    for attempt in history.attempts:
        oracles = ", ".join(
            f"{item.oracle} {item.verdict if item.verdict else item.status}"
            for item in attempt.oracles
        )
        reasons = _attempt_reasons(attempt.oracles, attempt.problems)
        sha = "none" if attempt.diff_sha256 is None else attempt.diff_sha256
        verdict = "none" if attempt.in_loop_verdict is None else attempt.in_loop_verdict.value
        rows.append(
            f"<tr><td>{attempt.number}</td><td>{_text(attempt.outcome)}</td>"
            f"<td>{_code(sha)}</td><td>{_text(verdict)}</td>"
            f"<td>{_text(oracles)}{_reason_items(reasons)}</td></tr>"
        )
    final = history.final
    limits = history.limits
    return (
        '<section id="attempts"><h2>Attempt history</h2>'
        '<div class="tablewrap"><table><thead><tr><th>#</th><th>outcome</th><th>diff sha256</th>'
        "<th>in-loop verdict</th><th>oracles and reasons</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
        f"<p>Decision: {_code(final.decision)}, verdict {_code(final.verdict.value)}, "
        f"{final.attempts_used} of {limits.max_attempts} attempt(s) used.</p>"
        f"<p>{_text(final.statement)}</p>"
        f'<p class="muted">The final decision is a separate verification with a held-out seed. '
        f"Limits: at most {limits.max_changed_lines} changed lines, {limits.max_files} file(s), "
        f"{limits.max_diff_bytes} bytes.</p></section>"
    )


def _attempt_reasons(oracles: Sequence[HistoryOracle], problems: Sequence[Reason]) -> list[Reason]:
    found: list[Reason] = list(problems)
    for item in oracles:
        found.extend(item.reasons)
    return found


def _provenance(manifest: Manifest, manifest_sha256: str) -> str:
    environment = manifest.environment
    tools = "".join(
        f"<li>{_code(name)} {_code(version)}</li>"
        for name, version in sorted(environment.tool_versions.items())
    )
    rows = [
        ("manifest sha256", _code(manifest_sha256)),
        ("Assay version", _code(manifest.assay_version)),
        ("runner image id", _code(environment.image_digest)),
        ("versions.lock sha256", _code(environment.versions_lock_sha256)),
        ("harness sha256", _code(manifest.inputs.harness_sha256)),
        ("files in the bundle", str(len(manifest.files))),
    ]
    if manifest.symbolic_environment is not None:
        rows.insert(3, ("symbolic image id", _code(manifest.symbolic_environment.image_digest)))
    body = "".join(f"<dt>{label}</dt><dd>{value}</dd>" for label, value in rows)
    return (
        '<section id="provenance"><h2>Manifest and tool versions</h2>'
        f"<dl>{body}</dl><p>Tool versions declared by the runner image:</p><ul>{tools}</ul>"
        '<p class="muted">The manifest hash is the sha256 of <code>'
        f"{_text(MANIFEST_FILE)}</code> as stored in the bundle.</p></section>"
    )


def _reproduce() -> str:
    return (
        '<section id="reproduce"><h2>How to reproduce</h2>'
        "<p>Re-run every oracle offline on the bundle and compare the verdicts with the "
        "manifest:</p>"
        f"<pre>{_text(REPLAY_COMMAND)}</pre>"
        "<p>The replay first checks the sha256 of every file against the manifest and runs "
        "nothing when one differs. It needs Docker and the runner image (<code>make image</code>)."
        " It prints <code>REPLAY MATCH</code> when the verdicts are equal.</p></section>"
    )


def _load_history(files: BundleFiles) -> tuple[FixHistory | None, bool]:
    if HISTORY_FILE not in files.paths:
        return None, False
    try:
        return FixHistory.model_validate_json(files.bytes(HISTORY_FILE), strict=True), False
    except (ValidationError, OSError):
        return None, True


def render_report(root: Path, manifest: Manifest) -> str:
    """The HTML report of the bundle at `root`, whose files were checked against `manifest`."""
    files = BundleFiles(root, manifest)
    history, unreadable = _load_history(files)
    manifest_sha256 = hashlib.sha256((root / MANIFEST_FILE).read_bytes()).hexdigest()
    title = f"Assay report: {manifest.final_verdict.value}"
    sections = [
        _banner(manifest),
        _meaning(manifest),
        _summary(manifest, history),
        _timeline(manifest, history),
        _oracles(manifest),
        _poc(files),
        _patch(files),
        _history(history, unreadable),
        _provenance(manifest, manifest_sha256),
        _reproduce(),
    ]
    head = (
        '<meta charset="utf-8">'
        f'<meta http-equiv="Content-Security-Policy" content="{escape(CSP, quote=True)}">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="color-scheme" content="light dark">'
        f"<title>{_text(title)}</title><style>{_CSS}</style>"
    )
    body = "\n".join(sections)
    return (
        f'<!doctype html>\n<html lang="en"><head>{head}</head><body><main>\n'
        f"<h1>Assay evidence report</h1>\n{body}\n</main></body></html>\n"
    )
