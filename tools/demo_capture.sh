#!/usr/bin/env bash
# One command that runs the example end to end and keeps every output for the documentation.
#
#   make demo-capture            (or: tools/demo_capture.sh [OUT_DIR])
#
# Needs Docker and the runner image (`make image`). It writes, under OUT_DIR (default
# demo-out/capture, ignored by Git): a transcript per step, the JSON and SARIF of the good and the
# overfit patch, the evidence bundles, the HTML reports and `STEPS.txt` with the exit code of each
# step. The expected exit codes are 0 for the good patch and 1 for the overfit one. Nothing here
# is invented: every file is the output of the command named in STEPS.txt.
set -uo pipefail

out="${1:-demo-out/capture}"
fixture="fixtures/reentrancy/single_function"
profile="quick"

if ! command -v docker > /dev/null 2>&1 || ! docker info > /dev/null 2>&1; then
  echo "error: Docker is missing or not running; this demo needs it (and 'make image')." >&2
  exit 4
fi

rm -rf "$out"
mkdir -p "$out"
: > "$out/STEPS.txt"
status=0

# step NAME EXPECTED_EXIT COMMAND...: runs the command, keeps its output and records its exit code.
step() {
  local name="$1" expected="$2"
  shift 2
  "$@" > "$out/$name.txt" 2>&1
  local code=$?
  printf '%-22s exit %s (expected %s)  %s\n' "$name" "$code" "$expected" "$*" >> "$out/STEPS.txt"
  if [ "$code" != "$expected" ]; then
    echo "unexpected exit code $code for step $name; see $out/$name.txt" >&2
    status=1
  fi
}

step doctor 0 uv run assay doctor

for label in good overfit; do
  expected=0
  [ "$label" = overfit ] && expected=1
  patch="$fixture/patches/$label.diff"
  step "verify-$label" "$expected" uv run assay verify --base "$fixture" --patch "$patch" \
    --poc "$fixture/poc" --profile "$profile" --bundle-out "$out/bundle-$label" \
    --ledger "$out/ledger-$label.db"
  step "verify-$label-json" "$expected" uv run assay verify --base "$fixture" --patch "$patch" \
    --poc "$fixture/poc" --profile "$profile" --json --sarif "$out/verify-$label.sarif" \
    --ledger "$out/ledger-$label.db"
  # The JSON goes to standard output; keep it as a file the report viewer can open.
  uv run assay verify --base "$fixture" --patch "$patch" --poc "$fixture/poc" \
    --profile "$profile" --json --ledger "$out/ledger-$label.db" > "$out/report-$label.json" 2> /dev/null
  step "report-$label" 0 uv run assay report "$out/bundle-$label" --out "$out/report-$label.html"
  step "replay-$label" 0 uv run assay replay "$out/bundle-$label"
done

step scan 0 uv run assay scan "$fixture" --format sarif --out "$out/scan.sarif" \
  --ledger "$out/ledger-scan.db"
step full-flow 0 uv run assay run "$fixture" --class reentrancy --mode replay \
  --cassette-dir demo/cassettes --profile "$profile" --ledger "$out/ledger-run.db" \
  --poc-dir "$out/run-poc" --bundle-out "$out/bundle-run"

echo "outputs in $out (see $out/STEPS.txt)"
cat "$out/STEPS.txt"
exit "$status"
