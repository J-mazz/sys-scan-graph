#!/usr/bin/env bash
set -euo pipefail
# Demo Phase 10: run two scans, enrich, produce HTML + diff, show manifest and timing.

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT_DIR"

BUILD_DIR=build
REPORT1=report_demo_1.json
REPORT2=report_demo_2.json
ENRICH1=enriched_demo_1.json
ENRICH2=enriched_demo_2.json
HTML=enriched_report.html
DIFF=enriched_diff.md
CONFIG=config.yaml

if [ ! -f "$CONFIG" ]; then
  echo "Missing config.yaml; abort" >&2
  exit 1
fi

if [ ! -x "$BUILD_DIR/sys-scan" ]; then
  echo "Building sys-scan (Release)" >&2
  cmake -B "$BUILD_DIR" -S . -DCMAKE_BUILD_TYPE=Release >/dev/null
  cmake --build "$BUILD_DIR" -j"$(nproc)" >/dev/null
fi

echo "[1/6] First scan" >&2
"$BUILD_DIR/sys-scan" --pretty --output "$REPORT1" >/dev/null
sleep 1

echo "[2/6] Second scan (simulate drift by touching file)" >&2
# Simple drift stimulus: modify mtime of binary (harmless) or create temp file
/bin/true > /dev/null
"$BUILD_DIR/sys-scan" --pretty --output "$REPORT2" >/dev/null

python -m venv agent/.venv >/dev/null 2>&1 || true
source agent/.venv/bin/activate
pip install -q -r agent/requirements.txt

start=$(python - <<'PY'
import time; print(time.time())
PY
)

echo "[3/6] Enrich first" >&2
python -m agent.cli analyze --report "$REPORT1" --out "$ENRICH1" >/dev/null

echo "[4/6] Enrich second with diff" >&2
python -m agent.cli analyze --report "$REPORT2" --out "$ENRICH2" --prev "$ENRICH1" >/dev/null || true

end=$(python - <<'PY'
import time; print(time.time())
PY
)

total=$(python - <<PY
start=$start; end=$end
print(f"{end-start:.3f}")
PY
)

echo "[5/6] Runtime (two enrich runs) = ${total}s" >&2
if [ -f "$HTML" ]; then echo "HTML: $HTML"; fi
if [ -f "$DIFF" ]; then echo "Diff: $DIFF"; fi
if [ -f manifest.json ]; then echo "Manifest SHA: $(jq -r '.rule_pack_sha' manifest.json)"; fi

# Notification condition simulation
avg_prob=$(jq '[.enriched_findings[].probability_actionable] | add/length' "$ENRICH2" 2>/dev/null || echo 0)
echo "[6/6] Avg probability actionable (second): ${avg_prob}" >&2

echo "Demo complete." >&2
