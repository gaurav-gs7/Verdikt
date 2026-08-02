#!/usr/bin/env bash
set -euo pipefail

DATASET="${1:-tests/fixtures/attackbench_smoke.jsonl}"
OUTPUT="${2:-build/attackbench-report.json}"
shift $(( $# > 0 ? 1 : 0 ))
shift $(( $# > 0 ? 1 : 0 ))

PYTHONPATH=src ./scripts/python.sh -m judikt.cli attackbench \
  "$DATASET" \
  --output "$OUTPUT" \
  "$@"
