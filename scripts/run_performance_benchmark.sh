#!/usr/bin/env bash
set -euo pipefail

OUTPUT="${1:-build/performance-report.json}"
shift $(( $# > 0 ? 1 : 0 ))

PYTHONPATH=src ./scripts/python.sh -m verdikt.cli performance \
  --output "$OUTPUT" \
  "$@"
