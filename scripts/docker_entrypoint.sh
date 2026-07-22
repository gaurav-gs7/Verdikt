#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/legacy_env.sh"

MODE="${VERDIKT_MODE:-real-mcp}"

case "${MODE}" in
  dashboard)
    exec python -m verdikt.cli dashboard --host 0.0.0.0 --port "${PORT:-8080}"
    ;;
  real-mcp)
    exec python -m verdikt.cli serve-real-mcp --host 0.0.0.0 --port "${PORT:-8080}"
    ;;
  *)
    echo "unsupported VERDIKT_MODE=${MODE}; expected dashboard or real-mcp" >&2
    exit 2
    ;;
esac
