#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
exec ./scripts/python.sh -m mcp_guard.cli interop "$@"
