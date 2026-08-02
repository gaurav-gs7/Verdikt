#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
PYTHONPATH=src exec ./scripts/python.sh -m judikt.cli demo "$@"
