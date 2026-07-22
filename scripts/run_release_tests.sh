#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p build

COMPOSE_FILE="deploy/qualification/docker-compose.yml"
MANAGED_INTEGRATIONS=false

cleanup() {
  if [[ "${MANAGED_INTEGRATIONS}" == "true" ]]; then
    docker compose -p verdikt-release-test -f "${COMPOSE_FILE}" down --volumes >/dev/null
  fi
}
trap cleanup EXIT

if [[ -z "${VERDIKT_TEST_REDIS_URL:-}" && -z "${VERDIKT_TEST_VAULT_ADDR:-}" && -z "${VERDIKT_TEST_VAULT_TOKEN:-}" ]]; then
  command -v docker >/dev/null 2>&1 || {
    echo "release tests require Docker or explicit Redis and Vault test endpoints" >&2
    exit 2
  }
  MANAGED_INTEGRATIONS=true
  docker compose -p verdikt-release-test -f "${COMPOSE_FILE}" up -d --wait
  export VERDIKT_TEST_REDIS_URL="redis://127.0.0.1:16379/15"
  export VERDIKT_TEST_VAULT_ADDR="http://127.0.0.1:18200"
  export VERDIKT_TEST_VAULT_TOKEN="verdikt-release-token"
elif [[ -z "${VERDIKT_TEST_REDIS_URL:-}" || -z "${VERDIKT_TEST_VAULT_ADDR:-}" || -z "${VERDIKT_TEST_VAULT_TOKEN:-}" ]]; then
  echo "set all of VERDIKT_TEST_REDIS_URL, VERDIKT_TEST_VAULT_ADDR, and VERDIKT_TEST_VAULT_TOKEN, or none of them" >&2
  exit 2
fi

export PYTHONPATH=src

./scripts/python.sh -m coverage erase
./scripts/python.sh -m coverage run --branch --source=verdikt -m unittest discover -s tests -v
./scripts/python.sh -m coverage report --show-missing --fail-under=85
./scripts/python.sh -m coverage json -o build/release-coverage.json

CRITICAL_MODULES="src/verdikt/audit_sink.py,src/verdikt/performance.py,src/verdikt/secrets.py,src/verdikt/slack_approval.py"
./scripts/python.sh -m coverage report --include="${CRITICAL_MODULES}" --show-missing --fail-under=100
./scripts/python.sh -m coverage json --include="${CRITICAL_MODULES}" -o build/critical-coverage.json

./scripts/run_evals.sh
./scripts/run_failure_tests.sh
./scripts/run_attackbench.sh \
  tests/fixtures/attackbench_smoke.jsonl \
  build/attackbench-smoke.json \
  --dataset-id verdikt-tier2-smoke \
  --expected-samples 8 \
  --min-precision 1 \
  --min-recall 1 \
  --min-f1 1
./scripts/run_performance_benchmark.sh \
  build/performance-smoke.json \
  --iterations 25 \
  --warmup 5 \
  --max-p99-ms 100 \
  --min-throughput 10
./scripts/run_community_interop.sh --output build/community-interop.json

echo "Verdikt release qualification passed."
