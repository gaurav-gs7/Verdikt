#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TF_DIR="${ROOT_DIR}/infra/aws/serverless"

REGION="${AWS_REGION:-us-east-1}"
APP_NAME="${MCP_GUARD_SERVERLESS_APP_NAME:-gatetrace-serverless}"
API_TOKEN="${MCP_GUARD_API_TOKEN:-local-demo-token-change-me}"
APPROVAL_SECRET="${MCP_GUARD_APPROVAL_SECRET:-local-dev-approval-secret-change-me}"

"${ROOT_DIR}/scripts/aws/preflight_identity.sh" >/dev/null
ZIP_PATH="$("${ROOT_DIR}/scripts/aws/package_serverless.sh")"

terraform -chdir="${TF_DIR}" init

terraform -chdir="${TF_DIR}" apply -auto-approve \
  -target=aws_secretsmanager_secret.api_token \
  -target=aws_secretsmanager_secret.approval_secret \
  -var="aws_region=${REGION}" \
  -var="app_name=${APP_NAME}" \
  -var="lambda_zip_path=${ZIP_PATH}" \
  -var="api_token=${API_TOKEN}" \
  -var="approval_secret=${APPROVAL_SECRET}"

aws secretsmanager put-secret-value \
  --region "${REGION}" \
  --secret-id "${APP_NAME}/api-token" \
  --secret-string "${API_TOKEN}" >/dev/null

aws secretsmanager put-secret-value \
  --region "${REGION}" \
  --secret-id "${APP_NAME}/approval-secret" \
  --secret-string "${APPROVAL_SECRET}" >/dev/null

terraform -chdir="${TF_DIR}" apply -auto-approve \
  -var="aws_region=${REGION}" \
  -var="app_name=${APP_NAME}" \
  -var="lambda_zip_path=${ZIP_PATH}" \
  -var="api_token=${API_TOKEN}" \
  -var="approval_secret=${APPROVAL_SECRET}"

terraform -chdir="${TF_DIR}" output
