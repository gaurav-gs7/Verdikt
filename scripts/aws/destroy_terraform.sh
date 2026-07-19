#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TF_DIR="${ROOT_DIR}/infra/aws/terraform"

REGION="${AWS_REGION:-us-east-1}"
APP_NAME="${MCP_GUARD_TF_APP_NAME:-gatetrace-mcp-tf}"
REPOSITORY="${MCP_GUARD_TF_ECR_REPOSITORY:-gatetrace-mcp}"
TAG="${MCP_GUARD_IMAGE_TAG:-latest}"
INSTANCE_TYPE="${MCP_GUARD_INSTANCE_TYPE:-t3.micro}"
AMI_SSM_PARAMETER="${MCP_GUARD_AMI_SSM_PARAMETER:-/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64}"
ALLOWED_CIDR="${MCP_GUARD_ALLOWED_CIDR:-0.0.0.0/0}"
CONTAINER_MODE="${MCP_GUARD_MODE:-real-mcp}"
HTTP_BEARER_TOKEN="${MCP_GUARD_HTTP_BEARER_TOKEN:-}"
APPROVAL_SECRET="${MCP_GUARD_APPROVAL_SECRET:-local-dev-approval-secret-change-me}"

"${ROOT_DIR}/scripts/aws/preflight_identity.sh" >/dev/null

terraform -chdir="${TF_DIR}" destroy -auto-approve \
  -var="aws_region=${REGION}" \
  -var="app_name=${APP_NAME}" \
  -var="repository_name=${REPOSITORY}" \
  -var="image_tag=${TAG}" \
  -var="instance_type=${INSTANCE_TYPE}" \
  -var="ami_ssm_parameter=${AMI_SSM_PARAMETER}" \
  -var="container_mode=${CONTAINER_MODE}" \
  -var="http_bearer_token=${HTTP_BEARER_TOKEN}" \
  -var="approval_secret=${APPROVAL_SECRET}" \
  -var="allowed_cidr=${ALLOWED_CIDR}"
