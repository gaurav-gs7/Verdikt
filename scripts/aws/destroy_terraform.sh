#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../legacy_env.sh"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TF_DIR="${ROOT_DIR}/infra/aws/terraform"

REGION="${AWS_REGION:-us-east-1}"
APP_NAME="${VERDIKT_TF_APP_NAME:-verdikt-tf}"
REPOSITORY="${VERDIKT_TF_ECR_REPOSITORY:-verdikt}"
TAG="${VERDIKT_IMAGE_TAG:-latest}"
INSTANCE_TYPE="${VERDIKT_INSTANCE_TYPE:-t3.micro}"
AMI_SSM_PARAMETER="${VERDIKT_AMI_SSM_PARAMETER:-/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64}"
ALLOWED_CIDR="${VERDIKT_ALLOWED_CIDR:-127.0.0.1/32}"
CONTAINER_MODE="${VERDIKT_MODE:-real-mcp}"
HTTP_BEARER_TOKEN="${VERDIKT_HTTP_BEARER_TOKEN:-}"
APPROVAL_SECRET="${VERDIKT_APPROVAL_SECRET:-local-dev-approval-secret-change-me}"

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
