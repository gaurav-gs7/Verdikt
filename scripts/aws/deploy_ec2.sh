#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../legacy_env.sh"

REGION="${AWS_REGION:-us-east-1}"
STACK_NAME="${VERDIKT_STACK_NAME:-verdikt-free-tier}"
INSTANCE_TYPE="${VERDIKT_INSTANCE_TYPE:-t3.micro}"
ALLOWED_CIDR="${VERDIKT_ALLOWED_CIDR:-0.0.0.0/0}"
TEMPLATE="${VERDIKT_TEMPLATE:-infra/aws/cloudformation/verdikt-ec2.yml}"
CONTAINER_MODE="${VERDIKT_MODE:-real-mcp}"
HTTP_BEARER_TOKEN="${VERDIKT_HTTP_BEARER_TOKEN:-}"
APPROVAL_SECRET="${VERDIKT_APPROVAL_SECRET:-local-dev-approval-secret-change-me}"

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <ecr-image-uri>" >&2
  echo "example: $0 123456789012.dkr.ecr.us-east-1.amazonaws.com/verdikt:latest" >&2
  exit 2
fi

IMAGE_URI="$1"

./scripts/aws/preflight_identity.sh >/dev/null

aws cloudformation deploy \
  --region "${REGION}" \
  --stack-name "${STACK_NAME}" \
  --template-file "${TEMPLATE}" \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    ImageUri="${IMAGE_URI}" \
    InstanceType="${INSTANCE_TYPE}" \
    AllowedCidr="${ALLOWED_CIDR}" \
    ContainerMode="${CONTAINER_MODE}" \
    HttpBearerToken="${HTTP_BEARER_TOKEN}" \
    ApprovalSecret="${APPROVAL_SECRET}"

aws cloudformation describe-stacks \
  --region "${REGION}" \
  --stack-name "${STACK_NAME}" \
  --query "Stacks[0].Outputs" \
  --output table
