# GateTrace MCP Terraform Deployment

This Terraform module is the production-facing real MCP deployment path for GateTrace MCP. It provisions:

- Amazon ECR repository with scan-on-push and AES256 encryption
- ECR lifecycle policy that keeps the most recent five images
- EC2 instance profile and IAM role
- SSM Session Manager permissions
- Security group for the dashboard port
- One encrypted-root-volume EC2 instance running the GateTrace MCP Docker image
- Official MCP Streamable HTTP endpoint at `/mcp`
- Health and Prometheus-style metrics endpoints at `/healthz` and `/metrics`
- AWS Secrets Manager storage for bearer-token and approval-token secrets

The module uses default names that avoid colliding with the CloudFormation demo path.

## Fast Path

From the repository root:

```bash
export AWS_REGION=us-east-1
export MCP_GUARD_ALLOWED_CIDR="$(curl -s https://checkip.amazonaws.com)/32"
export MCP_GUARD_MODE=real-mcp
export MCP_GUARD_HTTP_BEARER_TOKEN="$(openssl rand -hex 24)"
export MCP_GUARD_APPROVAL_SECRET="$(openssl rand -hex 32)"
./scripts/aws/deploy_terraform.sh
```

Destroy resources after the demo:

```bash
./scripts/aws/destroy_terraform.sh
```

For ARM/free-tier experiments:

```bash
export MCP_GUARD_INSTANCE_TYPE=t4g.micro
export MCP_GUARD_DOCKER_PLATFORM=linux/arm64
export MCP_GUARD_AMI_SSM_PARAMETER=/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64
./scripts/aws/deploy_terraform.sh
```

## Manual Path

```bash
cd infra/aws/terraform
terraform init
terraform apply -target=aws_ecr_repository.app
```

Then build and push the image from the repository root:

```bash
export MCP_GUARD_ECR_REPOSITORY=mcp-guard-terraform
export MCP_GUARD_IMAGE_TAG=latest
IMAGE_URI=$(./scripts/aws/build_push_ecr.sh)
echo "$IMAGE_URI"
```

Finish the infrastructure apply:

```bash
cd infra/aws/terraform
terraform apply \
  -var="repository_name=mcp-guard-terraform" \
  -var="image_tag=latest" \
  -var="allowed_cidr=<your-public-ip>/32"
```

Terraform outputs the dashboard URL and SSM command.

In `real-mcp` mode, point MCP clients to:

```text
http://<public-dns>:8080/mcp
```

Use the bearer token through an `Authorization: Bearer ...` header when your MCP client supports custom headers. If not, restrict the security group to your own IP and treat the network boundary as the demo control.

Terraform creates the secret containers and IAM permissions. The deploy script writes secret values with AWS CLI so live secret strings are not stored through Terraform-managed secret-version resources.

## Interview Talking Point

Terraform is the stronger resume signal because it shows modular infrastructure as code, stateful provisioning, repeatable cleanup, IAM modeling, and cost-aware cloud operations. CloudFormation remains in this repo as the AWS-native baseline.
