output "ecr_repository_url" {
  description = "ECR repository URL used by the deployment."
  value       = aws_ecr_repository.app.repository_url
}

output "image_uri" {
  description = "Container image URI expected by the EC2 instance."
  value       = local.image_uri
}

output "instance_id" {
  description = "EC2 instance ID."
  value       = aws_instance.app.id
}

output "public_dns_name" {
  description = "Public DNS name for the EC2 instance."
  value       = aws_instance.app.public_dns
}

output "dashboard_url" {
  description = "Verdikt service URL. In real-mcp mode, use /mcp for MCP clients and /healthz for health checks."
  value       = "http://${aws_instance.app.public_dns}:${var.app_port}"
}

output "mcp_endpoint_url" {
  description = "Official MCP Streamable HTTP endpoint."
  value       = "http://${aws_instance.app.public_dns}:${var.app_port}/mcp"
}

output "ssm_connect_command" {
  description = "Session Manager command for shell access without SSH keys."
  value       = "aws ssm start-session --target ${aws_instance.app.id}"
}

output "http_bearer_token_secret_arn" {
  description = "Secrets Manager ARN storing the remote MCP bearer token."
  value       = aws_secretsmanager_secret.http_bearer_token.arn
}

output "approval_secret_arn" {
  description = "Secrets Manager ARN storing the approval-token HMAC secret."
  value       = aws_secretsmanager_secret.approval_secret.arn
}

output "audit_hmac_secret_arn" {
  description = "Secrets Manager ARN storing the audit-evidence HMAC secret."
  value       = aws_secretsmanager_secret.audit_hmac_secret.arn
}
