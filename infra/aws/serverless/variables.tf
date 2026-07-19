variable "aws_region" {
  description = "AWS region for the serverless GateTrace MCP deployment."
  type        = string
  default     = "us-east-1"
}

variable "app_name" {
  description = "Name prefix for all serverless resources."
  type        = string
  default     = "gatetrace-serverless"
}

variable "lambda_zip_path" {
  description = "Path to the packaged Lambda artifact produced by scripts/aws/package_serverless.sh."
  type        = string
}

variable "api_token" {
  description = "Bearer token required by API Gateway callers. Replace this for real deployments."
  type        = string
  default     = "local-demo-token-change-me"
  sensitive   = true
}

variable "approval_secret" {
  description = "HMAC secret for signed approval tokens. Use Secrets Manager for stricter production."
  type        = string
  default     = "local-dev-approval-secret-change-me"
  sensitive   = true
}

variable "lambda_runtime" {
  description = "Python runtime for the gateway and tool Lambdas."
  type        = string
  default     = "python3.11"
}

variable "log_retention_days" {
  description = "CloudWatch log retention for Lambda log groups."
  type        = number
  default     = 7
}

variable "gateway_reserved_concurrency" {
  description = "Small concurrency cap to keep free-tier demos controlled."
  type        = number
  default     = 5
}

variable "tool_reserved_concurrency" {
  description = "Small concurrency cap for the mock tool Lambda."
  type        = number
  default     = 5
}

variable "audit_retention_days" {
  description = "DynamoDB TTL retention for audit events."
  type        = number
  default     = 14
}
