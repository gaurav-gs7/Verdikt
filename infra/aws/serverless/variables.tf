variable "aws_region" {
  description = "AWS region for the serverless Verdikt deployment."
  type        = string
  default     = "us-east-1"
}

variable "app_name" {
  description = "Name prefix for all serverless resources."
  type        = string
  default     = "verdikt-serverless"
}

variable "lambda_zip_path" {
  description = "Path to the packaged Lambda artifact produced by scripts/aws/package_serverless.sh."
  type        = string
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
