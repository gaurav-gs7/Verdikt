output "api_base_url" {
  description = "API Gateway HTTP API base URL."
  value       = aws_apigatewayv2_api.http.api_endpoint
}

output "health_check_command" {
  description = "Authenticated health check command."
  value       = "curl -s -H 'Authorization: Bearer <token>' ${aws_apigatewayv2_api.http.api_endpoint}/healthz"
}

output "gateway_lambda_name" {
  description = "Gateway Lambda function name."
  value       = aws_lambda_function.gateway.function_name
}

output "tool_lambda_name" {
  description = "Mock tool Lambda function name."
  value       = aws_lambda_function.tool.function_name
}

output "state_table_name" {
  description = "DynamoDB table for policies, approvals, rate limits, kill switches, and circuit breakers."
  value       = aws_dynamodb_table.state.name
}

output "audit_table_name" {
  description = "DynamoDB audit events table."
  value       = aws_dynamodb_table.audit.name
}

output "event_bus_name" {
  description = "EventBridge bus for remediation findings."
  value       = aws_cloudwatch_event_bus.bus.name
}

output "findings_queue_url" {
  description = "SQS queue receiving EventBridge remediation findings."
  value       = aws_sqs_queue.findings.url
}

output "cloudwatch_dashboard_name" {
  description = "CloudWatch dashboard for Judikt serverless operations."
  value       = aws_cloudwatch_dashboard.ops.dashboard_name
}

output "api_token_secret_arn" {
  description = "Secrets Manager ARN storing the API bearer token."
  value       = aws_secretsmanager_secret.api_token.arn
}

output "approval_secret_arn" {
  description = "Secrets Manager ARN storing the approval-token HMAC secret."
  value       = aws_secretsmanager_secret.approval_secret.arn
}

output "audit_hmac_secret_arn" {
  description = "Secrets Manager ARN storing the independent audit HMAC secret."
  value       = aws_secretsmanager_secret.audit_hmac_secret.arn
}
