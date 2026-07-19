provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.common_tags
  }
}

data "aws_caller_identity" "current" {}

locals {
  common_tags = {
    Project     = "GateTrace MCP"
    ManagedBy   = "Terraform"
    Environment = "serverless-demo"
  }

  gateway_function_name = "${var.app_name}-gateway"
  tool_function_name    = "${var.app_name}-mock-tool"
  metric_namespace      = "GateTrace/Serverless"
}

resource "aws_dynamodb_table" "state" {
  name         = "${var.app_name}-state"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }
}

resource "aws_dynamodb_table" "audit" {
  name         = "${var.app_name}-audit"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "correlation_id"
  range_key    = "event_id"

  attribute {
    name = "correlation_id"
    type = "S"
  }

  attribute {
    name = "event_id"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }
}

resource "aws_dynamodb_table_item" "default_policy" {
  table_name = aws_dynamodb_table.state.name
  hash_key   = aws_dynamodb_table.state.hash_key
  range_key  = aws_dynamodb_table.state.range_key

  item = jsonencode({
    pk = {
      S = "POLICY"
    }
    sk = {
      S = "default"
    }
    document = {
      S = file("${path.module}/../../../config/policies.yaml")
    }
  })
}

resource "aws_secretsmanager_secret" "api_token" {
  name                    = "${var.app_name}/api-token"
  description             = "Bearer token for GateTrace MCP serverless API callers."
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret" "approval_secret" {
  name                    = "${var.app_name}/approval-secret"
  description             = "HMAC secret for GateTrace MCP signed approval tokens."
  recovery_window_in_days = 0
}

resource "aws_sqs_queue" "findings_dlq" {
  name                      = "${var.app_name}-findings-dlq"
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue" "findings" {
  name                       = "${var.app_name}-findings"
  visibility_timeout_seconds = 60
  message_retention_seconds  = 345600

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.findings_dlq.arn
    maxReceiveCount     = 3
  })
}

resource "aws_cloudwatch_event_bus" "bus" {
  name = "${var.app_name}-bus"
}

resource "aws_cloudwatch_event_rule" "remediation_findings" {
  name           = "${var.app_name}-remediation-findings"
  event_bus_name = aws_cloudwatch_event_bus.bus.name

  event_pattern = jsonencode({
    source        = ["gatetrace.mcp"]
    "detail-type" = ["RemediationFinding"]
  })
}

resource "aws_cloudwatch_event_target" "findings_queue" {
  rule           = aws_cloudwatch_event_rule.remediation_findings.name
  event_bus_name = aws_cloudwatch_event_bus.bus.name
  target_id      = "gatetrace-findings"
  arn            = aws_sqs_queue.findings.arn
}

resource "aws_sqs_queue_policy" "allow_eventbridge" {
  queue_url = aws_sqs_queue.findings.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.findings.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.remediation_findings.arn
          }
        }
      }
    ]
  })
}

resource "aws_iam_role" "gateway_lambda" {
  name = "${var.app_name}-gateway-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role" "tool_lambda" {
  name = "${var.app_name}-tool-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "gateway_basic" {
  role       = aws_iam_role.gateway_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "tool_basic" {
  role       = aws_iam_role.tool_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "gateway_xray" {
  role       = aws_iam_role.gateway_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_iam_role_policy_attachment" "tool_xray" {
  role       = aws_iam_role.tool_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_iam_role_policy" "gateway_runtime" {
  name = "gateway-runtime"
  role = aws_iam_role.gateway_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = aws_lambda_function.tool.arn
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:UpdateItem"
        ]
        Resource = [
          aws_dynamodb_table.state.arn,
          aws_dynamodb_table.audit.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "events:PutEvents"
        ]
        Resource = aws_cloudwatch_event_bus.bus.arn
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = local.metric_namespace
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          aws_secretsmanager_secret.api_token.arn,
          aws_secretsmanager_secret.approval_secret.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "tool_runtime" {
  name = "tool-runtime"
  role = aws_iam_role.tool_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ]
        Resource = aws_dynamodb_table.state.arn
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "gateway" {
  name              = "/aws/lambda/${local.gateway_function_name}"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "tool" {
  name              = "/aws/lambda/${local.tool_function_name}"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "tool" {
  function_name                  = local.tool_function_name
  role                           = aws_iam_role.tool_lambda.arn
  handler                        = "mcp_guard.serverless.tool_handler"
  runtime                        = var.lambda_runtime
  filename                       = var.lambda_zip_path
  source_code_hash               = filebase64sha256(var.lambda_zip_path)
  timeout                        = 10
  memory_size                    = 256
  reserved_concurrent_executions = var.tool_reserved_concurrency

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      AWS_XRAY_CONTEXT_MISSING = "LOG_ERROR"
      STATE_TABLE_NAME         = aws_dynamodb_table.state.name
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.tool,
    aws_iam_role_policy_attachment.tool_basic,
    aws_iam_role_policy_attachment.tool_xray,
    aws_iam_role_policy.tool_runtime
  ]
}

resource "aws_lambda_function" "gateway" {
  function_name                  = local.gateway_function_name
  role                           = aws_iam_role.gateway_lambda.arn
  handler                        = "mcp_guard.serverless.gateway_handler"
  runtime                        = var.lambda_runtime
  filename                       = var.lambda_zip_path
  source_code_hash               = filebase64sha256(var.lambda_zip_path)
  timeout                        = 15
  memory_size                    = 256
  reserved_concurrent_executions = var.gateway_reserved_concurrency

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      AUDIT_TABLE_NAME               = aws_dynamodb_table.audit.name
      AWS_XRAY_CONTEXT_MISSING       = "LOG_ERROR"
      EVENT_BUS_NAME                 = aws_cloudwatch_event_bus.bus.name
      MCP_GUARD_API_TOKEN_SECRET_ARN = aws_secretsmanager_secret.api_token.arn
      MCP_GUARD_APPROVAL_SECRET_ARN  = aws_secretsmanager_secret.approval_secret.arn
      STATE_TABLE_NAME               = aws_dynamodb_table.state.name
      TOOL_FUNCTION_NAME             = aws_lambda_function.tool.function_name
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.gateway,
    aws_dynamodb_table_item.default_policy,
    aws_iam_role_policy_attachment.gateway_basic,
    aws_iam_role_policy_attachment.gateway_xray,
    aws_iam_role_policy.gateway_runtime
  ]
}

resource "aws_apigatewayv2_api" "http" {
  name          = "${var.app_name}-http-api"
  protocol_type = "HTTP"

  cors_configuration {
    allow_headers = ["authorization", "content-type"]
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_origins = ["*"]
    max_age       = 300
  }
}

resource "aws_apigatewayv2_integration" "gateway" {
  api_id                 = aws_apigatewayv2_api.http.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.gateway.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "default" {
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.gateway.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.http.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_burst_limit = 10
    throttling_rate_limit  = 5
  }
}

resource "aws_lambda_permission" "allow_apigw" {
  statement_id  = "AllowExecutionFromHttpApi"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.gateway.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http.execution_arn}/*/*"
}

resource "aws_cloudwatch_metric_alarm" "blocked_calls" {
  alarm_name          = "${var.app_name}-blocked-calls"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "BlockedCalls"
  namespace           = local.metric_namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "high_risk_allowed" {
  alarm_name          = "${var.app_name}-high-risk-allowed"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "HighRiskAllowedCalls"
  namespace           = local.metric_namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_dashboard" "ops" {
  dashboard_name = "${var.app_name}-ops"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title   = "GateTrace MCP Decisions"
          region  = var.aws_region
          view    = "timeSeries"
          stacked = false
          metrics = [
            [local.metric_namespace, "AllowedCalls"],
            [".", "BlockedCalls"],
            [".", "HighRiskAllowedCalls"]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Gateway and Tool Lambda Errors"
          region = var.aws_region
          view   = "timeSeries"
          metrics = [
            ["AWS/Lambda", "Errors", "FunctionName", aws_lambda_function.gateway.function_name],
            [".", ".", ".", aws_lambda_function.tool.function_name]
          ]
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 6
        width  = 24
        height = 6
        properties = {
          title  = "Recent Gateway Logs"
          region = var.aws_region
          query  = "SOURCE '${aws_cloudwatch_log_group.gateway.name}' | fields @timestamp, @message | sort @timestamp desc | limit 50"
          view   = "table"
        }
      }
    ]
  })
}
