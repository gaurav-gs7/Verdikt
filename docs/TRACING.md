# AWS Tracing And Observability

Verdikt has two tracing stories:

1. Local/OpenInference tracing for AI tool-governance spans.
2. AWS-native tracing for deployed services.

## Local OpenInference Tracing

Enable console spans:

```bash
VERDIKT_TELEMETRY=console ./scripts/run_demo.sh
```

Enable OTLP:

```bash
export VERDIKT_TELEMETRY=otlp
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:6006/v1/traces
./scripts/run_real_mcp_http.sh
```

Important spans:

- `verdikt.call_tool`
- `verdikt.real_mcp.call_tool`
- `verdikt.policy.evaluate`
- `mcp.<tool_name>`
- `groq.incident_summary`

## AWS Serverless Tracing

Terraform enables Lambda active tracing:

```text
tracing_config {
  mode = "Active"
}
```

Both gateway and tool Lambdas can publish traces to AWS X-Ray through `AWSXRayDaemonWriteAccess`.

Use traces to answer:

- Did API Gateway reach the gateway Lambda?
- Did the gateway invoke the tool Lambda?
- Was latency caused by cold start, DynamoDB, Secrets Manager, or tool execution?
- Did policy deny the call before the tool ran?

## Metrics

Serverless custom metrics:

- `AllowedCalls`
- `BlockedCalls`
- `HighRiskAllowedCalls`
- `ToolCallLatencyMs`
- `CircuitBreakerOpen`

Local/EC2 Prometheus-style metrics:

```bash
curl -H "Authorization: Bearer $VERDIKT_HTTP_BEARER_TOKEN" http://<host>:8080/metrics
```

## Interview Framing

> I separated AI-aware tracing from cloud-native tracing. OpenInference spans explain tool-governance decisions, while AWS X-Ray and CloudWatch explain infrastructure latency and failures.
