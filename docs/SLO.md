# Verdikt SLOs

These SLOs frame Verdikt as an AI operations control plane. They are intentionally practical for a free-tier demo, but written the way a production service would be reviewed.

## Service Boundaries

User-facing paths:

- Real MCP server on EC2/Docker: `/mcp`, `/healthz`, `/metrics`
- Serverless control plane: API Gateway routes `/call`, `/approval`, `/healthz`, `/tools`, `/events`, `/state`

Critical dependency paths:

- Policy evaluation
- Approval-token verification
- Audit write
- Tool adapter call
- Metrics/tracing emission

## Availability SLO

Target:

```text
99.5% monthly availability for guarded tool-call API paths
```

Good events:

- `/healthz` returns HTTP 200.
- MCP tool call returns a structured allowed/blocked response.
- Serverless `/call` returns HTTP 200 or HTTP 403 with a policy decision.

Bad events:

- 5xx response from gateway.
- timeout before a policy decision is returned.
- failed audit write on an allowed destructive action.

## Latency SLO

Target:

```text
95% of guarded read-only tool calls complete under 750 ms locally/EC2.
95% of serverless guarded tool calls complete under 1500 ms.
```

Reasoning:

- Policy checks should be fast and deterministic.
- Serverless cold starts are tolerated for a free-tier demo, but should be visible in CloudWatch.

## Safety SLO

Target:

```text
100% of destructive actions require signed approval.
100% of audit records redact configured secret patterns.
0 known bypasses in adversarial evals.
```

Measured by:

- `./scripts/run_evals.sh`
- `./scripts/run_failure_tests.sh`
- unit tests around approval binding, redaction, kill switches, and circuit breakers

## Error Budget Policy

If the availability error budget burns faster than 25% in a day:

- freeze new write-capable tool exposure
- inspect CloudWatch/Lambda errors or EC2 container logs
- run failure tests locally
- verify recent policy changes

If any safety SLO fails:

- disable affected tool through kill switch
- rotate approval secret
- preserve audit evidence
- open an incident
- do not re-enable until a test/eval reproduces the fix
