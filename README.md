# GateTrace MCP

GateTrace MCP is a deterministic security and reliability control plane for Model Context Protocol (MCP) tool execution. It governs the request before an external tool runs, inspects the untrusted result before it reaches an agent, and produces tamper-evident operational evidence for both decisions.

The core demo runs on an 8 GB laptop with Python only, no local model, and no API key. Optional profiles add the official MCP SDK, Redis, OpenTelemetry/OpenInference, Docker observability, AWS deployment, and a Groq incident summary. No LLM participates in an allow or deny decision.

## Why This Project

An MCP server can expose operationally powerful tools to an AI agent. The interesting production question is not whether the agent can call a tool. It is whether the platform can constrain, observe, disable, and explain those calls under pressure.

GateTrace MCP demonstrates:

- MCP gateway proxying over JSON-RPC stdio
- Official MCP SDK Streamable HTTP server for production-facing clients
- Operator-configured proxying to independently built stdio MCP servers
- Versioned interoperability harness for official Filesystem, Memory, and GitHub MCP servers
- Minimal subprocess environments that expose only explicitly brokered upstream credentials
- Recursive tool-description and JSON Schema inspection before trust
- SHA-256 tool-definition pinning and fail-closed rug-pull detection
- Deterministic direct and indirect prompt-injection inspection
- Quarantine envelopes that do not return malicious text to the agent
- Policy-as-code allowlists and blocked argument patterns
- JWT/OIDC resource-server authentication with issuer, audience, group, and scope validation
- Authenticated-subject binding that rejects caller actor spoofing
- OAuth protected-resource metadata and caller-token passthrough denial
- Scoped OAuth challenges and exact HTTP Origin validation
- HMAC-signed approval tokens for restart and rollback operations
- Slack button approvals with signed callbacks, approver allowlists, deduplication, and replay protection
- Rollback-plan enforcement before production-impacting actions execute
- Dry-run-only and shadow-mode outcomes for safe agent evaluation
- Deterministic risk scoring for production actions
- Secret redaction for audit logs and agent-visible responses
- Per-tool rate limits and immediate kill switches
- Optional Redis-backed distributed rate limits for multi-replica deployments
- Circuit breakers for repeated upstream tool failures
- Hash-chained and optionally HMAC-signed local audit evidence
- JSONL or S3 audit shipping plus individually signed DynamoDB serverless events
- Correlation IDs, Prometheus metrics, OpenInference/OpenTelemetry traces, and AWS X-Ray
- Docker Compose observability stack with Prometheus, Grafana, Tempo, Jaeger, and Redis
- Helm chart for Kubernetes deployment
- Optional Groq incident analysis with an offline fallback
- Optional OpenInference-compatible traces exported through OpenTelemetry
- MCP-38 coverage matrix and adversarial policy regression suite
- AWS Secrets Manager, X-Ray tracing, IAM review, SLOs, runbooks, and failure-mode tests

## Architecture

```mermaid
flowchart LR
    Agent["AI agent or MCP client"] --> Auth["OAuth/JWT authentication"]
    Auth --> Request["Identity + allowlist + risk + rate + approval"]
    Request -->|"deny"| Evidence["Signed audit + metrics + trace"]
    Request -->|"allow"| Integrity["Pinned tool metadata check"]
    Integrity --> Upstream["Built-in or external MCP server"]
    Upstream --> Inspect["Result injection scan"]
    Inspect -->|"quarantine"| Evidence
    Inspect -->|"safe"| Redact["Recursive redaction"]
    Redact --> Agent
    Redact --> Evidence
    Evidence --> Sink["SQLite/JSONL/S3 or DynamoDB/CloudWatch"]
```

The upstream tool servers are separate subprocesses:

- `platform-ops`: production service health, sanitized config, logs, allowlisted diagnostics, rolling restart, and deployment rollback.
- `kubernetes`: pod status, guarded pod restart, and rollout status. It uses a safe simulator by default and can be pointed at `kubectl` with `MCP_GUARD_KUBERNETES_MODE=kubectl` for a controlled lab.
- `incident`: create incidents, attach correlated evidence, and read timelines.

## Quick Start

Requirements: macOS or Linux and Python 3.11+.

The launch scripts automatically use `.venv/bin/python` when a project virtual environment exists. Otherwise, they use the system `python3`.

To use an isolated audit database for a run:

```bash
./scripts/run_demo.sh --audit-db /tmp/mcp-guard-demo.db
```

```bash
./scripts/run_demo.sh
```

Common developer commands:

```bash
make test
make demo
make eval
make failure-test
make interop-community
make trace
make observability-up
make helm-template
```

Start the dashboard:

```bash
./scripts/run_dashboard.sh
```

Then open [http://127.0.0.1:8080](http://127.0.0.1:8080). The page includes buttons for allowed calls, blocked calls, an approved rollback drill, secret redaction, and kill-switch testing.

Loopback is the only unauthenticated mode. Binding to any other interface fails
closed unless `MCP_GUARD_API_TOKEN` is set. The browser asks for the token once
and keeps it in session storage.

To expose GateTrace MCP itself as a stdio MCP server:

```bash
./scripts/run_mcp_gateway.sh
```

For an MCP client configuration, use:

```json
{
  "mcpServers": {
    "gatetrace-mcp": {
      "command": "/absolute/path/to/MCP-Guard/scripts/run_mcp_gateway.sh"
    }
  }
}
```

### External MCP Servers

Set `MCP_GUARD_UPSTREAM_CONFIG` to a JSON file using the shape in [`config/upstreams.example.json`](config/upstreams.example.json). Commands are executed directly without a shell. Sensitive upstream credentials should use `from_env` or `from_aws_secret`; caller-supplied OAuth tokens are denied recursively by policy.

The test suite launches [`tests/fixtures/external_mcp_server.py`](tests/fixtures/external_mcp_server.py) as an independent process and proves normal and text-only responses, paginated discovery, server-initiated requests, environment isolation, injected-result quarantine, and changed metadata blocking. The versioned [community interoperability harness](docs/COMMUNITY_INTEROP.md) separately targets the official MCP Filesystem and Memory servers plus GitHub's official read-only server.

## Optional Groq Integration

The demo produces a deterministic local incident summary by default. To add a hosted LLM summary:

```bash
export GROQ_API_KEY="your-key"
export GROQ_MODEL="openai/gpt-oss-20b"
./scripts/run_demo.sh
```

The gateway keeps working if Groq is unavailable. Policy evaluation never depends on the model.

## Dashboard API

| Endpoint | Purpose |
| --- | --- |
| `GET /healthz` | Readiness check |
| `GET /api/tools` | List upstream MCP tools |
| `GET /api/events` | Read recent correlated audit events |
| `GET /api/kill-switches` | Read disabled tools and servers |
| `GET /api/telemetry` | Read OpenInference tracing mode and OTLP endpoint |
| `GET /api/audit-integrity` | Verify the local audit hash chain and signatures |
| `GET /metrics` | Prometheus-style counters |
| `POST /api/call` | Invoke a guarded tool |
| `POST /api/approval` | Issue a short-lived approval token |
| `POST /api/kill-switch` | Enable or disable a tool or server |
| `POST /api/analyze` | Summarize recent audit evidence |

Example:

```bash
curl -s http://127.0.0.1:8080/api/call \
  -H 'Content-Type: application/json' \
  -d '{"server":"platform-ops","tool":"platform.health","arguments":{"service":"payments-api"}}'
```

Issue a signed approval token for a rollback:

```bash
TOKEN=$(./scripts/python.sh -m mcp_guard.cli issue-approval \
  --actor gaurav \
  --reason "rollback after elevated 5xx rate" \
  --server platform-ops \
  --tool platform.rollback_deployment \
  --arguments '{"service":"payments-api","version":"payments-api@2026.05.2","actor":"gaurav","rollback_plan":"verify service health and restore previous release if errors increase"}')

curl -s http://127.0.0.1:8080/api/call \
  -H 'Content-Type: application/json' \
  -d "{\"server\":\"platform-ops\",\"tool\":\"platform.rollback_deployment\",\"arguments\":{\"service\":\"payments-api\",\"version\":\"payments-api@2026.05.2\",\"actor\":\"gaurav\",\"rollback_plan\":\"verify service health and restore previous release if errors increase\",\"approval_token\":\"$TOKEN\"}}"
```

## Test

```bash
PYTHONPATH=src ./scripts/python.sh -m unittest discover -s tests -v
```

The suite exercises the actual subprocess MCP boundary as well as allow, deny, redaction, approval, kill-switch, circuit-breaker, audit, and fallback-analysis behavior.

Run the adversarial eval harness:

```bash
./scripts/run_evals.sh
```

The evals cover unsafe diagnostics, direct prompt injection, token passthrough, unapproved destructive actions, unknown tools, safe diagnostics, health checks, and audit redaction. The report also validates all 38 entries in [`config/mcp38_coverage.json`](config/mcp38_coverage.json): currently 12 covered, 21 partial, and 5 explicitly not covered under the definition stored in that file.

Run the failure-mode harness:

```bash
./scripts/run_failure_tests.sh
```

It validates approval gates, kill switches, circuit breakers, redaction, and rate limits.

## Docker

Build and run the production-facing real MCP container:

```bash
make docker-build
docker run --rm -p 8080:8080 \
  -e MCP_GUARD_HTTP_BEARER_TOKEN="local-dev-token" \
  gatetrace-mcp:local
```

The container binds to `0.0.0.0`, so startup fails closed unless bearer/JWT auth is configured or `MCP_GUARD_ALLOW_UNAUTHENTICATED_REMOTE=true` is explicitly set for an isolated lab.

The container defaults to the official MCP Streamable HTTP server:

```text
GET  /healthz
GET  /metrics
POST /mcp
GET  /mcp
```

Use a bearer token for remote demos:

```bash
docker run --rm -p 8080:8080 \
  -e MCP_GUARD_HTTP_BEARER_TOKEN="$(openssl rand -hex 24)" \
  gatetrace-mcp:local
```

To run the dashboard container instead:

```bash
docker run --rm -p 8080:8080 \
  -e MCP_GUARD_MODE=dashboard \
  -e MCP_GUARD_API_TOKEN="$(openssl rand -hex 24)" \
  gatetrace-mcp:local
```

Dashboard API clients must send `Authorization: Bearer $MCP_GUARD_API_TOKEN`.
The health endpoint and dashboard page remain unauthenticated; dashboard APIs
and `/metrics` are protected.

## Real MCP Server

GateTrace MCP now includes an official MCP SDK server using Streamable HTTP. It exposes production-operations tools through the same policy, risk, approval, redaction, audit, metrics, kill-switch, rate-limit, and circuit-breaker controls used by the rest of the project.

Run locally:

```bash
export MCP_GUARD_HTTP_BEARER_TOKEN="local-dev-token"
./scripts/run_real_mcp_http.sh --host 127.0.0.1 --port 8080
```

MCP endpoint:

```text
http://127.0.0.1:8080/mcp
```

Production-style tools exposed by the MCP server:

- `platform.health`
- `platform.read_config`
- `platform.read_logs`
- `platform.run_diagnostic`
- `platform.restart_deployment`
- `platform.rollback_deployment`
- `kubernetes.get_pod`
- `kubernetes.restart_pod`
- `kubernetes.rollout_status`
- `incident.create`
- `incident.attach_evidence`
- `incident.timeline`
- `guard.issue_approval`
- `guard.request_approval`
- `guard.approval_status`
- `guard.call_upstream`
- `guard.set_tool_enabled`
- `guard.set_server_enabled`
- `guard.runtime_state`

## AWS Free-Tier Deployment

The primary complete AWS path is Terraform-managed EC2 running the official Streamable HTTP MCP container, with ECR, IAM, Secrets Manager, CloudWatch, X-Ray, SSM Session Manager, and encrypted EBS. The Lambda/API Gateway/DynamoDB/EventBridge/SQS stack is a separate serverless control-plane lab; it exercises stronger AWS serverless skills but exposes an HTTP tool API rather than claiming to be the official MCP transport.

Start with [docs/AWS_FREE_TIER_DEPLOY.md](docs/AWS_FREE_TIER_DEPLOY.md), then use [docs/AWS_AIOPS_SKILLS.md](docs/AWS_AIOPS_SKILLS.md) to turn the work into an AIOps/LLMOps learning roadmap.

For JWT auth, Redis-backed rate limits, Grafana/Tempo/Jaeger, and Helm usage, see [docs/PRODUCTION_ENHANCEMENTS.md](docs/PRODUCTION_ENHANCEMENTS.md).

Recommended serverless command shape:

```bash
export AWS_REGION=us-east-1
export MCP_GUARD_API_TOKEN="$(openssl rand -hex 24)"
export MCP_GUARD_APPROVAL_SECRET="$(openssl rand -hex 32)"
./scripts/aws/deploy_serverless.sh
```

Destroy the serverless deployment after demos:

```bash
./scripts/aws/destroy_serverless.sh
```

EC2 Terraform command shape:

```bash
export AWS_REGION=us-east-1
export MCP_GUARD_ALLOWED_CIDR="$(curl -s https://checkip.amazonaws.com)/32"
export MCP_GUARD_HTTP_BEARER_TOKEN="$(openssl rand -hex 24)"
export MCP_GUARD_APPROVAL_SECRET="$(openssl rand -hex 32)"
./scripts/aws/deploy_terraform.sh
```

Destroy the Terraform deployment after demos:

```bash
./scripts/aws/destroy_terraform.sh
```

CloudFormation fallback:

```bash
export AWS_REGION=us-east-1
IMAGE_URI=$(./scripts/aws/build_push_ecr.sh)
./scripts/aws/deploy_ec2.sh "$IMAGE_URI"
```

Delete the CloudFormation stack after demos:

```bash
./scripts/aws/delete_stack.sh
```

## Optional OpenInference Tracing

The default demo has no third-party runtime dependencies. For AI-aware distributed traces, install the observability profile:

```bash
python3 -m pip install -e '.[observability]'
```

Print OpenInference-compatible spans to the terminal:

```bash
MCP_GUARD_TELEMETRY=console ./scripts/run_demo.sh
```

Export spans over OTLP HTTP to a local Phoenix instance or another OTLP-compatible backend:

```bash
export MCP_GUARD_TELEMETRY=otlp
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:6006/v1/traces
./scripts/run_dashboard.sh
```

The trace hierarchy is intentionally security-aware:

```text
mcp_guard.call_tool                 CHAIN
  mcp_guard.policy.evaluate         GUARDRAIL
  mcp.platform.health               TOOL       # only created for forwarded calls
groq.incident_summary               LLM        # only created when Groq is called
```

Arguments and outputs are redacted before they are attached to spans. The upstream MCP subprocess protocol is implemented locally for this lightweight demo, so `openinference-instrumentation-mcp` auto-instrumentation is not used. If the transport is migrated to the official MCP Python SDK, that package can be added for cross-process context propagation.

## Threat Model

Implemented and tested controls directly address:

- Agent attempts to access sensitive local paths such as `.ssh`, `.aws`, and `.env`.
- Agent attempts to run unsafe network commands in diagnostic arguments.
- Direct prompt injection embedded in tool arguments.
- Indirect prompt injection embedded in an external MCP tool result.
- Poisoned tool descriptions, nested schema fields, exact-name shadowing, and rug pulls.
- Caller token passthrough and authenticated actor spoofing.
- Unauthorized restart or rollback actions.
- Secret leakage from upstream tool responses or recorded arguments.
- Repeated high-volume calls to expensive or destructive tools.
- Fast containment of a compromised tool or MCP server.
- Audit-record mutation and loss of local-only evidence through optional central shipping.

Explicit gaps remain: GateTrace MCP is an OAuth resource server, not an authorization server; PKCE and per-client consent belong in the chosen IdP/client flow. It does not yet provide multi-tenant isolation, semantic DLP for privacy inference, complete Host-header and deployment-edge DNS-rebinding defenses beyond Origin validation, cryptographically signed policy bundles, OS-level upstream sandboxes, or complete MCP resource/prompt proxying. The coverage matrix treats these as partial or not covered rather than presenting the project as universally production complete.

## Design Notes

The short design write-up is in [docs/DESIGN_NOTES.md](docs/DESIGN_NOTES.md), the production roadmap is in [docs/ROADMAP.md](docs/ROADMAP.md), the AWS learning plan is in [docs/AWS_AIOPS_SKILLS.md](docs/AWS_AIOPS_SKILLS.md), and the production operations docs are in [docs/SLO.md](docs/SLO.md), [docs/RUNBOOKS.md](docs/RUNBOOKS.md), [docs/IAM_REVIEW.md](docs/IAM_REVIEW.md), [docs/TRACING.md](docs/TRACING.md), [docs/FAILURE_TESTING.md](docs/FAILURE_TESTING.md), [docs/CICD.md](docs/CICD.md), [docs/COMMUNITY_INTEROP.md](docs/COMMUNITY_INTEROP.md), and [docs/PRODUCTION_ENHANCEMENTS.md](docs/PRODUCTION_ENHANCEMENTS.md).

## License

This project is licensed under the Apache License 2.0. In brief, you may use, modify, distribute, and sublicense the code, including in commercial projects, as long as you preserve copyright and license notices. The license also includes an express patent grant and is provided without warranties.

See [LICENSE](LICENSE) for the full terms and [SECURITY.md](SECURITY.md) for the
supported deployment boundary and vulnerability reporting guidance.
