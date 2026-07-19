# Production Enhancements

This document covers the higher-signal production features added on top of the free-tier GateTrace MCP path.

## OAuth 2.1 Resource Server And JWT Auth

The real MCP HTTP server supports two authentication modes:

- Static bearer token for simple demos.
- JWT validation for production-style identity.

For remote JWT mode, GateTrace MCP acts as the protected resource server. The authorization server or IdP owns user login, authorization code flow, PKCE, client registration, and consent. GateTrace MCP validates the resulting access token and advertises protected-resource metadata at `/.well-known/oauth-protected-resource`.

Local HS256 JWT mode:

```bash
export MCP_GUARD_JWT_HS256_SECRET="local-jwt-secret"
export MCP_GUARD_JWT_ISSUER="https://issuer.example.test"
export MCP_GUARD_RESOURCE_URI="http://127.0.0.1:8080/mcp"
export MCP_GUARD_JWT_AUDIENCE="http://127.0.0.1:8080/mcp"
export MCP_GUARD_AUTHORIZATION_SERVER="https://issuer.example.test"
export MCP_GUARD_REQUIRED_SCOPES="mcp:tools"
export MCP_GUARD_JWT_REQUIRED_GROUP="sre"
export MCP_GUARD_ADMIN_SCOPE="mcp:admin"
export MCP_GUARD_ADMIN_GROUP="mcp-admin"
./scripts/run_real_mcp_http.sh
```

OIDC/Cognito-style RS256 mode uses JWKS and the optional `auth` dependency:

```bash
export MCP_GUARD_JWT_JWKS_URL="https://cognito-idp.us-east-1.amazonaws.com/<pool-id>/.well-known/jwks.json"
export MCP_GUARD_JWT_ISSUER="https://cognito-idp.us-east-1.amazonaws.com/<pool-id>"
export MCP_GUARD_JWT_AUDIENCE="<resource-audience-issued-by-your-idp>"
export MCP_GUARD_RESOURCE_URI="https://guard.example.com/mcp"
export MCP_GUARD_AUTHORIZATION_SERVER="https://your-authorization-server.example.com"
export MCP_GUARD_REQUIRED_SCOPES="mcp:tools"
export MCP_GUARD_JWT_REQUIRED_GROUP="sre"
```

JWT mode fails startup unless issuer, audience, canonical resource URI, and authorization-server discovery are configured. Unauthorized responses advertise protected-resource metadata and required scopes. Requests that include an HTTP `Origin` header must match the canonical resource origin; set `MCP_GUARD_ALLOWED_ORIGINS` to a comma-separated allowlist when a separate browser application calls the MCP endpoint.

JWT identity is bound into policy evaluation. If a token subject is `readonly` and the tool arguments claim `actor=sre-oncall`, the call is denied with `identity_mismatch`. Fields such as `access_token`, `authorization`, and `upstream_token` are rejected recursively, so a caller token is never forwarded to an upstream service.

Static bearer mode remains useful for a single-user lab, but it is not presented as OAuth identity and cannot be enabled alongside JWT mode. Non-loopback binding fails at startup when neither mode is configured unless `MCP_GUARD_ALLOW_UNAUTHENTICATED_REMOTE=true` is explicitly set. Kill switches, direct approval administration, and audit runtime state require the `mcp:admin` scope or configured admin group for JWT callers.

## External MCP Servers And Credential Brokering

Set an upstream registry file:

```bash
export MCP_GUARD_UPSTREAM_CONFIG="$PWD/config/upstreams.example.json"
./scripts/run_mcp_gateway.sh
```

Each upstream command is started directly without a shell. Tool names must be globally unique, the complete definitions are scanned and pinned, and pins are rechecked before every call. Use `MCP_GUARD_TOOL_PIN_MODE=refresh` only during an intentional reviewed upgrade, then return to `enforce`.

Secret-looking environment values cannot be literals in the registry. Use either:

```json
{"UPSTREAM_TOKEN": {"from_env": "OPERATOR_MANAGED_TOKEN"}}
```

or:

```json
{"UPSTREAM_TOKEN": {"from_aws_secret": "gatetrace/upstreams/github", "json_key": "token"}}
```

Local source installs that use Secrets Manager or the S3 audit sink need the AWS profile:

```bash
python3 -m pip install -e '.[aws]'
```

The production container includes this profile. Lambda uses the AWS-managed `boto3` runtime dependency.

The official Streamable HTTP server exposes these configured servers through `guard.call_upstream`; the stdio gateway transparently advertises their original tools.

## Slack Human Approval

Configure a Slack app with interactivity enabled and set its request URL to:

```text
https://<gate-host>/integrations/slack/actions
```

Set:

```bash
export MCP_GUARD_SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export MCP_GUARD_SLACK_SIGNING_SECRET="..."
export MCP_GUARD_SLACK_APPROVER_IDS="U012345,U067890"
export MCP_GUARD_SLACK_MAX_PENDING_PER_REQUESTER=5
```

The agent calls `guard.request_approval`, an authorized engineer chooses Approve or Deny, and the original authenticated requester polls `guard.approval_status`. Callback signatures and timestamps are verified, identical pending requests are deduplicated, and the issued token remains bound to the exact server, tool, argument digest, requester, and expiry. Direct token issuance through the remote tool is disabled unless `MCP_GUARD_ALLOW_DIRECT_APPROVAL=true` is deliberately set.

## Tamper-Evident Audit Shipping

Local records form a SHA-256 chain. Set `MCP_GUARD_AUDIT_HMAC_SECRET` to add an independent HMAC signature and verify it through `/api/audit-integrity` or `guard.runtime_state`.

Ship redacted envelopes to JSONL:

```bash
export MCP_GUARD_AUDIT_SINK=jsonl
export MCP_GUARD_AUDIT_JSONL_PATH=/var/log/gatetrace/audit.jsonl
```

Or S3:

```bash
export MCP_GUARD_AUDIT_SINK=s3
export MCP_GUARD_AUDIT_S3_BUCKET=<audit-bucket>
export MCP_GUARD_AUDIT_S3_PREFIX=gatetrace-mcp/audit
export MCP_GUARD_AUDIT_SINK_STRICT=true
```

The serverless deployment stores individually HMAC-signed envelopes in DynamoDB and reports verification of recent events in `/state`. S3 Object Lock is not provisioned by this repository, so the S3 sink is centrally durable but not automatically immutable.

Interview angle:

> GateTrace MCP separates transport authentication from tool authorization. JWT proves caller identity at the HTTP boundary; policy-as-code still decides which actor can run each tool.

## Redis-Backed Distributed Rate Limits

Local mode uses an in-process limiter. Production mode can use Redis:

```bash
export MCP_GUARD_REDIS_URL="redis://localhost:6379/0"
export MCP_GUARD_REDIS_REQUIRED=true
```

The policy engine applies rate limits by tool, actor/tool, production environment/tool, and optional global budget. Redis makes those counters shared across replicas.

## Observability Stack

Run the local observability stack:

```bash
make observability-up
```

Services:

- GateTrace MCP: http://127.0.0.1:8080
- Prometheus: http://127.0.0.1:9090
- Grafana: http://127.0.0.1:3000, admin/admin
- Tempo: http://127.0.0.1:3200
- Jaeger UI: http://127.0.0.1:16686
- Redis: 127.0.0.1:6379

GateTrace MCP emits Prometheus metrics at `/metrics` and OTLP traces to Tempo by default in this stack. Jaeger is included as an alternate trace UI/collector for demos that prefer Jaeger.

## Helm Chart

Render the chart:

```bash
make helm-template
```

Install into a lab cluster:

```bash
helm upgrade --install mcp-guard ./charts/mcp-guard \
  --set image.repository=<your-image-repo> \
  --set image.tag=<tag> \
  --set auth.bearerToken=<token> \
  --set approvalSecret=<approval-secret>
```

Useful production values:

```bash
--set redis.url=redis://redis-master.default.svc.cluster.local:6379/0
--set telemetry.mode=otlp
--set telemetry.otlpEndpoint=http://tempo.default.svc.cluster.local:4318/v1/traces
--set serviceMonitor.enabled=true
```

Interview angle:

> The same real MCP server can run locally, on AWS EC2, or as a Kubernetes workload via Helm, with consistent policy, auth, metrics, tracing, and rate-limit behavior.
