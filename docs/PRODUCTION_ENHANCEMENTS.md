# Production Enhancements

This document covers the higher-signal production features added on top of the free-tier Verdikt path.

## OAuth 2.1 Resource Server And JWT Auth

The real MCP HTTP server supports two authentication modes:

- Static bearer token for simple demos.
- JWT validation for production-style identity.

For remote JWT mode, Verdikt acts as the protected resource server. The authorization server or IdP owns user login, authorization code flow, PKCE, client registration, and consent. Verdikt validates the resulting access token and advertises protected-resource metadata at `/.well-known/oauth-protected-resource`.

Local HS256 JWT mode:

```bash
export VERDIKT_JWT_HS256_SECRET="local-jwt-secret"
export VERDIKT_JWT_ISSUER="https://issuer.example.test"
export VERDIKT_RESOURCE_URI="http://127.0.0.1:8080/mcp"
export VERDIKT_JWT_AUDIENCE="http://127.0.0.1:8080/mcp"
export VERDIKT_AUTHORIZATION_SERVER="https://issuer.example.test"
export VERDIKT_REQUIRED_SCOPES="mcp:tools"
export VERDIKT_JWT_REQUIRED_GROUP="sre"
export VERDIKT_ADMIN_SCOPE="mcp:admin"
export VERDIKT_ADMIN_GROUP="mcp-admin"
./scripts/run_real_mcp_http.sh
```

OIDC/Cognito-style RS256 mode uses JWKS and the optional `auth` dependency:

```bash
export VERDIKT_JWT_JWKS_URL="https://cognito-idp.us-east-1.amazonaws.com/<pool-id>/.well-known/jwks.json"
export VERDIKT_JWT_ISSUER="https://cognito-idp.us-east-1.amazonaws.com/<pool-id>"
export VERDIKT_JWT_AUDIENCE="<resource-audience-issued-by-your-idp>"
export VERDIKT_RESOURCE_URI="https://verdikt.example.com/mcp"
export VERDIKT_AUTHORIZATION_SERVER="https://your-authorization-server.example.com"
export VERDIKT_REQUIRED_SCOPES="mcp:tools"
export VERDIKT_JWT_REQUIRED_GROUP="sre"
```

JWT mode fails startup unless issuer, audience, canonical resource URI, and authorization-server discovery are configured. Unauthorized responses advertise protected-resource metadata and required scopes. Requests that include an HTTP `Origin` header must match the canonical resource origin; set `VERDIKT_ALLOWED_ORIGINS` to a comma-separated allowlist when a separate browser application calls the MCP endpoint.

JWT identity is bound into policy evaluation. If a token subject is `readonly` and the tool arguments claim `actor=sre-oncall`, the call is denied with `identity_mismatch`. Fields such as `access_token`, `authorization`, and `upstream_token` are rejected recursively, so a caller token is never forwarded to an upstream service.

Static bearer mode remains useful for a single-user lab, but it is not presented as OAuth identity and cannot be enabled alongside JWT mode. Non-loopback binding fails at startup when neither mode is configured unless `VERDIKT_ALLOW_UNAUTHENTICATED_REMOTE=true` is explicitly set. Kill switches, direct approval administration, and audit runtime state require the `mcp:admin` scope or configured admin group for JWT callers.

## External MCP Servers And Credential Brokering

Set an upstream registry file:

```bash
export VERDIKT_UPSTREAM_CONFIG="$PWD/config/upstreams.example.json"
./scripts/run_mcp_gateway.sh
```

Each upstream command is started directly without a shell. Tool names must be globally unique, the complete definitions are scanned and pinned, and pins are rechecked before every call. Use `VERDIKT_TOOL_PIN_MODE=refresh` only during an intentional reviewed upgrade, then return to `enforce`.

Secret-looking environment values cannot be literals in the registry. Use either:

```json
{"UPSTREAM_TOKEN": {"from_env": "OPERATOR_MANAGED_TOKEN"}}
```

or:

```json
{"UPSTREAM_TOKEN": {"from_aws_secret": "verdikt/upstreams/github", "json_key": "token"}}
```

Local source installs that use Secrets Manager or the S3 audit sink need the AWS profile:

```bash
python3 -m pip install -e '.[aws]'
```

The production container includes this profile. Lambda uses the AWS-managed `boto3` runtime dependency.

The official Streamable HTTP server exposes these configured servers through `verdikt.call_upstream`; the stdio gateway transparently advertises their original tools.

## Slack Human Approval

Configure a Slack app with interactivity enabled and set its request URL to:

```text
https://<gate-host>/integrations/slack/actions
```

Set:

```bash
export VERDIKT_SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export VERDIKT_SLACK_SIGNING_SECRET="..."
export VERDIKT_SLACK_APPROVER_IDS="U012345,U067890"
export VERDIKT_SLACK_MAX_PENDING_PER_REQUESTER=5
```

The agent calls `verdikt.request_approval`, an authorized engineer chooses Approve or Deny, and the original authenticated requester polls `verdikt.approval_status`. Callback signatures and timestamps are verified, identical pending requests are deduplicated, and the issued token remains bound to the exact server, tool, argument digest, requester, and expiry. Direct token issuance through the remote tool is disabled unless `VERDIKT_ALLOW_DIRECT_APPROVAL=true` is deliberately set.

## Tamper-Evident Audit Shipping

Local records form a SHA-256 chain. Set `VERDIKT_AUDIT_HMAC_SECRET` to add an independent HMAC signature and verify it through `/api/audit-integrity` or `verdikt.runtime_state`.

Production startup can require that key and verify all existing records before accepting traffic:

```bash
export VERDIKT_AUDIT_HMAC_SECRET="$(openssl rand -hex 32)"
export VERDIKT_AUDIT_SIGNATURE_REQUIRED=true
export VERDIKT_AUDIT_VERIFY_ON_STARTUP=true
```

Missing signing material or a changed historical row then fails startup. The report distinguishes legacy unsigned events from sealed events.

Ship redacted envelopes to JSONL:

```bash
export VERDIKT_AUDIT_SINK=jsonl
export VERDIKT_AUDIT_JSONL_PATH=/var/log/verdikt/audit.jsonl
```

Or S3:

```bash
export VERDIKT_AUDIT_SINK=s3
export VERDIKT_AUDIT_S3_BUCKET=<audit-bucket>
export VERDIKT_AUDIT_S3_PREFIX=verdikt/audit
export VERDIKT_AUDIT_SINK_STRICT=true
```

The serverless deployment stores individually HMAC-signed envelopes in DynamoDB and reports verification of recent events in `/state`. S3 Object Lock is not provisioned by this repository, so the S3 sink is centrally durable but not automatically immutable.

Interview angle:

> Verdikt separates transport authentication from tool authorization. JWT proves caller identity at the HTTP boundary; policy-as-code still decides which actor can run each tool.

## Redis-Backed Distributed Rate Limits

Local mode uses an in-process limiter. Production mode can use Redis:

```bash
export VERDIKT_REDIS_URL="redis://localhost:6379/0"
export VERDIKT_REDIS_REQUIRED=true
```

The policy engine applies rate limits by tool, actor/tool, production environment/tool, and optional global budget. Redis makes those counters shared across replicas.

The Redis operation uses one atomic Lua script for increment and expiry. Logical keys are SHA-256 hashed before storage, so actor names are not exposed in the Redis keyspace. CI starts Redis 7 and proves that two separate limiter instances consume the same limit.

## Argus Incident And RCA Integration

A security control is more useful when a malicious tool attempt enters the incident pipeline. Configure the real MCP runtime to send selected findings to Argus's actual Alertmanager ingestion endpoint:

```bash
export VERDIKT_ARGUS_URL="https://argus.example.com"
export VERDIKT_ARGUS_TOKEN_SECRET_ARN="arn:aws:secretsmanager:us-east-1:123456789012:secret:argus-service-token"
export VERDIKT_ARGUS_HMAC_SECRET="independent-proxy-verification-key"
```

For local Argus development, `VERDIKT_ARGUS_API_TOKEN` can hold the operator-managed service token directly. Caller JWTs, OAuth tokens, tool arguments, results, and raw injected text are never forwarded. The Alertmanager envelope contains policy metadata, correlation ID, risk score, and SHA-256 evidence hashes.

Flow:

```text
blocked MCP call
  -> signed Verdikt audit record
  -> durable SQLite finding outbox
  -> authenticated Alertmanager POST
  -> Argus dedupe/grouping
  -> incident + signal + timeline
  -> Argus RCA and remediation workflow
```

Failed HTTP deliveries remain in the outbox and a background worker retries them with exponential backoff. Only an error hash is retained. Repeated instances of the same server/tool/rule are grouped into a five-minute dedupe window instead of creating one incident per request. `verdikt.runtime_state` exposes pending, retrying, and delivered counts, while `verdikt_findings_total` exposes initial delivery outcomes to Prometheus. Routine `approval_required` decisions and successful critical actions do not page on-call by default; security, integrity, identity, rate-limit, circuit, and kill-switch rules do. Override the denied-rule set with `VERDIKT_FINDING_RULES`, the dedupe window with `VERDIKT_FINDING_DEDUPE_WINDOW_SECONDS`, or deliberately include successful critical actions with `VERDIKT_FINDING_INCLUDE_ALLOWED_CRITICAL=true`.

Non-loopback HTTP is rejected by default. Use HTTPS in production. `VERDIKT_ARGUS_ALLOW_INSECURE_HTTP=true` exists only for a trusted internal lab network.

The AWS serverless deployment has the cloud-native equivalent: versioned, hash-only finding envelopes go to EventBridge and then SQS/DLQ.

## MCP-AttackBench-Compatible Evaluation

Run the bundled adapter smoke profile:

```bash
make attackbench-smoke
```

The smoke corpus proves parsing, classification, metrics, thresholds, and report privacy; it is deliberately not advertised as a score on the 70,448-sample independent corpus. See [ATTACKBENCH.md](ATTACKBENCH.md) for the full-corpus command, field mapping, CI evidence, and interpretation limits.

## Observability Stack

Run the local observability stack:

```bash
make observability-up
```

Services:

- Verdikt: http://127.0.0.1:8080
- Prometheus: http://127.0.0.1:9090
- Grafana: http://127.0.0.1:3000, admin/admin
- Tempo: http://127.0.0.1:3200
- Jaeger UI: http://127.0.0.1:16686
- Redis: 127.0.0.1:6379

Verdikt emits Prometheus metrics at `/metrics` and OTLP traces to Tempo by default in this stack. Jaeger is included as an alternate trace UI/collector for demos that prefer Jaeger.

## Helm Chart

Render the chart:

```bash
make helm-template
```

Install into a lab cluster:

```bash
helm upgrade --install verdikt ./charts/verdikt \
  --set image.repository=<your-image-repo> \
  --set image.tag=<tag> \
  --set auth.bearerToken=<token> \
  --set approvalSecret=<approval-secret> \
  --set audit.hmacSecret=<independent-audit-secret>
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
