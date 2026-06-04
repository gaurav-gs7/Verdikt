# MCP-Guard Design Notes

These notes capture the main engineering choices behind MCP-Guard and are useful for interview walkthroughs.

## Core Boundary

MCP-Guard is a gateway, not an agent. It does not try to make the LLM smarter. It constrains what the agent can do when it reaches for production tools.

The central rule is:

```text
deterministic policy before execution, redaction before observability, audit after every decision
```

## Why The LLM Is Not In The Enforcement Path

The LLM can summarize recent audit evidence, but it cannot approve tool calls. Authorization needs to be deterministic, explainable, testable, and available when a hosted model API is down.

## Approval Tokens

Destructive operations can be approved with an HMAC token bound to:

- server
- tool
- exact arguments
- actor
- reason
- expiration time

The demo still accepts `approved: true` for quick walkthroughs, but the signed token flow is the production-shaped path.

## Risk Scoring

Each request receives a deterministic risk score. The score is not a machine-learning model; it is an explainable heuristic based on tool type, server, service criticality, and release references. That makes it useful for demos and policy decisions without making enforcement opaque.

## Observability

MCP-Guard emits three kinds of evidence:

- SQLite audit events for durable local evidence.
- Prometheus metrics for aggregate operational signals.
- OpenInference-compatible spans for request-level trace explanation.

Those are deliberately separate. Traces may be sampled; audits should not be.

## Production Upgrade Path

The current project is production-shaped but local. The next real upgrades are OAuth/OIDC identity, Redis-backed distributed rate limits, Postgres audit storage, OPA/Cedar policies, Kubernetes/Prometheus integrations, and append-only audit export.

