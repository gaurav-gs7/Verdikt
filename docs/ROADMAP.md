# Production Roadmap

## Priority 1: Identity And Approval

- Replace demo boolean approvals with signed approval tokens everywhere.
- Add OIDC JWT validation.
- Bind approvals to actor, environment, service, tool, arguments, and expiry.
- Add two-person approval for critical-risk actions.

## Priority 2: Real AIOps Integrations

- Kubernetes MCP server for deployments, pods, events, rollouts, and restarts.
- Prometheus MCP server for SLO burn rate and error budget checks.
- Loki or Datadog MCP server for logs.
- PagerDuty or Opsgenie MCP server for incidents.
- GitHub MCP server for deployment SHA and PR context.

## Priority 3: Policy Engine

- Add OPA/Rego or Cedar policy evaluation.
- Version policy bundles.
- Add signed policy releases.
- Keep fast deny rules for obvious exfiltration patterns.

## Priority 4: Distributed Runtime

- Postgres audit store.
- Redis distributed rate limits.
- Durable kill switches.
- Idempotency keys.
- HA dashboard/API deployment.

## Priority 5: Supply Chain

- SBOM generation.
- Dependency scanning.
- Signed container images.
- SLSA provenance.
- Release workflow.

## Priority 6: Agent Safety Evals

- Expand the adversarial eval corpus.
- Add prompt-injection fixtures from logs and incident comments.
- Track pass/fail history in CI.
- Fail builds on policy regressions.

