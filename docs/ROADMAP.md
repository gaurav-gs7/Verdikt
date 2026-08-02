# Production Roadmap

## Implemented Baseline

- JWT/JWKS resource-server validation with audience and scope checks.
- Identity-bound policy evaluation and token-passthrough denial.
- Slack signed-callback approval with exact-argument token binding.
- Redis and DynamoDB distributed rate limits.
- Tool metadata inspection, pinning, shadow detection, and result quarantine.
- Versioned official Filesystem, Memory, and GitHub MCP interoperability profiles.
- External subprocess environment isolation with explicit credential brokering.
- AWS Secrets Manager and Vault KV secret brokerage across runtime credentials.
- Hash-chained local audit plus JSONL/S3/SIEM shipping and signed DynamoDB events.
- Generic HTTPS and Splunk HEC audit contracts with optional HMAC signing.
- Reproducible guarded-call latency and throughput evidence in CI.
- Evasion-resistant content inspection: base64/hex/URL-decoded payload rescanning,
  homoglyph/leetspeak/spaced-letter normalization, a small non-English phrase set
  (Spanish, French, German, Portuguese, Chinese, Russian), and cross-argument
  split-field scanning (`src/judikt/content_guard.py`). This raises recall against
  known plain-regex bypasses; it is still a deterministic heuristic layer, not a
  semantic/model-based detector, and does not by itself justify moving MCP-19 or
  MCP-12 from `partial` to `covered` in `config/mcp38_coverage.json`.

## Priority 1: Identity And Approval

- Add two-person approval for critical-risk actions.
- Test against a deployed Cognito or other OAuth 2.1 authorization server with per-client consent and PKCE.

## Priority 2: Real AIOps Integrations

- Expand the guarded Kubernetes adapter from pod status/restart/rollout status into events, deployment history, and namespace inventory.
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

- Provision S3 Object Lock or another immutable audit destination.
- Durable kill switches across all runtime modes.
- Idempotency keys.
- ECS/Fargate or multi-AZ deployment for non-free-tier production hosting.

## Priority 5: Supply Chain

- SBOM generation.
- Dependency scanning.
- Signed container images.
- SLSA provenance.
- Release workflow with GitHub Actions environment approvals.

## Priority 6: Agent Safety Evals

- Expand MCP-38 covered controls beyond the current 12 categories.
- Encoded, multilingual, and split-field injection fixtures now exist
  (`tests/test_content_security.py`); low-and-slow (rate/time-based) injection
  detection is still open.
- Replace or supplement the regex/heuristic detection core with a semantic or
  embedding-based check for paraphrased/novel injection phrasing that no fixed
  pattern set will catch — this remains the largest gap in MCP-19/MCP-12/MCP-20.
- Track pass/fail history in CI.
- Fail builds on policy regressions.
