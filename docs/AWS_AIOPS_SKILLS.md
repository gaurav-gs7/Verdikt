# AWS AIOps / LLMOps Skill Plan

Use GateTrace MCP as a practical AWS learning project instead of a static demo.

## Phase 1: Free-Tier Deployment

- Build a Docker image locally.
- Push it to ECR.
- Deploy it with Terraform to EC2.
- Keep CloudFormation as an alternate AWS-native deployment path.
- Access the instance through SSM Session Manager.
- Expose only port `8080` through a security group.
- Destroy the infrastructure after demos.

Resume signal: container deployment, IAM, EC2, ECR, Terraform, CloudFormation, SSM.

## Phase 1B: Serverless AIOps Control Plane

- Deploy API Gateway HTTP API to front the control plane.
- Run deterministic policy enforcement in a gateway Lambda.
- Run production-like tools in a separate mock tool Lambda.
- Store policies, approvals, rate limits, circuit breakers, kill switches, service state, and audit events in DynamoDB.
- Emit remediation finding events through EventBridge.
- Route findings to SQS with a dead-letter queue.
- Emit CloudWatch custom metrics, alarms, logs, and dashboard widgets.

Resume signal: serverless architecture, event-driven AIOps, DynamoDB state modeling, operational telemetry, Terraform.

## Deployment Comparison

GateTrace MCP has two AWS learning paths. They are useful for different reasons.

### Free-Tier Real MCP Deployment

This is the main deployment path for the project. The MCP client can run locally, while GateTrace MCP runs on AWS as a Dockerized real MCP Streamable HTTP server on EC2.

AWS services involved:

- EC2 free-tier instance
- ECR
- Docker
- Terraform
- IAM instance role
- Security group
- SSM Session Manager
- EBS storage
- Secrets Manager or SSM Parameter Store for runtime secrets
- CloudWatch-ready logs and metrics

Why it matters:

- It is the clearest real MCP story.
- It shows practical AWS deployment skills.
- It is free-tier friendly and easy to demo.
- It proves you can containerize, deploy, secure, and operate an AI infrastructure service.

Hiring signal:

- Strong for SRE, DevOps, Platform Engineer, Systems Development Engineer, and AI Infrastructure roles.
- Best resume framing: real MCP server on AWS Free Tier with Terraform, Docker, IAM, SSM, ECR, and operational guardrails.

### Serverless AIOps Deployment

This is the AWS-native AIOps architecture variant. It does not run the real MCP transport. Instead, it applies the same GateTrace MCP safety model to an event-driven serverless control plane.

AWS services involved:

- API Gateway HTTP API
- Lambda gateway
- Lambda tool adapter
- DynamoDB audit and state tables
- EventBridge
- SQS and DLQ
- CloudWatch logs, metrics, alarms, and dashboard
- X-Ray tracing
- Secrets Manager
- Terraform

Why it matters:

- It shows deeper AWS-native architecture skills.
- It demonstrates event-driven remediation patterns.
- It shows DynamoDB state modeling, custom metrics, alarms, tracing, and DLQ handling.
- It is useful for explaining how GateTrace MCP could evolve into a larger AIOps platform.

Hiring signal:

- Strong for AIOps, LLMOps, cloud platform, and serverless-heavy roles.
- Best resume framing: experimental serverless AIOps control plane using API Gateway, Lambda, DynamoDB, EventBridge, SQS, CloudWatch, X-Ray, and Terraform.

### Which One To Lead With

Lead with the free-tier real MCP deployment because it is simpler, more honest, and directly tied to MCP:

> Local MCP client -> AWS EC2 real MCP server -> GateTrace MCP runtime -> guarded operational tools.

Mention the serverless deployment as an additional AWS/AIOps exploration:

> I also built a serverless AIOps variant to demonstrate event-driven remediation, DynamoDB-backed state, CloudWatch/X-Ray observability, and DLQ-based failure handling.

Summary:

| Path | Best For | AWS Skill Signal | AIOps Hiring Signal | Risk |
| --- | --- | --- | --- | --- |
| Free-tier real MCP on EC2 | Main project story | Strong practical AWS | Strong and clear | Low confusion |
| Serverless AIOps variant | AWS breadth | Stronger AWS breadth | Strong for AIOps/serverless | Can confuse MCP story |

## Phase 2: Observability

- Add CloudWatch logs from the container.
- Add CloudWatch alarms for instance health.
- Export `/metrics` to a Prometheus-compatible collector later.
- Keep OpenInference OTLP export as the AI trace story.
- Use AWS X-Ray active tracing for Lambda request paths.
- Keep SLOs and runbooks in version control.

Resume signal: AIOps observability and operational telemetry.

## Phase 3: Security

- Store approval and bearer-token secrets in AWS Secrets Manager.
- Add IAM least-privilege policy reviews.
- Restrict security group ingress to your IP.
- Add AWS Budget alerts before testing.
- Use GitHub Actions OIDC instead of long-lived AWS access keys.

Resume signal: cloud security and cost-aware operations.

## Phase 4: Production-Like Integrations

- Build a read-only CloudWatch MCP server.
- Build a read-only ECS or EC2 inventory MCP server.
- Add a policy rule that blocks write operations unless a signed approval token is present.

Resume signal: LLMOps tool governance for cloud operations.

## Phase 5: LinkedIn Story

Short post outline:

1. Problem: AI agents should not get direct production access.
2. Design: MCP gateway with deterministic policy before execution.
3. AWS: deployed a serverless control plane with API Gateway, Lambda, DynamoDB, EventBridge, SQS, CloudWatch, and Terraform; also built EC2/ECR and CloudFormation alternatives.
4. Safety: signed approvals, risk scoring, redaction, kill switches, evals.
5. Observability: metrics, audit logs, OpenInference traces.
6. Reliability: SLOs, runbooks, failure-mode tests, and circuit breakers.
7. Lesson: LLMs can explain incidents, but deterministic systems must authorize actions.
