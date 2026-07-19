from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    level: str
    evidence: list[str]


class RiskEngine:
    """Small deterministic risk scorer for explaining why actions need controls."""

    def assess(self, server: str, tool: str, arguments: dict[str, Any]) -> RiskAssessment:
        score = 10
        evidence = ["base MCP tool invocation risk"]
        if server == "platform-ops":
            score += 10
            evidence.append("production operations server")
        if server == "kubernetes":
            score += 20
            evidence.append("kubernetes operations server")
        if tool.endswith("rollback_deployment"):
            score += 55
            evidence.append("deployment rollback can change live production traffic")
        elif tool.endswith("restart_deployment"):
            score += 45
            evidence.append("deployment restart can affect availability")
        elif tool.endswith("restart_pod"):
            score += 50
            evidence.append("pod restart can affect production availability")
        elif tool.endswith("run_diagnostic"):
            score += 25
            evidence.append("diagnostic commands can expose infrastructure details")
        elif tool.endswith("read_config"):
            score += 20
            evidence.append("configuration may contain secrets")
        elif tool.endswith("read_logs"):
            score += 15
            evidence.append("logs may include sensitive operational context")
        if arguments.get("service") == "payments-api":
            score += 10
            evidence.append("payments-api is business critical")
        if arguments.get("namespace") in {"prod", "production"}:
            score += 10
            evidence.append("request targets a production namespace")
        if "payment" in str(arguments.get("pod", "")):
            score += 10
            evidence.append("request targets a payment-system pod")
        if any(str(value).startswith("payments-api@") for value in arguments.values()):
            score += 5
            evidence.append("request references a production release artifact")
        score = min(score, 100)
        if score >= 80:
            level = "critical"
        elif score >= 60:
            level = "high"
        elif score >= 35:
            level = "medium"
        else:
            level = "low"
        return RiskAssessment(score, level, evidence)
