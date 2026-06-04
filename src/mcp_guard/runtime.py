from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any

from .audit import AuditStore
from .groq import IncidentAnalyst
from .metrics import Metrics
from .models import ToolCallResult
from .policy import PolicyEngine
from .protocol import MCPProtocolError, StdioMCPClient
from .telemetry import Telemetry


class MCPGuardRuntime:
    def __init__(self, policy_path: Path, audit_path: Path) -> None:
        self.policy = PolicyEngine(policy_path)
        self.audit = AuditStore(audit_path)
        self.metrics = Metrics()
        self.telemetry = Telemetry()
        self.analyst = IncidentAnalyst(telemetry=self.telemetry)
        self.clients = {
            "platform-ops": StdioMCPClient("platform-ops"),
            "incident": StdioMCPClient("incident"),
        }

    def list_tools(self) -> dict[str, list[dict[str, Any]]]:
        return {server: client.list_tools() for server, client in self.clients.items()}

    def call_tool(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        correlation_id: str | None = None,
    ) -> ToolCallResult:
        correlation_id = correlation_id or str(uuid.uuid4())
        started = time.perf_counter()
        safe_arguments = self.policy.redact(arguments)
        result: Any = None
        with self.telemetry.span(
            "mcp_guard.call_tool",
            "CHAIN",
            {
                "mcp_guard.correlation_id": correlation_id,
                "mcp_guard.server": server,
                "mcp_guard.tool": tool,
            },
        ) as request_span:
            request_span.set_json_input(safe_arguments)
            with self.telemetry.span(
                "mcp_guard.policy.evaluate",
                "GUARDRAIL",
                {"mcp_guard.server": server, "mcp_guard.tool": tool},
            ) as policy_span:
                policy_span.set_json_input(safe_arguments)
                decision = self.policy.evaluate(server, tool, arguments)
                policy_span.set_policy(
                    allowed=decision.allowed,
                    rule=decision.rule,
                    reason=decision.reason,
                )
                policy_span.set_attribute("mcp_guard.risk.score", decision.risk_score)
                policy_span.set_attribute("mcp_guard.risk.level", decision.risk_level)
            reason = decision.reason
            allowed = decision.allowed
            rule = decision.rule
            if allowed:
                client = self.clients.get(server)
                if client is None:
                    allowed = False
                    rule = "unknown_server"
                    reason = f"unknown MCP server: {server}"
                else:
                    try:
                        with self.telemetry.span(
                            f"mcp.{tool}",
                            "TOOL",
                            {
                                "tool.name": tool,
                                "mcp_guard.server": server,
                                "mcp_guard.correlation_id": correlation_id,
                            },
                        ) as tool_span:
                            tool_span.set_json_input(safe_arguments)
                            result = self.policy.redact(client.call_tool(tool, arguments))
                            tool_span.set_json_output(result)
                    except MCPProtocolError as exc:
                        allowed = False
                        rule = "upstream_error"
                        reason = str(exc)
            request_span.set_policy(allowed=allowed, rule=rule, reason=reason)
            request_span.set_attribute("mcp_guard.risk.score", decision.risk_score)
            request_span.set_attribute("mcp_guard.risk.level", decision.risk_level)
            request_span.set_json_output({"allowed": allowed, "result": result})
        duration_ms = (time.perf_counter() - started) * 1000
        self.audit.record(
            correlation_id=correlation_id,
            server=server,
            tool=tool,
            allowed=allowed,
            rule=rule,
            reason=reason,
            arguments=safe_arguments,
            result=result,
            duration_ms=duration_ms,
        )
        self.metrics.observe(server, tool, allowed, duration_ms)
        return ToolCallResult(
            correlation_id,
            allowed,
            server,
            tool,
            reason,
            result,
            risk_score=decision.risk_score,
            risk_level=decision.risk_level,
        )

    def summarize_recent_events(self, limit: int = 100) -> dict[str, Any]:
        return self.analyst.summarize(self.audit.recent(limit))

    def close(self) -> None:
        for client in self.clients.values():
            client.close()
        self.audit.close()
