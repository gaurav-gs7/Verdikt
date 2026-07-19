from __future__ import annotations

from typing import Any

from .models import Tool
from .protocol import MCPProtocolError, serve_stdio
from .runtime import MCPGuardRuntime


def serve_gateway(runtime: MCPGuardRuntime) -> None:
    indexed_tools: dict[str, str] = {}
    tools: list[Tool] = []
    for server, upstream_tools in runtime.list_tools().items():
        for upstream in upstream_tools:
            indexed_tools[upstream["name"]] = server
            tools.append(
                Tool(
                    upstream["name"],
                    f"[proxied via GateTrace MCP from {server}] {upstream['description']}",
                    upstream["inputSchema"],
                )
            )

    def call(tool: str, arguments: dict[str, Any]) -> Any:
        server = indexed_tools.get(tool)
        if server is None:
            raise MCPProtocolError(f"unknown proxied tool: {tool}")
        guarded = runtime.call_tool(server, tool, arguments)
        if not guarded.allowed:
            return {
                "blocked": True,
                "correlation_id": guarded.correlation_id,
                "reason": guarded.reason,
            }
        return guarded.as_dict()

    try:
        serve_stdio("gatetrace-mcp", tools, call)
    finally:
        runtime.close()
