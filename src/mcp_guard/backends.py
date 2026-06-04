from __future__ import annotations

import datetime as dt
import secrets
from typing import Any

from .models import Tool
from .protocol import MCPProtocolError, serve_stdio


def _schema(**properties: dict[str, str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": [name for name in properties if name != "approved"],
        "additionalProperties": False,
    }


PLATFORM_TOOLS = [
    Tool(
        "platform.health",
        "Inspect the deployment health, replica counts, release, and error rate of a production service.",
        _schema(service={"type": "string"}),
    ),
    Tool(
        "platform.read_config",
        "Read runtime configuration for a production service. Secrets are redacted by MCP-Guard.",
        _schema(service={"type": "string"}),
    ),
    Tool(
        "platform.read_logs",
        "Read recent application logs for a production service.",
        _schema(service={"type": "string"}, query={"type": "string"}, limit={"type": "integer"}),
    ),
    Tool(
        "platform.run_diagnostic",
        "Run an allowlisted diagnostic command against a production service.",
        _schema(service={"type": "string"}, command={"type": "string"}),
    ),
    Tool(
        "platform.restart_deployment",
        "Perform a rolling restart of a production deployment after explicit approval.",
        _schema(service={"type": "string"}, approved={"type": "boolean"}),
    ),
    Tool(
        "platform.rollback_deployment",
        "Roll a production deployment back to a known release after explicit approval.",
        _schema(
            service={"type": "string"},
            version={"type": "string"},
            approved={"type": "boolean"},
        ),
    ),
]

INCIDENT_TOOLS = [
    Tool(
        "incident.create",
        "Create an operational incident.",
        _schema(title={"type": "string"}, severity={"type": "string"}),
    ),
    Tool(
        "incident.attach_evidence",
        "Attach a correlated audit event to an incident.",
        _schema(incident_id={"type": "string"}, evidence={"type": "object"}),
    ),
    Tool(
        "incident.timeline",
        "Read the incident timeline.",
        _schema(incident_id={"type": "string"}),
    ),
]


class PlatformOpsBackend:
    def __init__(self) -> None:
        self.services = {
            "payments-api": {
                "status": "degraded",
                "release": "payments-api@2026.05.3",
                "replicas": {"desired": 4, "available": 4},
                "error_rate_5m": 0.042,
                "p99_latency_ms": 836,
                "restarts": 0,
            },
            "checkout-worker": {
                "status": "healthy",
                "release": "checkout-worker@2026.05.1",
                "replicas": {"desired": 3, "available": 3},
                "error_rate_5m": 0.001,
                "p99_latency_ms": 142,
                "restarts": 0,
            },
        }

    def call(self, tool: str, arguments: dict[str, Any]) -> Any:
        service = arguments.get("service", "")
        if service not in self.services:
            raise MCPProtocolError(f"unknown service: {service}")
        state = self.services[service]
        if tool == "platform.health":
            return {"service": service, **state}
        if tool == "platform.read_config":
            return {
                "service": service,
                "environment": "production",
                "region": "us-east-1",
                "log_level": "INFO",
                "database_pool_size": 20,
                "api_key": "sk-demo-sensitive-value",
            }
        if tool == "platform.read_logs":
            return {
                "service": service,
                "query": arguments["query"],
                "logs": [
                    "2026-05-31T09:15:02Z WARN payment provider timeout dependency=stripe",
                    "2026-05-31T09:15:03Z ERROR request failed route=/v1/charge status=503",
                ][: arguments["limit"]],
            }
        if tool == "platform.run_diagnostic":
            command = arguments["command"]
            diagnostics = {
                "dependency-health": "stripe-api=degraded postgres=healthy redis=healthy",
                "error-rate": "http_5xx_rate_5m=0.042 timeout_rate_5m=0.038",
                "latency-summary": "p50_ms=91 p95_ms=440 p99_ms=836",
            }
            if command not in diagnostics:
                raise MCPProtocolError(f"diagnostic command is not allowlisted: {command}")
            return {"service": service, "command": command, "output": diagnostics[command]}
        if tool == "platform.restart_deployment":
            state["restarts"] += 1
            return {"service": service, "action": "rolling_restart", "status": "completed", **state}
        if tool == "platform.rollback_deployment":
            previous = state["release"]
            state["release"] = arguments["version"]
            state["status"] = "healthy"
            state["error_rate_5m"] = 0.003
            state["p99_latency_ms"] = 176
            return {
                "service": service,
                "action": "deployment_rollback",
                "from_release": previous,
                "to_release": state["release"],
                "status": "completed",
            }
        raise MCPProtocolError(f"unsupported platform tool: {tool}")


class IncidentBackend:
    def __init__(self) -> None:
        self.incidents: dict[str, dict[str, Any]] = {}

    def call(self, tool: str, arguments: dict[str, Any]) -> Any:
        if tool == "incident.create":
            incident_id = f"INC-{secrets.token_hex(3).upper()}"
            incident = {
                "id": incident_id,
                "title": arguments["title"],
                "severity": arguments["severity"],
                "timeline": [_timeline("incident created")],
            }
            self.incidents[incident_id] = incident
            return incident
        incident_id = arguments["incident_id"]
        if incident_id not in self.incidents:
            raise MCPProtocolError(f"unknown incident: {incident_id}")
        incident = self.incidents[incident_id]
        if tool == "incident.attach_evidence":
            incident["timeline"].append(_timeline("evidence attached", arguments["evidence"]))
            return incident
        if tool == "incident.timeline":
            return incident
        raise MCPProtocolError(f"unsupported incident tool: {tool}")


def _timeline(event: str, details: Any = None) -> dict[str, Any]:
    item = {"at": dt.datetime.now(dt.UTC).isoformat(), "event": event}
    if details is not None:
        item["details"] = details
    return item


def run_backend(name: str) -> None:
    if name == "platform-ops":
        backend = PlatformOpsBackend()
        serve_stdio("platform-ops-mcp", PLATFORM_TOOLS, backend.call)
        return
    if name == "incident":
        backend = IncidentBackend()
        serve_stdio("incident-mcp", INCIDENT_TOOLS, backend.call)
        return
    raise SystemExit(f"unknown backend: {name}")
