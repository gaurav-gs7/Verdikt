from __future__ import annotations

import datetime as dt
import os
import secrets
import subprocess
from typing import Any

from .models import Tool
from .protocol import MCPProtocolError, serve_stdio


def _schema(**properties: dict[str, str]) -> dict[str, Any]:
    optional = {
        "approved",
        "approval_token",
        "actor",
        "auto_create_incident",
        "dry_run",
        "environment",
        "incident_id",
        "requested_by",
        "rollback_plan",
        "shadow_mode",
        "user",
    }
    return {
        "type": "object",
        "properties": properties,
        "required": [name for name in properties if name not in optional],
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
        "Read runtime configuration for a production service. Secrets are redacted by Verdikt.",
        _schema(service={"type": "string"}),
    ),
    Tool(
        "platform.read_logs",
        "Read recent application logs for a production service.",
        _schema(
            service={"type": "string"},
            query={"type": "string"},
            limit={"type": "integer", "minimum": 1, "maximum": 100},
        ),
    ),
    Tool(
        "platform.run_diagnostic",
        "Run an allowlisted diagnostic command against a production service.",
        _schema(service={"type": "string"}, command={"type": "string"}),
    ),
    Tool(
        "platform.restart_deployment",
        "Perform a rolling restart of a production deployment after explicit approval.",
        _schema(
            service={"type": "string"},
            actor={"type": "string"},
            environment={"type": "string"},
            rollback_plan={"type": "string"},
            approval_token={"type": "string"},
            approved={"type": "boolean"},
            dry_run={"type": "boolean"},
            shadow_mode={"type": "boolean"},
            incident_id={"type": "string"},
            auto_create_incident={"type": "boolean"},
        ),
    ),
    Tool(
        "platform.rollback_deployment",
        "Roll a production deployment back to a known release after explicit approval.",
        _schema(
            service={"type": "string"},
            version={"type": "string"},
            actor={"type": "string"},
            environment={"type": "string"},
            rollback_plan={"type": "string"},
            approval_token={"type": "string"},
            approved={"type": "boolean"},
            dry_run={"type": "boolean"},
            shadow_mode={"type": "boolean"},
            incident_id={"type": "string"},
            auto_create_incident={"type": "boolean"},
        ),
    ),
]

KUBERNETES_TOOLS = [
    Tool(
        "kubernetes.get_pod",
        "Read pod status from a Kubernetes namespace. Uses a safe simulator by default.",
        _schema(namespace={"type": "string"}, pod={"type": "string"}),
    ),
    Tool(
        "kubernetes.restart_pod",
        "Restart a Kubernetes pod through a guarded delete-and-recreate workflow. Requires actor, approval, and rollback plan in production.",
        _schema(
            namespace={"type": "string"},
            pod={"type": "string"},
            actor={"type": "string"},
            environment={"type": "string"},
            rollback_plan={"type": "string"},
            approval_token={"type": "string"},
            approved={"type": "boolean"},
            dry_run={"type": "boolean"},
            shadow_mode={"type": "boolean"},
            incident_id={"type": "string"},
            auto_create_incident={"type": "boolean"},
        ),
    ),
    Tool(
        "kubernetes.rollout_status",
        "Read rollout status for a Kubernetes deployment.",
        _schema(namespace={"type": "string"}, deployment={"type": "string"}),
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
            limit = arguments["limit"]
            if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
                raise MCPProtocolError("log limit must be an integer between 1 and 100")
            return {
                "service": service,
                "query": arguments["query"],
                "logs": [
                    "2026-05-31T09:15:02Z WARN payment provider timeout dependency=stripe",
                    "2026-05-31T09:15:03Z ERROR request failed route=/v1/charge status=503",
                ][:limit],
            }
        if tool == "platform.run_diagnostic":
            command = arguments["command"]
            diagnostics = {
                "dependency-health": "stripe-api=degraded postgres=healthy redis=healthy",
                "error-rate": "http_5xx_rate_5m=0.042 timeout_rate_5m=0.038",
                "latency-summary": "p50_ms=91 p95_ms=440 p99_ms=836",
            }
            if command not in diagnostics:
                raise MCPProtocolError("diagnostic command is not allowlisted")
            return {"service": service, "command": command, "output": diagnostics[command]}
        if tool == "platform.restart_deployment":
            state["restarts"] += 1
            return {
                "service": service,
                **state,
                "service_status": state["status"],
                "action": "rolling_restart",
                "status": "completed",
            }
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


class KubernetesBackend:
    """Kubernetes operations adapter.

    The default mode is a deterministic simulator so the project remains safe,
    portable, and free-tier friendly. Set VERDIKT_KUBERNETES_MODE=kubectl to
    point the adapter at a real kubeconfig for a controlled lab environment.
    """

    def __init__(self) -> None:
        self.mode = os.getenv("VERDIKT_KUBERNETES_MODE", "simulated").lower()
        if self.mode not in {"simulated", "kubectl"}:
            raise ValueError("VERDIKT_KUBERNETES_MODE must be simulated or kubectl")
        self.pods = {
            ("prod", "payment-service-xyz"): {
                "namespace": "prod",
                "pod": "payment-service-xyz",
                "deployment": "payment-service",
                "status": "Running",
                "restarts": 0,
                "ready": True,
                "node": "ip-10-0-12-44.ec2.internal",
            },
            ("prod", "payments-api-7d9f5d"): {
                "namespace": "prod",
                "pod": "payments-api-7d9f5d",
                "deployment": "payments-api",
                "status": "Running",
                "restarts": 1,
                "ready": True,
                "node": "ip-10-0-9-13.ec2.internal",
            },
        }

    def call(self, tool: str, arguments: dict[str, Any]) -> Any:
        if tool == "kubernetes.get_pod":
            return self._get_pod(arguments)
        if tool == "kubernetes.restart_pod":
            return self._restart_pod(arguments)
        if tool == "kubernetes.rollout_status":
            return self._rollout_status(arguments)
        raise MCPProtocolError(f"unsupported kubernetes tool: {tool}")

    def _get_pod(self, arguments: dict[str, Any]) -> dict[str, Any]:
        namespace = arguments["namespace"]
        pod = arguments["pod"]
        if self.mode == "kubectl":
            return self._kubectl_json(["get", "pod", pod, "-n", namespace, "-o", "json"])
        return dict(self._pod(namespace, pod))

    def _restart_pod(self, arguments: dict[str, Any]) -> dict[str, Any]:
        namespace = arguments["namespace"]
        pod = arguments["pod"]
        if self.mode == "kubectl":
            output = self._kubectl(["delete", "pod", pod, "-n", namespace, "--wait=false"])
            return {
                "namespace": namespace,
                "pod": pod,
                "action": "pod_restart",
                "mode": "kubectl",
                "status": "delete_requested",
                "output": output,
            }
        state = self._pod(namespace, pod)
        state["restarts"] += 1
        state["last_restart_at"] = dt.datetime.now(dt.UTC).isoformat()
        return {
            "namespace": namespace,
            "pod": pod,
            "deployment": state["deployment"],
            "action": "pod_restart",
            "mode": "simulated",
            "status": "completed",
            "restarts": state["restarts"],
        }

    def _rollout_status(self, arguments: dict[str, Any]) -> dict[str, Any]:
        namespace = arguments["namespace"]
        deployment = arguments["deployment"]
        if self.mode == "kubectl":
            output = self._kubectl(["rollout", "status", f"deployment/{deployment}", "-n", namespace])
            return {"namespace": namespace, "deployment": deployment, "status": output}
        matching = [pod for pod in self.pods.values() if pod["namespace"] == namespace and pod["deployment"] == deployment]
        return {
            "namespace": namespace,
            "deployment": deployment,
            "available_pods": len([pod for pod in matching if pod["ready"]]),
            "desired_pods": max(len(matching), 1),
            "status": "healthy" if matching else "unknown",
        }

    def _pod(self, namespace: str, pod: str) -> dict[str, Any]:
        key = (namespace, pod)
        if key not in self.pods:
            raise MCPProtocolError(f"unknown pod: {namespace}/{pod}")
        return self.pods[key]

    @staticmethod
    def _kubectl(args: list[str]) -> str:
        command = ["kubectl", *args]
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
            )
        except FileNotFoundError as exc:
            raise MCPProtocolError("kubectl executable was not found") from exc
        except subprocess.TimeoutExpired as exc:
            raise MCPProtocolError("kubectl command timed out") from exc
        if completed.returncode != 0:
            raise MCPProtocolError(
                f"kubectl command failed with exit code {completed.returncode}"
            )
        return completed.stdout.strip()

    def _kubectl_json(self, args: list[str]) -> dict[str, Any]:
        import json

        try:
            value = json.loads(self._kubectl(args))
        except json.JSONDecodeError as exc:
            raise MCPProtocolError("kubectl returned malformed JSON") from exc
        if not isinstance(value, dict):
            raise MCPProtocolError("kubectl returned a non-object JSON response")
        return value


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
    if name == "kubernetes":
        backend = KubernetesBackend()
        serve_stdio("kubernetes-mcp", KUBERNETES_TOOLS, backend.call)
        return
    raise SystemExit(f"unknown backend: {name}")
