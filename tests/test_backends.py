from __future__ import annotations

import os
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from judikt.backends import (
    INCIDENT_TOOLS,
    KUBERNETES_TOOLS,
    PLATFORM_TOOLS,
    IncidentBackend,
    KubernetesBackend,
    PlatformOpsBackend,
    run_backend,
)
from judikt.protocol import MCPProtocolError


class PlatformOpsBackendTest(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = PlatformOpsBackend()

    def test_every_platform_tool_and_state_transition(self) -> None:
        health = self.backend.call("platform.health", {"service": "payments-api"})
        self.assertEqual(health["status"], "degraded")

        config = self.backend.call("platform.read_config", {"service": "payments-api"})
        self.assertTrue(config["api_key"].startswith("sk-"))

        logs = self.backend.call(
            "platform.read_logs",
            {"service": "payments-api", "query": "status=503", "limit": 1},
        )
        self.assertEqual(len(logs["logs"]), 1)
        self.assertEqual(logs["query"], "status=503")

        for command in ("dependency-health", "error-rate", "latency-summary"):
            with self.subTest(command=command):
                diagnostic = self.backend.call(
                    "platform.run_diagnostic",
                    {"service": "payments-api", "command": command},
                )
                self.assertEqual(diagnostic["command"], command)
                self.assertTrue(diagnostic["output"])

        restarted = self.backend.call(
            "platform.restart_deployment", {"service": "payments-api"}
        )
        self.assertEqual(restarted["restarts"], 1)
        self.assertEqual(restarted["status"], "completed")
        self.assertEqual(restarted["service_status"], "degraded")
        rolled_back = self.backend.call(
            "platform.rollback_deployment",
            {"service": "payments-api", "version": "payments-api@stable"},
        )
        self.assertEqual(rolled_back["from_release"], "payments-api@2026.05.3")
        self.assertEqual(rolled_back["to_release"], "payments-api@stable")
        self.assertEqual(
            self.backend.call("platform.health", {"service": "payments-api"})["status"],
            "healthy",
        )

    def test_invalid_service_tool_diagnostic_and_log_limits_fail_closed(self) -> None:
        with self.assertRaisesRegex(MCPProtocolError, "unknown service"):
            self.backend.call("platform.health", {"service": "missing"})
        with self.assertRaisesRegex(MCPProtocolError, "unsupported platform tool"):
            self.backend.call("platform.unknown", {"service": "payments-api"})
        with self.assertRaisesRegex(MCPProtocolError, "not allowlisted") as raised:
            self.backend.call(
                "platform.run_diagnostic",
                {"service": "payments-api", "command": "secret-value"},
            )
        self.assertNotIn("secret-value", str(raised.exception))

        for limit in (0, -1, 101, True, "10"):
            with self.subTest(limit=limit), self.assertRaisesRegex(
                MCPProtocolError, "integer between 1 and 100"
            ):
                self.backend.call(
                    "platform.read_logs",
                    {"service": "payments-api", "query": "error", "limit": limit},
                )

    def test_log_tool_schema_enforces_the_same_bounds(self) -> None:
        tool = next(tool for tool in PLATFORM_TOOLS if tool.name == "platform.read_logs")
        limit = tool.input_schema["properties"]["limit"]
        self.assertEqual(limit["minimum"], 1)
        self.assertEqual(limit["maximum"], 100)


class KubernetesBackendTest(unittest.TestCase):
    def test_simulator_supports_all_tools_and_unknown_paths(self) -> None:
        with patch.dict(os.environ, {"JUDIKT_KUBERNETES_MODE": "simulated"}, clear=False):
            backend = KubernetesBackend()
        pod = backend.call(
            "kubernetes.get_pod",
            {"namespace": "prod", "pod": "payment-service-xyz"},
        )
        self.assertTrue(pod["ready"])
        restarted = backend.call(
            "kubernetes.restart_pod",
            {"namespace": "prod", "pod": "payment-service-xyz"},
        )
        self.assertEqual(restarted["restarts"], 1)
        self.assertIn("last_restart_at", backend.pods[("prod", "payment-service-xyz")])
        rollout = backend.call(
            "kubernetes.rollout_status",
            {"namespace": "prod", "deployment": "payment-service"},
        )
        self.assertEqual(rollout["status"], "healthy")
        unknown_rollout = backend.call(
            "kubernetes.rollout_status",
            {"namespace": "prod", "deployment": "missing"},
        )
        self.assertEqual(unknown_rollout["status"], "unknown")
        self.assertEqual(unknown_rollout["desired_pods"], 1)

        with self.assertRaisesRegex(MCPProtocolError, "unknown pod"):
            backend.call(
                "kubernetes.get_pod",
                {"namespace": "prod", "pod": "missing"},
            )
        with self.assertRaisesRegex(MCPProtocolError, "unsupported kubernetes tool"):
            backend.call("kubernetes.unknown", {})

    def test_invalid_mode_does_not_silently_fall_back_to_simulation(self) -> None:
        with patch.dict(
            os.environ, {"JUDIKT_KUBERNETES_MODE": "kubeclt"}, clear=False
        ), self.assertRaisesRegex(ValueError, "simulated or kubectl"):
            KubernetesBackend()

    def test_kubectl_mode_uses_fixed_argument_vectors_for_all_tools(self) -> None:
        calls: list[list[str]] = []

        def run(command: list[str], **kwargs: object) -> SimpleNamespace:
            calls.append(command)
            if command[1:3] == ["get", "pod"]:
                return SimpleNamespace(returncode=0, stdout='{"status":{"phase":"Running"}}', stderr="")
            return SimpleNamespace(returncode=0, stdout="successful", stderr="")

        with patch.dict(
            os.environ, {"JUDIKT_KUBERNETES_MODE": "kubectl"}, clear=False
        ), patch("judikt.backends.subprocess.run", side_effect=run):
            backend = KubernetesBackend()
            pod = backend.call(
                "kubernetes.get_pod", {"namespace": "prod", "pod": "payments-abc"}
            )
            restart = backend.call(
                "kubernetes.restart_pod",
                {"namespace": "prod", "pod": "payments-abc"},
            )
            rollout = backend.call(
                "kubernetes.rollout_status",
                {"namespace": "prod", "deployment": "payments"},
            )

        self.assertEqual(pod["status"]["phase"], "Running")
        self.assertEqual(restart["status"], "delete_requested")
        self.assertEqual(rollout["status"], "successful")
        self.assertEqual(
            calls,
            [
                ["kubectl", "get", "pod", "payments-abc", "-n", "prod", "-o", "json"],
                ["kubectl", "delete", "pod", "payments-abc", "-n", "prod", "--wait=false"],
                ["kubectl", "rollout", "status", "deployment/payments", "-n", "prod"],
            ],
        )

    def test_kubectl_failures_are_bounded_and_do_not_leak_stderr(self) -> None:
        failures = [
            (FileNotFoundError(), "executable was not found"),
            (subprocess.TimeoutExpired(["kubectl"], 20), "timed out"),
        ]
        for failure, message in failures:
            with self.subTest(message=message), patch(
                "judikt.backends.subprocess.run", side_effect=failure
            ), self.assertRaisesRegex(MCPProtocolError, message):
                KubernetesBackend._kubectl(["get", "pod", "x"])

        with patch(
            "judikt.backends.subprocess.run",
            return_value=SimpleNamespace(
                returncode=7, stdout="", stderr="token=private-cluster-secret"
            ),
        ), self.assertRaisesRegex(MCPProtocolError, "exit code 7") as raised:
            KubernetesBackend._kubectl(["get", "pod", "x"])
        self.assertNotIn("private-cluster-secret", str(raised.exception))

        invalid_json = ["not-json", "[]"]
        for output in invalid_json:
            with self.subTest(output=output), patch(
                "judikt.backends.KubernetesBackend._kubectl", return_value=output
            ), self.assertRaisesRegex(MCPProtocolError, "malformed JSON|non-object"):
                KubernetesBackend()._kubectl_json(["get", "pod", "x"])


class IncidentBackendTest(unittest.TestCase):
    def test_incident_lifecycle_and_errors(self) -> None:
        backend = IncidentBackend()
        incident = backend.call(
            "incident.create", {"title": "Payment errors", "severity": "SEV-2"}
        )
        self.assertTrue(incident["id"].startswith("INC-"))
        self.assertEqual(incident["timeline"][0]["event"], "incident created")
        attached = backend.call(
            "incident.attach_evidence",
            {"incident_id": incident["id"], "evidence": {"correlation_id": "corr-1"}},
        )
        self.assertEqual(attached["timeline"][-1]["event"], "evidence attached")
        timeline = backend.call("incident.timeline", {"incident_id": incident["id"]})
        self.assertEqual(len(timeline["timeline"]), 2)

        with self.assertRaisesRegex(MCPProtocolError, "unknown incident"):
            backend.call("incident.timeline", {"incident_id": "INC-MISSING"})
        with self.assertRaisesRegex(MCPProtocolError, "unsupported incident tool"):
            backend.call("incident.unknown", {"incident_id": incident["id"]})


class BackendEntrypointTest(unittest.TestCase):
    def test_backend_entrypoint_dispatches_all_known_servers(self) -> None:
        expected = {
            "platform-ops": ("platform-ops-mcp", PLATFORM_TOOLS),
            "kubernetes": ("kubernetes-mcp", KUBERNETES_TOOLS),
            "incident": ("incident-mcp", INCIDENT_TOOLS),
        }
        for name, (server_name, tools) in expected.items():
            with self.subTest(name=name), patch("judikt.backends.serve_stdio") as serve:
                run_backend(name)
            self.assertEqual(serve.call_args.args[0], server_name)
            self.assertEqual(serve.call_args.args[1], tools)

        with self.assertRaisesRegex(SystemExit, "unknown backend"):
            run_backend("missing")


if __name__ == "__main__":
    unittest.main()
