from __future__ import annotations

import json
import re
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from .approval import ApprovalAuthority, ApprovalTokenError
from .models import PolicyDecision
from .risk import RiskEngine


class PolicyEngine:
    def __init__(self, policy_path: Path) -> None:
        # JSON is a YAML subset, which keeps this demo dependency-free.
        self.config = json.loads(policy_path.read_text())
        self.approvals = ApprovalAuthority()
        self.risk = RiskEngine()
        self._blocked = [re.compile(pattern, re.IGNORECASE) for pattern in self.config["blocked_argument_patterns"]]
        self._redacted_keys = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.config["redacted_key_patterns"]
        ]
        self._redacted_values = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.config["redacted_value_patterns"]
        ]
        self._calls: dict[str, deque[float]] = defaultdict(deque)
        self._disabled_tools: set[str] = set()
        self._disabled_servers: set[str] = set()
        self._lock = threading.Lock()

    def evaluate(self, server: str, tool: str, arguments: dict[str, Any]) -> PolicyDecision:
        with self._lock:
            risk = self.risk.assess(server, tool, arguments)
            if server in self._disabled_servers:
                return self._decision(False, f"server {server!r} is disabled by kill switch", "kill_switch", risk)
            if tool in self._disabled_tools:
                return self._decision(False, f"tool {tool!r} is disabled by kill switch", "kill_switch", risk)
            if tool not in self.config["allowed_tools"].get(server, []):
                return self._decision(False, f"tool {tool!r} is not allowlisted for {server!r}", "allowlist", risk)
            serialized = json.dumps(arguments, sort_keys=True)
            if any(pattern.search(serialized) for pattern in self._blocked):
                return self._decision(False, "arguments matched a blocked security pattern", "blocked_pattern", risk)
            if tool in self.config["approval_required"] and not self._has_approval(server, tool, arguments):
                return self._decision(
                    False,
                    f"approval token is required for this {risk.level}-risk action",
                    "approval_required",
                    risk,
                )
            if not self._within_rate_limit(tool):
                return self._decision(False, "tool call exceeded its per-minute limit", "rate_limit", risk)
            return self._decision(True, "allowed by policy", "allow", risk)

    def issue_approval(
        self,
        *,
        actor: str,
        reason: str,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        ttl_seconds: int = 300,
    ) -> str:
        return self.approvals.issue(
            actor=actor,
            reason=reason,
            server=server,
            tool=tool,
            arguments=arguments,
            ttl_seconds=ttl_seconds,
        )

    def redact(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: "[REDACTED]" if self._is_redacted_key(str(key)) else self.redact(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self.redact(item) for item in value]
        if isinstance(value, str):
            result = value
            for pattern in self._redacted_values:
                result = pattern.sub("[REDACTED]", result)
            return result
        return value

    def set_tool_enabled(self, tool: str, enabled: bool) -> None:
        with self._lock:
            if enabled:
                self._disabled_tools.discard(tool)
            else:
                self._disabled_tools.add(tool)

    def set_server_enabled(self, server: str, enabled: bool) -> None:
        with self._lock:
            if enabled:
                self._disabled_servers.discard(server)
            else:
                self._disabled_servers.add(server)

    def kill_switches(self) -> dict[str, list[str]]:
        with self._lock:
            return {
                "disabled_tools": sorted(self._disabled_tools),
                "disabled_servers": sorted(self._disabled_servers),
            }

    def _within_rate_limit(self, tool: str) -> bool:
        now = time.monotonic()
        calls = self._calls[tool]
        while calls and calls[0] <= now - 60:
            calls.popleft()
        limit = self.config["rate_limits_per_minute"].get(
            tool, self.config["rate_limits_per_minute"]["default"]
        )
        if len(calls) >= limit:
            return False
        calls.append(now)
        return True

    def _is_redacted_key(self, key: str) -> bool:
        return any(pattern.search(key) for pattern in self._redacted_keys)

    def _has_approval(self, server: str, tool: str, arguments: dict[str, Any]) -> bool:
        token = arguments.get("approval_token")
        if isinstance(token, str) and token:
            try:
                self.approvals.verify(token=token, server=server, tool=tool, arguments=arguments)
                return True
            except ApprovalTokenError:
                return False
        return bool(self.config.get("allow_demo_boolean_approval", True) and arguments.get("approved") is True)

    @staticmethod
    def _decision(allowed: bool, reason: str, rule: str, risk: Any) -> PolicyDecision:
        return PolicyDecision(
            allowed,
            reason,
            rule,
            risk_score=risk.score,
            risk_level=risk.level,
            evidence=risk.evidence,
        )
