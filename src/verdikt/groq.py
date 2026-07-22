from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from .telemetry import Telemetry


class IncidentAnalyst:
    def __init__(self, api_key: str | None = None, telemetry: Telemetry | None = None) -> None:
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        self.model = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
        self.telemetry = telemetry or Telemetry()

    def summarize(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        if not self.api_key:
            return {"provider": "local-fallback", "summary": self._fallback(events)}
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are an SRE incident analyst. Summarize the supplied MCP audit events "
                        "in five concise bullets: impact, blocked activity, allowed actions, "
                        "likely cause, and next remediation. Do not invent facts."
                    ),
                },
                {"role": "user", "content": json.dumps(events[:30], sort_keys=True)},
            ],
            "temperature": 0.1,
        }
        with self.telemetry.span(
            "groq.incident_summary",
            "LLM",
            {"llm.provider": "groq", "llm.model_name": self.model},
        ) as span:
            span.set_json_input({"events": events[:30]})
            request = urllib.request.Request(
                "https://api.groq.com/openai/v1/chat/completions",
                data=json.dumps(payload).encode(),
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=15) as response:
                    body = json.load(response)
                result = {
                    "provider": "groq",
                    "model": self.model,
                    "summary": body["choices"][0]["message"]["content"],
                }
            except (urllib.error.URLError, KeyError, TimeoutError) as exc:
                result = {
                    "provider": "local-fallback",
                    "warning": f"Groq request failed: {exc}",
                    "summary": self._fallback(events),
                }
            span.set_json_output(result)
            return result

    @staticmethod
    def _fallback(events: list[dict[str, Any]]) -> str:
        blocked = [event for event in events if not event["allowed"]]
        allowed = [event for event in events if event["allowed"]]
        rules = sorted({event["rule"] for event in blocked})
        return "\n".join(
            [
                f"- Impact: reviewed {len(events)} MCP tool calls; {len(blocked)} were blocked.",
                f"- Blocked activity: rules triggered: {', '.join(rules) if rules else 'none'}.",
                f"- Allowed actions: {len(allowed)} calls completed through the gateway.",
                "- Likely cause: inspect the correlated audit events before assigning root cause.",
                "- Next remediation: keep risky tools approval-gated and validate kill-switch drills.",
            ]
        )
