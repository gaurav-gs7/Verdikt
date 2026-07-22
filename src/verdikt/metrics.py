from __future__ import annotations

import threading
from collections import Counter


class Metrics:
    def __init__(self) -> None:
        self._counters: Counter[tuple[str, str, str]] = Counter()
        self._duration_total_ms: Counter[tuple[str, str]] = Counter()
        self._finding_counters: Counter[str] = Counter()
        self._lock = threading.Lock()

    def observe(self, server: str, tool: str, allowed: bool, duration_ms: float) -> None:
        outcome = "allowed" if allowed else "blocked"
        with self._lock:
            self._counters[(server, tool, outcome)] += 1
            self._duration_total_ms[(server, tool)] += duration_ms

    def observe_finding(self, outcome: str) -> None:
        with self._lock:
            self._finding_counters[outcome] += 1

    def render(self) -> str:
        lines = [
            "# HELP verdikt_tool_calls_total MCP tool calls evaluated by the gateway.",
            "# TYPE verdikt_tool_calls_total counter",
        ]
        with self._lock:
            for (server, tool, outcome), count in sorted(self._counters.items()):
                lines.append(
                    f'verdikt_tool_calls_total{{server="{server}",tool="{tool}",outcome="{outcome}"}} {count}'
                )
            lines.extend(
                [
                    "# HELP verdikt_tool_duration_ms_total Total gateway tool-call duration in milliseconds.",
                    "# TYPE verdikt_tool_duration_ms_total counter",
                ]
            )
            for (server, tool), duration_ms in sorted(self._duration_total_ms.items()):
                lines.append(
                    f'verdikt_tool_duration_ms_total{{server="{server}",tool="{tool}"}} {duration_ms:.3f}'
                )
            lines.extend(
                [
                    "# HELP verdikt_findings_total Security findings exported by outcome.",
                    "# TYPE verdikt_findings_total counter",
                ]
            )
            for outcome, count in sorted(self._finding_counters.items()):
                lines.append(f'verdikt_findings_total{{outcome="{outcome}"}} {count}')
        return "\n".join(lines) + "\n"
