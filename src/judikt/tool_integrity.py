from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .content_guard import ContentGuard


class ToolIntegrityError(RuntimeError):
    pass


@dataclass(frozen=True)
class ToolIntegrityReport:
    server: str
    digest: str
    status: str
    tool_count: int

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class ToolIntegrityStore:
    """Trust-on-first-use pins for MCP tool definitions with fail-closed drift checks."""

    def __init__(self, path: Path, content_guard: ContentGuard, mode: str | None = None) -> None:
        self.path = path
        self.content_guard = content_guard
        self.mode = mode or os.getenv("JUDIKT_TOOL_PIN_MODE", "enforce")
        if self.mode not in {"enforce", "refresh", "disabled"}:
            raise ValueError("tool pin mode must be enforce, refresh, or disabled")
        self._lock = threading.Lock()

    def verify(self, server: str, tools: list[dict[str, Any]]) -> ToolIntegrityReport:
        inspection = self.content_guard.inspect(tools)
        if not inspection.allowed:
            rules = sorted({finding.rule for finding in inspection.findings})
            raise ToolIntegrityError(
                f"tool metadata from {server!r} was quarantined: {', '.join(rules)}"
            )
        digest = _tool_digest(tools)
        if self.mode == "disabled":
            return ToolIntegrityReport(server, digest, "disabled", len(tools))
        with self._lock:
            pins = self._read()
            observed = pins.get(server)
            if observed is None or self.mode == "refresh":
                pins[server] = digest
                self._write(pins)
                status = "pinned" if observed is None else "refreshed"
                return ToolIntegrityReport(server, digest, status, len(tools))
            if observed != digest:
                raise ToolIntegrityError(
                    f"tool definition drift detected for {server!r}; explicit pin refresh is required"
                )
            return ToolIntegrityReport(server, digest, "verified", len(tools))

    def _read(self) -> dict[str, str]:
        if not self.path.exists():
            return {}
        parsed = json.loads(self.path.read_text())
        if not isinstance(parsed, dict):
            raise ToolIntegrityError("tool pin file must contain a JSON object")
        return {str(key): str(value) for key, value in parsed.items()}

    def _write(self, pins: dict[str, str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(pins, indent=2, sort_keys=True) + "\n")
        temporary.replace(self.path)


def _tool_digest(tools: list[dict[str, Any]]) -> str:
    canonical = json.dumps(tools, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def verify_unique_tool_names(definitions: dict[str, list[dict[str, Any]]]) -> None:
    owners: dict[str, str] = {}
    for server, tools in definitions.items():
        for tool in tools:
            name = str(tool.get("name", ""))
            if not name:
                raise ToolIntegrityError(f"MCP server {server!r} advertised a tool without a name")
            previous = owners.get(name)
            if previous is not None:
                raise ToolIntegrityError(
                    f"cross-server tool shadowing detected: {name!r} is advertised by {previous!r} and {server!r}"
                )
            owners[name] = server
