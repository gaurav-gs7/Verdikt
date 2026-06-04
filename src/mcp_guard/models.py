from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)

    def as_mcp(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    rule: str
    risk_score: int = 0
    risk_level: str = "low"
    evidence: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolCallResult:
    correlation_id: str
    allowed: bool
    server: str
    tool: str
    reason: str
    result: Any = None
    risk_score: int = 0
    risk_level: str = "low"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)
