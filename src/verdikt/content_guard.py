from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ContentFinding:
    rule: str
    severity: str
    path: str
    evidence_hash: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class ContentInspection:
    allowed: bool
    findings: list[ContentFinding]
    content_hash: str
    scanned_strings: int
    truncated: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "findings": [finding.as_dict() for finding in self.findings],
            "content_hash": self.content_hash,
            "scanned_strings": self.scanned_strings,
            "truncated": self.truncated,
        }


DEFAULT_INJECTION_RULES = {
    "instruction_override": r"\b(ignore|disregard|forget)\b.{0,80}\b(previous|prior|system|developer|safety)\b.{0,40}\b(instruction|message|rule|policy)s?\b",
    "authority_impersonation": r"\b(system|developer|administrator)\s*(message|instruction|override)\s*[:=]",
    "secret_exfiltration": r"\b(exfiltrat|upload|send|post|transmit)\w*\b.{0,100}\b(secret|credential|token|api[_ -]?key|environment variable)s?\b",
    "tool_coercion": r"\b(you\s+must|must|immediately|first|before\s+responding|without\s+asking)\b.{0,60}\b(call|invoke|execute|run|use)\b",
    "concealment": r"\b(do not|don't|never)\b.{0,60}\b(tell|show|mention|reveal|notify)\b.{0,40}\b(user|operator|reviewer)\b",
    "role_reassignment": r"\byou are now\b|\bact as\b.{0,50}\b(system|administrator|root|developer)\b",
}

INVISIBLE_CONTROL_PATTERN = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")


class ContentGuard:
    """Deterministic inspection for untrusted MCP results and tool metadata."""

    def __init__(
        self,
        *,
        mode: str = "fail_closed",
        max_scan_bytes: int = 262_144,
        rules: dict[str, str] | None = None,
    ) -> None:
        if mode not in {"fail_closed", "report_only", "disabled"}:
            raise ValueError("content inspection mode must be fail_closed, report_only, or disabled")
        self.mode = mode
        self.max_scan_bytes = max_scan_bytes
        self._rules = {
            name: re.compile(pattern, re.IGNORECASE | re.DOTALL)
            for name, pattern in (rules or DEFAULT_INJECTION_RULES).items()
        }

    @classmethod
    def from_policy(cls, config: dict[str, Any]) -> "ContentGuard":
        settings = config.get("inbound_content_inspection", {})
        return cls(
            mode=str(settings.get("mode", "fail_closed")),
            max_scan_bytes=int(settings.get("max_scan_bytes", 262_144)),
            rules=settings.get("patterns") or None,
        )

    def inspect(self, value: Any) -> ContentInspection:
        canonical = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
        content_hash = hashlib.sha256(canonical.encode()).hexdigest()
        if self.mode == "disabled":
            return ContentInspection(True, [], content_hash, 0)

        findings: list[ContentFinding] = []
        scanned_bytes = 0
        scanned_strings = 0
        truncated = False
        for path, text in _walk_strings(value):
            encoded = text.encode(errors="replace")
            remaining = self.max_scan_bytes - scanned_bytes
            if remaining <= 0:
                truncated = True
                break
            if len(encoded) > remaining:
                truncated = True
            candidate = encoded[:remaining].decode(errors="replace")
            scanned_bytes += len(candidate.encode())
            scanned_strings += 1
            for name, pattern in self._rules.items():
                match = pattern.search(candidate)
                if match:
                    findings.append(_finding(name, "high", path, match.group(0)))
            invisible = INVISIBLE_CONTROL_PATTERN.search(candidate)
            if invisible:
                findings.append(_finding("invisible_unicode_control", "high", path, invisible.group(0)))

        if truncated:
            findings.append(_finding("scan_limit_exceeded", "high", "$", content_hash))

        blocked = bool(findings) and self.mode == "fail_closed"
        return ContentInspection(not blocked, findings, content_hash, scanned_strings, truncated)


def quarantine_result(inspection: ContentInspection) -> dict[str, Any]:
    return {
        "quarantined": True,
        "executed": True,
        "reason": "MCP tool output matched deterministic prompt-injection rules",
        "inspection": inspection.as_dict(),
    }


def _walk_strings(value: Any, path: str = "$") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(value, str):
        found.append((path, value))
    elif isinstance(value, dict):
        for key, item in value.items():
            found.extend(_walk_strings(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(_walk_strings(item, f"{path}[{index}]"))
    return found


def _finding(rule: str, severity: str, path: str, evidence: str) -> ContentFinding:
    return ContentFinding(
        rule=rule,
        severity=severity,
        path=path,
        evidence_hash=hashlib.sha256(evidence.encode()).hexdigest(),
    )
