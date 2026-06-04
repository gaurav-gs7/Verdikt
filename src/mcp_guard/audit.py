from __future__ import annotations

import datetime as dt
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any


class AuditStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                correlation_id TEXT NOT NULL,
                server TEXT NOT NULL,
                tool TEXT NOT NULL,
                allowed INTEGER NOT NULL,
                rule TEXT NOT NULL,
                reason TEXT NOT NULL,
                arguments_json TEXT NOT NULL,
                result_json TEXT,
                duration_ms REAL NOT NULL
            )
            """
        )
        self._connection.commit()

    def record(
        self,
        *,
        correlation_id: str,
        server: str,
        tool: str,
        allowed: bool,
        rule: str,
        reason: str,
        arguments: Any,
        result: Any,
        duration_ms: float,
    ) -> None:
        with self._lock:
            self._connection.execute(
                """
                INSERT INTO audit_events (
                    created_at, correlation_id, server, tool, allowed, rule,
                    reason, arguments_json, result_json, duration_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    dt.datetime.now(dt.UTC).isoformat(),
                    correlation_id,
                    server,
                    tool,
                    int(allowed),
                    rule,
                    reason,
                    json.dumps(arguments, sort_keys=True),
                    json.dumps(result, sort_keys=True) if result is not None else None,
                    round(duration_ms, 3),
                ),
            )
            self._connection.commit()

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        events = []
        for row in rows:
            event = dict(row)
            event["allowed"] = bool(event["allowed"])
            event["arguments"] = json.loads(event.pop("arguments_json"))
            raw_result = event.pop("result_json")
            event["result"] = json.loads(raw_result) if raw_result is not None else None
            events.append(event)
        return events

    def close(self) -> None:
        self._connection.close()

