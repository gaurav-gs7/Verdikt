from __future__ import annotations

import json
import os
import threading
import uuid
from pathlib import Path
from typing import Any, Protocol


class AuditSink(Protocol):
    name: str

    def write(self, event: dict[str, Any]) -> None:
        ...


class NullAuditSink:
    name = "none"

    def write(self, event: dict[str, Any]) -> None:
        return


class JsonlAuditSink:
    name = "jsonl"

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line)
                handle.flush()


class S3AuditSink:
    name = "s3"

    def __init__(self, bucket: str, prefix: str = "verdikt/audit") -> None:
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover - optional AWS path
            raise RuntimeError("S3 audit shipping requires boto3") from exc
        self._client = boto3.client("s3")
        self.bucket = bucket
        self.prefix = prefix.strip("/")

    def write(self, event: dict[str, Any]) -> None:
        created_at = str(event["created_at"])
        day = created_at[:10]
        key = f"{self.prefix}/date={day}/{created_at}-{uuid.uuid4()}.json"
        self._client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=json.dumps(event, sort_keys=True, separators=(",", ":")).encode(),
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )


def build_audit_sink(default_jsonl_path: Path) -> AuditSink:
    mode = os.getenv("VERDIKT_AUDIT_SINK", "none").lower()
    if mode in {"", "none", "disabled"}:
        return NullAuditSink()
    if mode == "jsonl":
        path = Path(os.getenv("VERDIKT_AUDIT_JSONL_PATH", str(default_jsonl_path)))
        return JsonlAuditSink(path)
    if mode == "s3":
        bucket = os.getenv("VERDIKT_AUDIT_S3_BUCKET", "")
        if not bucket:
            raise RuntimeError("VERDIKT_AUDIT_S3_BUCKET is required for the S3 audit sink")
        return S3AuditSink(bucket, os.getenv("VERDIKT_AUDIT_S3_PREFIX", "verdikt/audit"))
    raise RuntimeError(f"unsupported audit sink mode: {mode}")
