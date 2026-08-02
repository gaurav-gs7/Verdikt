from __future__ import annotations

import argparse
import asyncio
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any


SENSITIVE_KEY_PARTS = ("api_key", "authorization", "password", "secret", "token")


class MCPClientError(RuntimeError):
    pass


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Call a remote Judikt server through the official Streamable HTTP MCP client."
    )
    result.add_argument(
        "--url",
        default=os.getenv("JUDIKT_MCP_URL", "http://127.0.0.1:8080/mcp"),
    )
    result.add_argument(
        "--token",
        default=os.getenv("JUDIKT_HTTP_BEARER_TOKEN", ""),
        help="Bearer token. Prefer JUDIKT_HTTP_BEARER_TOKEN to keep it out of shell history.",
    )
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="initialize an MCP session and list advertised tools")

    call = commands.add_parser("call", help="call one MCP tool and print its real response")
    call.add_argument("tool")
    arguments = call.add_mutually_exclusive_group()
    arguments.add_argument("--arguments", default="{}", help="JSON object sent to the tool")
    arguments.add_argument("--arguments-file", type=Path, help="path to a JSON argument object")
    call.add_argument(
        "--load-secret",
        action="append",
        default=[],
        metavar="FIELD=PATH",
        help="load a secret from a mode-0600 file into a request field",
    )
    call.add_argument(
        "--save-secret",
        action="append",
        default=[],
        metavar="FIELD=PATH",
        help="save a response field to a mode-0600 file and redact it from stdout",
    )
    call.add_argument(
        "--select",
        action="append",
        default=[],
        metavar="PATH",
        help="print only a dotted response path; may be repeated",
    )
    return result


def main() -> None:
    args = parser().parse_args()
    try:
        raise SystemExit(asyncio.run(_run(args)))
    except (MCPClientError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"mcp-client: {exc}") from None


async def _run(args: argparse.Namespace) -> int:
    try:
        import httpx
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client
    except ImportError as exc:  # pragma: no cover - optional dependency path
        raise MCPClientError(
            "remote client dependencies are missing; install python3 -m pip install -e '.[mcp]'"
        ) from exc

    headers = {"Authorization": f"Bearer {args.token}"} if args.token else {}
    async with httpx.AsyncClient(headers=headers, timeout=15) as http_client:
        async with streamable_http_client(args.url, http_client=http_client) as streams:
            read_stream, write_stream, _ = streams
            async with ClientSession(read_stream, write_stream) as session:
                initialized = await session.initialize()
                if args.command == "list":
                    listed = await session.list_tools()
                    names = sorted(tool.name for tool in listed.tools)
                    server_info = getattr(initialized, "serverInfo", None)
                    server_name = getattr(server_info, "name", "unknown")
                    print(
                        "mcp.transport=streamable-http "
                        f"protocol={initialized.protocolVersion} server={server_name}"
                    )
                    print(f"mcp.tools.count={len(names)}")
                    print("mcp.tools=" + ",".join(names))
                    return 0

                arguments = _load_arguments(args)
                safe_arguments = _redact(arguments)
                print(f"request.tool={args.tool}")
                print("request.arguments=" + _compact(safe_arguments))
                response = await session.call_tool(args.tool, arguments)
                if response.isError:
                    raise MCPClientError(f"MCP tool returned a protocol error: {response}")
                payload = response.structuredContent
                if not isinstance(payload, dict):
                    raise MCPClientError("MCP tool response did not contain structured object content")
                for field, destination in _assignments(args.save_secret):
                    value = _lookup(payload, field)
                    if not isinstance(value, str) or not value:
                        raise MCPClientError(f"response field {field!r} is not a non-empty string")
                    _write_secret(destination, value)
                    print(f"secret.{field}=saved path={destination} mode=0600")
                _print_response(payload, args.select)
                return 0


def _load_arguments(args: argparse.Namespace) -> dict[str, Any]:
    raw = args.arguments_file.read_text() if args.arguments_file else args.arguments
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise MCPClientError("tool arguments must decode to a JSON object")
    for field, source in _assignments(args.load_secret):
        mode = stat.S_IMODE(source.stat().st_mode)
        if mode & 0o077:
            raise MCPClientError(f"secret file must not grant group or other access: {source}")
        _assign(parsed, field, source.read_text().strip())
    return parsed


def _assignments(values: list[str]) -> list[tuple[str, Path]]:
    result: list[tuple[str, Path]] = []
    for value in values:
        field, separator, raw_path = value.partition("=")
        if not separator or not field.strip() or not raw_path.strip():
            raise MCPClientError("secret mappings must use FIELD=PATH")
        result.append((field.strip(), Path(raw_path).expanduser()))
    return result


def _write_secret(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        try:
            os.write(descriptor, (value + "\n").encode())
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        temporary.chmod(0o600)
        temporary.replace(path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def _print_response(payload: dict[str, Any], selected: list[str]) -> None:
    safe = _redact(payload)
    if selected:
        for path in selected:
            print(f"response.{path}=" + _compact(_lookup(safe, path)))
        return
    if {"allowed", "action", "rule"}.issubset(safe):
        print(
            "response.verdict="
            f"allowed:{str(bool(safe['allowed'])).lower()} "
            f"action:{safe['action']} rule:{safe['rule']} "
            f"risk:{safe.get('risk_level', 'unknown')}/{safe.get('risk_score', 0)}"
        )
        print(f"response.reason={safe.get('reason', '')}")
        print("response.result=" + _compact(_result_summary(safe.get("result"))))
        print(f"response.correlation_id={safe.get('correlation_id', '')}")
        return
    print("response=" + _compact(safe))


def _result_summary(value: Any) -> Any:
    if not isinstance(value, dict) or not value.get("quarantined"):
        return value
    inspection = value.get("inspection")
    findings = inspection.get("findings", []) if isinstance(inspection, dict) else []
    return {
        "quarantined": True,
        "executed": bool(value.get("executed")),
        "finding_count": len(findings),
        "rules": sorted(
            {
                str(finding.get("rule"))
                for finding in findings
                if isinstance(finding, dict) and finding.get("rule")
            }
        ),
        "content_hash": inspection.get("content_hash") if isinstance(inspection, dict) else "",
        "unsafe_text_exposed": False,
    }


def _lookup(value: Any, path: str) -> Any:
    current = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise MCPClientError(f"field path not found: {path}")
        current = current[part]
    return current


def _assign(value: dict[str, Any], path: str, assigned: Any) -> None:
    parts = path.split(".")
    current = value
    for part in parts[:-1]:
        child = current.setdefault(part, {})
        if not isinstance(child, dict):
            raise MCPClientError(f"cannot assign nested field through non-object: {path}")
        current = child
    current[parts[-1]] = assigned


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]"
            if any(part in key.lower() for part in SENSITIVE_KEY_PARTS)
            else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _compact(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


if __name__ == "__main__":
    main()
