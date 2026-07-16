from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .backends import run_backend
from .demo import run_demo
from .evals import print_evals
from .gateway import serve_gateway
from .http_app import serve_dashboard
from .runtime import MCPGuardRuntime


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="MCP-Guard runtime firewall")
    result.add_argument("--policy", type=Path, default=PROJECT_ROOT / "config" / "policies.yaml")
    result.add_argument("--audit-db", type=Path, default=PROJECT_ROOT / "data" / "mcp_guard.db")
    subparsers = result.add_subparsers(dest="command", required=True)
    demo = subparsers.add_parser("demo", help="run the interview demo")
    _add_runtime_options(demo)
    gateway = subparsers.add_parser("serve-mcp", help="expose MCP-Guard over JSON-RPC stdio")
    _add_runtime_options(gateway)
    dashboard = subparsers.add_parser("dashboard", help="run the local HTTP dashboard")
    _add_runtime_options(dashboard)
    dashboard.add_argument("--host", default="127.0.0.1")
    dashboard.add_argument("--port", default=8080, type=int)
    approval = subparsers.add_parser("issue-approval", help="issue a signed approval token")
    _add_runtime_options(approval)
    approval.add_argument("--actor", required=True)
    approval.add_argument("--reason", required=True)
    approval.add_argument("--server", required=True)
    approval.add_argument("--tool", required=True)
    approval.add_argument("--arguments", required=True, help="JSON arguments the token is bound to")
    approval.add_argument("--ttl-seconds", type=int, default=300)
    evals = subparsers.add_parser("eval", help="run adversarial safety evals")
    _add_runtime_options(evals)
    backend = subparsers.add_parser("backend", help=argparse.SUPPRESS)
    backend.add_argument("name", choices=["platform-ops", "incident"])
    return result


def _add_runtime_options(command: argparse.ArgumentParser) -> None:
    command.add_argument("--policy", type=Path, default=argparse.SUPPRESS)
    command.add_argument("--audit-db", type=Path, default=argparse.SUPPRESS)


def main() -> None:
    args = parser().parse_args()
    if args.command == "backend":
        run_backend(args.name)
        return
    if args.command == "eval":
        raise SystemExit(print_evals(args.policy))
    runtime = MCPGuardRuntime(args.policy, args.audit_db)
    if args.command == "demo":
        try:
            run_demo(runtime)
        finally:
            runtime.close()
    elif args.command == "serve-mcp":
        serve_gateway(runtime)
    elif args.command == "dashboard":
        serve_dashboard(runtime, args.host, args.port, os.getenv("MCP_GUARD_API_TOKEN"))
    elif args.command == "issue-approval":
        try:
            arguments = json.loads(args.arguments)
            if not isinstance(arguments, dict):
                raise ValueError("--arguments must decode to a JSON object")
            token = runtime.policy.issue_approval(
                actor=args.actor,
                reason=args.reason,
                server=args.server,
                tool=args.tool,
                arguments=arguments,
                ttl_seconds=args.ttl_seconds,
            )
            print(token)
        finally:
            runtime.close()


if __name__ == "__main__":
    main()
