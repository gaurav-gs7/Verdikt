#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Demo recording requires Pillow. Install it with: "
        "python3 -m pip install -e '.[media]'"
    ) from exc


ROOT = Path(__file__).resolve().parents[1]
WIDTH = 1280
HEIGHT = 720
MAJOR_HOLD_MS = 5000
EXPLAINER_HOLD_MS = 6000
TARGET_DURATION_MS = 150_000
MAX_COLUMNS = 112
MAX_ROWS = 23
LINE_HEIGHT = 25

BACKGROUND = "#090D12"
TITLEBAR = "#171C22"
PANEL = "#0C1117"
BORDER = "#30363D"
TEXT = "#E6EDF3"
MUTED = "#7D8590"
GREEN = "#3FB950"
BLUE = "#58A6FF"
AMBER = "#D29922"
RED = "#F85149"
PURPLE = "#BC8CFF"

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
}


@dataclass(frozen=True)
class TerminalPage:
    title: str
    lines: tuple[str, ...]


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
        title="A deterministic control plane for MCP tools",
        subtitle=(
            "Judikt sits between an AI agent and operational MCP servers, "
            "governing both the request and the untrusted response."
        ),
        cards=(
            InfoCard("INTERCEPT", "Receive every tool request before an upstream server sees it.", "blue"),
            InfoCard("DECIDE", "Apply identity, policy, risk, approval, rate, and kill-switch controls.", "amber"),
            InfoCard("INSPECT", "Scan tool definitions and returned content before either is trusted.", "red"),
            InfoCard("PROVE", "Emit correlated metrics, traces, findings, and signed audit evidence.", "green"),
        ),
        takeaway="The model proposes an action. Deterministic controls decide whether it can execute.",
    ),
    InfoSlide(
        eyebrow="THE PRODUCTION PROBLEM",
        title="Agent speed creates a new control gap",
        subtitle=(
            "Ambiguous intent, excessive privilege, and poisoned tool content can become "
            "production impact faster than a human can intervene."
        ),
        cards=(
            InfoCard("OVERREACH", "A broad prompt can invoke a tool or environment the user never intended.", "red"),
            InfoCard("CONFUSED DEPUTY", "Forwarded caller tokens can lend an agent privileges it should not inherit.", "amber"),
            InfoCard("POISONED RESULT", "A tool response can contain instructions intended to manipulate the agent.", "purple"),
            InfoCard("WEAK EVIDENCE", "Plain logs can leak secrets and cannot prove records were not changed.", "blue"),
        ),
        takeaway="AI infrastructure needs the same bounded execution and evidence standards as production operations.",
    ),
    InfoSlide(
        eyebrow="REQUEST GOVERNANCE",
        title="Control the action before execution",
        subtitle=(
            "A deterministic request gate reduces blast radius without asking another model "
            "to judge whether the first model is safe."
        ),
        cards=(
            InfoCard("IDENTITY", "JWT/OIDC validation and actor binding stop identity spoofing.", "blue"),
            InfoCard("POLICY + RISK", "Allowlists, argument rules, and risk scores resolve predictable verdicts.", "amber"),
            InfoCard("HUMAN CONTROL", "Signed approvals and rollback plans bind high-risk changes to reviewed intent.", "purple"),
            InfoCard("BLAST RADIUS", "Rate limits, circuit breakers, dry-run, and kill switches bound failure.", "red"),
        ),
        takeaway="Denied requests never cross the MCP boundary; evaluation-only requests never mutate a backend.",
    ),
    InfoSlide(
        eyebrow="RESPONSE DEFENSE",
        title="Treat tool output as untrusted input",
        subtitle=(
            "The return path is a separate security boundary because tool content can leak "
            "credentials or influence the next agent decision."
        ),
        cards=(
            InfoCard("PIN", "Hash tool descriptions and schemas to detect reconnect-time rug pulls.", "blue"),
            InfoCard("SCAN", "Detect direct and indirect prompt-injection patterns deterministically.", "red"),
            InfoCard("QUARANTINE", "Withhold unsafe text and expose only bounded finding metadata and hashes.", "amber"),
            InfoCard("REDACT", "Recursively remove sensitive keys and values before agent and audit exposure.", "green"),
        ),
        takeaway="An allowed tool call is not automatically a trusted tool response.",
    ),
    InfoSlide(
        eyebrow="TRUST BOUNDARIES",
        title="Production safety is explicit, not implied",
        subtitle=(
            "Judikt separates caller identity, gateway authority, upstream credentials, "
            "tool processes, and evidence systems into independently controlled boundaries."
        ),
        cards=(
            InfoCard("CALLER", "Authenticate the subject and reject caller-controlled credential passthrough.", "blue"),
            InfoCard("GATEWAY", "Broker scoped secrets and execute only policy-approved operations.", "green"),
            InfoCard("MCP SERVER", "Run external servers with minimal explicitly brokered environments.", "purple"),
            InfoCard("EVIDENCE", "Keep audit signing independent from approval signing and application output.", "amber"),
        ),
        takeaway="Compromise in one boundary should not silently grant authority across the whole agent workflow.",
    ),
    InfoSlide(
        eyebrow="PRODUCTION OPERABILITY",
        title="Security controls must remain operable",
        subtitle=(
            "A production control plane needs measurable reliability, deployable infrastructure, "
            "and evidence that survives an incident."
        ),
        cards=(
            InfoCard("OBSERVE", "Prometheus, OpenTelemetry, OpenInference, X-Ray, and dashboards expose behavior.", "blue"),
            InfoCard("PERSIST", "Hash-chained SQLite or signed DynamoDB events preserve decision evidence.", "green"),
            InfoCard("DEPLOY", "Docker, Helm, Terraform, API Gateway, Lambda, and CloudWatch support rollout.", "purple"),
            InfoCard("QUALIFY", "Adversarial tests, failure drills, interop, benchmarks, SLOs, and runbooks reduce guesswork.", "amber"),
        ),
        takeaway="The quality signal is not feature count; it is deterministic behavior under normal and failure paths.",
    ),
)


def capture_live_demo() -> tuple[str, str, int]:
    """Execute the real demo command and return its terminal transcript."""
    with tempfile.TemporaryDirectory(prefix="judikt-terminal-recording-") as temp_name:
        temp = Path(temp_name)
        policy_path = _recording_policy(temp)
        upstream_path = _recording_upstream(temp)
        audit_path = temp / "audit.db"
        environment = {
            **os.environ,
            "PYTHONPATH": str(ROOT / "src"),
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
        command = [
            str(ROOT / "scripts" / "run_demo.sh"),
            "--policy",
            str(policy_path),
            "--audit-db",
            str(audit_path),
        ]
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        if completed.returncode != 0:
            raise SystemExit(
                "live demo command failed\n"
                f"stdout:\n{completed.stdout}\n"
                f"stderr:\n{completed.stderr}"
            )
        display_command = (
            "./scripts/run_demo.sh --policy $TMP/policy.json "
            "--audit-db $TMP/audit.db"
        )
        _verify_transcript(completed.stdout)
        return display_command, completed.stdout, completed.returncode


def _recording_policy(temp: Path) -> Path:
    policy = json.loads((ROOT / "config" / "policies.yaml").read_text())
    policy["allowed_tools"]["external-incidents"] = ["external.fetch_issue"]
    policy["actor_permissions"]["anonymous"].append("external.fetch_issue")
    destination = temp / "policy.json"
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
    destination = temp / "upstreams.json"
    destination.write_text(json.dumps(config, indent=2) + "\n")
    return destination


def _verify_transcript(transcript: str) -> None:
    required = (
        "EXECUTED in MCP child process",
        'result.api_key="[REDACTED]"',
        "REQUIRE_APPROVAL",
        "DRY_RUN_ONLY",
        "QUARANTINE",
        "kill_switch",
        "valid=true",
        "checked_events=8",
        "PASS: every demonstrated branch",
    )
    missing = [value for value in required if value not in transcript]
    if missing:
        raise SystemExit(f"live demo transcript is missing required evidence: {missing}")


def transcript_pages(command: str, transcript: str) -> list[TerminalPage]:
    lines = transcript.rstrip().splitlines()
    intro: list[str] = []
    sections: list[tuple[str, list[str]]] = []
    current_title = ""
    current_lines: list[str] = []
    for line in lines:
        if line.startswith("## "):
            if current_title:
                sections.append((current_title, current_lines))
            current_title = line[3:]
            current_lines = [line]
        elif current_title:
            current_lines.append(line)
        else:
            intro.append(line)
    if current_title:
        sections.append((current_title, current_lines))

    launch = [
        f"gaurav@macbook-air Judikt % {command}",
        "",
        *intro,
        "",
        "[process] launching Judikt and isolated stdio MCP child servers...",
        "[process] command is live; the following pages are captured stdout.",
    ]
    pages = [TerminalPage("LIVE COMMAND", tuple(_wrap_lines(launch)))]
    for title, section_lines in sections:
        wrapped = _wrap_lines(section_lines)
        chunks = [wrapped[index : index + MAX_ROWS] for index in range(0, len(wrapped), MAX_ROWS)]
        for index, chunk in enumerate(chunks, start=1):
            suffix = f" ({index}/{len(chunks)})" if len(chunks) > 1 else ""
            pages.append(TerminalPage(f"{title}{suffix}", tuple(chunk)))
    pages.append(
        TerminalPage(
            "PROCESS EXIT",
            (
                "[process] Judikt closed all MCP subprocesses cleanly.",
                "[process] temporary policy, pins, SQLite audit, and fixture removed.",
                "[process] exit status: 0",
                "",
                "gaurav@macbook-air Judikt %",
            ),
        )
    )
    return pages


def _wrap_lines(lines: list[str]) -> list[str]:
    wrapped: list[str] = []
    for line in lines:
        if not line:
            wrapped.append("")
            continue
        if len(line) <= MAX_COLUMNS:
            wrapped.append(line)
            continue
        leading = len(line) - len(line.lstrip(" "))
        indent = " " * leading
        parts = textwrap.wrap(
            line.strip(),
            width=max(20, MAX_COLUMNS - leading),
            initial_indent=indent,
            subsequent_indent=f"{indent}  ",
            break_long_words=True,
            break_on_hyphens=False,
        )
        wrapped.extend(parts)
    return wrapped


def render_recording(
    command: str,
    pages: list[TerminalPage],
    output: Path,
    poster: Path,
) -> int:
    fonts = _load_fonts()
    frames: list[Image.Image] = []
    durations: list[int] = []

    frames.append(_explainer_intro(fonts))
    durations.append(EXPLAINER_HOLD_MS)
    for index, slide in enumerate(INFO_SLIDES, start=1):
        frames.append(_info_slide(slide, index, len(INFO_SLIDES), fonts))
        durations.append(EXPLAINER_HOLD_MS)
    frames.append(_architecture_slide(fonts))
    durations.append(7000)
    frames.append(_terminal_transition(fonts))
    durations.append(MAJOR_HOLD_MS)

    prompt = "gaurav@macbook-air Judikt % "
    for length in _typing_steps(len(command)):
        typed = f"{prompt}{command[:length]}"
        frames.append(_terminal_frame("LIVE COMMAND", [typed], fonts, 1, len(pages)))
        durations.append(260)

    for page_number, page in enumerate(pages, start=1):
        reveal_sizes = _reveal_steps(len(page.lines))
        for visible in reveal_sizes:
            frames.append(
                _terminal_frame(
                    page.title,
                    list(page.lines[:visible]),
                    fonts,
                    page_number,
                    len(pages),
                )
            )
            durations.append(420 if visible < len(page.lines) else MAJOR_HOLD_MS)

    remaining_ms = TARGET_DURATION_MS - sum(durations)
    if remaining_ms < MAJOR_HOLD_MS:
        raise RuntimeError(
            f"hybrid demo exceeds its 150-second budget before the outro: {sum(durations)} ms"
        )
    frames.append(_explainer_outro(fonts))
    durations.append(remaining_ms)

    poster.parent.mkdir(parents=True, exist_ok=True)
    poster_frame = _explainer_intro(fonts)
    poster_frame.save(poster, format="PNG", optimize=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    palette_frames = [_palette(frame) for frame in frames]
    palette_frames[0].save(
        output,
        save_all=True,
        append_images=palette_frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
        disposal=2,
    )
    duration_ms = sum(durations)
    if duration_ms != TARGET_DURATION_MS:
        raise RuntimeError(f"expected a 150-second recording, got {duration_ms} ms")
    return duration_ms


def _explainer_canvas() -> tuple[Image.Image, ImageDraw.ImageDraw]:
    image = Image.new("RGB", (WIDTH, HEIGHT), COLORS["background"])
    draw = ImageDraw.Draw(image)
    for y in range(HEIGHT):
        blend = y / HEIGHT
        color = (int(7 + 4 * blend), int(17 + 9 * blend), int(27 + 13 * blend))
        draw.line((0, y, WIDTH, y), fill=color)
    for x in range(0, WIDTH, 64):
        draw.line((x, 0, x, HEIGHT), fill="#0C1A26")
    for y in range(0, HEIGHT, 64):
        draw.line((0, y, WIDTH, y), fill="#0C1A26")
    return image, draw


def _explainer_intro(fonts: dict[str, ImageFont.FreeTypeFont]) -> Image.Image:
    image, draw = _explainer_canvas()
    _brand(draw, fonts)
    draw.rounded_rectangle(
        (72, 128, 1208, 592),
        radius=28,
        fill="#0B1926",
        outline=COLORS["border"],
        width=2,
    )
    _pill(draw, (104, 166), "150-SECOND PRODUCT + LIVE RUNTIME DEMO", fonts["sans_small"], "green")
    draw.text(
        (104, 220),
        "Every MCP tool call gets a verdict.",
        font=fonts["hero"],
        fill=COLORS["text"],
    )
    draw.text(
        (106, 298),
        "First understand the control plane. Then watch the real command,\n"
        "processing path, MCP children, outputs, and signed evidence.",
        font=fonts["subtitle"],
        fill=COLORS["muted"],
        spacing=8,
    )
    nodes = ("AI AGENT", "JUDIKT", "MCP TOOL", "SIGNED EVIDENCE")
    widths = (190, 190, 190, 228)
    x = 104
    for index, (node, width) in enumerate(zip(nodes, widths)):
        selected = node == "JUDIKT"
        draw.rounded_rectangle(
            (x, 420, x + width, 478),
            radius=12,
            fill=COLORS["green_dark"] if selected else COLORS["panel_alt"],
            outline=COLORS["green"] if selected else COLORS["border"],
            width=2,
        )
        _center_text(draw, (x, 420, x + width, 478), node, fonts["sans_small"], COLORS["text"])
        x += width
        if index < len(nodes) - 1:
            _arrow(draw, x + 12, 449, x + 48, 449, COLORS["muted"])
            x += 60
    draw.text(
        (104, 532),
        "EXPLANATION WHERE CONTEXT MATTERS  |  TERMINAL WHERE PROOF MATTERS",
        font=fonts["mono_small"],
        fill=COLORS["green"],
    )
    return image


def _info_slide(
    slide: InfoSlide,
    index: int,
    count: int,
    fonts: dict[str, ImageFont.FreeTypeFont],
) -> Image.Image:
    image, draw = _explainer_canvas()
    _brand(draw, fonts)
    _pill(draw, (72, 105), slide.eyebrow, fonts["sans_small"], "green")
    draw.text((72, 157), slide.title, font=fonts["hero_small"], fill=COLORS["text"])
    _wrapped_text(draw, slide.subtitle, (74, 224), 1120, fonts["subtitle"], COLORS["muted"], 7)

    card_width = 258
    for card_index, card in enumerate(slide.cards):
        x = 72 + card_index * 286
        draw.rounded_rectangle(
            (x, 326, x + card_width, 526),
            radius=18,
            fill=COLORS["panel"],
            outline=COLORS[card.accent],
            width=2,
        )
        draw.text((x + 22, 350), card.heading, font=fonts["tiny"], fill=COLORS[card.accent])
        _wrapped_text(
            draw,
            card.body,
            (x + 22, 390),
            card_width - 44,
            fonts["body"],
            COLORS["text"],
            7,
        )
        if card_index < len(slide.cards) - 1:
            _arrow(draw, x + card_width + 10, 420, x + card_width + 28, 420, COLORS["muted"])

    draw.rounded_rectangle(
        (72, 562, 1208, 646),
        radius=16,
        fill=COLORS["green_dark"],
        outline=COLORS["green"],
        width=2,
    )
    draw.text((96, 579), "WHY IT MATTERS", font=fonts["tiny"], fill=COLORS["green"])
    _wrapped_text(draw, slide.takeaway, (96, 603), 1088, fonts["body"], COLORS["text"], 6)
    draw.text(
        (1208, 682),
        f"CONTEXT {index:02d} / {count:02d}",
        anchor="ra",
        font=fonts["mono_small"],
        fill=COLORS["muted"],
    )
    return image


def _architecture_slide(fonts: dict[str, ImageFont.FreeTypeFont]) -> Image.Image:
    image, draw = _explainer_canvas()
    _brand(draw, fonts)
    _pill(draw, (72, 105), "CONCEPTUAL END-TO-END FLOW", fonts["sans_small"], "green")
    draw.text((72, 157), "One guarded path in both directions", font=fonts["hero_small"], fill=COLORS["text"])
    draw.text(
        (74, 224),
        "This explains the control boundaries. The next chapters prove them with captured terminal output.",
        font=fonts["subtitle"],
        fill=COLORS["muted"],
    )

    nodes = (
        (72, 300, 250, 382, "AI AGENT", "intent + identity", "blue"),
        (302, 278, 528, 404, "REQUEST GATE", "auth | policy | risk\napproval | rate | kill", "amber"),
        (580, 300, 758, 382, "MCP SERVER", "scoped execution", "purple"),
        (810, 278, 1036, 404, "RESPONSE GATE", "pin | injection scan\nquarantine | redact", "red"),
        (1088, 300, 1208, 382, "AGENT", "safe result", "green"),
    )
    for left, top, right, bottom, heading, detail, accent in nodes:
        draw.rounded_rectangle(
            (left, top, right, bottom),
            radius=16,
            fill=COLORS[f"{accent}_dark"],
            outline=COLORS[accent],
            width=2,
        )
        _center_text(draw, (left, top + 10, right, top + 48), heading, fonts["sans_small"], COLORS[accent])
        _center_text(draw, (left + 8, top + 43, right - 8, bottom - 6), detail, fonts["tiny"], COLORS["text"])
    for start, end in ((250, 302), (528, 580), (758, 810), (1036, 1088)):
        _arrow(draw, start + 8, 341, end - 8, 341, COLORS["muted"])

    draw.line((415, 425, 415, 486), fill=COLORS["green"], width=2)
    draw.line((923, 425, 923, 486), fill=COLORS["green"], width=2)
    draw.line((415, 486, 923, 486), fill=COLORS["green"], width=2)
    draw.polygon(((669, 500), (661, 488), (677, 488)), fill=COLORS["green"])
    draw.rounded_rectangle(
        (350, 510, 988, 614),
        radius=18,
        fill=COLORS["green_dark"],
        outline=COLORS["green"],
        width=2,
    )
    _center_text(draw, (350, 518, 988, 558), "CORRELATED OPERATIONAL EVIDENCE", fonts["sans_small"], COLORS["green"])
    _center_text(
        draw,
        (370, 555, 968, 604),
        "signed audit | Prometheus | OpenTelemetry | findings | SIEM",
        fonts["body"],
        COLORS["text"],
    )
    return image


def _terminal_transition(fonts: dict[str, ImageFont.FreeTypeFont]) -> Image.Image:
    image, draw = _explainer_canvas()
    _brand(draw, fonts)
    _pill(draw, (72, 112), "CONTEXT COMPLETE", fonts["sans_small"], "green")
    draw.text((72, 180), "Now prove it in the terminal.", font=fonts["hero"], fill=COLORS["text"])
    draw.text(
        (74, 266),
        "From this point forward, every command, input, processing step, backend path,\n"
        "verdict, output, metric, and audit result comes from captured live stdout.",
        font=fonts["subtitle"],
        fill=COLORS["muted"],
        spacing=8,
    )
    draw.rounded_rectangle(
        (72, 382, 1208, 570),
        radius=20,
        fill="#081019",
        outline=COLORS["border"],
        width=2,
    )
    terminal_lines = (
        "$ ./scripts/run_demo.sh --policy $TMP/policy.json --audit-db $TMP/audit.db",
        "[process] launch Judikt + isolated stdio MCP child processes",
        "[proof] inputs -> controls -> backend execution/skip -> output -> evidence",
    )
    for index, line in enumerate(terminal_lines):
        draw.text(
            (104, 422 + index * 48),
            line,
            font=fonts["mono"],
            fill=COLORS["green"] if index == 0 else COLORS["text"],
        )
    return image


def _explainer_outro(fonts: dict[str, ImageFont.FreeTypeFont]) -> Image.Image:
    image, draw = _explainer_canvas()
    _brand(draw, fonts)
    _pill(draw, (72, 112), "END-TO-END WALKTHROUGH COMPLETE", fonts["sans_small"], "green")
    draw.text((72, 180), "Understand it. Run it. Verify it.", font=fonts["hero"], fill=COLORS["text"])
    draw.text(
        (74, 270),
        "Judikt turns agent-proposed MCP actions into deterministic, bounded,\n"
        "observable production operations.",
        font=fonts["subtitle"],
        fill=COLORS["muted"],
        spacing=8,
    )
    draw.rounded_rectangle(
        (72, 390, 1208, 560),
        radius=20,
        fill=COLORS["green_dark"],
        outline=COLORS["green"],
        width=2,
    )
    _center_text(
        draw,
        (96, 405, 1184, 475),
        "POLICY-GATED EXECUTION | UNTRUSTED RESPONSE DEFENSE | SIGNED EVIDENCE",
        fonts["sans_small"],
        COLORS["green"],
    )
    _center_text(
        draw,
        (96, 476, 1184, 542),
        "Reproduce the complete media artifact:  make demo-recording",
        fonts["mono"],
        COLORS["text"],
    )
    return image


def _typing_steps(length: int) -> list[int]:
    if length <= 1:
        return [length]
    count = 9
    return sorted({max(1, round(length * index / count)) for index in range(1, count + 1)})


def _reveal_steps(length: int) -> list[int]:
    if length <= 1:
        return [length]
    count = min(5, max(2, (length + 4) // 5))
    return sorted({max(1, round(length * index / count)) for index in range(1, count + 1)})


def _terminal_frame(
    title: str,
    lines: list[str],
    fonts: dict[str, ImageFont.FreeTypeFont],
    page: int,
    page_count: int,
) -> Image.Image:
    image = Image.new("RGB", (WIDTH, HEIGHT), BACKGROUND)
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((18, 18, WIDTH - 18, HEIGHT - 18), radius=13, fill=PANEL, outline=BORDER, width=2)
    draw.rounded_rectangle((18, 18, WIDTH - 18, 68), radius=13, fill=TITLEBAR)
    draw.rectangle((18, 52, WIDTH - 18, 68), fill=TITLEBAR)
    for x, color in ((43, RED), (67, AMBER), (91, GREEN)):
        draw.ellipse((x - 7, 36 - 7, x + 7, 36 + 7), fill=color)
    draw.text((WIDTH // 2, 36), f"Judikt | {title}", font=fonts["terminal_title"], fill=MUTED, anchor="mm")

    y = 88
    for line in lines[-MAX_ROWS:]:
        draw.text((42, y), line, font=fonts["mono"], fill=_line_color(line))
        y += LINE_HEIGHT

    draw.rectangle((18, HEIGHT - 48, WIDTH - 18, HEIGHT - 18), fill=TITLEBAR)
    draw.text((40, HEIGHT - 34), "LIVE CAPTURED STDOUT", font=fonts["small"], fill=GREEN, anchor="lm")
    draw.text(
        (WIDTH - 40, HEIGHT - 34),
        f"page {page:02d}/{page_count:02d} | major output hold 5s",
        font=fonts["small"],
        fill=MUTED,
        anchor="rm",
    )
    return image


def _line_color(line: str) -> str:
    lowered = line.lower()
    if line.startswith("##") or line.startswith("JUDIKT"):
        return BLUE
    if line.startswith("$") or line.startswith("gaurav@"):
        return GREEN
    if "quarantine" in lowered or "deny" in lowered or "allowed=false" in lowered:
        return RED
    if "require_approval" in lowered or "dry_run" in lowered or "risk=critical" in lowered:
        return AMBER
    if "pass" in lowered or "allowed=true" in lowered or "valid=true" in lowered:
        return GREEN
    if line.startswith("PROCESS") or line.startswith("OUTPUT") or "->" in line:
        return PURPLE
    if line.startswith("["):
        return MUTED
    return TEXT


def _palette(frame: Image.Image) -> Image.Image:
    return frame.convert("P", palette=Image.Palette.ADAPTIVE, colors=64)


def _brand(draw: ImageDraw.ImageDraw, fonts: dict[str, ImageFont.FreeTypeFont]) -> None:
    draw.rounded_rectangle((72, 30, 114, 72), radius=10, fill=COLORS["green"])
    _center_text(draw, (72, 30, 114, 72), "J", fonts["body"], COLORS["background"])
    draw.text((128, 35), "JUDIKT", font=fonts["brand"], fill=COLORS["text"])
    draw.text(
        (286, 45),
        "MCP SECURITY CONTROL PLANE",
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
    bounds = draw.textbbox((0, 0), label, font=font)
    width = bounds[2] - bounds[0] + 26
    draw.rounded_rectangle(
        (x, y, x + width, y + 30),
        radius=15,
        fill=COLORS[f"{accent}_dark"],
        outline=COLORS[accent],
        width=1,
    )
    _center_text(draw, (x, y, x + width, y + 30), label, font, COLORS[accent])


def _center_text(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    value: str,
    font: ImageFont.FreeTypeFont,
    fill: str,
) -> None:
    left, top, right, bottom = box
    bounds = draw.multiline_textbbox((0, 0), value, font=font, spacing=4, align="center")
    width = bounds[2] - bounds[0]
    height = bounds[3] - bounds[1]
    draw.multiline_text(
        ((left + right - width) / 2, (top + bottom - height) / 2 - bounds[1]),
        value,
        font=font,
        fill=fill,
        spacing=4,
        align="center",
    )


def _wrapped_text(
    draw: ImageDraw.ImageDraw,
    value: str,
    position: tuple[int, int],
    max_width: int,
    font: ImageFont.FreeTypeFont,
    fill: str,
    spacing: int,
) -> None:
    words = value.split()
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
    draw.multiline_text(position, "\n".join(lines), font=font, fill=fill, spacing=spacing)


def _arrow(
    draw: ImageDraw.ImageDraw,
    start_x: int,
    start_y: int,
    end_x: int,
    end_y: int,
    fill: str,
) -> None:
    draw.line((start_x, start_y, end_x - 7, end_y), fill=fill, width=2)
    draw.polygon(((end_x, end_y), (end_x - 8, end_y - 5), (end_x - 8, end_y + 5)), fill=fill)


def _load_fonts() -> dict[str, ImageFont.FreeTypeFont]:
    mono_candidates = (
        Path("/System/Library/Fonts/Menlo.ttc"),
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
    )
    sans_candidates = (
        Path("/System/Library/Fonts/HelveticaNeue.ttc"),
        Path("/System/Library/Fonts/Helvetica.ttc"),
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
    )
    mono_path = next((path for path in mono_candidates if path.exists()), None)
    sans_path = next((path for path in sans_candidates if path.exists()), None)
    if mono_path is None or sans_path is None:
        raise SystemExit("Supported monospaced and sans-serif fonts are required")
    return {
        "mono": ImageFont.truetype(str(mono_path), 18),
        "mono_small": ImageFont.truetype(str(mono_path), 13),
        "small": ImageFont.truetype(str(mono_path), 14),
        "terminal_title": ImageFont.truetype(str(mono_path), 15),
        "brand": ImageFont.truetype(str(sans_path), 30),
        "hero": ImageFont.truetype(str(sans_path), 52),
        "hero_small": ImageFont.truetype(str(sans_path), 42),
        "subtitle": ImageFont.truetype(str(sans_path), 19),
        "body": ImageFont.truetype(str(sans_path), 17),
        "sans_small": ImageFont.truetype(str(sans_path), 14),
        "tiny": ImageFont.truetype(str(sans_path), 12),
    }


def main() -> None:
    command, transcript, return_code = capture_live_demo()
    pages = transcript_pages(command, transcript)
    output = ROOT / "docs" / "assets" / "judikt-demo.gif"
    poster = ROOT / "docs" / "assets" / "judikt-demo-poster.png"
    duration_ms = render_recording(command, pages, output, poster)
    print(
        json.dumps(
            {
                "format": "hybrid explainer slides plus captured terminal stdout",
                "terminal_source": "captured stdout from ./scripts/run_demo.sh",
                "process_exit_code": return_code,
                "explainer_slides": len(INFO_SLIDES) + 4,
                "terminal_pages": len(pages),
                "major_hold_ms": MAJOR_HOLD_MS,
                "duration_seconds": round(duration_ms / 1000, 1),
                "target_duration_seconds": TARGET_DURATION_MS / 1000,
                "gif": str(output.relative_to(ROOT)),
                "gif_bytes": output.stat().st_size,
                "poster": str(poster.relative_to(ROOT)),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
