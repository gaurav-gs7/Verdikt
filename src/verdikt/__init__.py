"""Verdikt security and reliability control plane."""

from __future__ import annotations

import os


def promote_legacy_environment() -> None:
    """Map pre-Verdikt environment names without overriding new settings."""
    for name, value in tuple(os.environ.items()):
        if name.startswith("MCP_GUARD_"):
            os.environ.setdefault("VERDIKT_" + name.removeprefix("MCP_GUARD_"), value)


promote_legacy_environment()

__version__ = "0.2.0"
