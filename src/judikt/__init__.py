"""Judikt security and reliability control plane."""

from __future__ import annotations

import os


def promote_legacy_environment() -> None:
    """Map pre-Judikt environment names without overriding new settings."""
    environment = tuple(os.environ.items())
    for prefix in ("MCP_GUARD_",):
        for name, value in environment:
            if name.startswith(prefix):
                os.environ.setdefault("JUDIKT_" + name.removeprefix(prefix), value)


promote_legacy_environment()

__version__ = "0.3.0"
