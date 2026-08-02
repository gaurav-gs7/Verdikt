"""Compatibility namespace for MCP-Guard installations upgrading to Judikt."""

from __future__ import annotations

from pathlib import Path

# Resolve legacy submodule imports from the canonical Judikt package directory.
__path__ = [str(Path(__file__).resolve().parents[1] / "judikt")]

from judikt import __version__  # noqa: E402,F401
