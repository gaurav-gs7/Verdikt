"""Compatibility namespace for installations created before Verdikt 0.2."""

from __future__ import annotations

import os
from pathlib import Path


for name, value in tuple(os.environ.items()):
    if name.startswith("MCP_GUARD_"):
        os.environ.setdefault("VERDIKT_" + name.removeprefix("MCP_GUARD_"), value)

# Resolve legacy submodule imports from the canonical Verdikt package directory.
__path__ = [str(Path(__file__).resolve().parents[1] / "verdikt")]

from verdikt import __version__  # noqa: E402,F401
