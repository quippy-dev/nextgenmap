"""Compatibility shim for legacy res.searchsploit imports."""

import sys
from pathlib import Path


SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if SRC_DIR.exists():
    sys.path.insert(0, str(SRC_DIR))

from nextgenmap.searchsploit import SearchSploitWidget  # noqa: F401

__all__ = ["SearchSploitWidget"]
