"""Compatibility shim for legacy res.scheduler imports."""

import sys
from pathlib import Path


SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if SRC_DIR.exists():
    sys.path.insert(0, str(SRC_DIR))

from nextgenmap.scheduler import SchedulerDialog  # noqa: F401

__all__ = ["SchedulerDialog"]
