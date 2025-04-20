"""Compatibility shim for legacy res.nmap_utils imports."""

import sys
from pathlib import Path


SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if SRC_DIR.exists():
    sys.path.insert(0, str(SRC_DIR))

from nextgenmap.nmap_utils import (  # noqa: F401
    NmapProcess,
    setup_profiles,
    highlight_rules,
    custom_split,
    remove_argument,
    exclude_args_dict,
    strip_output_flags,
)

__all__ = [
    "NmapProcess",
    "setup_profiles",
    "highlight_rules",
    "custom_split",
    "remove_argument",
    "exclude_args_dict",
    "strip_output_flags",
]
