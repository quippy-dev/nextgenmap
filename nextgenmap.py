"""Legacy entry point kept for GUI compatibility."""

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent
SRC_DIR = REPO_ROOT / "src"
if SRC_DIR.exists():
    sys.path.insert(0, str(SRC_DIR))

from nextgenmap.app import main


if __name__ == "__main__":
    raise SystemExit(main())
