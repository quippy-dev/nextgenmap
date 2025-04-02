from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RESOURCES_DIR = PROJECT_ROOT / "res"
ENTRYPOINT = PROJECT_ROOT / "nextgenmap.py"


def _script_info() -> tuple[str, Path]:
    main = sys.modules.get("__main__")
    if main and getattr(main, "__file__", None):
        main_path = Path(main.__file__).resolve()
        if PROJECT_ROOT in main_path.parents or main_path == ENTRYPOINT:
            return ENTRYPOINT.name, PROJECT_ROOT
        return main_path.name, main_path.parent
    return ENTRYPOINT.name, PROJECT_ROOT


SCRIPT_NAME, SCRIPT_DIR = _script_info()


def resource_path(*parts: str) -> Path:
    return RESOURCES_DIR.joinpath(*parts)
