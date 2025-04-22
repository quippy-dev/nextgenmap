from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINT = PROJECT_ROOT / "nextgenmap.py"


def _resolve_res_package_dir() -> Path | None:
    try:
        import res  # type: ignore
    except Exception:
        return None

    res_file = getattr(res, "__file__", None)
    if not res_file:
        return None
    return Path(res_file).resolve().parent


RESOURCES_DIR = _resolve_res_package_dir() or (PROJECT_ROOT / "res")


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
    candidate = RESOURCES_DIR.joinpath(*parts)
    if candidate.exists():
        return candidate
    return (PROJECT_ROOT / "res").joinpath(*parts)
