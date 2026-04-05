import sys
from pathlib import Path


def bundle_root() -> Path:
    """Directory that contains bundled read-only resources."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent.parent


def app_root() -> Path:
    """Directory that should hold writable runtime state."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def resource_path(relative_path: str) -> str:
    """Resolve a bundled/static resource path."""
    return str((bundle_root() / relative_path).resolve())


def runtime_path(relative_path: str) -> str:
    """Resolve a writable runtime path next to the app."""
    return str((app_root() / relative_path).resolve())


def resolve_runtime_path(path_like: str) -> str:
    """Resolve absolute paths as-is and relative paths under app_root()."""
    path = Path(path_like)
    if path.is_absolute():
        return str(path)
    return runtime_path(str(path))


def runtime_or_resource_path(relative_path: str) -> str:
    """Prefer an external runtime file, then fall back to the bundled copy."""
    runtime_candidate = Path(runtime_path(relative_path))
    if runtime_candidate.exists():
        return str(runtime_candidate)
    return resource_path(relative_path)
