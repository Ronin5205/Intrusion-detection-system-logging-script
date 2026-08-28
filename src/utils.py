from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_config_path() -> Path:
    return project_root() / "config" / "config.json"


def load_config(path: Path | None = None) -> dict[str, Any]:
    config_path = path or default_config_path()
    with config_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def resolve_config_path(value: str | None, base: Path | None = None) -> Path | None:
    if not value:
        return None
    path = Path(value)
    if path.is_absolute():
        return path
    root = base or project_root()
    return (root / path).resolve()


def resolve_config_paths(config: dict[str, Any]) -> dict[str, Any]:
    resolved = dict(config)
    path_keys = (
        "log_directory",
        "sid_msg_map",
        "gen_msg_map",
        "classification_config",
        "output_csv",
        "output_summary",
        "state_directory",
    )
    for key in path_keys:
        if key in resolved and isinstance(resolved[key], str):
            resolved[key] = str(resolve_config_path(resolved[key]))

    extra_maps = resolved.get("extra_sid_msg_maps", [])
    if isinstance(extra_maps, list):
        resolved["extra_sid_msg_maps"] = [
            str(resolve_config_path(path)) for path in extra_maps if path
        ]
    return resolved


def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def load_json_file(path: Path, default: dict[str, Any] | None = None) -> dict[str, Any]:
    if not path.exists():
        return default or {}
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def save_json_file(path: Path, data: dict[str, Any]) -> None:
    ensure_directory(path.parent)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
