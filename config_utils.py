from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import yaml


DEFAULT_CONFIG_PATH = Path(r"Magneto\config\default.yaml")

def load_config(config_path: str | Path = DEFAULT_CONFIG_PATH) -> Dict[str, Any]:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    if not isinstance(cfg, dict):
        raise ValueError("Config file must load into a dictionary.")

    return cfg


def get_device_config(cfg: Dict[str, Any]) -> str:
    runtime = cfg.get("runtime", {})
    return str(runtime.get("device", "auto")).lower()


if __name__ == "__main__":
    cfg = load_config()
    print("Loaded config successfully.")
    print(cfg["project"]["root_dir"])