from __future__ import annotations

import os

from odb_autodba.utils.env_loader import load_project_dotenv


def load_env() -> None:
    load_project_dotenv()


def env_flag(name: str, default: bool = False) -> bool:
    load_env()
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}
