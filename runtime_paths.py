from __future__ import annotations

import os
import re
from pathlib import Path

from odb_autodba.config import get_default_oracle_target
from odb_autodba.utils.env_loader import load_project_dotenv


PACKAGE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = PACKAGE_ROOT.parent
DEFAULT_RUNTIME_ROOT = REPO_ROOT / "runtime" / "databases"


def get_database_runtime_dir(db_key: str | None = None) -> Path:
    root = _runtime_root()
    safe_key = _resolve_db_key(db_key)
    path = root / safe_key
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_traces_dir(db_key: str | None = None) -> Path:
    path = get_database_runtime_dir(db_key=db_key) / "traces"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_indexes_dir(db_key: str | None = None) -> Path:
    path = get_database_runtime_dir(db_key=db_key) / "indexes"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_exports_dir(db_key: str | None = None) -> Path:
    path = get_database_runtime_dir(db_key=db_key) / "exports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_locks_dir(db_key: str | None = None) -> Path:
    path = get_database_runtime_dir(db_key=db_key) / "locks"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _runtime_root() -> Path:
    load_project_dotenv()
    configured = (os.getenv("ODB_AUTODBA_RUNTIME_ROOT") or "").strip()
    if configured:
        root = Path(configured)
        if not root.is_absolute():
            root = Path.cwd() / root
    else:
        root = DEFAULT_RUNTIME_ROOT
    root.mkdir(parents=True, exist_ok=True)
    return root


def _resolve_db_key(db_key: str | None) -> str:
    raw = (db_key or "").strip() or get_default_oracle_target().db_key
    safe = re.sub(r"[^a-z0-9_-]+", "-", raw.strip().lower())
    safe = re.sub(r"-{2,}", "-", safe).strip("-_")
    return safe or "default"
