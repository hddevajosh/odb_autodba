from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv


def load_project_dotenv() -> None:
    """Load .env from common launch locations without overriding shell env."""
    package_root = Path(__file__).resolve().parents[1]
    repo_root = package_root.parent
    candidates = (
        Path.cwd() / ".env",
        repo_root / ".env",
        package_root / ".env",
    )
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.exists():
            load_dotenv(resolved, override=False)
