from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
import urllib.request
from typing import Callable

from odb_autodba.frontend import gradio_app
from odb_autodba.utils.env_loader import load_project_dotenv

LOGGER = logging.getLogger("odb_autodba.all_in_one")


def resolve_mcp_host_port() -> tuple[str, int]:
    load_project_dotenv()
    host = (os.getenv("ODB_AUTODBA_MCP_HOST") or "127.0.0.1").strip() or "127.0.0.1"
    port_raw = (os.getenv("ODB_AUTODBA_MCP_PORT") or "8000").strip()
    try:
        port = int(port_raw)
    except ValueError:
        port = 8000
    return host, port


def build_default_base_url(host: str, port: int) -> str:
    return f"http://{host}:{port}"


def resolve_mcp_base_url(host: str, port: int) -> str:
    load_project_dotenv()
    configured = (os.getenv("ODB_AUTODBA_MCP_BASE_URL") or "").strip()
    if configured:
        return configured.rstrip("/")
    return build_default_base_url(host, port)


def is_mcp_running(base_url: str, *, timeout_seconds: float = 2.0) -> bool:
    try:
        payload = _get_json(f"{base_url.rstrip('/')}/", timeout_seconds=timeout_seconds)
    except Exception:
        return False
    return bool(payload.get("ok"))


def wait_for_mcp_ready(base_url: str, timeout_seconds: float = 30.0) -> bool:
    deadline = time.monotonic() + max(0.1, timeout_seconds)
    while time.monotonic() < deadline:
        if is_mcp_running(base_url, timeout_seconds=2.0):
            return True
        time.sleep(0.5)
    return False


def start_mcp_subprocess(*, python_executable: str | None = None) -> subprocess.Popen:
    exe = python_executable or sys.executable
    env = os.environ.copy()
    LOGGER.info(
        "mcp_subprocess_env openai_api_key_present=%s reviewer_provider=%s reviewer_model=%s reviewer_timeout_sec=%s",
        str(bool((env.get("OPENAI_API_KEY") or "").strip())).lower(),
        str(env.get("ODB_AUTODBA_ACTION_REVIEWER_PROVIDER") or env.get("ODB_AUTODBA_REVIEWER_PROVIDER") or "auto"),
        str(env.get("ODB_AUTODBA_OPENAI_REVIEW_MODEL") or env.get("OPENAI_MODEL") or "gpt-5.5"),
        str(env.get("ODB_AUTODBA_OPENAI_REVIEW_TIMEOUT_SEC") or "30"),
    )
    return subprocess.Popen([exe, "-m", "odb_autodba.mcp.server"], env=env)


def configure_gradio_mcp_env(base_url: str) -> None:
    os.environ["ODB_AUTODBA_USE_MCP"] = "true"
    os.environ["ODB_AUTODBA_MCP_BASE_URL"] = base_url.rstrip("/")
    os.environ["ODB_AUTODBA_MCP_FALLBACK_LOCAL"] = "true"


def resolve_gradio_host_port() -> tuple[str, int]:
    load_project_dotenv()
    host = (os.getenv("ODB_AUTODBA_GRADIO_HOST") or "127.0.0.1").strip() or "127.0.0.1"
    port_raw = (os.getenv("ODB_AUTODBA_GRADIO_PORT") or "7860").strip()
    try:
        port = int(port_raw)
    except ValueError:
        port = 7860
    return host, port


def launch_gradio() -> None:
    gradio_host, gradio_port = resolve_gradio_host_port()
    app = gradio_app.build_app()
    kwargs = {
        "server_name": gradio_host,
        "server_port": gradio_port,
    }
    app.launch(**kwargs)


def shutdown_mcp_subprocess(proc: subprocess.Popen | None) -> None:
    if proc is None:
        return
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def run_all_in_one(*, launch_gradio_fn: Callable[[], None] | None = None, readiness_timeout_seconds: float = 30.0) -> None:
    host, port = resolve_mcp_host_port()
    base_url = resolve_mcp_base_url(host, port)
    gradio_host, gradio_port = resolve_gradio_host_port()
    launch_fn = launch_gradio_fn or launch_gradio
    LOGGER.info(
        "all_in_one_env openai_api_key_present=%s reviewer_provider=%s reviewer_model=%s reviewer_timeout_sec=%s",
        str(bool((os.getenv("OPENAI_API_KEY") or "").strip())).lower(),
        str(os.getenv("ODB_AUTODBA_ACTION_REVIEWER_PROVIDER") or os.getenv("ODB_AUTODBA_REVIEWER_PROVIDER") or "auto"),
        str(os.getenv("ODB_AUTODBA_OPENAI_REVIEW_MODEL") or os.getenv("OPENAI_MODEL") or "gpt-5.5"),
        str(os.getenv("ODB_AUTODBA_OPENAI_REVIEW_TIMEOUT_SEC") or "30"),
    )

    owned_proc: subprocess.Popen | None = None
    started_here = False
    if is_mcp_running(base_url):
        LOGGER.info("MCP server already running; reusing backend at %s", base_url)
    else:
        LOGGER.info("MCP server not running; starting backend at %s", base_url)
        owned_proc = start_mcp_subprocess()
        started_here = True

    try:
        if not wait_for_mcp_ready(base_url, timeout_seconds=readiness_timeout_seconds):
            raise RuntimeError(f"MCP server readiness check failed for {base_url}")
        LOGGER.info("MCP backend ready at %s", base_url)
        configure_gradio_mcp_env(base_url)
        LOGGER.info("Starting Gradio UI at http://%s:%s", gradio_host, gradio_port)
        LOGGER.info("Execution mode forced to MCP: ODB_AUTODBA_USE_MCP=true")
        launch_fn()
    except KeyboardInterrupt:
        LOGGER.info("Shutdown requested via Ctrl+C")
        raise
    finally:
        if started_here:
            LOGGER.info("Stopping owned MCP backend process")
            shutdown_mcp_subprocess(owned_proc)
        LOGGER.info("All-in-one launcher stopped")


def _get_json(url: str, *, timeout_seconds: float) -> dict:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
        text = response.read().decode("utf-8", errors="replace")
    payload = json.loads(text) if text else {}
    if isinstance(payload, dict):
        return payload
    return {}


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    run_all_in_one()


if __name__ == "__main__":
    main()
