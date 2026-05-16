---
component_id: 1.2
component_name: Lifecycle & Service Orchestrator
---

# Lifecycle & Service Orchestrator

## Component Description

Manages the operational state of the platform, handling concurrent execution of the Gradio UI and MCP server subprocesses, including environment and port management.

---

## Key References:

### /home/neha/projects/agents/odb_autodba/all_in_one.py (lines 104-134)
```
def run_all_in_one(*, launch_gradio_fn: Callable[[], None] | None = None, readiness_timeout_seconds: float = 30.0) -> None:
    host, port = resolve_mcp_host_port()
    base_url = resolve_mcp_base_url(host, port)
    gradio_host, gradio_port = resolve_gradio_host_port()
    launch_fn = launch_gradio_fn or launch_gradio

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
```

### /home/neha/projects/agents/odb_autodba/all_in_one.py (lines 58-61)
```
def start_mcp_subprocess(*, python_executable: str | None = None) -> subprocess.Popen:
    exe = python_executable or sys.executable
    env = os.environ.copy()
    return subprocess.Popen([exe, "-m", "odb_autodba.mcp.server"], env=env)
```


## Source Files:

- `all_in_one.py`

