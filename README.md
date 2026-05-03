# Oracle AutoDBA — AI-Powered Oracle DBA Platform

Oracle AutoDBA is an AI-driven Oracle DBA assistant for operational analysis and diagnostics.
It combines health checks, AI investigations, an MCP backend, and a file-backed job queue for reliable async workflows.

## Key Features

- Oracle Health Check
- Active Sessions analysis
- Historical Trends
- AI Investigation
- Root Cause Analysis
- Multi-database support
- MCP backend with job queue
- Dynamic Oracle connection input from UI
- SSH host checks (optional)
- Recent Jobs panel

## Architecture

```text
+----------------+     +----------------+     +----------------+     +----------------+     +----------------+
|   Gradio UI    | --> |    MCP API     | --> |   Job Queue    | --> |  Service Layer | --> | Oracle Engine  |
+----------------+     +----------------+     +----------------+     +----------------+     +----------------+
```

## Quick Start

```bash
uv run -m odb_autodba.all_in_one
```

This command:
- Starts the MCP backend
- Starts the Gradio UI
- Runs the UI in MCP mode

## Execution Modes

### MCP mode (recommended)

Use async jobs via the MCP backend:

```env
ODB_AUTODBA_USE_MCP=true
```

### Local mode

Use direct in-process execution without MCP job queue:

```env
ODB_AUTODBA_USE_MCP=false
```

## UI Overview

Main UI components:
- Target Database dropdown (registry targets)
- Ad-hoc Oracle target input (dynamic target creation)
- Action buttons:
  - `Check Health`
  - `Show Active Sessions`
  - `Historical Trends`
  - `Investigate with AI`
- Compact Recent Jobs panel

## Multi-Database Support

Oracle targets are isolated by `db_key`, allowing concurrent workflows across environments.

- Registry-based targets from configuration
- Dynamic targets submitted from the UI
- Runtime artifacts isolated per database key

Example runtime layout:

```text
runtime/databases/<db_key>/...
```

## Environment Configuration

Use a local `.env` file for runtime configuration and secrets. Start from `.env.example`.

- Keep credentials in environment variables
- Do not hardcode passwords in source files
- Do not commit real secrets

## MCP API Endpoints

- `GET /databases`
- `POST /health`
- `POST /sessions`
- `POST /history`
- `POST /investigate`
- `GET /job/{job_id}`
- `GET /jobs`

## Job Queue Behavior

MCP endpoints enqueue async jobs that move through:

```text
pending -> running -> completed | failed
```

The queue supports:
- Concurrency limits by job type
- Timeout-based failure handling
- Retention cleanup for old finished jobs
- Duplicate job detection (dedup window)

## Host Checks

Host checks are configurable with `ODB_AUTODBA_HOST_CHECK_MODE`:

- `disabled`: skip host checks
- `local_app_host`: collect metrics from the AutoDBA app host
- `ssh_remote`: collect remote Oracle host metrics via SSH

Notes:
- SSH checks are optional
- SSH failures are non-fatal for DB health
- Reports include host check scope and warnings when unavailable

## Development / Testing

Run all tests:

```bash
uv run python -m unittest
```

Run focused verification suites:

```bash
uv run python -m unittest odb_autodba.verification.<test_module>
```

## Notes / Security

- Provide passwords via environment variables only
- Dynamic targets from the UI do not persist plaintext passwords
- Safe serialization (`safe_dict`) avoids exposing secret values
- Job and API outputs should remain sanitized

## Roadmap (Optional)

- Expanded performance baselines for workload-aware recommendations
- Deeper investigation trace analytics
- Additional deployment templates for production environments

## Contributing (Optional)

1. Fork and create a feature branch.
2. Keep changes scoped and add/adjust tests.
3. Run `uv run python -m unittest` before opening a PR.
