from __future__ import annotations

import os
import re
import subprocess
import time
from typing import Any

from odb_autodba.models.schemas import CpuHotspotSection, HostProcessRow, HostSnapshot, MemoryHotspotSection


def _run(cmd: list[str], *, timeout: int = 3) -> str:
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=timeout).strip()
    except Exception:
        return ""


def _run_rc(cmd: list[str], *, timeout: int = 3) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return int(proc.returncode), proc.stdout or "", proc.stderr or ""
    except Exception as exc:
        return 999, "", str(exc)


def collect_host_snapshot() -> HostSnapshot:
    filesystems = _collect_filesystems()
    notes: list[str] = []

    top_n = _env_int("PROCESS_TOP_N", 5)
    cpu_threshold = _env_float("HOST_CPU_HOTSPOT_THRESHOLD_PCT", 70.0)
    mem_threshold = _env_float("HOST_MEMORY_HOTSPOT_THRESHOLD_PCT", 80.0)
    container_cpu_threshold = _env_float("CONTAINER_CPU_HOTSPOT_THRESHOLD_PCT", 70.0)
    container_mem_threshold = _env_float("CONTAINER_MEMORY_HOTSPOT_THRESHOLD_PCT", 80.0)

    top_cpu_processes = _collect_process_rows(sort_key="cpu", limit=top_n)
    top_memory_processes = _collect_process_rows(sort_key="memory", limit=top_n)

    loadavg = _run(["cat", "/proc/loadavg"]) if os.path.exists("/proc/loadavg") else ""
    cpu_pct = _host_cpu_pct()
    memory_pct, swap_pct = _memory_percentages()

    mount_points = _collect_mount_points()
    docker_container = _detect_oracle_docker_container()
    docker_stats: dict[str, Any] = {}
    if docker_container:
        docker_stats = _docker_stats(docker_container) or {}
        docker_mounts = _docker_mount_points(docker_container)
        if docker_mounts:
            mount_points["container"] = docker_mounts
    else:
        notes.append("Docker Oracle container was not detected or Docker is not accessible.")

    container_cpu_pct = _as_float((docker_stats or {}).get("cpu_pct"))
    container_mem_pct = _as_float((docker_stats or {}).get("memory_pct"))

    cpu_hotspot = _build_cpu_hotspot_section(
        host_cpu_pct=cpu_pct,
        container_cpu_pct=container_cpu_pct,
        top_processes=top_cpu_processes,
        top_n=top_n,
        threshold_pct=cpu_threshold,
        container_threshold_pct=container_cpu_threshold,
    )
    memory_hotspot = _build_memory_hotspot_section(
        host_memory_pct=memory_pct,
        container_memory_pct=container_mem_pct,
        top_processes=top_memory_processes,
        top_n=top_n,
        threshold_pct=mem_threshold,
        container_threshold_pct=container_mem_threshold,
    )

    return HostSnapshot(
        cpu_pct=cpu_pct,
        memory_pct=memory_pct,
        swap_pct=swap_pct,
        filesystems=filesystems,
        top_processes=top_cpu_processes,
        docker_container=docker_container,
        docker_stats=docker_stats,
        top_memory_processes=top_memory_processes,
        cpu_hotspot=cpu_hotspot,
        memory_hotspot=memory_hotspot,
        load_average=loadavg,
        mount_points=mount_points,
        notes=notes,
    )


def _collect_filesystems() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    df_out = _run(["df", "-hP"])
    for line in df_out.splitlines()[1:11]:
        parts = line.split()
        if len(parts) >= 6:
            out.append(
                {
                    "filesystem": parts[0],
                    "size": parts[1],
                    "used": parts[2],
                    "avail": parts[3],
                    "use_pct": parts[4],
                    "mount": parts[5],
                }
            )
    return out


def _collect_process_rows(*, sort_key: str, limit: int) -> list[HostProcessRow]:
    normalized = "cpu" if sort_key.lower().startswith("cpu") else "memory"
    sort_expr = "-pcpu" if normalized == "cpu" else "-pmem"
    cmd = [
        "bash",
        "-lc",
        f"ps -eo pid,pcpu,pmem,rss,vsz,comm,args --sort={sort_expr} | head -n {max(limit, 1) + 1}",
    ]
    output = _run(cmd)
    rows: list[HostProcessRow] = []
    for line in output.splitlines()[1:]:
        parsed = _parse_process_line(line)
        if not parsed:
            continue
        if normalized == "memory":
            parsed.swap_mb = _swap_mb_for_pid(parsed.pid)
        rows.append(parsed)
    return rows[: max(limit, 1)]


def _parse_process_line(line: str) -> HostProcessRow | None:
    parts = line.split(None, 6)
    if len(parts) < 6:
        return None
    pid, pcpu, pmem, rss_kb, vsz_kb, comm = parts[:6]
    args = parts[6] if len(parts) > 6 else comm
    group, oracle_type = _guess_process_group(comm=comm, command=args)
    return HostProcessRow(
        pid=str(pid),
        spid=str(pid),
        cpu_pct=_as_float(pcpu),
        memory_pct=_as_float(pmem),
        rss_mb=_kb_to_mb(rss_kb),
        vsz_mb=_kb_to_mb(vsz_kb),
        command=args.strip(),
        process_name=comm.strip(),
        process_group=group,
        oracle_process_type_guess=oracle_type,
    )


def _guess_process_group(*, comm: str, command: str) -> tuple[str, str | None]:
    text = f"{comm} {command}".lower()
    if "oracle" not in text and " ora_" not in text and not text.startswith("ora_"):
        return "non_oracle", None

    background_tokens = (
        "ora_pmon",
        "ora_smon",
        "ora_dbw",
        "ora_lgwr",
        "ora_ckpt",
        "ora_mmon",
        "ora_mmnl",
        "ora_reco",
        "ora_arc",
        "ora_lreg",
        "ora_cjq",
        "ora_dia",
        "ora_vktm",
    )
    for token in background_tokens:
        if token in text:
            return "oracle_background", token

    if re.search(r"\bora_[a-z0-9]+\b", text):
        return "oracle_background", "ora_background"
    if "(local=" in text or "(description=" in text:
        return "oracle_foreground", "oracle_client"
    return "oracle_foreground", "oracle_process"


def _build_cpu_hotspot_section(
    *,
    host_cpu_pct: float | None,
    container_cpu_pct: float | None,
    top_processes: list[HostProcessRow],
    top_n: int,
    threshold_pct: float,
    container_threshold_pct: float,
) -> CpuHotspotSection:
    host_trigger = host_cpu_pct is not None and host_cpu_pct >= threshold_pct
    container_trigger = container_cpu_pct is not None and container_cpu_pct >= container_threshold_pct
    triggered = bool(host_trigger or container_trigger)
    visible_processes = top_processes[:top_n] if triggered else []
    notes: list[str] = []
    if host_trigger:
        notes.append(f"Host CPU {host_cpu_pct:.1f}% is above threshold {threshold_pct:.1f}%.")
    if container_trigger:
        notes.append(f"Oracle container CPU {container_cpu_pct:.1f}% is above threshold {container_threshold_pct:.1f}%.")

    return CpuHotspotSection(
        triggered=triggered,
        threshold_pct=threshold_pct,
        container_threshold_pct=container_threshold_pct,
        host_cpu_pct=host_cpu_pct,
        container_cpu_pct=container_cpu_pct,
        top_n=top_n,
        top_processes=visible_processes,
        top_oracle_foreground=_top_process_label(top_processes, metric="cpu", group="oracle_foreground"),
        top_oracle_background=_top_process_label(top_processes, metric="cpu", group="oracle_background"),
        top_non_oracle=_top_process_label(top_processes, metric="cpu", group="non_oracle"),
        interpretation=_hotspot_interpretation(metric="cpu", triggered=triggered, rows=(visible_processes or top_processes[:top_n])),
        notes=notes,
    )


def _build_memory_hotspot_section(
    *,
    host_memory_pct: float | None,
    container_memory_pct: float | None,
    top_processes: list[HostProcessRow],
    top_n: int,
    threshold_pct: float,
    container_threshold_pct: float,
) -> MemoryHotspotSection:
    host_trigger = host_memory_pct is not None and host_memory_pct >= threshold_pct
    container_trigger = container_memory_pct is not None and container_memory_pct >= container_threshold_pct
    triggered = bool(host_trigger or container_trigger)
    visible_processes = top_processes[:top_n] if triggered else []
    notes: list[str] = []
    if host_trigger:
        notes.append(f"Host memory {host_memory_pct:.1f}% is above threshold {threshold_pct:.1f}%.")
    if container_trigger:
        notes.append(f"Oracle container memory {container_memory_pct:.1f}% is above threshold {container_threshold_pct:.1f}%.")

    return MemoryHotspotSection(
        triggered=triggered,
        threshold_pct=threshold_pct,
        container_threshold_pct=container_threshold_pct,
        host_memory_pct=host_memory_pct,
        container_memory_pct=container_memory_pct,
        top_n=top_n,
        top_processes=visible_processes,
        top_oracle_foreground=_top_process_label(top_processes, metric="memory", group="oracle_foreground"),
        top_oracle_background=_top_process_label(top_processes, metric="memory", group="oracle_background"),
        top_non_oracle=_top_process_label(top_processes, metric="memory", group="non_oracle"),
        interpretation=_hotspot_interpretation(metric="memory", triggered=triggered, rows=(visible_processes or top_processes[:top_n])),
        notes=notes,
    )


def _hotspot_interpretation(*, metric: str, triggered: bool, rows: list[HostProcessRow]) -> str:
    if not triggered:
        return f"{metric.upper()} hotspot analysis was not triggered because utilization stayed below configured thresholds."
    if not rows:
        return "Hotspot analysis was triggered, but top OS process evidence could not be collected from this environment."

    oracle_foreground = _sum_metric(rows, metric=metric, group="oracle_foreground")
    oracle_background = _sum_metric(rows, metric=metric, group="oracle_background")
    non_oracle = _sum_metric(rows, metric=metric, group="non_oracle")

    if non_oracle > (oracle_foreground + oracle_background):
        return "Non-Oracle process activity is the primary host consumer in the captured top process set."
    if oracle_foreground >= oracle_background and oracle_foreground > 0:
        return "Resource pressure is dominated by Oracle foreground activity in the captured top process set."
    if oracle_background > 0:
        return "Resource pressure is dominated by Oracle background processes in the captured top process set."
    return "No single Oracle process group dominates the captured host process consumption."


def _sum_metric(rows: list[HostProcessRow], *, metric: str, group: str) -> float:
    field = "cpu_pct" if metric == "cpu" else "memory_pct"
    total = 0.0
    for row in rows:
        if row.process_group != group:
            continue
        value = getattr(row, field, None)
        if value is not None:
            total += float(value)
    return total


def _top_process_label(rows: list[HostProcessRow], *, metric: str, group: str) -> str | None:
    field = "cpu_pct" if metric == "cpu" else "memory_pct"
    candidates = [row for row in rows if row.process_group == group]
    if not candidates:
        return None
    top = max(candidates, key=lambda row: getattr(row, field, 0.0) or 0.0)
    value = getattr(top, field, None)
    if value is None:
        return f"pid={top.pid} {top.process_name or top.command or 'process'}"
    return f"pid={top.pid} {top.process_name or top.command or 'process'} ({value:.1f}%)"


def _swap_mb_for_pid(pid: str | None) -> float | None:
    if not pid:
        return None
    status_path = f"/proc/{pid}/status"
    if not os.path.exists(status_path):
        return None
    try:
        with open(status_path, "r", encoding="utf-8") as handle:
            for line in handle:
                if not line.startswith("VmSwap:"):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    return None
                return round(float(parts[1]) / 1024.0, 2)
    except Exception:
        return None
    return None


def _host_cpu_pct() -> float | None:
    try:
        first = _read_proc_stat_cpu()
        time.sleep(0.15)
        second = _read_proc_stat_cpu()
        if not first or not second:
            return None
        idle_delta = second["idle"] - first["idle"]
        total_delta = second["total"] - first["total"]
        if total_delta <= 0:
            return None
        return round(100.0 * (1.0 - idle_delta / total_delta), 2)
    except Exception:
        return None


def _read_proc_stat_cpu() -> dict[str, float] | None:
    if not os.path.exists("/proc/stat"):
        return None
    line = (_run(["head", "-n", "1", "/proc/stat"]) or "").strip()
    parts = line.split()
    if len(parts) < 5 or parts[0] != "cpu":
        return None
    values = [float(part) for part in parts[1:] if part.replace(".", "", 1).isdigit()]
    if len(values) < 4:
        return None
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return {"idle": idle, "total": sum(values)}


def _memory_percentages() -> tuple[float | None, float | None]:
    if not os.path.exists("/proc/meminfo"):
        return None, None
    values: dict[str, float] = {}
    for line in _run(["cat", "/proc/meminfo"]).splitlines():
        parts = line.replace(":", "").split()
        if len(parts) >= 2:
            try:
                values[parts[0]] = float(parts[1])
            except ValueError:
                continue
    mem_total = values.get("MemTotal")
    mem_available = values.get("MemAvailable")
    swap_total = values.get("SwapTotal")
    swap_free = values.get("SwapFree")
    memory_pct = None
    swap_pct = None
    if mem_total and mem_available is not None:
        memory_pct = round(100.0 * (1.0 - mem_available / mem_total), 2)
    if swap_total and swap_total > 0 and swap_free is not None:
        swap_pct = round(100.0 * (1.0 - swap_free / swap_total), 2)
    return memory_pct, swap_pct


def _collect_mount_points() -> dict[str, Any]:
    host = {
        "df_hpt": _run(["df", "-hPT"], timeout=4),
        "df_i": _run(["df", "-i"], timeout=4),
        "mount": "\n".join(_run(["mount"], timeout=4).splitlines()[:200]),
    }
    return {"host": {key: value for key, value in host.items() if value}}


def _detect_oracle_docker_container() -> str | None:
    rc, out, _ = _run_rc(["docker", "ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Ports}}"], timeout=4)
    if rc != 0 or not out.strip():
        return None
    rows = out.strip().splitlines()
    for line in rows:
        parts = line.split("\t")
        if len(parts) >= 3 and "1521" in parts[2]:
            return parts[0].strip() or None
    first = rows[0].split("\t")[0].strip()
    return first or None


def _docker_stats(container_id: str) -> dict[str, Any] | None:
    fmt = "{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"
    rc, out, _ = _run_rc(["docker", "stats", "--no-stream", "--format", fmt, container_id], timeout=4)
    if rc != 0 or not out.strip():
        return None
    parts = out.strip().splitlines()[0].split("\t")
    if len(parts) < 3:
        return None
    return {"cpu_pct": _parse_pct(parts[0]), "memory_usage": parts[1].strip(), "memory_pct": _parse_pct(parts[2])}


def _docker_mount_points(container_id: str) -> dict[str, str]:
    def dex(command: str) -> str:
        return _run(["docker", "exec", container_id, "bash", "-lc", command], timeout=6)

    out = {
        "df_hpt": dex("df -hPT"),
        "df_i": dex("df -i"),
        "mount": "\n".join(dex("mount").splitlines()[:200]),
    }
    return {key: value for key, value in out.items() if value}


def _parse_pct(value: str) -> float | None:
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)%", value or "")
    return float(match.group(1)) if match else None


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return float(default)
    try:
        return float(raw)
    except Exception:
        return float(default)


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return max(int(raw), 1)
    except Exception:
        return default


def _as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except Exception:
        return None


def _kb_to_mb(value: Any) -> float | None:
    val = _as_float(value)
    if val is None:
        return None
    return round(val / 1024.0, 2)
