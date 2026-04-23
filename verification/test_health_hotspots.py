from __future__ import annotations

import unittest
from unittest.mock import patch

from odb_autodba.db.extended_health_checks import _lock_wait_without_blocker_note, _tablespace_allocation_note
from odb_autodba.db.health_checks import (
    _apply_memory_compact_note,
    _build_hotspot_sections,
    _correlate_host_hotspots_with_db,
    _enrich_top_sql_row,
    _host_health_section,
)
from odb_autodba.db.running_sessions import map_top_processes_to_sessions
from odb_autodba.host.health_checks import _build_cpu_hotspot_section, _build_memory_hotspot_section
from odb_autodba.models.schemas import (
    CpuHotspotSection,
    HealthCheckSection,
    HealthSnapshot,
    HostProcessRow,
    HostSnapshot,
    MemoryHotspotSection,
    SessionProcessCorrelationRow,
    TopSqlRow,
)
from odb_autodba.utils.formatter import render_health_snapshot_report


class HealthHotspotTests(unittest.TestCase):
    def test_cpu_threshold_not_crossed_no_hotspot_section(self) -> None:
        cpu_hotspot = _build_cpu_hotspot_section(
            host_cpu_pct=45.0,
            container_cpu_pct=40.0,
            top_processes=[HostProcessRow(pid="111", spid="111", cpu_pct=22.5, process_group="oracle_foreground")],
            top_n=5,
            threshold_pct=70.0,
            container_threshold_pct=70.0,
        )
        self.assertFalse(cpu_hotspot.triggered)
        self.assertEqual(cpu_hotspot.top_processes, [])

    def test_cpu_threshold_crossed_hotspot_section_shown(self) -> None:
        host = HostSnapshot(
            cpu_hotspot=CpuHotspotSection(
                triggered=True,
                host_cpu_pct=88.0,
                top_processes=[HostProcessRow(pid="201", spid="201", cpu_pct=51.2, process_group="oracle_foreground")],
            ),
            memory_hotspot=MemoryHotspotSection(triggered=False),
        )
        sections = _build_hotspot_sections(host)
        self.assertTrue(any(section.name == "CPU Hotspots" for section in sections))

    def test_memory_threshold_crossed_hotspot_section_shown(self) -> None:
        host = HostSnapshot(
            cpu_hotspot=CpuHotspotSection(triggered=False),
            memory_hotspot=MemoryHotspotSection(
                triggered=True,
                host_memory_pct=91.0,
                top_processes=[HostProcessRow(pid="301", spid="301", memory_pct=27.4, process_group="oracle_background")],
            ),
        )
        sections = _build_hotspot_sections(host)
        self.assertTrue(any(section.name == "Memory Hotspots" for section in sections))

    def test_process_to_session_correlation_success(self) -> None:
        with patch(
            "odb_autodba.db.running_sessions.fetch_all",
            return_value=[
                {
                    "spid": "4321",
                    "os_pid": "4321",
                    "inst_id": 1,
                    "sid": 45,
                    "serial_num": 987,
                    "username": "APP",
                    "status": "ACTIVE",
                    "sql_id": "abc123xyz9",
                    "event": "db file sequential read",
                    "wait_class": "User I/O",
                    "module": "api",
                    "program": "python",
                    "machine": "app1",
                    "logon_time": "2026-04-21 04:30:00",
                }
            ],
        ):
            mapped_rows, mapped_count, _notes = map_top_processes_to_sessions(
                [HostProcessRow(pid="4321", spid="4321", process_group="oracle_foreground")]
            )
        self.assertEqual(mapped_count, 1)
        self.assertEqual(len(mapped_rows[0].session_correlations), 1)
        self.assertEqual(mapped_rows[0].session_correlations[0].sid, 45)

    def test_process_to_session_correlation_fallback(self) -> None:
        with patch("odb_autodba.db.running_sessions.fetch_all", side_effect=RuntimeError("ORA-00942")):
            mapped_rows, mapped_count, notes = map_top_processes_to_sessions(
                [HostProcessRow(pid="9999", spid="9999", process_group="oracle_foreground")]
            )
        self.assertEqual(mapped_count, 0)
        self.assertEqual(len(mapped_rows[0].session_correlations), 0)
        self.assertTrue(any("no rows" in note.lower() for note in notes))

    def test_enriched_top_sql_row_has_context_and_per_exec(self) -> None:
        row = _enrich_top_sql_row(
            {
                "sql_id": "xyza12345678",
                "parsing_schema_name": "APP",
                "module": "order_service",
                "program": "python3",
                "elapsed_s": 12.0,
                "cpu_s": 8.0,
                "executions": 4,
                "buffer_gets": 10000,
                "disk_reads": 200,
                "rows_processed": 40,
                "sql_text": "select * from orders where id = :1",
            }
        )
        self.assertEqual(row.get("ela_per_exec_s"), 3.0)
        self.assertEqual(row.get("cpu_per_exec_s"), 2.0)
        self.assertEqual(row.get("buffer_gets_per_exec"), 2500.0)
        self.assertEqual(row.get("disk_reads_per_exec"), 50.0)
        self.assertTrue(row.get("sql_classification"))
        self.assertTrue(row.get("workload_interpretation"))

    def test_cpu_hotspot_correlation_success_with_sql_context(self) -> None:
        host = HostSnapshot(
            cpu_hotspot=CpuHotspotSection(
                triggered=True,
                host_cpu_pct=89.0,
                top_processes=[HostProcessRow(pid="5001", spid="5001", cpu_pct=35.0, process_group="oracle_foreground")],
            ),
            memory_hotspot=MemoryHotspotSection(triggered=False),
        )
        correlated_process = HostProcessRow(
            pid="5001",
            spid="5001",
            cpu_pct=35.0,
            process_group="oracle_foreground",
            session_correlations=[
                SessionProcessCorrelationRow(
                    sid=52,
                    serial_num=1122,
                    inst_id=1,
                    username="APP",
                    sql_id="abc123def45",
                    module="order_api",
                    program="python",
                    pga_used_mb=220.0,
                    pga_alloc_mb=240.0,
                )
            ],
        )
        with patch(
            "odb_autodba.db.health_checks.map_top_processes_to_sessions",
            return_value=([correlated_process], 1, []),
        ):
            enriched = _correlate_host_hotspots_with_db(
                host,
                notes=[],
                top_sql_by_cpu=[TopSqlRow(sql_id="abc123def45", parsing_schema_name="APP", module="order_api", program="python", cpu_s=120.0)],
                top_session_candidates=[],
                current_sql_candidates=[],
                top_pga_candidates=[],
            )
        self.assertEqual(enriched.cpu_hotspot.correlation_confidence, "high")
        self.assertEqual(enriched.cpu_hotspot.correlation_summary.hotspot_correlation_success, "1/1")
        self.assertTrue(enriched.cpu_hotspot.oracle_correlated_rows)
        row = enriched.cpu_hotspot.oracle_correlated_rows[0]
        self.assertEqual(row.sql_id, "abc123def45")
        self.assertEqual(row.module, "order_api")
        self.assertEqual(row.program, "python")
        self.assertEqual(row.process_group, "oracle_fg")

    def test_cpu_hotspot_failed_os_mapping_uses_db_cpu_candidates(self) -> None:
        host = HostSnapshot(
            cpu_hotspot=CpuHotspotSection(
                triggered=True,
                host_cpu_pct=88.0,
                top_processes=[HostProcessRow(pid="7001", spid="7001", cpu_pct=40.0, process_group="oracle_foreground")],
            ),
            memory_hotspot=MemoryHotspotSection(triggered=False),
        )
        with patch(
            "odb_autodba.db.health_checks.map_top_processes_to_sessions",
            return_value=(host.cpu_hotspot.top_processes, 0, ["Oracle process-to-session correlation returned no rows for sampled SPIDs."]),
        ):
            enriched = _correlate_host_hotspots_with_db(
                host,
                notes=[],
                top_sql_by_cpu=[
                    TopSqlRow(
                        sql_id="b6usrg82hwsa3",
                        parsing_schema_name="DEVA1",
                        module="batch_loader",
                        program="java",
                        cpu_s=180.0,
                        cpu_per_exec_s=2.3,
                        sql_classification="application_sql",
                    )
                ],
                top_session_candidates=[],
                current_sql_candidates=[],
                top_pga_candidates=[],
            )
        self.assertEqual(enriched.cpu_hotspot.correlation_confidence, "low")
        self.assertTrue(enriched.cpu_hotspot.oracle_candidate_sql)
        self.assertTrue(any("candidate" in note.lower() for note in enriched.cpu_hotspot.notes))

    def test_memory_hotspot_with_pga_session_correlation(self) -> None:
        host = HostSnapshot(
            cpu_hotspot=CpuHotspotSection(triggered=False),
            memory_hotspot=MemoryHotspotSection(
                triggered=True,
                host_memory_pct=92.0,
                top_processes=[HostProcessRow(pid="9001", spid="9001", memory_pct=22.0, process_group="oracle_foreground")],
            ),
        )
        correlated_process = HostProcessRow(
            pid="9001",
            spid="9001",
            memory_pct=22.0,
            process_group="oracle_foreground",
            session_correlations=[
                SessionProcessCorrelationRow(
                    sid=84,
                    serial_num=4521,
                    inst_id=1,
                    username="APP",
                    sql_id="dyb4hb8sdadmz",
                    module="etl_job",
                    program="python",
                    pga_used_mb=780.0,
                    pga_alloc_mb=900.0,
                    temp_used_mb=120.0,
                )
            ],
        )
        with patch(
            "odb_autodba.db.health_checks.map_top_processes_to_sessions",
            return_value=([correlated_process], 1, []),
        ):
            enriched = _correlate_host_hotspots_with_db(
                host,
                notes=[],
                top_sql_by_cpu=[],
                top_session_candidates=[],
                current_sql_candidates=[],
                top_pga_candidates=[],
            )
        self.assertEqual(enriched.memory_hotspot.correlation_confidence, "high")
        self.assertTrue(enriched.memory_hotspot.oracle_correlated_rows)
        self.assertGreater(enriched.memory_hotspot.oracle_correlated_rows[0].pga_used_mb or 0, 700)

    def test_cpu_hotspot_uses_sql_monitor_candidates_when_os_mapping_fails(self) -> None:
        host = HostSnapshot(
            cpu_hotspot=CpuHotspotSection(
                triggered=True,
                host_cpu_pct=87.0,
                top_processes=[HostProcessRow(pid="8001", spid="8001", cpu_pct=31.0, process_group="oracle_foreground")],
            ),
            memory_hotspot=MemoryHotspotSection(triggered=False),
        )
        with patch(
            "odb_autodba.db.health_checks.map_top_processes_to_sessions",
            return_value=(host.cpu_hotspot.top_processes, 0, ["Oracle process-to-session correlation returned no rows for sampled SPIDs."]),
        ):
            enriched = _correlate_host_hotspots_with_db(
                host,
                notes=[],
                top_sql_by_cpu=[],
                top_session_candidates=[],
                current_sql_candidates=[
                    {
                        "inst_id": 1,
                        "sid": 88,
                        "serial_num": 9021,
                        "username": "DEVA1",
                        "sql_id": "20sagypbxp6vk",
                        "cpu_s": 99.0,
                        "program": "python",
                        "module": "api_worker",
                    }
                ],
                top_pga_candidates=[],
            )
        self.assertEqual(enriched.cpu_hotspot.correlation_confidence, "low")
        self.assertIn("20sagypbxp6vk", enriched.cpu_hotspot.correlation_summary.top_oracle_candidate_sql_ids)
        self.assertTrue(any(row.source == "sql_monitor_current_sql" for row in enriched.cpu_hotspot.oracle_candidate_sql))

    def test_memory_compact_note_added_when_no_memory_hotspot_but_pga_heavy(self) -> None:
        sections = [HealthCheckSection(name="Memory And Configuration", status="OK", summary="summary", rows=[], notes=[])]
        host = HostSnapshot(
            cpu_hotspot=CpuHotspotSection(triggered=False),
            memory_hotspot=MemoryHotspotSection(triggered=False),
        )
        notes: list[str] = []
        _apply_memory_compact_note(
            snapshot_sections=sections,
            host_snapshot=host,
            raw_evidence={
                "memory_config": {
                    "top_pga_sessions": [
                        {
                            "sid": 41,
                            "serial_num": 112,
                            "username": "APP",
                            "sql_id": "memsql01",
                            "module": "etl",
                            "program": "python",
                            "pga_used_mb": 950.0,
                        }
                    ],
                    "top_cpu_sessions": [{"sid": 41, "sql_id": "memsql01"}],
                }
            },
            notes=notes,
        )
        self.assertTrue(sections[0].notes)
        self.assertIn("largest Oracle PGA consumer", sections[0].notes[0])
        self.assertIn("memsql01", sections[0].notes[0])

    def test_ora_01653_with_low_tablespace_usage_note(self) -> None:
        note = _tablespace_allocation_note(
            alert_rows=[{"code": "ORA-01653", "message": "unable to extend table DEVA1.CPU_MEM_TEST in tablespace USERS"}],
            tablespace_rows=[{"tablespace_name": "USERS", "used_pct": 42.0}],
        )
        self.assertIsNotNone(note)
        self.assertIn("Overall tablespace usage is low", note or "")

    def test_tx_row_lock_wait_without_blocker_note(self) -> None:
        note = _lock_wait_without_blocker_note(
            wait_rows=[{"event": "enq: TX - row lock contention", "wait_class": "Application"}],
            has_blockers=False,
        )
        self.assertIsNotNone(note)
        self.assertIn("no active blocker", note or "")

    def test_host_cpu_low_container_cpu_high_interpretation(self) -> None:
        host = HostSnapshot(
            cpu_pct=22.0,
            docker_container="oracle-db",
            docker_stats={"cpu_pct": 95.0, "memory_pct": 64.0},
            cpu_hotspot=CpuHotspotSection(triggered=True, host_cpu_pct=22.0, container_cpu_pct=95.0),
            memory_hotspot=MemoryHotspotSection(triggered=False),
        )
        section = _host_health_section(host)
        self.assertIn("localized DB/container pressure", section.summary)

    def test_top_sql_overlap_note_rendered(self) -> None:
        snapshot = HealthSnapshot(
            generated_at="2026-04-22T00:00:00Z",
            top_sql_by_cpu=[TopSqlRow(sql_id="x1"), TopSqlRow(sql_id="x2"), TopSqlRow(sql_id="x3")],
            top_sql_by_elapsed=[TopSqlRow(sql_id="x1"), TopSqlRow(sql_id="x2"), TopSqlRow(sql_id="z9")],
        )
        rendered = render_health_snapshot_report(snapshot)
        self.assertIn("Top elapsed and top CPU SQL sets largely overlap", rendered)

    def test_formatter_hotspot_context_shows_sql_module_program(self) -> None:
        snapshot = HealthSnapshot(
            generated_at="2026-04-22T00:00:00Z",
            health_sections=[
                HealthCheckSection(
                    name="CPU Hotspots",
                    status="WARNING",
                    summary="CPU hotspot triggered.",
                    rows=[
                        {
                            "row_type": "os_sample",
                            "os_pid": "4321",
                            "spid": "4321",
                            "process_group": "oracle_foreground",
                            "cpu_pct": 48.2,
                            "sid": 55,
                            "serial_num": 1033,
                            "username": "DEVA1",
                            "sql_id": "cpu123",
                            "module": "scheduler_worker",
                            "program": "oracle@db (J000)",
                        }
                    ],
                )
            ],
            top_sql_by_cpu=[TopSqlRow(sql_id="cpu123", module="scheduler_worker", program="oracle@db (J000)", cpu_s=44.0)],
            top_sql_by_elapsed=[TopSqlRow(sql_id="cpu123", module="scheduler_worker", program="oracle@db (J000)", elapsed_s=88.0)],
        )
        rendered = render_health_snapshot_report(snapshot)
        self.assertIn("cpu123", rendered)
        self.assertIn("scheduler_worker", rendered)
        self.assertIn("oracle@db", rendered)

    def test_formatter_renders_hotspots_and_top_sql_context(self) -> None:
        snapshot = HealthSnapshot(
            generated_at="2026-04-21T00:00:00Z",
            top_sql_by_cpu=[
                TopSqlRow(
                    sql_id="cpu123",
                    parsing_schema_name="APP",
                    module="api",
                    program="python",
                    cpu_s=20.0,
                    elapsed_s=22.0,
                    executions=100,
                    cpu_per_exec_s=0.2,
                    ela_per_exec_s=0.22,
                    buffer_gets_per_exec=1200.0,
                    disk_reads_per_exec=6.0,
                    sql_classification="application_sql",
                    workload_interpretation="likely CPU-heavy",
                )
            ],
            top_sql_by_elapsed=[
                TopSqlRow(
                    sql_id="ela123",
                    parsing_schema_name="SYS",
                    module="DBMS_SCHEDULER",
                    program="oracle",
                    cpu_s=8.0,
                    elapsed_s=25.0,
                    executions=5,
                    cpu_per_exec_s=1.6,
                    ela_per_exec_s=5.0,
                    buffer_gets_per_exec=5000.0,
                    disk_reads_per_exec=700.0,
                    sql_classification="internal scheduler workload",
                    workload_interpretation="low-frequency but expensive",
                )
            ],
            health_sections=[
                HealthCheckSection(
                    name="CPU Hotspots",
                    status="WARNING",
                    summary="CPU hotspot triggered.",
                    rows=[{"os_pid": "4321", "process_group": "oracle_foreground", "cpu_pct": 48.2, "sid": 55, "sql_id": "cpu123"}],
                )
            ],
        )
        rendered = render_health_snapshot_report(snapshot)
        self.assertIn("Top SQL by Elapsed", rendered)
        self.assertIn("Top SQL by CPU", rendered)
        self.assertIn("CPU Hotspots", rendered)
        self.assertIn("likely CPU-heavy", rendered)


if __name__ == "__main__":
    unittest.main()
