from __future__ import annotations

import unittest

from odb_autodba.models.schemas import HealthCheckSection, HealthSnapshot
from odb_autodba.utils.formatter import _prepare_rows_for_section, render_health_snapshot_report


class StorageSizingTests(unittest.TestCase):
    def test_tablespace_allocated_and_max_are_separate(self) -> None:
        rows = _prepare_rows_for_section(
            "Tablespace Usage",
            [
                {
                    "tablespace_name": "USERS",
                    "allocated_mb": 1024.0,
                    "used_mb": 512.0,
                    "free_allocated_mb": 512.0,
                    "allocated_used_pct": 50.0,
                    "max_mb": 32768.0,
                    "max_used_pct": 1.56,
                    "autoextensible": "YES",
                }
            ],
        )
        row = rows[0]
        self.assertEqual(row.get("allocated_gb"), "1.00")
        self.assertEqual(row.get("used_gb"), "0.50")
        self.assertEqual(row.get("free_allocated_gb"), "0.50")
        self.assertEqual(row.get("max_gb"), "32.00")
        self.assertEqual(row.get("allocated_used_pct"), "50.00%")
        self.assertEqual(row.get("max_used_pct"), "1.56%")

    def test_free_allocated_does_not_use_maxbytes(self) -> None:
        rows = _prepare_rows_for_section(
            "Tablespace Usage",
            [
                {
                    "tablespace_name": "SYSTEM",
                    "allocated_mb": 1024.0,
                    "used_mb": 768.0,
                    "free_allocated_mb": 256.0,
                    "allocated_used_pct": 75.0,
                    "max_mb": 1048576.0,
                    "max_free_mb": 1047808.0,
                    "max_used_pct": 0.07,
                    "autoextensible": "YES",
                }
            ],
        )
        row = rows[0]
        self.assertEqual(row.get("free_allocated_gb"), "0.25")
        self.assertEqual(row.get("allocated_used_pct"), "75.00%")

    def test_report_shows_allocated_columns(self) -> None:
        snapshot = HealthSnapshot(
            generated_at="2026-05-01T00:00:00Z",
            health_sections=[
                HealthCheckSection(
                    name="Tablespace Usage",
                    status="WARNING",
                    summary="Tablespace snapshot",
                    rows=[
                        {
                            "tablespace_name": "USERS",
                            "allocated_mb": 2048.0,
                            "used_mb": 1024.0,
                            "free_allocated_mb": 1024.0,
                            "allocated_used_pct": 50.0,
                            "max_mb": 4096.0,
                            "max_used_pct": 25.0,
                            "autoextensible": "YES",
                        }
                    ],
                )
            ],
        )
        rendered = render_health_snapshot_report(snapshot)
        self.assertIn("allocated_gb", rendered)
        self.assertIn("free_allocated_gb", rendered)
        self.assertNotIn("32.00 TB", rendered)


if __name__ == "__main__":
    unittest.main()
