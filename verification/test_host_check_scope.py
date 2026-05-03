from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from odb_autodba.host.health_checks import (
    HOST_CHECK_MODE_DISABLED,
    HOST_CHECK_MODE_LOCAL_APP_HOST,
    HOST_CHECK_MODE_SSH_REMOTE,
    HostCheckConfig,
    collect_host_snapshot_for_mode,
    resolve_host_check_mode,
)
from odb_autodba.models.schemas import HealthSnapshot
from odb_autodba.utils.formatter import render_health_snapshot_report


class HostCheckScopeTests(unittest.TestCase):
    def test_mode_priority_prefers_odb_env_then_fallback(self) -> None:
        with patch.dict(
            os.environ,
            {
                "ODB_AUTODBA_HOST_CHECK_MODE": "disabled",
                "HOST_CHECK_MODE": "ssh_remote",
                "ENABLE_HOST_CHECKS": "true",
            },
            clear=True,
        ):
            self.assertEqual(resolve_host_check_mode(), "disabled")

        with patch.dict(
            os.environ,
            {
                "HOST_CHECK_MODE": "ssh_remote",
                "ENABLE_HOST_CHECKS": "true",
            },
            clear=True,
        ):
            self.assertEqual(resolve_host_check_mode(), "ssh_remote")

    def test_disabled_mode_skips_host_checks_and_marks_observability_gap(self) -> None:
        snapshot, metadata = collect_host_snapshot_for_mode(HostCheckConfig(mode=HOST_CHECK_MODE_DISABLED))
        self.assertIsNone(snapshot)
        self.assertEqual(metadata.get("host_check_scope"), "disabled")
        self.assertIn("Oracle-side signals", metadata.get("host_check_warning") or "")

    def test_local_mode_labels_metrics_as_local_app_host(self) -> None:
        with patch("odb_autodba.host.health_checks._collect_filesystems", return_value=[]), patch(
            "odb_autodba.host.health_checks._collect_process_rows", return_value=[]
        ), patch("odb_autodba.host.health_checks._collect_mount_points", return_value={}), patch(
            "odb_autodba.host.health_checks._detect_oracle_docker_container", return_value=None
        ), patch("odb_autodba.host.health_checks._host_cpu_pct", return_value=10.0), patch(
            "odb_autodba.host.health_checks._memory_percentages", return_value=(20.0, 0.0)
        ):
            snapshot, metadata = collect_host_snapshot_for_mode(HostCheckConfig(mode=HOST_CHECK_MODE_LOCAL_APP_HOST))
        self.assertIsNotNone(snapshot)
        assert snapshot is not None
        self.assertEqual(snapshot.host_check_scope, "local_app_host")
        self.assertEqual(snapshot.host_check_label, "Local AutoDBA app host")
        self.assertIn("AutoDBA runtime machine", snapshot.host_check_warning or "")
        self.assertEqual(metadata.get("host_check_scope"), "local_app_host")

    def test_ssh_failure_marks_unavailable_without_crash(self) -> None:
        with patch("odb_autodba.host.health_checks.paramiko", None), patch(
            "odb_autodba.host.health_checks.shutil.which", return_value="/usr/bin/ssh"
        ), patch(
            "odb_autodba.host.health_checks._run_remote_commands_via_system_ssh",
            return_value=(255, "", "auth failed password=hunter2"),
        ):
            snapshot, metadata = collect_host_snapshot_for_mode(
                HostCheckConfig(
                    mode=HOST_CHECK_MODE_SSH_REMOTE,
                    ssh_host="db01.internal",
                    ssh_port=22,
                    ssh_user="oracle",
                    ssh_timeout_seconds=3,
                )
            )
        self.assertIsNone(snapshot)
        self.assertEqual(metadata.get("host_check_scope"), "unavailable")
        warning = metadata.get("host_check_warning") or ""
        self.assertIn("Remote SSH host check failed", warning)
        self.assertNotIn("hunter2", warning)

    def test_report_ssh_mode_still_shows_remote_scope_when_unavailable(self) -> None:
        snapshot = HealthSnapshot(
            generated_at="2026-05-01T00:00:00Z",
            raw_evidence={
                "host_check": {
                    "host_check_mode": "ssh_remote",
                    "host_check_scope": "unavailable",
                    "host_check_label": "Host metrics unavailable",
                    "host_check_warning": "Remote SSH host check failed: timeout",
                    "host_check_target": "10.2.x.x",
                }
            },
        )
        rendered = render_health_snapshot_report(snapshot)
        self.assertIn("- Mode: ssh_remote", rendered)
        self.assertIn("- Scope: Remote Oracle DB host via SSH", rendered)
        self.assertIn("- Host: 10.2.x.x", rendered)
        self.assertIn("- Note: Remote SSH host check failed: timeout", rendered)

    def test_report_includes_host_check_scope_block(self) -> None:
        snapshot = HealthSnapshot(
            generated_at="2026-05-01T00:00:00Z",
            raw_evidence={
                "host_check": {
                    "host_check_mode": "disabled",
                    "host_check_scope": "disabled",
                    "host_check_label": "Host checks disabled",
                    "host_check_warning": "Host OS metrics disabled; database health is based on Oracle-side signals only.",
                    "host_check_target": "",
                }
            },
        )
        rendered = render_health_snapshot_report(snapshot)
        self.assertIn("Host Check Scope", rendered)
        self.assertIn("- Mode: disabled", rendered)
        self.assertIn("- Scope: Host checks disabled", rendered)

    def test_ssh_secret_not_rendered_in_report(self) -> None:
        snapshot = HealthSnapshot(
            generated_at="2026-05-01T00:00:00Z",
            raw_evidence={
                "host_check": {
                    "host_check_mode": "ssh_remote",
                    "host_check_scope": "unavailable",
                    "host_check_label": "Host metrics unavailable",
                    "host_check_warning": "Remote SSH host check failed: password=***REDACTED***",
                    "host_check_target": "10.2.x.x",
                }
            },
        )
        rendered = render_health_snapshot_report(snapshot)
        self.assertIn("***REDACTED***", rendered)
        self.assertNotIn("hunter2", rendered)


if __name__ == "__main__":
    unittest.main()
