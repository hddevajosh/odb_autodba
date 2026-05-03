from __future__ import annotations

import unittest
from unittest.mock import patch

from odb_autodba.host import health_checks
from odb_autodba.host.health_checks import HostCheckConfig, collect_host_snapshot_for_mode


def _ssh_stdout() -> str:
    parts = {
        "uptime": " 13:11:35 up 12 days,  2:13,  2 users,  load average: 0.42, 0.38, 0.41",
        "free": """              total        used        free      shared  buff/cache   available\nMem:           16000        8000        2000         500        6000        7000\nSwap:           4000         200        3800""",
        "df": """Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1       100G   60G   40G  60% /""",
        "vmstat": """procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----\n r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st\n 1  0      0 100000  20000 300000    0    0     1     2   30   40 20 10 68  2  0""",
        "ps_cpu": """    PID COMMAND         %CPU %MEM\n    101 oracle          45.0 12.0\n    202 java            15.0  8.0""",
        "ps_mem": """    PID COMMAND         %CPU %MEM\n    303 oracle          20.0 25.0\n    404 python           5.0 10.0""",
    }
    lines: list[str] = []
    for key, _ in health_checks.SSH_COMMANDS:
        lines.append(parts[key])
        lines.append(f"{health_checks.SSH_SECTION_DELIMITER}{key}")
    return "\n".join(lines)


class SshHostChecksTests(unittest.TestCase):
    def test_ssh_remote_uses_paramiko_when_available(self) -> None:
        with patch("odb_autodba.host.health_checks.paramiko", object()), patch(
            "odb_autodba.host.health_checks._run_remote_commands_via_paramiko",
            return_value={
                "uptime": "up 1 day",
                "free": "Mem: 100 80 20\nSwap: 10 1 9",
                "df": "Filesystem Size Used Avail Use% Mounted on\n/dev/sda1 10G 5G 5G 50% /",
                "vmstat": "procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----\n r  b swpd free buff cache si so bi bo in cs us sy id wa st\n 1 0 0 1 1 1 0 0 0 0 0 0 20 5 75 0 0",
                "ps_cpu": "PID COMMAND %CPU %MEM\n100 oracle 30.0 10.0",
                "ps_mem": "PID COMMAND %CPU %MEM\n100 oracle 30.0 10.0",
            },
        ), patch("odb_autodba.host.health_checks.shutil.which", return_value=None):
            snapshot, metadata = collect_host_snapshot_for_mode(
                HostCheckConfig(mode="ssh_remote", ssh_host="10.20.30.40", ssh_user="oracle", ssh_timeout_seconds=5)
            )

        self.assertIsNotNone(snapshot)
        assert snapshot is not None
        self.assertEqual(snapshot.host_check_scope, "remote_db_host_ssh")
        self.assertEqual(snapshot.host_check_label, "Remote Oracle DB host via SSH")
        self.assertEqual(snapshot.host_check_target, "10.20.x.x")
        self.assertEqual(metadata.get("host_check_scope"), "remote_db_host_ssh")

    def test_paramiko_failure_falls_back_to_system_ssh(self) -> None:
        with patch("odb_autodba.host.health_checks.paramiko", object()), patch(
            "odb_autodba.host.health_checks._run_remote_commands_via_paramiko",
            side_effect=RuntimeError("paramiko auth failed password=secret"),
        ), patch("odb_autodba.host.health_checks.shutil.which", return_value="/usr/bin/ssh"), patch(
            "odb_autodba.host.health_checks._run_remote_commands_via_system_ssh",
            return_value=(0, _ssh_stdout(), ""),
        ):
            snapshot, metadata = collect_host_snapshot_for_mode(
                HostCheckConfig(mode="ssh_remote", ssh_host="db01.internal", ssh_user="oracle", ssh_timeout_seconds=5)
            )

        self.assertIsNotNone(snapshot)
        assert snapshot is not None
        self.assertEqual(snapshot.host_check_scope, "remote_db_host_ssh")
        self.assertEqual(metadata.get("host_check_scope"), "remote_db_host_ssh")

    def test_missing_dependencies_marks_unavailable(self) -> None:
        with patch("odb_autodba.host.health_checks.paramiko", None), patch("odb_autodba.host.health_checks.shutil.which", return_value=None):
            snapshot, metadata = collect_host_snapshot_for_mode(
                HostCheckConfig(mode="ssh_remote", ssh_host="db01.internal", ssh_user="oracle", ssh_timeout_seconds=5)
            )

        self.assertIsNone(snapshot)
        self.assertEqual(metadata.get("host_check_scope"), "unavailable")
        self.assertIn("unavailable", (metadata.get("host_check_warning") or "").lower())

    def test_ssh_failure_warning_is_sanitized(self) -> None:
        with patch("odb_autodba.host.health_checks.paramiko", None), patch(
            "odb_autodba.host.health_checks.shutil.which", return_value="/usr/bin/ssh"
        ), patch(
            "odb_autodba.host.health_checks._run_remote_commands_via_system_ssh",
            return_value=(255, "", "auth failed password=hunter2"),
        ):
            snapshot, metadata = collect_host_snapshot_for_mode(
                HostCheckConfig(mode="ssh_remote", ssh_host="db01.internal", ssh_user="oracle", ssh_timeout_seconds=5)
            )

        self.assertIsNone(snapshot)
        warning = str(metadata.get("host_check_warning") or "")
        self.assertIn("Remote SSH host check failed", warning)
        self.assertNotIn("hunter2", warning)

    def test_system_ssh_script_contains_required_read_only_commands(self) -> None:
        script = health_checks._build_remote_command_script()
        self.assertIn("uptime", script)
        self.assertIn("free -m", script)
        self.assertIn("df -hP", script)
        self.assertIn("vmstat 1 2", script)
        self.assertIn("--sort=-%cpu", script)
        self.assertIn("--sort=-%mem", script)


if __name__ == "__main__":
    unittest.main()
