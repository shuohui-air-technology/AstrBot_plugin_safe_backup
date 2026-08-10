from __future__ import annotations

import json
import io
from dataclasses import replace
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

from safe_backup.setup import SetupConfig, artifact_digest


ROOT = Path(__file__).resolve().parents[1]


def completed(*, code=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)


class fake_process:
    def __init__(self, *, code=0, stdout="", stderr="", timeout=False):
        self.returncode = code
        self.stdout = io.BytesIO(stdout.encode("utf-8"))
        self.stderr = io.BytesIO(stderr.encode("utf-8"))
        self._timeout = timeout

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self._timeout:
            raise subprocess.TimeoutExpired("synthetic", timeout)
        return self.returncode

    def terminate(self):
        self.returncode = 1


class TaskControlTests(unittest.TestCase):
    def setUp(self):
        self.config = SetupConfig(
            astrbot_root=Path(r"C:\\Astr Bot"),
            destination=Path(r"D:\\Safe Backup"),
            napcat_root=None,
            plugin_dir=ROOT,
            python_path=Path(r"C:\\Astr Bot\\venv\\Scripts\\python.exe"),
            retention=5,
            week_start=0,
            schedule_time="12:34",
            source_fingerprint="0123456789abcdef" * 4,
            source_fingerprints={},
            config_fingerprint="fedcba9876543210" * 4,
            artifact_digest=artifact_digest(ROOT),
        )

    def spec(self):
        from safe_backup.task_control import task_spec
        return task_spec(self.config, self.config.plugin_dir, self.config.python_path)

    def task_result(self, operation, status="installed", code=0):
        return json.dumps({
            "operation": operation,
            "fingerprint": self.config.source_fingerprint[:12],
            "status": status,
            "code": code,
        })

    def test_task_spec_uses_hidden_launcher_and_limited_identity(self):
        spec = self.spec()
        self.assertEqual(spec.name, "AstrBot Safe Backup 0123456789ab")
        self.assertEqual(spec.run_level, "Limited")
        self.assertEqual(spec.logon_type, "Interactive")
        self.assertEqual(spec.launcher, self.config.plugin_dir / "scripts" / "task_launcher.ps1")
        self.assertEqual(spec.arguments[:4], ("--astrbot-root", r"C:\Astr Bot", "--destination", r"D:\Safe Backup"))
        self.assertIn("--scheduled", spec.arguments)

    def test_adapter_uses_list_arguments_without_a_shell(self):
        from safe_backup.task_control import PowerShellTaskAdapter, TaskControlError
        calls = []

        def fake_popen(argv, **kwargs):
            calls.append((argv, kwargs))
            return fake_process(stdout=self.task_result("install"))

        with mock.patch("safe_backup.task_control.subprocess.Popen", side_effect=fake_popen), \
                mock.patch("safe_backup.task_control.subprocess.run", return_value=completed(stdout=self.task_result("install"))):
            result = PowerShellTaskAdapter().install(self.spec())

        self.assertEqual(result.status, "installed")
        self.assertIsInstance(calls[0][0], list)
        self.assertFalse(calls[0][1]["shell"])
        self.assertIn("-NoProfile", calls[0][0])
        self.assertIn("-NonInteractive", calls[0][0])
        self.assertEqual(calls[0][0][calls[0][0].index("-File") + 1],
                         str(Path(__file__).resolve().parents[1] / "scripts" / "install_task.ps1"))

    def test_adapter_returns_only_typed_matching_json_records(self):
        from safe_backup.task_control import PowerShellTaskAdapter, TaskControlError

        with mock.patch("safe_backup.task_control.subprocess.Popen", return_value=fake_process(stdout=self.task_result("install"))), \
                mock.patch("safe_backup.task_control.subprocess.run", return_value=completed(stdout=self.task_result("install"))):
            result = PowerShellTaskAdapter().install(self.spec())
        self.assertEqual((result.code, result.status, result.fingerprint),
                         (0, "installed", "0123456789ab"))

        malformed = '{"operation":"install","fingerprint":"0123456789ab","status":"installed","code":"0"}'
        with mock.patch("safe_backup.task_control.subprocess.Popen", return_value=fake_process(stdout=malformed)), \
                mock.patch("safe_backup.task_control.subprocess.run", return_value=completed(stdout=malformed)):
            with self.assertRaisesRegex(TaskControlError, "invalid task response"):
                PowerShellTaskAdapter().install(self.spec())

    def test_adapter_rejects_oversized_or_path_leaking_output_with_fixed_error(self):
        from safe_backup import task_control
        from safe_backup.task_control import PowerShellTaskAdapter, TaskControlError

        with mock.patch("safe_backup.task_control.subprocess.Popen", return_value=fake_process(stdout="x" * (task_control.MAX_OUTPUT_BYTES + 1))), \
                mock.patch("safe_backup.task_control.subprocess.run", return_value=completed(stdout="x" * (task_control.MAX_OUTPUT_BYTES + 1))):
            with self.assertRaisesRegex(TaskControlError, "task response too large") as raised:
                PowerShellTaskAdapter().install(self.spec())
        self.assertNotIn(r"C:\\", str(raised.exception))

    def test_adapter_maps_launch_and_timeout_failures_without_paths(self):
        from safe_backup.task_control import PowerShellTaskAdapter, TaskControlError

        with mock.patch("safe_backup.task_control.subprocess.Popen", side_effect=OSError(r"C:\\secret\\powershell.exe")), \
                mock.patch("safe_backup.task_control.subprocess.run", side_effect=OSError(r"C:\\secret\\powershell.exe")):
            with self.assertRaisesRegex(TaskControlError, "task process failed") as raised:
                PowerShellTaskAdapter().install(self.spec())
        self.assertNotIn(r"C:\\secret", str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)

        with mock.patch("safe_backup.task_control.subprocess.Popen", return_value=fake_process(timeout=True)), \
                mock.patch("safe_backup.task_control.subprocess.run", return_value=completed(stdout=self.task_result("install"))), \
                mock.patch("safe_backup.task_control.PROCESS_TIMEOUT_SECONDS", 0):
            with self.assertRaisesRegex(TaskControlError, "task operation timed out"):
                PowerShellTaskAdapter().install(self.spec())

    def test_adapter_rejects_a_manual_launcher_or_argument_grammar_before_launch(self):
        from safe_backup.task_control import PowerShellTaskAdapter, TaskControlError, TaskSpec
        bad = TaskSpec(
            name="AstrBot Safe Backup 0123456789ab",
            description="AstrBotSafeBackup:v1:0123456789ab",
            launcher=Path(r"C:\\arbitrary.ps1"),
            arguments=("--astrbot-root", r"C:\\Astr Bot", "--scheduled"),
            user_id="synthetic",
        )
        with mock.patch("safe_backup.task_control.subprocess.Popen") as launch, \
                mock.patch("safe_backup.task_control.subprocess.run", return_value=completed(stdout=self.task_result("install"))):
            with self.assertRaisesRegex(TaskControlError, "invalid task specification"):
                PowerShellTaskAdapter().install(bad)
            with self.assertRaisesRegex(TaskControlError, "invalid task specification"):
                PowerShellTaskAdapter().install(replace(self.spec(), launcher=Path(r"C:\\attacker\\scripts\\task_launcher.ps1")))
        launch.assert_not_called()

    def test_install_and_new_update_reject_artifact_digest_not_bound_to_local_files(self):
        """A task admission may not trust an arbitrary non-zero digest string."""
        from safe_backup.task_control import PowerShellTaskAdapter, TaskControlError

        current = self.spec()
        forged = replace(current, arguments=current.arguments[:-2] + ("f" * 64,) + current.arguments[-1:])
        old = replace(current, arguments=current.arguments[:-2] + ("e" * 64,) + current.arguments[-1:])
        with mock.patch("safe_backup.task_control.subprocess.Popen") as launch:
            with self.assertRaisesRegex(TaskControlError, "artifact"):
                PowerShellTaskAdapter().install(forged)
            with self.assertRaisesRegex(TaskControlError, "artifact"):
                PowerShellTaskAdapter().update(old, forged)
        launch.assert_not_called()

    def test_discovery_distinguishes_missing_exact_and_foreign_without_task_enumeration(self):
        from safe_backup.task_control import PowerShellTaskAdapter, TaskControlError

        adapter = PowerShellTaskAdapter()
        missing = adapter._parse_discovery_result(json.dumps({
            "operation": "discover", "fingerprint": "0123456789ab",
            "status": "missing", "code": 0,
        }), "0123456789ab")
        self.assertEqual(missing.status, "missing")
        exact = adapter._parse_discovery_result(json.dumps({
            "operation": "discover", "fingerprint": "0123456789ab",
            "status": "exact", "code": 0,
            "arguments": list(self.spec().arguments),
        }), "0123456789ab")
        self.assertEqual(exact.status, "exact")
        self.assertEqual(exact.spec.arguments[3], r"D:\Safe Backup")
        with self.assertRaisesRegex(TaskControlError, "foreign task"):
            PowerShellTaskAdapter()._parse_discovery_result(json.dumps({
                "operation": "discover", "fingerprint": "0123456789ab",
                "status": "foreign", "code": 3,
            }), "0123456789ab")

    def test_update_serializes_expected_old_and_new_specs(self):
        from safe_backup.task_control import PowerShellTaskAdapter, TaskControlError
        calls = []
        old = self.spec()
        new = replace(old, arguments=old.arguments[:11] + ("13:00",) + old.arguments[12:])
        def fake_popen(argv, **_kwargs):
            calls.append(argv)
            return fake_process(stdout=self.task_result("update", "updated"))
        with mock.patch("safe_backup.task_control.subprocess.Popen", side_effect=fake_popen):
            PowerShellTaskAdapter().update(old, new)
        self.assertIn("-ExpectedLauncherArgumentsJson", calls[0])
        self.assertIn("-LauncherArgumentsJson", calls[0])
        with self.assertRaisesRegex(TaskControlError, "invalid task response"):
            PowerShellTaskAdapter()._parse_discovery_result(json.dumps({
                "operation": "discover", "fingerprint": "0123456789ab",
                "status": "missing", "code": False,
            }), "0123456789ab")

    def test_trigger_reproves_exact_identity_before_requesting_start(self):
        from safe_backup.task_control import PowerShellTaskAdapter
        calls = []

        def fake_popen(argv, **_kwargs):
            calls.append(argv)
            return fake_process(stdout=self.task_result("trigger", "triggered"))

        with mock.patch("safe_backup.task_control.subprocess.Popen", side_effect=fake_popen):
            result = PowerShellTaskAdapter().trigger(self.spec())
        self.assertEqual("triggered", result.status)
        self.assertEqual(str(ROOT / "scripts" / "start_task.ps1"),
                         calls[0][calls[0].index("-File") + 1])


if __name__ == "__main__":
    unittest.main()
