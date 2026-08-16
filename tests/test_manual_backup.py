import datetime as dt
import hashlib
import os
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path

from safe_backup import engine


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "manual_backup.ps1"


def _powershells():
    return [name for name in ("powershell.exe", "pwsh") if shutil.which(name)]


class ManualBackupScriptContractTests(unittest.TestCase):
    def test_script_is_visible_and_read_only_to_the_scheduled_task(self):
        text = SCRIPT.read_text(encoding="utf-8-sig")
        self.assertIn("Get-ScheduledTask -TaskPath '\\' -TaskName $identity.Name", text)
        self.assertIn("NextRunTime", text)
        self.assertIn("last_successful_archive_sha256", text)
        self.assertIn("'SetDestination'", text)
        self.assertIn("[string]$Destination", text)
        self.assertIn("--force", text)
        self.assertIn("--manual", text)
        self.assertIn("不计入自动备份周期", text)
        self.assertIn("Get-EngineArgumentValue", text)
        self.assertNotIn("EngineArguments[7]", text)
        self.assertIn("never changes a Scheduled Task", text)
        self.assertNotIn("Start-ScheduledTask", text)
        self.assertNotIn("Set-ScheduledTask", text)
        self.assertNotIn("Register-ScheduledTask", text)
        self.assertNotIn("Unregister-ScheduledTask", text)
        self.assertNotRegex(text, r"Remove-Item[^\r\n]*\.zip")

    def test_manual_destination_gate_treats_absolute_path_results_as_strings(self):
        text = SCRIPT.read_text(encoding="utf-8-sig")
        # Get-AbsolutePath returns a normalized string.  Keep this regression
        # guard so a new target cannot fail before the real destination gate.
        self.assertNotIn("$sourcePath.FullName", text)
        self.assertNotIn("$napcatPath.FullName", text)
        self.assertNotIn("Split-Path -LiteralPath", text)
        self.assertIn("[IO.Directory]::GetParent($candidateText)", text)
        self.assertIn("[string]$sourcePath", text)
        self.assertIn("[string]$napcatPath", text)

    def test_manual_engine_mode_cannot_be_marked_as_scheduled(self):
        with self.assertRaises(SystemExit):
            engine.parse_args([
                "--astrbot-root", "C:\\AstrBot", "--destination", "C:\\Backup",
                "--manual", "--scheduled", "--artifact-digest", "a" * 64,
            ])

    @unittest.skipUnless(_powershells(), "PowerShell unavailable")
    def test_script_parses_as_utf8_in_windows_powershell(self):
        executable = _powershells()[0]
        path = str(SCRIPT).replace("'", "''")
        command = (
            "$text=[IO.File]::ReadAllText('" + path + "',[Text.Encoding]::UTF8);"
            "[scriptblock]::Create($text)|Out-Null;Write-Output PARSE_OK"
        )
        result = subprocess.run(
            [executable, "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, check=False, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PARSE_OK", result.stdout)


class ManualRepeatAndTargetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="safe-backup-manual-")
        self.root = Path(self.temp.name)
        self.astrbot = self.root / "AstrBot"
        data = self.astrbot / "data"
        (data / "config").mkdir(parents=True)
        for name in ("cmd_config.json", "plugins.json", "mcp_server.json", "skills.json"):
            (data / name).write_text("{}", encoding="utf-8")
        (data / "config" / "settings.json").write_text('{"manual":true}', encoding="utf-8")
        connection = sqlite3.connect(data / "main.db")
        connection.execute("create table values_table (value text)")
        connection.execute("insert into values_table values ('manual')")
        connection.commit()
        connection.close()
        self.destination = self.root / "scheduled-target"
        self.alternate = self.root / "manual-target"
        self.now = dt.datetime(2026, 8, 16, 12, tzinfo=dt.timezone(dt.timedelta(hours=8)))

    def tearDown(self):
        self.temp.cleanup()

    def args(self, destination, *extra):
        return engine.parse_args([
            "--astrbot-root", str(self.astrbot), "--destination", str(destination),
            *extra,
        ])

    def run_backup(self, destination, *extra):
        return engine.run(
            self.args(destination, "--manual", *extra),
            process_probe=lambda _root: False,
            now=self.now,
        )

    def test_manual_force_can_run_twice_in_one_cycle(self):
        first = self.run_backup(self.destination, "--force")
        self.assertEqual(first.code, 0, first.message)
        second = self.run_backup(self.destination, "--force")
        self.assertEqual(second.code, 0, second.message)
        self.assertNotEqual(first.archive.name, second.archive.name)
        archives = sorted((self.destination / "managed").rglob("*.zip"))
        self.assertEqual(len(archives), 2)

    def test_manual_target_override_uses_new_empty_directory_without_touching_old_target(self):
        first = self.run_backup(self.destination, "--force")
        self.assertEqual(first.code, 0, first.message)
        old_bytes = first.archive.read_bytes()
        old_digest = hashlib.sha256(old_bytes).hexdigest()
        second = self.run_backup(self.alternate, "--force")
        self.assertEqual(second.code, 0, second.message)
        self.assertTrue(second.archive.is_file())
        self.assertEqual(first.archive.read_bytes(), old_bytes)
        self.assertEqual(hashlib.sha256(first.archive.read_bytes()).hexdigest(), old_digest)
        self.assertNotEqual(first.archive.parent, second.archive.parent)

    def test_manual_snapshot_does_not_advance_automatic_cycle_state(self):
        automatic = engine.run(
            self.args(self.destination),
            process_probe=lambda _root: False,
            now=self.now,
        )
        self.assertEqual(automatic.code, 0, automatic.message)
        before = engine.load_state(self.destination)
        self.assertIsNotNone(before)
        manual = self.run_backup(self.destination)
        self.assertEqual(manual.code, 0, manual.message)
        self.assertFalse(manual.counts_as_scheduled_success)
        after = engine.load_state(self.destination)
        self.assertEqual(after, before)
        self.assertEqual(after["last_successful_archive"], automatic.archive.name)
        self.assertEqual(after["last_successful_cycle"], before["last_successful_cycle"])
        self.assertNotEqual(manual.archive.name, automatic.archive.name)

    def test_manual_failure_does_not_mark_automatic_state_failed(self):
        automatic = engine.run(
            self.args(self.destination),
            process_probe=lambda _root: False,
            now=self.now,
        )
        self.assertEqual(automatic.code, 0, automatic.message)
        before = engine.load_state(self.destination)
        failed = engine.run(
            self.args(self.destination, "--manual"),
            process_probe=lambda _root: True,
            now=self.now,
        )
        self.assertNotEqual(failed.code, 0)
        self.assertEqual(engine.load_state(self.destination), before)
