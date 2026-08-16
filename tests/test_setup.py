from __future__ import annotations

import datetime as dt
import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from safe_backup.engine import load_state
from safe_backup import engine
from safe_backup import setup as setup_module
from safe_backup.setup import (
    SETUP_FREE_SPACE_FLOOR,
    InitializationLedger,
    build_setup_config,
    initialize_destination,
    rollback_initialized_destination,
)


class SetupFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="safe-backup-setup-")
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "home"
        self.home.mkdir()
        self.astrbot = self.root / "astrbot"
        (self.astrbot / "data" / "config").mkdir(parents=True)
        (self.astrbot / "data" / "config" / "settings.json").write_text(
            '{"synthetic": true}', encoding="utf-8"
        )
        for name in ("cmd_config.json", "plugins.json", "mcp_server.json", "skills.json"):
            (self.astrbot / "data" / name).write_text("{}", encoding="utf-8")
        database = sqlite3.connect(self.astrbot / "data" / "state.db")
        database.execute("create table sample(value text)")
        database.commit()
        database.close()
        self.plugin_dir = self.root / "plugin"
        self.plugin_dir.mkdir()
        self.python = self.root / "python.exe"
        self.python.write_bytes(b"synthetic")
        self.now = dt.datetime(2026, 8, 9, 12, tzinfo=dt.timezone.utc)
        self.config = build_setup_config(
            astrbot_root=self.astrbot,
            destination_text="",
            user_profile=self.home,
            plugin_dir=self.plugin_dir,
            python_path=self.python,
            retention=5,
            weekday="Sunday",
            schedule_time="12:00",
            napcat_root=None,
        )

    def tearDown(self):
        self.temporary.cleanup()

    def source_snapshot(self):
        inventory = {}
        for path in self.astrbot.rglob("*"):
            stat_result = path.lstat()
            inventory[path.relative_to(self.astrbot).as_posix()] = (
                stat_result.st_dev,
                stat_result.st_ino,
                stat_result.st_mode,
                stat_result.st_size,
                stat_result.st_mtime_ns,
            )
        return inventory

    def test_blank_destination_resolves_under_user_profile(self):
        self.assertEqual(self.config.destination.parent, self.home / "AstrBotSafeBackups")
        self.assertEqual(self.config.destination.name, self.config.source_fingerprint[:12])

    def test_initialize_destination_writes_authoritative_initialized_journal(self):
        state = initialize_destination(self.config, now=self.now)
        self.assertEqual(state["last_result"], "INITIALIZED")
        self.assertTrue(state["owner_uuid"])
        self.assertEqual(load_state(self.config.destination), state)
        self.assertNotIn("last_successful_archive", state)
        self.assertNotIn("database_layout", state)

    def test_rollback_initialized_destination_removes_only_the_exact_new_ledger(self):
        ledger = InitializationLedger()
        state = initialize_destination(self.config, now=self.now, ledger=ledger)
        self.assertTrue(rollback_initialized_destination(self.config, state, ledger))
        self.assertFalse(self.config.destination.exists())

    def test_rollback_preserves_a_preexisting_empty_destination_identity(self):
        self.config.destination.mkdir(parents=True)
        before = self.config.destination.stat().st_ino
        ledger = InitializationLedger()
        state = initialize_destination(self.config, now=self.now, ledger=ledger)
        self.assertTrue(rollback_initialized_destination(self.config, state, ledger))
        self.assertTrue(self.config.destination.exists())
        self.assertEqual(self.config.destination.stat().st_ino, before)
        self.assertEqual(list(self.config.destination.iterdir()), [])

    def test_setup_does_not_mutate_or_open_source_database(self):
        source = self.astrbot / "data" / "state.db"
        before = (source.read_bytes(), source.stat().st_mtime_ns, source.lstat().st_ino)
        inventory_before = self.source_snapshot()
        with mock.patch.object(engine.sqlite3, "connect", side_effect=AssertionError("SQLite must not open")):
            initialize_destination(self.config, now=self.now)
        self.assertEqual(
            (source.read_bytes(), source.stat().st_mtime_ns, source.lstat().st_ino), before
        )
        self.assertEqual(self.source_snapshot(), inventory_before)

    def test_initialized_state_allows_the_first_cold_backup_to_discover_layout(self):
        initialize_destination(self.config, now=self.now)
        args = engine.parse_args([
            "--astrbot-root", str(self.astrbot),
            "--destination", str(self.config.destination),
        ])
        result = engine.run(args, process_probe=lambda _root: False, now=self.now + dt.timedelta(minutes=1))
        self.assertEqual(result.code, 0, result.message)
        self.assertEqual(load_state(self.config.destination)["last_result"], "FULL_SUCCESS")

    def test_low_space_setup_removes_only_its_new_destination(self):
        with self.assertRaises(engine.BackupError) as raised:
            initialize_destination(
                self.config, now=self.now,
                free_space_probe=lambda _path: SETUP_FREE_SPACE_FLOOR - 1,
            )
        self.assertEqual(raised.exception.code, 1)
        self.assertFalse(self.config.destination.exists())
        self.assertFalse(self.config.destination.parent.exists())

    def test_nonempty_destination_is_preserved_and_not_adopted(self):
        self.config.destination.mkdir(parents=True)
        marker = self.config.destination / "foreign.txt"
        marker.write_text("preserve", encoding="utf-8")
        with self.assertRaises(engine.BackupError):
            initialize_destination(self.config, now=self.now)
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve")

    def test_unsupported_volume_removes_only_known_setup_scaffolding(self):
        with self.assertRaises(engine.BackupError) as raised:
            initialize_destination(self.config, now=self.now, volume_probe=lambda _path: "FAT32")
        self.assertEqual(raised.exception.code, 3)
        self.assertFalse(self.config.destination.exists())

    def test_exact_setup_floor_is_accepted(self):
        state = initialize_destination(
            self.config, now=self.now,
            free_space_probe=lambda _path: SETUP_FREE_SPACE_FLOOR,
        )
        self.assertEqual(state["last_result"], "INITIALIZED")
        self.assertTrue((self.config.destination / "managed" / state["owner_uuid"]).is_dir())

    def test_overlap_rejection_leaves_source_inventory_unchanged(self):
        before = self.source_snapshot()
        with self.assertRaises(engine.BackupError):
            build_setup_config(
                astrbot_root=self.astrbot,
                destination_text=str(self.astrbot / "data" / "backup"),
                user_profile=self.home,
                plugin_dir=self.plugin_dir,
                python_path=self.python,
                retention=5,
                weekday="Sunday",
                schedule_time="12:00",
                napcat_root=None,
            )
        self.assertEqual(self.source_snapshot(), before)

    def test_reparse_rejection_does_not_create_destination(self):
        with mock.patch.object(engine, "is_reparse", return_value=True):
            with self.assertRaises(engine.BackupError):
                build_setup_config(
                    astrbot_root=self.astrbot,
                    destination_text=str(self.root / "backup"),
                    user_profile=self.home,
                    plugin_dir=self.plugin_dir,
                    python_path=self.python,
                    retention=5,
                    weekday="Sunday",
                    schedule_time="12:00",
                    napcat_root=None,
                )
        self.assertFalse((self.root / "backup").exists())

    def test_real_temporary_junction_in_destination_ancestor_is_rejected_without_output(self):
        """A real junction supplements symlink tests on hosts with no symlink privilege."""
        real_parent = self.root / "real-output-parent"
        real_parent.mkdir()
        junction = self.root / "junction-output-parent"
        created = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(real_parent)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
        self.addCleanup(lambda: junction.exists() and junction.rmdir())
        target = junction / "backup"
        with self.assertRaises(engine.BackupError):
            build_setup_config(
                astrbot_root=self.astrbot, destination_text=str(target),
                user_profile=self.home, plugin_dir=self.plugin_dir, python_path=self.python,
                retention=5, weekday="Sunday", schedule_time="12:00", napcat_root=None,
            )
        self.assertFalse((real_parent / "backup").exists())

    def test_real_temporary_junction_in_default_destination_profile_is_rejected(self):
        real_profile = self.root / "real-profile"
        real_profile.mkdir()
        junction = self.root / "junction-profile"
        created = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(real_profile)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
        self.addCleanup(lambda: junction.exists() and junction.rmdir())
        with self.assertRaises(engine.BackupError):
            build_setup_config(
                astrbot_root=self.astrbot, destination_text="", user_profile=junction,
                plugin_dir=self.plugin_dir, python_path=self.python,
                retention=5, weekday="Sunday", schedule_time="12:00", napcat_root=None,
            )
        self.assertFalse((real_profile / "AstrBotSafeBackups").exists())

    def test_output_admission_rejects_ads_and_volume_root_before_initialization(self):
        invalid = (
            self.root / "output:stream",
            Path(self.root.anchor),
            Path("relative-output"),
            Path(r"\\?\C:\device-output"),
        )
        for candidate in invalid:
            with self.subTest(candidate=str(candidate)):
                with self.assertRaises(engine.BackupError):
                    setup_module._checked_output_absolute(candidate)

    def test_output_admission_normalizes_dotdot_and_overlap_is_case_insensitive(self):
        normalized = setup_module._checked_output_absolute(self.root / "outer" / ".." / "safe-output")
        self.assertEqual(normalized, (self.root / "safe-output").resolve(strict=False))
        mixed_case_source = Path(str(self.astrbot).upper()) / "DATA" / "backup"
        with self.assertRaises(engine.BackupError):
            build_setup_config(
                astrbot_root=self.astrbot, destination_text=str(mixed_case_source),
                user_profile=self.home, plugin_dir=self.plugin_dir, python_path=self.python,
                retention=5, weekday="Sunday", schedule_time="12:00", napcat_root=None,
            )

    def test_output_admission_rechecks_resolved_root_after_dotdot_and_junction(self):
        volume_root = Path(self.root.anchor)
        disguised_roots = (
            volume_root / "safe-backup-review" / "..",
            volume_root / "safe-backup-review" / "nested" / ".." / "..",
        )
        for candidate in disguised_roots:
            with self.subTest(candidate=str(candidate)):
                with self.assertRaises(engine.BackupError):
                    setup_module._checked_output_absolute(candidate)

        junction = self.root / "junction-to-root"
        created = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(volume_root)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
        self.addCleanup(lambda: junction.exists() and junction.rmdir())
        # The lexical ancestor is a junction and the resolved target is a
        # volume root; either condition must reject before output creation.
        with self.assertRaises(engine.BackupError):
            setup_module._checked_output_absolute(junction)

    def test_writer_failure_rolls_back_exact_setup_scaffolding(self):
        def fail_writer(_path, _value):
            raise OSError(r"C:\secret\writer-failure")

        with self.assertRaises(engine.BackupError) as raised:
            initialize_destination(self.config, now=self.now, writer=fail_writer)
        self.assertEqual(raised.exception.message if hasattr(raised.exception, "message") else str(raised.exception),
                         "setup state write failed")
        self.assertFalse(self.config.destination.exists())
        self.assertFalse(self.config.destination.parent.exists())

    def test_identity_substitution_preserves_uncertain_output(self):
        def substitute_owner(path, _value):
            destination = path.parent.parent
            owner = next((destination / "managed").iterdir())
            owner.rmdir()
            owner.mkdir()
            raise OSError(r"C:\secret\substitution")

        with self.assertRaises(engine.BackupError) as raised:
            initialize_destination(self.config, now=self.now, writer=substitute_owner)
        self.assertEqual(str(raised.exception), "setup state write failed")
        owner_dirs = list((self.config.destination / "managed").iterdir())
        self.assertEqual(len(owner_dirs), 1)
        self.assertTrue(owner_dirs[0].is_dir())

    def test_initialized_state_rejects_success_or_layout_fields(self):
        state = initialize_destination(self.config, now=self.now)
        state["last_successful_archive"] = "astrbot-safe-backup-20260809-120000-00000000-0000-4000-8000-000000000000.zip"
        for state_path in [self.config.destination / "state.json", *(
                self.config.destination / "state-journal").glob("*.json")]:
            state_path.write_text(json.dumps(state), encoding="utf-8")
        with self.assertRaises(engine.BackupError):
            load_state(self.config.destination)

    def test_setup_journal_hardlink_fails_closed_without_deleting_the_alias(self):
        initialize_destination(self.config, now=self.now)
        record = next((self.config.destination / "state-journal").glob("*.json"))
        alias = self.root / "foreign-journal-alias.json"
        os.link(record, alias)
        with self.assertRaises(engine.BackupError):
            load_state(self.config.destination)
        self.assertTrue(record.is_file())
        self.assertTrue(alias.is_file())

    def test_setup_journal_junction_fails_closed_and_preserves_original_journal(self):
        initialize_destination(self.config, now=self.now)
        journal = self.config.destination / "state-journal"
        original = self.config.destination / "preserved-journal"
        journal.rename(original)
        created = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(journal), str(original)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
        self.addCleanup(lambda: journal.exists() and journal.rmdir())
        with self.assertRaises(engine.BackupError):
            load_state(self.config.destination)
        self.assertTrue(original.is_dir())
        self.assertTrue(list(original.glob("*.json")))


if __name__ == "__main__":
    unittest.main()
