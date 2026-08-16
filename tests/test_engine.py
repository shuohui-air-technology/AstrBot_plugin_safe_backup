from __future__ import annotations

import datetime as dt
import json
import sqlite3
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from safe_backup import engine


class DatabaseLayoutTransitionTests(unittest.TestCase):
    def test_generic_rolling_sqlite_names_are_accepted(self):
        old = {
            "mains": [
                "AstrBot/data/main.db",
                "AstrBot/data/plugin_data/example/backups/snapshot_2026-08-15_120000.sqlite",
            ],
            "sidecars": ["AstrBot/data/main.db-wal"],
        }
        current = {
            "mains": [
                "AstrBot/data/main.db",
                "AstrBot/data/plugin_data/example/backups/snapshot_2026-08-16_120000.sqlite",
            ],
            "sidecars": ["AstrBot/data/main.db-wal"],
        }
        self.assertTrue(engine.compatible_database_layout_transition(old, current))

    def test_arbitrary_database_addition_or_removal_is_rejected(self):
        old = {"mains": ["AstrBot/data/main.db"], "sidecars": []}
        current = {"mains": ["AstrBot/data/main.db", "AstrBot/data/new.db"], "sidecars": []}
        self.assertFalse(engine.compatible_database_layout_transition(old, current))

    def test_sidecar_change_is_rejected_even_for_rolling_names(self):
        old = {
            "mains": ["AstrBot/data/roll_20260815.db"],
            "sidecars": ["AstrBot/data/roll_20260815.db-wal"],
        }
        current = {
            "mains": ["AstrBot/data/roll_20260816.db"],
            "sidecars": ["AstrBot/data/roll_20260816.db-wal"],
        }
        self.assertFalse(engine.compatible_database_layout_transition(old, current))

    def test_unbalanced_rotation_is_rejected(self):
        old = {
            "mains": [
                "AstrBot/data/roll_20260815.db",
                "AstrBot/data/roll_20260814.db",
            ],
            "sidecars": [],
        }
        current = {
            "mains": [
                "AstrBot/data/roll_20260816.db",
                "AstrBot/data/roll_20260815.db",
                "AstrBot/data/roll_20260814.db",
            ],
            "sidecars": [],
        }
        self.assertFalse(engine.compatible_database_layout_transition(old, current))


class NapCatWhitelistTransitionTests(unittest.TestCase):
    def test_same_version_additive_json_config_is_accepted(self):
        old = [
            "NapCat/versions/9.9.26-44498/resources/app/napcat/config/base.json",
        ]
        current = old + [
            "NapCat/versions/9.9.26-44498/resources/app/napcat/config/onebot11_123.json",
        ]
        self.assertTrue(engine.compatible_napcat_whitelist_transition(old, current, "9.9.26-44498"))

    def test_removed_or_other_version_config_is_rejected(self):
        old = [
            "NapCat/versions/9.9.26-44498/resources/app/napcat/config/base.json",
        ]
        self.assertFalse(engine.compatible_napcat_whitelist_transition(
            old, [], "9.9.26-44498"))
        self.assertFalse(engine.compatible_napcat_whitelist_transition(
            old,
            old + ["NapCat/versions/9.9.27-00001/resources/app/napcat/config/new.json"],
            "9.9.26-44498",
        ))


class EngineFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="safe-backup-test-")
        self.root = Path(self.temp.name)
        self.astrbot = self.root / "astrbot"
        data = self.astrbot / "data"
        (data / "config").mkdir(parents=True)
        (data / "empty").mkdir()
        (data / "config" / "settings.json").write_text('{"synthetic":true}', encoding="utf-8")
        for name in ("cmd_config.json", "plugins.json", "mcp_server.json", "skills.json"):
            (data / name).write_text("{}", encoding="utf-8")
        con = sqlite3.connect(data / "main.db")
        con.execute("create table sample(id integer primary key, value text)")
        con.execute("insert into sample(value) values ('synthetic')")
        con.commit()
        con.close()
        self.destination = self.root / "backup-output"

    def tearDown(self):
        self.temp.cleanup()

    def args(self, *extra):
        values = [
            "--astrbot-root", str(self.astrbot),
            "--destination", str(self.destination),
            *extra,
        ]
        if "--scheduled" in values and "--artifact-digest" not in values:
            values.extend(("--artifact-digest", "a" * 64))
        return engine.parse_args(values)

    def run_backup(self, *extra, **kwargs):
        return engine.run(
            self.args(*extra),
            process_probe=kwargs.pop("process_probe", lambda _root: False),
            **kwargs,
        )

    def test_full_backup_without_napcat_and_verify(self):
        before = {
            path.relative_to(self.astrbot): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in self.astrbot.rglob("*") if path.is_file()
        }
        result = self.run_backup()
        self.assertEqual(result.code, 0, result.message)
        self.assertTrue(result.archive.is_file())
        self.assertTrue(engine.verify_archive(result.archive))
        with zipfile.ZipFile(result.archive) as zf:
            names = set(zf.namelist())
            manifest = json.loads(zf.read("backup-manifest.json"))
        self.assertIn("AstrBot/data/empty/", names)
        self.assertIn("AstrBot/data/main.db", names)
        self.assertFalse(any(name.startswith("NapCat/") for name in names))
        self.assertFalse(manifest["napcat_enabled"])
        self.assertEqual(manifest["napcat_version"], "disabled")
        state = json.loads((self.destination / "state.json").read_text("utf-8"))
        self.assertEqual(state["managed_by"], engine.GENERATOR)
        self.assertEqual(state["state_namespace"], "community-v1")
        self.assertEqual(state["last_success_archive"], result.archive.name)
        after = {
            path.relative_to(self.astrbot): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in self.astrbot.rglob("*") if path.is_file()
        }
        self.assertEqual(before, after)

    def test_preflight_is_output_read_only(self):
        result = self.run_backup("--preflight")
        self.assertEqual(result.code, 0, result.message)
        self.assertFalse(self.destination.exists())

    def test_running_astrbot_fails_before_source_open_or_output(self):
        def forbidden_open(_path):
            raise AssertionError("source must not be opened")

        result = engine.run(
            self.args(),
            process_probe=lambda _root: True,
            source_opener=forbidden_open,
        )
        self.assertEqual(result.code, 1)
        self.assertFalse(self.destination.exists())

    def test_initial_nonempty_destination_is_never_adopted(self):
        self.destination.mkdir()
        marker = self.destination / "foreign.txt"
        marker.write_text("do not touch", encoding="utf-8")
        result = self.run_backup()
        self.assertEqual(result.code, 3)
        self.assertEqual(marker.read_text("utf-8"), "do not touch")
        self.assertEqual({p.name for p in self.destination.iterdir()}, {"foreign.txt"})

    def test_failed_first_run_cleans_only_its_scaffolding(self):
        def fail_writer(*_args, **_kwargs):
            raise engine.BackupError("synthetic archive failure", 1)

        result = self.run_backup(archive_writer=fail_writer)
        self.assertEqual(result.code, 1)
        self.assertFalse(self.destination.exists())

    def test_week_start_and_scheduled_noop(self):
        now = dt.datetime(2026, 8, 5, 12, tzinfo=dt.timezone(dt.timedelta(hours=8)))
        args = self.args("--scheduled", "--week-start", "0")
        first = engine.run(args, process_probe=lambda _root: False, now=now)
        self.assertEqual(first.code, 0, first.message)
        second = engine.run(
            args, process_probe=lambda _root: False, now=now + dt.timedelta(days=1)
        )
        self.assertEqual(second.code, 0, second.message)
        self.assertTrue(second.noop)
        state = json.loads((self.destination / "state.json").read_text("utf-8"))
        self.assertEqual(state["week_start"], "monday")

    def test_keep_week_and_time_changes_force_new_scheduled_backup(self):
        now = dt.datetime(2026, 8, 5, 12, tzinfo=dt.timezone(dt.timedelta(hours=8)))
        configurations = [
            ("--keep", "5", "--week-start", "6", "--schedule-time", "12:00"),
            ("--keep", "6", "--week-start", "6", "--schedule-time", "12:00"),
            ("--keep", "6", "--week-start", "0", "--schedule-time", "12:00"),
            ("--keep", "6", "--week-start", "0", "--schedule-time", "13:15"),
        ]
        archives = []
        for offset, configuration in enumerate(configurations):
            args = self.args("--scheduled", *configuration)
            result = engine.run(
                args, process_probe=lambda _root: False, now=now + dt.timedelta(minutes=offset)
            )
            self.assertEqual(result.code, 0, result.message)
            self.assertFalse(result.noop)
            archives.append(result.archive.name)
        self.assertEqual(len(set(archives)), 4)
        state = json.loads((self.destination / "state.json").read_text("utf-8"))
        self.assertEqual(state["week_start"], "monday")
        self.assertEqual(state["schedule_time"], "13:15")

    def test_source_and_napcat_identity_changes_remain_locked(self):
        first = self.run_backup()
        self.assertEqual(first.code, 0, first.message)
        other = self.root / "other-astrbot"
        shutil.copytree(self.astrbot, other)
        source_args = engine.parse_args([
            "--astrbot-root", str(other), "--destination", str(self.destination),
        ])
        source_result = engine.run(source_args, process_probe=lambda _root: False)
        self.assertEqual(source_result.code, 3)
        napcat = self.root / "napcat"
        napcat.mkdir()
        nap_args = engine.parse_args([
            "--astrbot-root", str(self.astrbot), "--napcat-root", str(napcat),
            "--destination", str(self.destination),
        ])
        nap_result = engine.run(nap_args, process_probe=lambda _root: False)
        self.assertNotEqual(nap_result.code, 0)

    def test_duplicate_zip_member_is_rejected(self):
        result = self.run_backup()
        self.assertEqual(result.code, 0, result.message)
        with zipfile.ZipFile(result.archive, "a") as zf:
            zf.writestr("AstrBot/data/config/settings.json", b"tampered")
        self.assertFalse(engine.verify_archive(result.archive))

    def test_layout_drift_fails_closed(self):
        first = self.run_backup()
        self.assertEqual(first.code, 0, first.message)
        (self.astrbot / "data" / "unknown.db").write_bytes(b"not sqlite")
        second = self.run_backup("--force")
        self.assertEqual(second.code, 1)
        archives = list((self.destination / "managed").rglob("*.zip"))
        self.assertEqual(len(archives), 1)

    def test_unc_and_mapped_drive_are_rejected(self):
        with self.assertRaises(engine.BackupError) as unc:
            engine.assert_local_path(Path(r"\\server\share\backup"), lambda _p: 3)
        self.assertEqual(unc.exception.code, 3)
        with self.assertRaises(engine.BackupError) as remote:
            engine.assert_local_path(self.destination, lambda _p: 4)
        self.assertEqual(remote.exception.code, 3)

    def test_ads_policy_allows_zone_and_rejects_other_streams(self):
        source = self.astrbot / "data" / "config" / "settings.json"
        with mock.patch.object(engine, "alternate_data_streams", return_value=[":Zone.Identifier:$DATA"]):
            engine.assert_safe_source_streams(source)
        with mock.patch.object(engine, "alternate_data_streams", return_value=[":secret:$DATA"]):
            with self.assertRaises(engine.BackupError):
                engine.assert_safe_source_streams(source)

    def test_keep_range_is_strict(self):
        for value in ("0", "31"):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                self.args("--keep", value)


class NapCatFixture(unittest.TestCase):
    def test_dynamic_version_whitelist(self):
        with tempfile.TemporaryDirectory(prefix="safe-backup-napcat-") as raw:
            root = Path(raw)
            shell = root / "NapCat.synthetic.Shell"
            version = "10.2.3-45678"
            active = shell / "versions" / version
            config_dir = active / "resources" / "app" / "napcat" / "config"
            config_dir.mkdir(parents=True)
            for name in ("napcat.bat", "napcat.quick.bat", "napcat.kill.qq.bat", "ReadMe.txt"):
                (shell / name).write_text("synthetic", encoding="utf-8")
            (shell / "versions" / "config.json").write_text(
                json.dumps({"baseVersion": "10.2.2-45677", "curVersion": version}), "utf-8"
            )
            metadata = {
                "version.json": {"QQNT.dll": "synthetic.dll"},
                "resources/app/application.json": {"package.json": "package.json"},
                "resources/app/package.json": {
                    "name": "qq-chat", "version": version, "buildVersion": 45678,
                },
                "resources/app/napcat/package.json": {"name": "napcat", "version": "1.2.3"},
                "resources/app/napcat/qqnt.json": {
                    "name": "qq-chat", "version": "10.2.2-45677", "buildVersion": 45677,
                },
            }
            for suffix, value in metadata.items():
                path = active / suffix
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(value), encoding="utf-8")
            (config_dir / "webui.json").write_text('{"port":12345}', encoding="utf-8")
            items, detected, whitelist = engine.napcat_items(root, engine.windows_shared_read)
            self.assertEqual(detected, version)
            self.assertTrue(any(item.archive.endswith("/config/webui.json") for item in items))
            self.assertEqual(whitelist, [item.archive for item in items])
            self.assertFalse(any("10.2.2-45677" in item.archive for item in items))
            with mock.patch.object(
                engine,
                "alternate_data_streams",
                side_effect=lambda path: [":secret:$DATA"] if Path(path).name == "napcat.bat" else [],
            ):
                with self.assertRaises(engine.BackupError):
                    engine.napcat_items(root, engine.windows_shared_read)


if __name__ == "__main__":
    unittest.main()
