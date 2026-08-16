"""High-risk synthetic regressions for the community cold-backup engine."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import sqlite3
import stat
import tempfile
import unittest
import uuid
import warnings
import zipfile
from pathlib import Path
from unittest import mock

from safe_backup import engine


TZ = dt.timezone(dt.timedelta(hours=8))


class RegressionFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="safe-backup-regression-")
        self.base = Path(self.temp.name).resolve()
        self.astr = self.base / "AstrBot"
        (self.astr / "data" / "config").mkdir(parents=True)
        (self.astr / "data" / "config" / "core.json").write_text('{"safe":true}', "utf-8")
        for name in ("cmd_config.json", "plugins.json", "mcp_server.json", "skills.json"):
            (self.astr / "data" / name).write_text("{}", "utf-8")
        self.db = self.astr / "data" / "state.db"
        con = sqlite3.connect(self.db)
        con.execute("create table t(value text)")
        con.execute("insert into t values ('synthetic')")
        con.commit()
        con.close()
        self.dest = self.base / "Backups"

    def tearDown(self):
        self.temp.cleanup()

    def args(self, *extra, destination=None, astr=None, nap=None):
        values = [
            "--astrbot-root", str(astr or self.astr),
            "--destination", str(destination or self.dest),
            *extra,
        ]
        if "--scheduled" in values and "--artifact-digest" not in values:
            values.extend(("--artifact-digest", "a" * 64))
        if nap is not None:
            values[2:2] = ["--napcat-root", str(nap)]
        return engine.parse_args(values)

    def run_backup(self, *extra, now=None, **kwargs):
        return engine.run(
            self.args(*extra),
            process_probe=kwargs.pop("process_probe", lambda _root: False),
            now=now,
            **kwargs,
        )

    def successful_archive(self, *extra, now=None):
        result = self.run_backup(*extra, now=now)
        self.assertEqual(result.code, 0, result.message)
        return result.archive

    @staticmethod
    def rewrite_archive(path: Path, mutate_manifest):
        with zipfile.ZipFile(path, "r") as source:
            members = [(info, source.read(info.filename)) for info in source.infolist()]
        target = path.with_suffix(".rewrite")
        with zipfile.ZipFile(target, "w", allowZip64=True) as output:
            for info, payload in members:
                if info.filename == "backup-manifest.json":
                    manifest = json.loads(payload)
                    mutate_manifest(manifest)
                    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
                output.writestr(info, payload)
        target.replace(path)


class SourceIdentityAndDriftTests(RegressionFixture):
    def test_missing_required_astrbot_anchor_fails_closed(self):
        (self.astr / "data" / "skills.json").unlink()
        result = self.run_backup()
        self.assertEqual(result.code, 1)
        self.assertFalse(self.dest.exists())

    def test_source_handle_must_match_requested_identity(self):
        requested = self.astr / "data" / "config" / "core.json"
        other = self.astr / "data" / "other.json"
        other.write_text("other", "utf-8")

        def wrong_handle(path):
            return open(other if Path(path) == requested else path, "rb")

        with self.assertRaises(engine.BackupError) as caught:
            engine.sha256_file(requested, wrong_handle)
        self.assertEqual(caught.exception.code, 3)

    def test_hardlinked_source_fails_closed(self):
        source = self.astr / "data" / "config" / "core.json"
        alias = self.astr / "data" / "config" / "alias.json"
        try:
            os.link(source, alias)
        except OSError:
            self.skipTest("hard links unavailable")
        self.assertEqual(self.run_backup().code, 1)
        self.assertFalse(self.dest.exists())

    def test_critical_directory_drift_is_failure(self):
        source = self.astr / "data" / "config" / "core.json"
        changed = False

        def mutating_reader(path):
            nonlocal changed
            handle = engine.windows_shared_read(path)
            if Path(path) == source and not changed:
                changed = True
                (source.parent / "appeared.json").write_text("new", "utf-8")
            return handle

        self.assertEqual(self.run_backup(source_opener=mutating_reader).code, 1)

    def test_noncritical_directory_drift_is_degraded(self):
        cache = self.astr / "data" / "temp"
        cache.mkdir()
        source = cache / "cache.bin"
        source.write_bytes(b"x")
        changed = False

        def mutating_reader(path):
            nonlocal changed
            handle = engine.windows_shared_read(path)
            if Path(path) == source and not changed:
                changed = True
                (cache / "appeared.bin").write_bytes(b"y")
            return handle

        self.assertEqual(self.run_backup(source_opener=mutating_reader).code, 2)

    def test_napcat_config_drift_is_always_critical(self):
        nap, config_file = self._make_napcat()
        changed = False

        def mutating_reader(path):
            nonlocal changed
            handle = engine.windows_shared_read(path)
            if Path(path) == config_file and not changed:
                changed = True
                config_file.write_text('{"changed":true}', "utf-8")
            return handle

        result = engine.run(
            self.args(nap=nap), process_probe=lambda _root: False,
            source_opener=mutating_reader,
        )
        self.assertEqual(result.code, 1)

    def test_directory_ads_is_rejected(self):
        original = engine.alternate_data_streams

        def streams(path):
            return [":secret:$DATA"] if Path(path).is_dir() else original(path)

        with mock.patch.object(engine, "alternate_data_streams", side_effect=streams):
            result = self.run_backup("--preflight")
        self.assertEqual(result.code, 1)
        self.assertFalse(self.dest.exists())

    def test_napcat_base_accepts_current_or_qqnt_and_config_json_must_parse(self):
        nap, config_file = self._make_napcat()
        version_config = next(nap.glob("NapCat.*.Shell/versions/config.json"))
        metadata = json.loads(version_config.read_text("utf-8"))
        metadata["baseVersion"] = metadata["curVersion"]
        version_config.write_text(json.dumps(metadata), "utf-8")
        first = engine.run(self.args(nap=nap), process_probe=lambda _root: False)
        self.assertEqual(first.code, 0, first.message)
        self.assertTrue(engine.verify_archive(first.archive))
        metadata["baseVersion"] = "9.9.9-9999"
        version_config.write_text(json.dumps(metadata), "utf-8")
        config_file.write_text("{broken-json", "utf-8")
        second = engine.run(self.args(nap=nap), process_probe=lambda _root: False)
        self.assertEqual(second.code, 1)

    def test_napcat_whitelist_addition_within_same_version_is_accepted(self):
        nap, config_file = self._make_napcat()
        first = engine.run(self.args(nap=nap), process_probe=lambda _root: False)
        self.assertEqual(first.code, 0, first.message)
        (config_file.parent / "new-account.json").write_text("{}", "utf-8")
        second = engine.run(self.args(nap=nap), process_probe=lambda _root: False)
        self.assertEqual(second.code, 0, second.message)
        self.assertTrue(engine.verify_archive(second.archive))

    def _make_napcat(self):
        nap = self.base / "NapCat"
        shell = nap / "NapCat.synthetic.Shell"
        version = "10.0.0-10000"
        active = shell / "versions" / version
        config_dir = active / "resources" / "app" / "napcat" / "config"
        config_dir.mkdir(parents=True)
        for name in ("napcat.bat", "napcat.quick.bat", "napcat.kill.qq.bat", "ReadMe.txt"):
            (shell / name).write_text(name, "utf-8")
        (shell / "versions" / "config.json").write_text(
            json.dumps({"baseVersion": "9.9.9-9999", "curVersion": version}), "utf-8"
        )
        metadata = {
            "version.json": {"QQNT.dll": "synthetic"},
            "resources/app/application.json": {"package.json": "synthetic"},
            "resources/app/package.json": {
                "name": "qq-chat", "version": version, "buildVersion": 10000,
            },
            "resources/app/napcat/package.json": {"name": "napcat", "version": "1.0.0"},
            "resources/app/napcat/qqnt.json": {
                "name": "qq-chat", "version": "9.9.9-9999", "buildVersion": 9999,
            },
        }
        for relative, value in metadata.items():
            target = active / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(value), "utf-8")
        config_file = config_dir / "webui.json"
        config_file.write_text('{"port":1234}', "utf-8")
        return nap, config_file


class SQLiteFamilyTests(RegressionFixture):
    def _output_close_injection(self, inject):
        original_connect = sqlite3.connect
        observed = {"path": None, "pending_output": None}

        def connect_with_output_close(target, *args, **kwargs):
            opened = original_connect(target, *args, **kwargs)
            if (kwargs.get("uri") and isinstance(target, str) and "?mode=rw" in target
                    and observed["pending_output"] is None):
                raw_path = target.split("?", 1)[0]
                if raw_path.startswith("file:///"):
                    raw_path = raw_path[len("file:///"):]
                observed["pending_output"] = Path(raw_path)
                return opened
            if (kwargs.get("uri") and isinstance(target, str) and "?mode=ro" in target
                    and observed["path"] is None):

                class InjectAfterClose:
                    def __getattr__(self, name):
                        return getattr(opened, name)

                    def close(self):
                        opened.close()
                        output = observed["pending_output"]
                        if output is None:
                            raise AssertionError("normalization output connection was not observed")
                        observed["path"] = output
                        inject(output)

                return InjectAfterClose()
            return opened

        return connect_with_output_close, observed

    def test_wal_mode_without_sidecars_normalizes_in_private_workspace(self):
        database = self.astr / "data" / "wal-without-sidecars.db"
        con = sqlite3.connect(database)
        con.execute("pragma journal_mode=wal")
        con.execute("create table isolated(value text)")
        con.execute("insert into isolated values ('private-family')")
        con.commit()
        con.close()
        self.assertFalse(Path(str(database) + "-wal").exists())
        self.assertFalse(Path(str(database) + "-shm").exists())
        before_bytes = database.read_bytes()
        before_names = {path.name for path in database.parent.iterdir()}

        archive = self.successful_archive()

        self.assertEqual(database.read_bytes(), before_bytes)
        self.assertEqual({path.name for path in database.parent.iterdir()}, before_names)
        self.assertFalse(list((self.dest / "staging").iterdir()))
        restored = self.base / "restored-wal-without-sidecars.db"
        with zipfile.ZipFile(archive) as zf:
            restored.write_bytes(zf.read("AstrBot/data/wal-without-sidecars.db"))
        check = sqlite3.connect(restored)
        try:
            self.assertEqual(
                check.execute("select value from isolated").fetchone()[0],
                "private-family",
            )
        finally:
            check.close()

    def test_live_wal_family_is_absorbed_into_normalized_database(self):
        wal_db = self.astr / "data" / "wal.db"
        con = sqlite3.connect(wal_db)
        con.execute("pragma journal_mode=wal")
        con.execute("pragma wal_autocheckpoint=0")
        con.execute("create table wal_data(value text)")
        con.execute("insert into wal_data values ('from-wal')")
        con.commit()
        self.assertTrue(Path(str(wal_db) + "-wal").exists())
        original_connect = sqlite3.connect
        observed = {"touched": False, "created": False, "private": False}

        def connect_and_mutate_sidecars(target, *args, **kwargs):
            opened = original_connect(target, *args, **kwargs)
            if (kwargs.get("uri") and isinstance(target, str) and "?mode=ro" in target
                    and not observed["touched"]):
                raw_path = target.split("?", 1)[0]
                if raw_path.startswith("file:///"):
                    raw_path = raw_path[len("file:///"):]
                changed_sidecar = Path(raw_path + "-shm")
                created_sidecar = Path(raw_path + "-journal")

                class MutateAfterClose:
                    def __getattr__(self, name):
                        return getattr(opened, name)

                    def close(self):
                        opened.close()
                        if changed_sidecar.is_file():
                            current = changed_sidecar.stat()
                            os.utime(
                                changed_sidecar,
                                ns=(current.st_atime_ns, current.st_mtime_ns + 5_000_000_000),
                            )
                            observed["touched"] = True
                            observed["private"] = ".normalization" in changed_sidecar.parts
                        if not created_sidecar.exists():
                            created_sidecar.write_bytes(b"synthetic-sidecar")
                            observed["created"] = True

                return MutateAfterClose()
            return opened

        try:
            with mock.patch.object(
                engine.sqlite3,
                "connect",
                side_effect=connect_and_mutate_sidecars,
            ):
                archive = self.successful_archive()
        finally:
            con.close()
        self.assertTrue(observed["touched"])
        self.assertTrue(observed["created"])
        self.assertTrue(observed["private"])
        with zipfile.ZipFile(archive) as zf:
            names = set(zf.namelist())
            self.assertIn("AstrBot/data/wal.db", names)
            self.assertNotIn("AstrBot/data/wal.db-wal", names)
            manifest = json.loads(zf.read("backup-manifest.json"))
        wal_result = next(x for x in manifest["database_results"] if x["path"].endswith("/wal.db"))
        self.assertEqual(wal_result["integrity_check"], "ok")
        self.assertIn("AstrBot/data/wal.db-wal", wal_result["sidecars_omitted"])
        self.assertFalse(list((self.dest / "staging").iterdir()))

    def test_output_close_sidecars_are_registered_and_cleaned(self):
        def add_sidecars(output):
            Path(str(output) + "-journal").write_bytes(b"synthetic-journal")
            Path(str(output) + "-wal").write_bytes(b"synthetic-wal")

        patched_connect, observed = self._output_close_injection(add_sidecars)
        with mock.patch.object(engine.sqlite3, "connect", side_effect=patched_connect):
            archive = self.successful_archive()

        self.assertIsNotNone(observed["path"])
        self.assertIn(".normalization", observed["path"].parts)
        self.assertFalse(list((self.dest / "staging").iterdir()))
        restored = self.base / "restored-output-sidecars.db"
        with zipfile.ZipFile(archive) as source:
            restored.write_bytes(source.read("AstrBot/data/state.db"))
        check = sqlite3.connect(restored)
        try:
            self.assertEqual(check.execute("select value from t").fetchone()[0], "synthetic")
        finally:
            check.close()

    def test_output_workspace_foreign_artifact_is_quarantined(self):
        def add_foreign(output):
            output.with_name("FOREIGN-OUTPUT.txt").write_text("preserve", encoding="utf-8")

        patched_connect, _observed = self._output_close_injection(add_foreign)
        with mock.patch.object(engine.sqlite3, "connect", side_effect=patched_connect):
            result = self.run_backup()

        foreign = list(self.dest.glob("staging/*/.normalization/*/*/FOREIGN-OUTPUT.txt"))
        self.assertEqual(result.code, 3)
        self.assertIn("SQLite workspace contains a foreign artifact", result.message)
        self.assertIn("quarantine preserved", result.message)
        self.assertEqual(len(foreign), 1)
        self.assertEqual(foreign[0].read_text(encoding="utf-8"), "preserve")

    def test_output_workspace_hardlink_is_quarantined(self):
        def add_hardlink(output):
            journal = Path(str(output) + "-journal")
            journal.write_bytes(b"linked")
            os.link(journal, Path(str(output) + "-wal"))

        patched_connect, _observed = self._output_close_injection(add_hardlink)
        with mock.patch.object(engine.sqlite3, "connect", side_effect=patched_connect):
            result = self.run_backup()

        linked = list(self.dest.glob("staging/*/.normalization/*/*/*.db-journal"))
        self.assertEqual(result.code, 3)
        self.assertIn("quarantine preserved", result.message)
        self.assertEqual(len(linked), 1)
        self.assertGreater(linked[0].stat().st_nlink, 1)

    def test_output_workspace_reparse_classification_is_quarantined(self):
        observed_reparse = {"path": None}
        original_is_reparse = engine.is_reparse

        def add_classified_reparse(output):
            observed_reparse["path"] = Path(str(output) + "-journal")
            observed_reparse["path"].write_bytes(b"preserve")

        def classify(path, st=None):
            return (observed_reparse["path"] is not None
                    and Path(path) == observed_reparse["path"]) or original_is_reparse(path, st)

        patched_connect, _observed = self._output_close_injection(add_classified_reparse)
        with (
            mock.patch.object(engine.sqlite3, "connect", side_effect=patched_connect),
            mock.patch.object(engine, "is_reparse", side_effect=classify),
        ):
            result = self.run_backup()

        self.assertEqual(result.code, 3)
        self.assertIn("quarantine preserved", result.message)
        self.assertTrue(observed_reparse["path"].is_file())

    def test_normalize_primary_error_survives_secondary_cleanup_failure(self):
        first = self.run_backup()
        self.assertEqual(first.code, 0, first.message)
        observed = {}

        def fail_normalize(stage, _layout, _ledger):
            observed["foreign"] = stage / "FOREIGN-NORMALIZE.txt"
            observed["foreign"].write_text("preserve", encoding="utf-8")
            raise engine.BackupError("staging SQLite integrity/normalization failed", 1)

        with mock.patch.object(engine, "normalize_databases", side_effect=fail_normalize):
            result = self.run_backup("--force")

        expected = (
            "staging SQLite integrity/normalization failed; "
            "staging cleanup failed; quarantine preserved"
        )
        self.assertEqual(result.code, 1)
        self.assertEqual(result.message, expected)
        state = json.loads((self.dest / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["last_failure_code"], 1)
        self.assertEqual(state["last_failure_phase"], "normalize")
        diagnostic = max((self.dest / "diagnostics").glob("diagnostic-*.json"),
                         key=lambda path: path.stat().st_mtime_ns)
        payload = json.loads(diagnostic.read_text(encoding="utf-8"))
        self.assertEqual(payload, {"code": 1, "message": expected})
        self.assertEqual(observed["foreign"].read_text(encoding="utf-8"), "preserve")

    def test_triple_failure_keeps_primary_cleanup_and_state_update_messages(self):
        first = self.run_backup()
        self.assertEqual(first.code, 0, first.message)
        old_state = json.loads((self.dest / "state.json").read_text(encoding="utf-8"))
        old_finals = set(self.dest.glob("managed/**/*.zip"))
        observed = {}

        def fail_normalize(stage, _layout, _ledger):
            observed["foreign"] = stage / "FOREIGN-TRIPLE.txt"
            observed["foreign"].write_text("preserve", encoding="utf-8")
            raise engine.BackupError("staging SQLite integrity/normalization failed", 1)

        def fail_state_writer(*_args):
            raise OSError("synthetic state writer failure")

        with mock.patch.object(engine, "normalize_databases", side_effect=fail_normalize):
            result = self.run_backup("--force", state_writer=fail_state_writer)

        expected = (
            "staging SQLite integrity/normalization failed; "
            "staging cleanup failed; quarantine preserved; "
            "failed-attempt state update failed"
        )
        self.assertEqual(result.code, 1)
        self.assertEqual(result.message, expected)
        current_state = json.loads((self.dest / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(current_state, old_state)
        self.assertEqual(current_state["last_result"], "FULL_SUCCESS")
        self.assertEqual(set(self.dest.glob("managed/**/*.zip")), old_finals)
        self.assertEqual(observed["foreign"].read_text(encoding="utf-8"), "preserve")
        diagnostic = max((self.dest / "diagnostics").glob("diagnostic-*.json"),
                         key=lambda path: path.stat().st_mtime_ns)
        self.assertEqual(
            json.loads(diagnostic.read_text(encoding="utf-8")),
            {"code": 1, "message": expected},
        )

    def test_orphan_sidecar_is_preserved_raw(self):
        orphan = self.astr / "data" / "old.db-wal"
        payload = b"synthetic orphan bytes"
        orphan.write_bytes(payload)
        archive = self.successful_archive()
        with zipfile.ZipFile(archive) as zf:
            self.assertEqual(zf.read("AstrBot/data/old.db-wal"), payload)
            manifest = json.loads(zf.read("backup-manifest.json"))
        result = next(x for x in manifest["database_results"] if x["path"].endswith("old.db-wal"))
        self.assertTrue(result["orphan_sidecar"])

    def test_corrupt_extension_database_never_publishes(self):
        (self.astr / "data" / "broken.db").write_bytes(b"not a sqlite database")
        self.assertEqual(self.run_backup().code, 1)
        self.assertFalse(list(self.dest.glob("managed/**/*.zip")))

    def test_extensionless_sqlite_is_discovered_and_normalized(self):
        hidden = self.astr / "data" / "database_without_extension"
        con = sqlite3.connect(hidden)
        con.execute("create table found(id integer)")
        con.commit()
        con.close()
        archive = self.successful_archive()
        with zipfile.ZipFile(archive) as zf:
            manifest = json.loads(zf.read("backup-manifest.json"))
        self.assertIn("AstrBot/data/database_without_extension", manifest["database_layout"]["mains"])

    def test_unknown_sidecar_and_super_journal_candidates_fail_closed(self):
        for name in ("state.db-unknown", "state.db-mj ABCDEF12"):
            with self.subTest(name=name):
                candidate = self.astr / "data" / name
                candidate.write_bytes(b"suspicious")
                result = self.run_backup("--preflight")
                self.assertEqual(result.code, 1)
                candidate.unlink()


class ZipAndManifestTests(RegressionFixture):
    def test_verification_checks_actual_extraction_volume_space(self):
        archive = self.successful_archive()
        with mock.patch.object(engine.shutil, "disk_usage", return_value=mock.Mock(free=0)):
            self.assertFalse(engine.verify_archive(archive))

    def test_path_traversal_member_is_rejected(self):
        archive = self.successful_archive()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with zipfile.ZipFile(archive, "a") as zf:
                zf.writestr("../escape.txt", b"x")
        self.assertFalse(engine.verify_archive(archive))

    def test_ads_style_member_name_is_rejected(self):
        archive = self.successful_archive()
        with zipfile.ZipFile(archive, "a") as zf:
            zf.writestr("AstrBot/data/file:stream", b"x")
        self.assertFalse(engine.verify_archive(archive))

    def test_unix_special_member_is_rejected(self):
        archive = self.successful_archive()
        info = zipfile.ZipInfo("AstrBot/data/device")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(archive, "a") as zf:
            zf.writestr(info, b"target")
        self.assertFalse(engine.verify_archive(archive))

    def test_member_size_limit_is_enforced(self):
        archive = self.successful_archive()
        with mock.patch.object(engine, "MAX_ARCHIVE_ENTRY", 1):
            self.assertFalse(engine.verify_archive(archive))

    def test_manifest_contract_requires_all_typed_fields(self):
        archive = self.successful_archive()
        with zipfile.ZipFile(archive) as zf:
            manifest = json.loads(zf.read("backup-manifest.json"))
        self.assertTrue(engine._valid_manifest_contract(manifest))
        del manifest["owner_uuid"]
        self.assertFalse(engine._valid_manifest_contract(manifest))
        manifest["owner_uuid"] = 7
        self.assertFalse(engine._valid_manifest_contract(manifest))

    def test_database_results_must_exactly_cover_discovered_candidates(self):
        archive = self.successful_archive()
        self.rewrite_archive(archive, lambda manifest: manifest.update(database_results=[]))
        self.assertFalse(engine.verify_archive(archive))

    def test_manifest_records_exact_counts_times_capabilities_and_required_anchors(self):
        root_toml = self.astr / "data" / "optional.toml"
        root_toml.write_text("synthetic = true", "utf-8")
        archive = self.successful_archive()
        with zipfile.ZipFile(archive) as zf:
            manifest = json.loads(zf.read("backup-manifest.json"))
        self.assertEqual(manifest["generator_version"], engine.GENERATOR_VERSION)
        self.assertEqual(manifest["capabilities"], engine.CAPABILITIES)
        self.assertEqual(manifest["warnings"], [])
        self.assertEqual(
            manifest["astrbot_root_config_anchors"],
            list(engine.ASTRBOT_REQUIRED_ANCHORS),
        )
        self.assertEqual(
            manifest["total_files"],
            sum(entry["kind"] == "file" for entry in manifest["entries"]),
        )
        self.assertEqual(
            manifest["total_bytes"],
            sum(entry["size"] for entry in manifest["entries"] if entry["kind"] == "file"),
        )
        self.assertLessEqual(
            dt.datetime.fromisoformat(manifest["started_at"]),
            dt.datetime.fromisoformat(manifest["finished_at"]),
        )

    def test_manifest_napcat_whitelist_is_exact(self):
        nap, _ = SourceIdentityAndDriftTests._make_napcat(self)
        result = engine.run(self.args(nap=nap), process_probe=lambda _root: False)
        self.assertEqual(result.code, 0, result.message)
        archive = result.archive
        self.rewrite_archive(
            archive,
            lambda manifest: manifest["napcat_whitelist"].pop(),
        )
        self.assertFalse(engine.verify_archive(archive))


class StateAndScheduleTests(RegressionFixture):
    def test_corrupt_state_fails_closed_without_rewrite(self):
        self.successful_archive()
        state = self.dest / "state.json"
        state.write_text("not-json", "utf-8")
        before = state.read_bytes()
        result = self.run_backup()
        self.assertEqual(result.code, 3)
        self.assertEqual(state.read_bytes(), before)

    def test_clock_rollback_is_rejected(self):
        now = dt.datetime(2026, 8, 9, 12, tzinfo=TZ)
        self.successful_archive("--scheduled", now=now)
        result = self.run_backup("--scheduled", now=now - dt.timedelta(minutes=1))
        self.assertEqual(result.code, 3)

    def test_noop_is_bound_to_existing_verified_archive(self):
        now = dt.datetime(2026, 8, 9, 12, tzinfo=TZ)
        archive = self.successful_archive("--scheduled", now=now)
        archive.unlink()
        result = self.run_backup("--scheduled", now=now + dt.timedelta(days=1))
        self.assertEqual(result.code, 3)

    def test_noop_does_not_open_sources(self):
        now = dt.datetime(2026, 8, 9, 12, tzinfo=TZ)
        self.successful_archive("--scheduled", now=now)

        def forbidden(_path):
            raise AssertionError("weekly noop must not open source files")

        result = engine.run(
            self.args("--scheduled"), process_probe=lambda _root: False,
            source_opener=forbidden, now=now + dt.timedelta(days=1),
        )
        self.assertEqual(result.code, 0)
        self.assertTrue(result.noop)

    def test_state_rejects_foreign_top_level_artifact(self):
        self.successful_archive()
        foreign = self.dest / "foreign.txt"
        foreign.write_text("preserve", "utf-8")
        result = self.run_backup()
        self.assertEqual(result.code, 3)
        self.assertEqual(foreign.read_text("utf-8"), "preserve")

    def test_state_rejects_other_managed_owner(self):
        self.successful_archive()
        foreign_owner = self.dest / "managed" / str(uuid.uuid4())
        foreign_owner.mkdir()
        result = self.run_backup()
        self.assertEqual(result.code, 3)
        self.assertTrue(foreign_owner.is_dir())


class PreflightAndLateProcessTests(RegressionFixture):
    def test_preflight_checks_space_without_creating_destination(self):
        with mock.patch.object(engine, "available_space_without_creating", return_value=0):
            result = self.run_backup("--preflight")
        self.assertEqual(result.code, 1)
        self.assertFalse(self.dest.exists())

    def test_late_process_gates_block_before_publish_and_state_commit(self):
        for block_on in (3, 4, 5):
            with self.subTest(block_on=block_on):
                destination = self.base / f"late-process-{block_on}"
                calls = 0

                def probe(_root):
                    nonlocal calls
                    calls += 1
                    return calls == block_on

                result = engine.run(
                    self.args(destination=destination),
                    process_probe=probe,
                )
                self.assertEqual(result.code, 1)
                self.assertGreaterEqual(calls, block_on)
                self.assertFalse(list(destination.glob("managed/**/*.zip")) if destination.exists() else [])
                self.assertFalse((destination / "state.json").exists())


class PublicationCleanupRetentionTests(RegressionFixture):
    def test_archive_writer_failure_removes_owned_partial_and_scaffolding(self):
        def fail(*_args, **_kwargs):
            raise engine.BackupError("synthetic writer failure", 1)

        result = self.run_backup(archive_writer=fail)
        self.assertEqual(result.code, 1)
        self.assertFalse(self.dest.exists())

    def test_state_commit_failure_removes_uncommitted_final(self):
        def fail_state(*_args, **_kwargs):
            raise engine.BackupError("synthetic state failure", 3)

        result = self.run_backup(state_writer=fail_state)
        self.assertNotEqual(result.code, 0)
        self.assertFalse(list(self.dest.glob("managed/**/*.zip")) if self.dest.exists() else [])

    def test_cleanup_refuses_replacement_identity(self):
        path = self.base / "owned.partial"
        path.write_bytes(b"owned")
        token = engine._path_token(path, regular=True, single_link=True)
        path.unlink()
        path.write_bytes(b"replacement")
        self.assertFalse(engine._safe_unlink_owned(path, token))
        self.assertEqual(path.read_bytes(), b"replacement")

    def test_publish_no_replace_preserves_existing_final(self):
        partial = self.base / "partial.zip"
        final = self.base / "final.zip"
        partial.write_bytes(b"verified")
        final.write_bytes(b"foreign")
        token = engine._path_token(partial, regular=True, single_link=True)
        digest = hashlib.sha256(partial.read_bytes()).hexdigest()
        with self.assertRaises(engine.BackupError):
            engine.publish_no_replace(partial, final, token, digest)
        self.assertEqual(final.read_bytes(), b"foreign")
        self.assertEqual(partial.read_bytes(), b"verified")

    def test_retention_never_deletes_corrupt_archive(self):
        start = dt.datetime(2026, 8, 9, 12, tzinfo=TZ)
        archives = [
            self.successful_archive("--force", "--keep", "3", now=start + dt.timedelta(minutes=i))
            for i in range(3)
        ]
        archives[0].write_bytes(b"corrupt but foreign-to-cleanup")
        state = json.loads((self.dest / "state.json").read_text("utf-8"))
        owner = self.dest / "managed" / state["owner_uuid"]
        engine.retain(owner, 1, state["owner_uuid"], state["source_fingerprints"], archives[-1])
        self.assertTrue(archives[0].exists())
        self.assertTrue(archives[-1].exists())

    def test_archive_writer_rejects_hardlinked_staging_file(self):
        stage = self.base / "stage"
        target = stage / "AstrBot" / "data" / "file.bin"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"x")
        alias = self.base / "alias.bin"
        try:
            os.link(target, alias)
        except OSError:
            self.skipTest("hard links unavailable")
        with self.assertRaises(engine.BackupError):
            engine._staging_files(stage)


class MutexAndProcessTests(RegressionFixture):
    def test_trusted_backup_commandline_requires_exact_entry_and_optional_single_b(self):
        engine_path = str(Path(engine.__file__).resolve())
        console_path = str(Path(engine.__file__).with_name("console_runner.py").resolve())
        astrbot_main = r"C:\Synthetic\AstrBot\main.py"

        self.assertTrue(engine._trusted_backup_process_commandline(
            f'"C:\\Python\\python.exe" "{engine_path}"'))
        self.assertTrue(engine._trusted_backup_process_commandline(
            f'"C:\\Python\\python.exe" -B "{engine_path}"'))
        self.assertTrue(engine._trusted_backup_process_commandline(
            f'"C:\\Python\\python.exe" -B "{console_path}"'))

        for commandline in (
            f'"C:\\Python\\python.exe" -E "{engine_path}"',
            f'"C:\\Python\\python.exe" -B -B "{engine_path}"',
            f'"C:\\Python\\python.exe" -m safe_backup.engine "{engine_path}"',
            f'"C:\\Python\\python.exe" -c pass "{engine_path}"',
            f'"C:\\Python\\python.exe" "{astrbot_main}" "{engine_path}"',
        ):
            with self.subTest(commandline=commandline):
                self.assertFalse(engine._trusted_backup_process_commandline(commandline))

    def test_napcat_base_must_bind_current_or_distinct_compatible_version(self):
        current = "9.9.26-44498"
        compatible = "9.9.22-40990"
        self.assertTrue(engine.valid_napcat_version_relation(current, current, compatible))
        self.assertTrue(engine.valid_napcat_version_relation(compatible, current, compatible))
        self.assertFalse(engine.valid_napcat_version_relation("9.9.20-10000", current, compatible))
        self.assertFalse(engine.valid_napcat_version_relation(current, current, current))
        self.assertFalse(engine.valid_napcat_version_relation("broken", current, compatible))

    def test_mutex_conflict_returns_exit_three(self):
        args = self.args()
        result = engine.run(args, instance_guard=lambda _destination: False)
        self.assertEqual(result.code, 3)

    def test_default_mutex_is_exclusive_and_releasable(self):
        first = engine.default_instance_guard(self.dest)
        self.assertNotIn(first, (False, None))
        try:
            self.assertFalse(engine.default_instance_guard(self.dest))
        finally:
            first.release()
        second = engine.default_instance_guard(self.dest)
        self.assertNotIn(second, (False, None))
        second.release()

    def test_process_matcher_requires_exact_interpreter_and_main(self):
        interpreter = self.astr / "venv" / "Scripts" / "python.exe"
        exact = f'"{interpreter}" main.py'
        self.assertTrue(engine.process_command_matches(interpreter, exact, interpreter))
        self.assertFalse(engine.process_command_matches(interpreter, f'"{interpreter}" worker.py', interpreter))
        other = self.base / "python.exe"
        self.assertFalse(engine.process_command_matches(other, exact, interpreter))

    def test_process_probe_detects_other_interpreter_with_absolute_target_main(self):
        root = Path(r"C:\Synthetic\AstrBot")
        rows = [{
            "ExecutablePath": r"C:\Python\python.exe",
            "CommandLine": r'"C:\Python\python.exe" "C:\Synthetic\AstrBot\main.py"',
        }]
        completed = mock.Mock(stdout=json.dumps(rows))
        with mock.patch.object(engine.subprocess, "run", return_value=completed):
            self.assertTrue(engine.default_process_probe(root))

    def test_process_probe_fails_closed_for_ambiguous_relative_main(self):
        root = Path(r"C:\Synthetic\AstrBot")
        rows = [{
            "ExecutablePath": r"C:\Python\python.exe",
            "CommandLine": r'"C:\Python\python.exe" main.py',
        }]
        completed = mock.Mock(stdout=json.dumps(rows))
        with mock.patch.object(engine.subprocess, "run", return_value=completed):
            self.assertIsNone(engine.default_process_probe(root))

    def test_non_windows_engine_fails_closed(self):
        args = mock.Mock(verify=None)
        with mock.patch.object(engine.os, "name", "posix"):
            result = engine.run(args)
        self.assertEqual(result.code, 3)


if __name__ == "__main__":
    unittest.main()
