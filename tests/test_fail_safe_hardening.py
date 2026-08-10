from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from safe_backup import engine
from tests.test_engine_regressions import RegressionFixture


class RegisteredStagingCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="registered-stage-")
        self.base = Path(self.temporary.name)
        self.stage = self.base / "stage"
        self.stage.mkdir()
        self.ledger = engine.StageLedger(self.stage)
        self.owned = self.stage / "owned.bin"
        self.owned.write_bytes(b"owned")
        self.ledger.register(self.owned, kind="file")

    def tearDown(self):
        self.temporary.cleanup()

    def test_foreign_entry_added_after_registration_blocks_cleanup(self):
        foreign = self.stage / "foreign.txt"
        foreign.write_text("preserve", encoding="utf-8")
        self.assertFalse(engine._safe_rmtree_registered(self.stage, self.ledger))
        self.assertEqual(foreign.read_text("utf-8"), "preserve")
        self.assertEqual(self.owned.read_bytes(), b"owned")

    def test_registered_leaf_replacement_blocks_cleanup(self):
        self.owned.unlink()
        self.owned.write_bytes(b"replacement")
        self.assertFalse(engine._safe_rmtree_registered(self.stage, self.ledger))
        self.assertEqual(self.owned.read_bytes(), b"replacement")

    def test_hardlink_added_after_registration_blocks_cleanup(self):
        alias = self.base / "alias.bin"
        try:
            os.link(self.owned, alias)
        except OSError:
            self.skipTest("hard links unavailable")
        self.assertFalse(engine._safe_rmtree_registered(self.stage, self.ledger))
        self.assertTrue(self.owned.exists())
        self.assertTrue(alias.exists())

    def test_change_between_two_inventory_rounds_blocks_cleanup(self):
        foreign = self.stage / "between-rounds.txt"

        def inject():
            foreign.write_text("preserve", encoding="utf-8")

        self.assertFalse(
            engine._safe_rmtree_registered(
                self.stage, self.ledger, between_rounds=inject
            )
        )
        self.assertEqual(foreign.read_text("utf-8"), "preserve")


class AutomaticRetentionTests(RegressionFixture):
    def test_default_limit_keeps_five_verified_bound_archives(self):
        start = engine.dt.datetime(2026, 8, 9, 12, tzinfo=engine.dt.timezone.utc)
        archives = [
            self.successful_archive(
                "--force", "--keep", "5", now=start + engine.dt.timedelta(minutes=index)
            )
            for index in range(6)
        ]

        self.assertFalse(archives[0].exists())
        self.assertEqual(set(archives[0].parent.glob("*.zip")), set(archives[1:]))

    def test_automatic_retention_keeps_only_three_verified_bound_archives(self):
        start = engine.dt.datetime(2026, 8, 9, 12, tzinfo=engine.dt.timezone.utc)
        archives = []
        oldest_hash = None
        for index in range(4):
            archive = self.successful_archive(
                "--force", "--keep", "3", now=start + engine.dt.timedelta(minutes=index)
            )
            archives.append(archive)
            if index == 0:
                oldest_hash = engine.hashlib.sha256(archive.read_bytes()).hexdigest()
        state = engine.load_state(self.dest)
        remaining = set(archives[0].parent.glob("*.zip"))

        self.assertFalse(archives[0].exists())
        self.assertEqual(remaining, set(archives[1:]))
        self.assertEqual(state["last_successful_archive"], archives[-1].name)
        self.assertEqual(state["last_result"], "FULL_SUCCESS")
        self.assertEqual(
            state["retention_candidates"],
            [{
                "archive": archives[0].name,
                "action": "auto-delete-authorized",
                "sha256": oldest_hash,
                "verified": True,
            }],
        )

    def test_valid_archive_without_authoritative_state_binding_is_never_deleted(self):
        start = engine.dt.datetime(2026, 8, 9, 12, tzinfo=engine.dt.timezone.utc)
        first = self.successful_archive("--force", "--keep", "3", now=start)
        unbound = first.parent / (
            "astrbot-safe-backup-20200101-000000-00000000-0000-4000-8000-000000000099.zip"
        )
        unbound.write_bytes(first.read_bytes())
        later = [
            self.successful_archive(
                "--force", "--keep", "3", now=start + engine.dt.timedelta(minutes=index)
            )
            for index in range(1, 4)
        ]

        self.assertTrue(unbound.exists(), "an unbound but structurally valid ZIP must be preserved")
        self.assertFalse(first.exists(), "the oldest journal-bound archive may be removed")
        self.assertTrue(all(path.exists() for path in later))

    def test_retention_planning_never_unlinks_before_authorization(self):
        archives = [self.successful_archive("--force", "--keep", "3") for _ in range(3)]
        state = engine.load_state(self.dest)
        owner_dir = self.dest / "managed" / state["owner_uuid"]
        plan = engine.retain(
            owner_dir, 1, state["owner_uuid"], state["source_fingerprints"], archives[-1]
        )
        self.assertTrue(all(path.exists() for path in archives))
        self.assertTrue(plan)
        self.assertTrue(all(isinstance(item, engine.RetentionPlanEntry) for item in plan))

    def test_retention_authorization_is_typed_persisted_and_observable(self):
        first = self.successful_archive("--keep", "1")
        first_hash = engine.hashlib.sha256(first.read_bytes()).hexdigest()
        result = self.run_backup("--force", "--keep", "1")
        self.assertEqual(result.code, 0, result.message)
        self.assertFalse(first.exists(), "a proven overflow archive should be deleted")
        state = engine.load_state(self.dest)
        expected = [{
            "archive": first.name,
            "action": "auto-delete-authorized",
            "sha256": first_hash,
            "verified": True,
        }]
        self.assertEqual(result.retention_candidates, expected)
        self.assertEqual(state["retention_candidates"], expected)
        self.assertNotIn(str(self.base), json.dumps(expected))

    def test_retention_verification_cleanup_failure_preserves_all_archives(self):
        first = self.successful_archive("--keep", "3")
        second = self.successful_archive("--force", "--keep", "3")
        original_verify = engine.verify_archive
        observed = {}

        def verify_with_retention_race(archive, *args, **kwargs):
            if Path(archive) == first:
                def inject(root, _ledger):
                    observed["quarantine"] = root
                    observed["foreign"] = root / "foreign-retention.txt"
                    observed["foreign"].write_text("preserve", encoding="utf-8")

                kwargs["verification_root"] = self.dest / "staging"
                kwargs["verification_hook"] = inject
            return original_verify(archive, *args, **kwargs)

        with mock.patch.object(
            engine, "verify_archive", side_effect=verify_with_retention_race
        ):
            result = self.run_backup("--force", "--keep", "1")

        self.assertEqual(result.code, 0, result.message)
        self.assertIn("retention", result.message)
        state = engine.load_state(self.dest)
        self.assertEqual(state["last_successful_archive"], result.archive.name)
        self.assertEqual(state["last_result"], "FULL_SUCCESS", result.message)
        self.assertEqual(set((first.parent).glob("*.zip")), {first, second, result.archive})
        self.assertEqual(observed["foreign"].read_text("utf-8"), "preserve")
        self.assertTrue(observed["quarantine"].is_dir())

    def test_authorization_state_commit_failure_deletes_nothing(self):
        first = self.successful_archive("--keep", "1")
        original_commit = engine.commit_state
        commit_calls = 0

        def fail_authorization_commit(*args, **kwargs):
            nonlocal commit_calls
            commit_calls += 1
            if commit_calls == 2:
                raise engine.BackupError("synthetic retention authorization failure", 3)
            return original_commit(*args, **kwargs)

        with mock.patch.object(engine, "commit_state", side_effect=fail_authorization_commit):
            result = self.run_backup("--force", "--keep", "1")

        self.assertEqual(result.code, 0, result.message)
        self.assertIn("retention", result.message)
        self.assertTrue(first.exists())
        self.assertTrue(result.archive.exists())
        state = engine.load_state(self.dest)
        self.assertEqual(state["last_successful_archive"], result.archive.name)
        self.assertEqual(state["retention_candidates"], [])

    def test_candidate_changed_after_authorization_is_preserved(self):
        first = self.successful_archive("--keep", "1")
        original_apply = engine._apply_retention_plan
        tampered = b"foreign replacement bytes"

        def race_before_delete(owner_dir, plan):
            first.write_bytes(tampered)
            return original_apply(owner_dir, plan)

        with mock.patch.object(
            engine, "_apply_retention_plan", side_effect=race_before_delete
        ):
            result = self.run_backup("--force", "--keep", "1")

        self.assertEqual(result.code, 0, result.message)
        self.assertIn("retention", result.message)
        self.assertEqual(first.read_bytes(), tampered)
        self.assertTrue(result.archive.exists())

    def test_corrupt_bound_archive_is_never_deleted(self):
        first = self.successful_archive("--keep", "1")
        first.write_bytes(b"not a zip")

        result = self.run_backup("--force", "--keep", "1")

        self.assertNotEqual(result.code, 0)
        self.assertEqual(first.read_bytes(), b"not a zip")
        self.assertIsNone(result.archive)

    def test_hardlinked_bound_archive_is_never_deleted(self):
        first = self.successful_archive("--keep", "1")
        alias = first.with_suffix(".hold")
        try:
            os.link(first, alias)
        except OSError as exc:
            self.skipTest(f"hard links unavailable: {exc}")

        result = self.run_backup("--force", "--keep", "1")

        self.assertNotEqual(result.code, 0)
        self.assertTrue(first.exists())
        self.assertTrue(alias.exists())
        self.assertIsNone(result.archive)

    def test_archive_with_ads_is_never_deleted(self):
        if os.name != "nt":
            self.skipTest("NTFS alternate streams are Windows-only")
        first = self.successful_archive("--keep", "1")
        stream = Path(str(first) + ":retention-test")
        try:
            stream.write_text("preserve", encoding="utf-8")
        except OSError as exc:
            self.skipTest(f"alternate streams unavailable: {exc}")

        result = self.run_backup("--force", "--keep", "1")

        self.assertTrue(first.exists())
        self.assertEqual(stream.read_text("utf-8"), "preserve")
        if result.archive is not None:
            self.assertTrue(result.archive.exists())

    def test_deletion_runs_only_after_success_and_authorization_commits(self):
        first = self.successful_archive("--keep", "1")
        original_commit = engine.commit_state
        original_apply = engine._apply_retention_plan
        events = []

        def record_commit(*args, **kwargs):
            result = original_commit(*args, **kwargs)
            events.append("commit")
            return result

        def record_apply(*args, **kwargs):
            events.append("apply")
            self.assertGreaterEqual(events.count("commit"), 2)
            return original_apply(*args, **kwargs)

        with mock.patch.object(engine, "commit_state", side_effect=record_commit), mock.patch.object(
            engine, "_apply_retention_plan", side_effect=record_apply
        ):
            result = self.run_backup("--force", "--keep", "1")

        self.assertEqual(result.code, 0, result.message)
        self.assertEqual(events[-1], "apply")
        self.assertFalse(first.exists())


class RecoverableStateTests(RegressionFixture):
    def test_durable_journal_survives_cache_commit_failure_and_keeps_final(self):
        calls = 0

        def fail_cache_only(path, value):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise engine.BackupError("synthetic cache failure", 3)
            return engine.atomic_json(path, value)

        result = self.run_backup(state_writer=fail_cache_only)
        self.assertEqual(result.code, 0, result.message)
        self.assertTrue(result.archive.is_file())
        recovered = engine.load_state(self.dest)
        self.assertEqual(recovered["last_successful_archive"], result.archive.name)
        self.assertTrue((self.dest / "state-journal").is_dir())

    def test_equally_revised_cache_with_different_content_fails_closed(self):
        result = self.run_backup()
        self.assertEqual(result.code, 0, result.message)
        authoritative = engine.load_state(self.dest)
        stale = dict(authoritative)
        stale["artifact_digest"] = "f" * 64
        (self.dest / "state.json").write_text(json.dumps(stale), encoding="utf-8")
        with self.assertRaises(engine.BackupError):
            engine.load_state(self.dest)

    def test_conflicting_same_revision_journals_fail_closed(self):
        result = self.run_backup()
        self.assertEqual(result.code, 0, result.message)
        state = engine.load_state(self.dest)
        state["state_revision"] = 7
        journal = self.dest / "state-journal"
        first = journal / "00000000-0000-4000-8000-000000000101.json"
        second = journal / "ffffffff-ffff-4fff-8fff-ffffffffffff.json"
        first.write_text(json.dumps(state), encoding="utf-8")
        state["artifact_digest"] = "f" * 64
        second.write_text(json.dumps(state), encoding="utf-8")
        with self.assertRaises(engine.BackupError):
            engine.load_state(self.dest)


class ZipBudgetTests(RegressionFixture):
    def test_manifest_limits_are_source_bound_and_include_compression_ratio(self):
        archive = self.successful_archive()
        with engine.zipfile.ZipFile(archive) as zf:
            manifest = json.loads(zf.read("backup-manifest.json"))
        limits = manifest["limits"]
        source_bytes = sum(path.stat().st_size for path in (self.astr / "data").rglob("*") if path.is_file())
        expected = engine.archive_budget(source_bytes, len(manifest["entries"]))
        self.assertEqual(limits, expected)
        self.assertLess(limits["max_archive_total"], engine.HARD_MAX_ARCHIVE_TOTAL + 1)
        self.assertIn("max_compression_ratio", limits)

    def test_compression_ratio_budget_rejects_zip_bomb_member(self):
        limits = engine.archive_budget(1024, 1)
        bomb = SimpleNamespace(file_size=limits["max_compression_ratio"] + 1, compress_size=1)
        self.assertFalse(engine._zip_info_within_budget(bomb, limits))


class RegisteredVerificationCleanupTests(RegressionFixture):
    def _verify_with_injection(self, injection):
        archive = self.successful_archive()
        verification_root = self.base / "verification"
        verification_root.mkdir()
        observed = {}

        def hook(root, ledger):
            observed["root"] = root
            observed["ledger"] = ledger
            injection(root, ledger, observed)

        verified = engine.verify_archive(
            archive,
            verification_root=verification_root,
            verification_hook=hook,
        )
        self.assertFalse(verified)
        self.assertRegex(observed["root"].name, r"^backup-verify-[0-9a-f-]{36}$")
        self.assertTrue(observed["root"].is_dir(), "unsafe cleanup must leave quarantine")
        return observed

    def test_foreign_file_before_cleanup_fails_and_is_preserved(self):
        def inject(root, _ledger, observed):
            observed["foreign"] = root / "foreign.txt"
            observed["foreign"].write_text("preserve", encoding="utf-8")

        observed = self._verify_with_injection(inject)
        self.assertEqual(observed["foreign"].read_text("utf-8"), "preserve")

    def test_registered_directory_leaf_replacement_is_preserved(self):
        def inject(root, _ledger, observed):
            original = root / "AstrBot" / "data"
            observed["moved"] = root.parent / "moved-data"
            original.rename(observed["moved"])
            original.mkdir()
            observed["replacement"] = original

        observed = self._verify_with_injection(inject)
        self.assertTrue(observed["replacement"].is_dir())
        self.assertTrue(observed["moved"].is_dir())

    def test_registered_database_hardlink_is_preserved(self):
        def inject(root, _ledger, observed):
            database = root / "AstrBot" / "data" / "state.db"
            observed["database"] = database
            observed["alias"] = root.parent / "database-alias.db"
            try:
                os.link(database, observed["alias"])
            except OSError:
                self.skipTest("hard links unavailable")

        observed = self._verify_with_injection(inject)
        self.assertTrue(observed["database"].is_file())
        self.assertTrue(observed["alias"].is_file())

    def test_registered_reparse_classification_fails_closed(self):
        original = engine.is_reparse

        def inject(root, _ledger, observed):
            observed["database"] = root / "AstrBot" / "data" / "state.db"
            patcher = mock.patch.object(
                engine,
                "is_reparse",
                side_effect=lambda path, st=None: (
                    True if Path(path) == observed["database"] else original(path, st)
                ),
            )
            observed["patcher"] = patcher
            patcher.start()
            self.addCleanup(patcher.stop)

        observed = self._verify_with_injection(inject)
        self.assertTrue(observed["database"].is_file())


@unittest.skipUnless(os.name == "nt", "Windows named mutex test")
class AstrBotRuntimeMutexTests(unittest.TestCase):
    def test_runtime_marker_blocks_engine_offline_guard(self):
        root = Path(tempfile.gettempdir()) / ("synthetic-astrbot-" + os.urandom(8).hex())
        marker = engine.acquire_runtime_marker(root)
        self.assertIsNotNone(marker)
        try:
            self.assertFalse(engine.default_astrbot_offline_guard(root))
        finally:
            marker.release()
        guard = engine.default_astrbot_offline_guard(root)
        self.assertNotIn(guard, (False, None))
        guard.release()


class FailurePhaseDeletionInvariantTests(RegressionFixture):
    def test_every_failure_phase_preserves_foreign_paths(self):
        for phase in sorted(engine.FAILURE_PHASES):
            with self.subTest(phase=phase):
                destination = self.base / ("phase-" + phase)
                outside = self.base / ("outside-" + phase + ".txt")
                outside.write_text("preserve", encoding="utf-8")
                injected = []

                def fail_at(current, stage, _ledger):
                    if current != phase:
                        return
                    if stage is not None and stage.is_dir():
                        foreign = stage / "foreign-in-stage.txt"
                        foreign.write_text("preserve", encoding="utf-8")
                        injected.append(foreign)
                    raise engine.BackupError("synthetic phase failure", 1)

                result = engine.run(
                    self.args(destination=destination),
                    process_probe=lambda _root: False,
                    phase_hook=fail_at,
                )
                if phase == "retention":
                    self.assertIn("retention", result.message)
                else:
                    self.assertNotEqual(result.code, 0)
                self.assertEqual(outside.read_text("utf-8"), "preserve")
                for foreign in injected:
                    self.assertEqual(foreign.read_text("utf-8"), "preserve")


class TaskSevenTransactionMatrixTests(RegressionFixture):
    """Cross-boundary faults must not replace a prior verified archive."""

    def test_archive_state_and_staging_faults_preserve_verified_history(self):
        cases = ("archive_writer", "state_commit", "staging_foreign")
        for label in cases:
            with self.subTest(boundary=label):
                destination = self.base / ("matrix-" + label)
                initial = engine.run(self.args(destination=destination), process_probe=lambda _root: False)
                self.assertEqual(initial.code, 0, initial.message)
                before = set(destination.glob("managed/**/*.zip"))
                state = engine.load_state(destination)
                current = engine.dt.datetime.fromisoformat(state["last_attempt_time_utc"])
                kwargs = {}
                foreign = None
                if label == "archive_writer":
                    kwargs["archive_writer"] = lambda *_args, **_kwargs: (_ for _ in ()).throw(
                        engine.BackupError("synthetic archive fault", 1)
                    )
                elif label == "state_commit":
                    kwargs["state_writer"] = lambda *_args, **_kwargs: (_ for _ in ()).throw(
                        engine.BackupError("synthetic state fault", 3)
                    )
                else:
                    def inject(phase, stage, _ledger):
                        nonlocal foreign
                        if phase == "copy" and stage is not None:
                            foreign = stage / "foreign-staging-entry.txt"
                            foreign.write_text("preserve", encoding="utf-8")
                            raise engine.BackupError("synthetic staging fault", 1)
                    kwargs["phase_hook"] = inject
                result = engine.run(
                    self.args("--force", destination=destination), process_probe=lambda _root: False,
                    now=current + engine.dt.timedelta(minutes=1), **kwargs,
                )
                self.assertNotEqual(result.code, 0, result.message)
                self.assertEqual(set(destination.glob("managed/**/*.zip")), before)
                self.assertTrue(initial.archive.is_file())
                self.assertTrue(engine.verify_archive(initial.archive))
                if foreign is not None:
                    self.assertEqual(foreign.read_text(encoding="utf-8"), "preserve")

    def test_source_wal_sidecar_drift_fails_without_replacing_verified_history(self):
        live = self.astr / "data" / "live-family.db"
        connection = engine.sqlite3.connect(live)
        try:
            connection.execute("pragma journal_mode=wal")
            connection.execute("pragma wal_autocheckpoint=0")
            connection.execute("create table live_entries(value text)")
            connection.execute("insert into live_entries values ('synthetic')")
            connection.commit()
            sidecar = Path(str(live) + "-wal")
            self.assertTrue(sidecar.is_file())
            initial = self.run_backup()
            self.assertEqual(initial.code, 0, initial.message)
            before = set(self.dest.glob("managed/**/*.zip"))
            prior = engine.load_state(self.dest)
            changed = False

            def mutate_during_copy(phase, _stage, _ledger):
                nonlocal changed
                if phase == "copy" and not changed:
                    changed = True
                    with sidecar.open("ab") as writer:
                        writer.write(b"changed-during-synthetic-copy")

            now = engine.dt.datetime.fromisoformat(prior["last_attempt_time_utc"])
            result = engine.run(
                self.args("--force"), process_probe=lambda _root: False,
                phase_hook=mutate_during_copy, now=now + engine.dt.timedelta(minutes=1),
            )
            self.assertNotEqual(result.code, 0, result.message)
            self.assertTrue(changed)
            self.assertEqual(set(self.dest.glob("managed/**/*.zip")), before)
            self.assertTrue(initial.archive.is_file())
            self.assertTrue(engine.verify_archive(initial.archive))
            self.assertNotEqual(engine.load_state(self.dest)["last_result"], "FULL_SUCCESS")
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
