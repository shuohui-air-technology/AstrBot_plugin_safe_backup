from __future__ import annotations

import asyncio
import datetime as dt
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REPOSITORY = Path(__file__).resolve().parents[1]
STUBS = Path(__file__).resolve().parent / "stubs"
sys.path.insert(0, str(STUBS))
sys.path.insert(0, str(REPOSITORY))

from astrbot.api import AstrBotConfig  # noqa: E402
from astrbot.api.event import AstrMessageEvent  # noqa: E402
from astrbot.api.star import Context  # noqa: E402
import main as plugin_main  # noqa: E402
from main import SafeBackupPlugin  # noqa: E402
from safe_backup.task_control import TaskDiscovery, TaskOperationResult  # noqa: E402
from safe_backup import engine  # noqa: E402


async def _collect(generator):
    return [item async for item in generator]


class _FakeTaskAdapter:
    """In-memory task boundary: task names are never sent to the host OS."""

    def __init__(self, *, task_exists=False):
        self.task_exists = task_exists
        self.current_spec = None
        self.operations = []
        self.installs = 0
        self.updates = 0
        self.removes = 0

    def _result(self, status, spec, code=0):
        return TaskOperationResult(code, status, spec.name.rsplit(" ", 1)[-1])

    def inspect(self, spec):
        self.operations.append("inspect")
        return (
            self._result("inspected", spec)
            if self.task_exists and self.current_spec == spec
            else self._result("failed", spec, 1)
        )

    def inspect_by_fingerprint(self, _fingerprint):
        self.operations.append("discover")
        return (
            TaskDiscovery("exact", self.current_spec)
            if self.task_exists else TaskDiscovery("missing", None)
        )

    def install(self, spec):
        self.operations.append("install")
        if self.task_exists:
            return self._result("failed", spec, 1)
        self.task_exists = True
        self.current_spec = spec
        self.installs += 1
        return self._result("installed", spec)

    def update(self, expected_old, spec=None):
        spec = spec or expected_old
        self.operations.append("update")
        if not self.task_exists or self.current_spec != expected_old:
            return self._result("failed", spec, 1)
        self.updates += 1
        self.current_spec = spec
        return self._result("updated", spec)

    def remove(self, spec):
        self.operations.append("remove")
        if not self.task_exists or self.current_spec != spec:
            return self._result("failed", spec, 1)
        self.task_exists = False
        self.current_spec = None
        self.removes += 1
        return self._result("removed", spec)


class PluginControlPlaneTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.astrbot = self.base / "SyntheticAstrBot"
        (self.astrbot / "data").mkdir(parents=True)
        self.destination = self.base / "NewBackupDestination"
        self.config = AstrBotConfig(
            destination_path=str(self.destination),
            retention_count=5,
            schedule_weekday="Sunday",
            schedule_time="12:00",
            napcat_enabled=False,
            napcat_root="",
        )
        self.plugin = SafeBackupPlugin(Context(), self.config)
        self.root_patch = patch.object(
            self.plugin, "_infer_astrbot_root", return_value=self.astrbot
        )
        self.root_patch.start()
        self.event = AstrMessageEvent()

    def tearDown(self):
        self.root_patch.stop()
        self.temporary.cleanup()

    def run_command(self, command):
        return asyncio.run(_collect(command))[0]

    def transactional_plugin(self, *, task_exists=False, waiter=None, verifier=None):
        """Build a plugin whose external task/process boundaries are deterministic."""
        adapter = _FakeTaskAdapter(task_exists=task_exists)
        package = self.base / "plugin-package"
        (package / "safe_backup").mkdir(parents=True)
        for name in ("__init__.py", "engine.py", "console_runner.py", "progress.py"):
            (package / "safe_backup" / name).write_text("# synthetic\n", encoding="utf-8")
        (package / "scripts").mkdir()
        for name in ("task_launcher.ps1", "run_backup_visible.ps1", "task_common.ps1", "install_task.ps1", "update_task.ps1", "remove_task.ps1"):
            (package / "scripts" / name).write_text("# synthetic", encoding="utf-8")
        plugin = SafeBackupPlugin(
            Context(), self.config,
            task_adapter=adapter,
            waiter_launcher=waiter or (lambda _config, _state: None),
            archive_verifier=verifier or (lambda _archive, _owner, _prints: True),
            user_profile=self.base / "profile",
            plugin_dir=package,
            python_path=Path(sys.executable),
            compatibility_gate=lambda: None,
        )
        (self.base / "profile").mkdir(exist_ok=True)
        patcher = patch.object(plugin, "_infer_astrbot_root", return_value=self.astrbot)
        patcher.start()
        self.addCleanup(patcher.stop)
        return plugin, adapter

    def test_setup_uses_the_real_exit_waiter_when_no_test_collaborator_is_supplied(self):
        adapter = _FakeTaskAdapter()
        plugin, _ = self.transactional_plugin(task_exists=False)
        plugin.task_adapter = adapter
        # Recreate the plugin without a custom waiter: setup must not retain a
        # permanently-failing placeholder once the production helper exists.
        with patch("main.launch_exit_waiter") as launch:
            plugin._waiter_launcher = plugin._default_waiter_launcher
            plugin._waiter_uses_ledger = True
            response = self.run_command(plugin.setup(self.event))
        self.assertIn("初始化完成", response)
        launch.assert_called_once()

    def _write_owned_state(self, **updates):
        self.destination.mkdir(exist_ok=True)
        validated = self.plugin._validated_config()
        owner = "00000000-0000-4000-8000-000000000001"
        state = {
            "schema": 1,
            "schema_version": 1,
            "managed_by": "astrbot_plugin_safe_backup",
            "state_namespace": "community-v1",
            "owner_uuid": owner,
            "state_revision": 0,
            "source_fingerprint": validated["source_fingerprint"],
            "source_fingerprints": validated["source_fingerprints"],
            "config_fingerprint": validated["config_fingerprint"],
            "artifact_digest": validated["artifact_digest"],
            "last_result": "FULL_SUCCESS",
            "database_layout": {"mains": [], "sidecars": []},
            "napcat_enabled": False,
            "napcat_version": "disabled",
            "napcat_whitelist": [],
            "week_start": "sunday",
            "schedule_time": "12:00",
            "timezone": "UTC",
            "last_cycle": "2026-08-02",
            "last_success_cycle": "2026-08-02",
            "last_success_archive": "astrbot-safe-backup-20260802-120000-00000000-0000-4000-8000-000000000002.zip",
            "last_success_archive_sha256": "a" * 64,
            "last_successful_cycle": "2026-08-02",
            "last_successful_archive": "astrbot-safe-backup-20260802-120000-00000000-0000-4000-8000-000000000002.zip",
            "last_successful_archive_sha256": "a" * 64,
            "last_attempt_time_utc": "2026-08-02T04:00:00+00:00",
            "last_attempt_time_local": "2026-08-02T12:00:00+08:00",
            "retention_candidates": [],
        }
        if "last_success_archive" in updates and "last_successful_archive" not in updates:
            updates["last_successful_archive"] = updates["last_success_archive"]
        if "last_successful_archive" in updates and "last_success_archive" not in updates:
            updates["last_success_archive"] = updates["last_successful_archive"]
        state.update(updates)
        managed = self.destination / "managed" / owner
        managed.mkdir(parents=True, exist_ok=True)
        (self.destination / "state.json").write_text(
            json.dumps(state), encoding="utf-8"
        )
        return state

    def _move_state_to_journal(self):
        state_path = self.destination / "state.json"
        journal = self.destination / "state-journal"
        journal.mkdir()
        journal_path = journal / "00000000-0000-4000-8000-000000000003.json"
        state_path.replace(journal_path)
        return journal_path

    def test_check_does_not_create_destination(self):
        self.assertFalse(self.destination.exists())
        response = self.run_command(self.plugin.check(self.event))
        self.assertIn("静态只读检查通过", response)
        self.assertFalse(self.destination.exists())

    def test_status_distinguishes_uninitialized_from_scheduled_execution(self):
        response = self.run_command(self.plugin.status(self.event))
        self.assertIn("计划任务管理：仅显式 setup/task 命令可修改；插件加载或卸载不会修改。", response)
        self.assertIn("备份执行：尚未初始化，不会按计划运行。", response)
        self.assertIn("尚未初始化", response)
        plugin, _adapter = self.transactional_plugin()
        self.run_command(plugin.setup(self.event))
        response = self.run_command(plugin.status(self.event))
        self.assertIn("计划任务管理：仅显式 setup/task 命令可修改；插件加载或卸载不会修改。", response)
        self.assertIn("备份执行：初始化后由计划任务按配置自动尝试。", response)

    def test_blank_destination_read_only_commands_share_default_resolution(self):
        self.config["destination_path"] = ""
        self.plugin._compatibility_gate = lambda: None
        self.plugin._user_profile = self.base
        for command in (
            self.plugin.status(self.event), self.plugin.check(self.event),
            self.plugin.history(self.event), self.plugin.verify(self.event, "latest"),
        ):
            response = self.run_command(command)
            self.assertNotIn("尚未配置", response)

    def test_default_compatibility_gate_uses_official_astrbot_version_and_rejects_reparse_ancestor(self):
        plugin, _adapter = self.transactional_plugin()
        plugin._default_compatibility_gate()
        with patch("main._is_reparse_point", side_effect=lambda path: path == plugin._plugin_dir.parent):
            with self.assertRaises(plugin_main.ControlError):
                plugin._default_compatibility_gate()

    def test_initialize_holds_runtime_marker_until_terminate(self):
        marker = unittest.mock.Mock()
        with patch.object(plugin_main, "acquire_runtime_marker", return_value=marker) as acquire:
            asyncio.run(self.plugin.initialize())
            acquire.assert_called_once_with(self.astrbot)
            asyncio.run(self.plugin.terminate())
        marker.release.assert_called_once_with()

    def test_nonempty_foreign_destination_is_rejected(self):
        self.destination.mkdir()
        (self.destination / "foreign.txt").write_text("foreign", encoding="utf-8")
        response = self.run_command(self.plugin.check(self.event))
        self.assertIn("不可信", response)
        self.assertEqual(
            (self.destination / "foreign.txt").read_text(encoding="utf-8"),
            "foreign",
        )

    def test_foreign_state_is_rejected(self):
        self.destination.mkdir()
        (self.destination / "state.json").write_text(
            '{"managed_by":"another-project"}', encoding="utf-8"
        )
        response = self.run_command(self.plugin.status(self.event))
        self.assertIn("不可信", response)

    def test_control_plane_accepts_trusted_journal_only_state(self):
        self._write_owned_state()
        self._move_state_to_journal()
        response = self.run_command(self.plugin.status(self.event))
        self.assertIn("配置与状态一致", response)

    def test_control_plane_rejects_hardlinked_state(self):
        self._write_owned_state()
        alias = self.base / "state-alias.json"
        try:
            os.link(self.destination / "state.json", alias)
        except OSError:
            self.skipTest("hard links unavailable")
        response = self.run_command(self.plugin.status(self.event))
        self.assertIn("状态", response)
        self.assertIn("失败", response)

    def test_control_plane_uses_engine_trusted_state_loader(self):
        self._write_owned_state()
        with patch("main.load_state", wraps=plugin_main.load_state) as loader:
            self.run_command(self.plugin.status(self.event))
        loader.assert_called_once_with(self.destination)

    def test_reparse_probe_oserror_fails_closed(self):
        with patch.object(Path, "lstat", side_effect=PermissionError("denied")):
            with self.assertRaises(plugin_main.ControlError):
                plugin_main._is_reparse_point(self.destination)

    def test_managed_owner_child_must_be_one_plain_directory(self):
        state = self._write_owned_state()
        owner = self.destination / "managed" / state["owner_uuid"]
        owner.rmdir()
        owner.write_text("not a directory", encoding="utf-8")
        response = self.run_command(self.plugin.status(self.event))
        self.assertIn("失败", response)

    def test_status_reports_automatic_retention_authorization_count(self):
        secret = str(self.base / "MUST_NOT_LEAK.zip")
        self._write_owned_state(
            retention_candidates=[
                {
                    "archive": "astrbot-safe-backup-20260801-120000-00000000-0000-4000-8000-000000000004.zip",
                    "action": "auto-delete-authorized",
                    "sha256": "a" * 64,
                    "verified": True,
                }
            ],
        )
        response = self.run_command(self.plugin.status(self.event))
        self.assertIn("自动清理授权数量：1", response)
        self.assertNotIn("MUST_NOT_LEAK", response)
        history = self.run_command(self.plugin.history(self.event))
        self.assertIn("自动清理授权数量：1", history)
        self.assertNotIn("astrbot-safe-backup-20260801", history)

    def test_owned_state_rejects_foreign_top_level_and_owner(self):
        state = self._write_owned_state()
        (self.destination / "foreign.txt").write_text("foreign", encoding="utf-8")
        response = self.run_command(self.plugin.status(self.event))
        self.assertIn("不可信", response)
        (self.destination / "foreign.txt").unlink()
        managed = self.destination / "managed"
        (managed / "00000000-0000-4000-8000-000000000002").mkdir()
        response = self.run_command(self.plugin.status(self.event))
        self.assertIn("不可信", response)

    def test_history_never_echoes_arbitrary_state_text(self):
        self._write_owned_state(
            recent_runs=[
                {
                    "time": "token=DO_NOT_PRINT",
                    "result": "secret value",
                    "stage": "cookie=DO_NOT_PRINT",
                }
            ]
        )
        response = self.run_command(self.plugin.history(self.event))
        self.assertNotIn("DO_NOT_PRINT", response)
        self.assertNotIn("secret value", response)

    def test_schedule_change_is_reported_as_update_not_foreign_source(self):
        self._write_owned_state()
        self.config["schedule_time"] = "13:15"
        response = self.run_command(self.plugin.status(self.event))
        self.assertIn("显式更新计划任务", response)
        self.assertIn("等待下一次成功冷备刷新状态", response)
        self.assertNotIn("源目录指纹不匹配", response)

    def test_setup_initializes_then_installs_reinspects_and_launches_waiter(self):
        events = []
        plugin, adapter = self.transactional_plugin(
            waiter=lambda _config, _state: events.append("waiter")
        )
        self.config["destination_path"] = ""
        response = self.run_command(plugin.setup(self.event))
        self.assertIn("初始化完成", response)
        self.assertIn("没有立即启动备份", response)
        self.assertEqual(adapter.operations, ["discover", "install", "inspect"])
        self.assertEqual(events, ["waiter"])

    def test_repeated_exact_setup_is_idempotent(self):
        plugin, adapter = self.transactional_plugin()
        self.run_command(plugin.setup(self.event))
        response = self.run_command(plugin.setup(self.event))
        self.assertEqual(adapter.installs, 1)
        self.assertIn("已经初始化", response)

    def test_setup_reports_drift_as_explicit_task_update(self):
        plugin, adapter = self.transactional_plugin()
        self.run_command(plugin.setup(self.event))
        self.config["schedule_time"] = "13:15"
        response = self.run_command(plugin.setup(self.event))
        self.assertIn("task update", response)
        self.assertEqual(adapter.installs, 1)

    def test_setup_rejects_exact_task_without_its_initialization_ledger(self):
        plugin, adapter = self.transactional_plugin(task_exists=True)
        response = self.run_command(plugin.setup(self.event))
        self.assertIn("失败", response)
        self.assertEqual(adapter.installs, 0)

    def test_setup_rolls_back_only_its_task_and_ledger_when_waiter_fails(self):
        def fail_waiter(_config, _state):
            raise RuntimeError(r"C:\\secret\\waiter")

        plugin, adapter = self.transactional_plugin(waiter=fail_waiter)
        response = self.run_command(plugin.setup(self.event))
        self.assertIn("失败", response)
        self.assertEqual(adapter.removes, 1)
        self.assertFalse(self.destination.exists())
        self.assertNotIn(r"C:\\secret", response)

    def test_task_update_and_remove_are_transactional_and_leave_files_on_remove(self):
        plugin, adapter = self.transactional_plugin()
        self.run_command(plugin.setup(self.event))
        self.config["schedule_time"] = "13:15"
        response = self.run_command(plugin.task(self.event, "update"))
        self.assertIn("更新", response)
        self.assertIn("状态绑定", response)
        self.assertIn("不会立即启动", response)
        self.assertEqual(adapter.updates, 1)
        response = self.run_command(plugin.task(self.event, "remove"))
        self.assertIn("移除", response)
        self.assertEqual(adapter.removes, 1)
        self.assertTrue(self.destination.exists())

    def test_same_destination_update_rebinds_initialized_state_and_first_scheduled_run(self):
        """A real TaskSpec update must not strand INITIALIZED state as unsafe."""
        data = self.astrbot / "data"
        (data / "config").mkdir(exist_ok=True)
        for name in ("cmd_config.json", "plugins.json", "mcp_server.json", "skills.json"):
            (data / name).write_text("{}", encoding="utf-8")
        plugin, adapter = self.transactional_plugin()
        self.assertIn("初始化完成", self.run_command(plugin.setup(self.event)))
        before = plugin._read_state(self.destination)
        self.assertEqual(before["last_result"], "INITIALIZED")
        self.config["retention_count"] = 6
        self.config["schedule_weekday"] = "Monday"
        self.config["schedule_time"] = "13:15"
        self.assertIn("已更新", self.run_command(plugin.task(self.event, "update")))
        self.assertEqual(adapter.current_spec, plugin.task_adapter.current_spec)
        state = plugin._read_state(self.destination)
        expected = plugin._setup_config()
        self.assertEqual(state["config_fingerprint"], expected.config_fingerprint)
        self.assertEqual(state["artifact_digest"], expected.artifact_digest)
        self.assertEqual(state["week_start"], "monday")
        self.assertEqual(state["schedule_time"], "13:15")
        self.assertEqual(state["state_revision"], before["state_revision"] + 1)
        self.assertEqual(state["owner_uuid"], before["owner_uuid"])
        self.assertEqual(state["source_fingerprints"], before["source_fingerprints"])
        self.assertNotIn("last_success_archive", state)

        args = engine.parse_args([
            "--astrbot-root", str(self.astrbot), "--destination", str(self.destination),
            "--keep", "6", "--week-start", "0", "--schedule-time", "13:15",
            "--scheduled", "--scheduled-probe", "--artifact-digest", expected.artifact_digest,
        ])
        self.assertEqual(engine.scheduled_probe(args, now=dt.datetime.now().astimezone()).code, 10)
        run_args = engine.parse_args([
            "--astrbot-root", str(self.astrbot), "--destination", str(self.destination),
            "--keep", "6", "--week-start", "0", "--schedule-time", "13:15",
            "--scheduled", "--artifact-digest", expected.artifact_digest,
        ])
        outcome = engine.run(run_args, process_probe=lambda _root: False)
        self.assertEqual(outcome.code, 0, outcome.message)
        self.assertTrue(outcome.archive.is_file())

    def test_same_destination_update_uncertainty_leaves_state_unchanged(self):
        plugin, adapter = self.transactional_plugin()
        self.run_command(plugin.setup(self.event))
        before = plugin._read_state(self.destination)
        self.config["schedule_time"] = "13:15"
        adapter.update = lambda _old, spec: adapter._result("updated", spec)
        # The old task remains authoritative after output loss; a guessed new
        # spec must never be accepted as an inspect success.
        response = self.run_command(plugin.task(self.event, "update"))
        self.assertIn("结果不确定", response)
        self.assertEqual(plugin._read_state(self.destination), before)

    def test_same_destination_update_journal_failure_quarantines_without_state_mutation(self):
        plugin, _adapter = self.transactional_plugin()
        self.run_command(plugin.setup(self.event))
        before = plugin._read_state(self.destination)
        self.config["schedule_time"] = "13:15"
        with patch("main.commit_state", side_effect=plugin_main.BackupError("synthetic", 3)):
            response = self.run_command(plugin.task(self.event, "update"))
        self.assertIn("结果不确定", response)
        self.assertEqual(plugin._read_state(self.destination), before)

    def test_verify_latest_uses_injected_read_only_verifier_without_echoing_archive(self):
        seen = []
        plugin, _adapter = self.transactional_plugin(
            verifier=lambda archive, owner, fingerprints: seen.append(
                (archive, owner, fingerprints)
            ) or True
        )
        self.plugin = plugin
        self._write_owned_state()
        archive = self.destination / "managed" / "00000000-0000-4000-8000-000000000001" / "astrbot-safe-backup-20260802-120000-00000000-0000-4000-8000-000000000002.zip"
        archive.write_bytes(b"synthetic")
        response = self.run_command(plugin.verify(self.event, "latest"))
        self.assertIn("通过", response)
        self.assertEqual(len(seen), 1)
        self.assertNotIn(str(archive), response)

    def test_verify_rejects_archive_outside_destination(self):
        outside = self.base / "outside.zip"
        outside.write_bytes(b"not a zip")
        self._write_owned_state(last_success_archive=str(outside))
        response = self.run_command(
            self.plugin.verify(self.event, "latest")
        )
        self.assertIn("不可信", response)

    def test_broken_reparse_ancestor_is_checked_without_exists_gate(self):
        candidate = self.base / "missing-link" / "child"
        with patch(
            "main._is_reparse_point",
            side_effect=lambda path: path.name == "missing-link",
        ):
            with self.assertRaises(plugin_main.ControlError):
                plugin_main._assert_no_existing_reparse_ancestor(candidate)

    def test_latest_archive_rejects_reparse_before_resolve(self):
        self._write_owned_state()
        with patch(
            "main._is_reparse_point",
            side_effect=lambda path: path.name == "managed",
        ):
            response = self.run_command(
                self.plugin.verify(self.event, "latest")
            )
        self.assertIn("失败", response)

    def test_verify_never_echoes_a_command_or_archive_path(self):
        self.destination.mkdir(exist_ok=True)
        state = self._write_owned_state()
        archive = (
            self.destination
            / "managed"
            / "00000000-0000-4000-8000-000000000001"
            / state["last_success_archive"]
        )
        archive.parent.mkdir(parents=True, exist_ok=True)
        archive.write_bytes(b"synthetic")
        original = archive.read_bytes()
        response = self.run_command(
            self.plugin.verify(self.event, "latest")
        )
        self.assertIn("验证", response)
        self.assertNotIn(str(self.base), response)
        self.assertNotIn(sys.executable, response)
        self.assertNotIn("--verify", response)
        self.assertEqual(archive.read_bytes(), original)

    def test_relative_destination_is_rejected(self):
        self.config["destination_path"] = "relative-backups"
        response = self.run_command(self.plugin.check(self.event))
        self.assertIn("必须是绝对路径", response)

    def test_mapped_network_destination_is_rejected_by_control_plane(self):
        with patch.object(
            plugin_main,
            "assert_local_path",
            side_effect=plugin_main.BackupError("mapped network drive", 3),
        ):
            response = self.run_command(self.plugin.check(self.event))
        self.assertIn("不能使用网络驱动器", response)

    def test_destination_overlapping_source_is_rejected(self):
        self.config["destination_path"] = str(self.astrbot / "data" / "backups")
        response = self.run_command(self.plugin.check(self.event))
        self.assertIn("互相包含", response)

    def test_napcat_is_optional_and_validated_when_enabled(self):
        response = self.run_command(self.plugin.check(self.event))
        self.assertIn("通过", response)
        self.config["napcat_enabled"] = True
        self.config["napcat_root"] = ""
        response = self.run_command(self.plugin.check(self.event))
        self.assertIn("NapCat 根目录尚未配置", response)

    def test_bad_schedule_and_retention_fail_closed(self):
        self.config["schedule_time"] = "25:00"
        response = self.run_command(self.plugin.check(self.event))
        self.assertIn("HH:MM", response)
        self.config["schedule_time"] = "12:00"
        self.config["retention_count"] = 0
        response = self.run_command(self.plugin.check(self.event))
        self.assertIn("1 到 30", response)


if __name__ == "__main__":
    unittest.main()
