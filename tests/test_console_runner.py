from __future__ import annotations

import io
import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from safe_backup.engine import Result


class ConsoleRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="safe-console-")
        self.destination = Path(self.temp.name) / "output"
        self.args = type("Args", (), {"destination": self.destination, "scheduled": False})()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _trusted_success(self):
        owner = "123e4567-e89b-42d3-a456-426614174000"
        name = "astrbot-safe-backup-20260809-120000-123e4567-e89b-42d3-a456-426614174000.zip"
        archive = self.destination / "managed" / owner / name
        archive.parent.mkdir(parents=True, exist_ok=True)
        (self.destination / "logs").mkdir(exist_ok=True)
        archive.write_bytes(b"synthetic verified archive")
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        state = {
            "managed_by": "astrbot_plugin_safe_backup", "state_namespace": "community-v1",
            "owner_uuid": owner, "last_result": "FULL_SUCCESS",
            "last_successful_archive": name, "last_successful_archive_sha256": digest,
        }
        return (Result(0, archive=archive, archive_sha256=digest,
                       publication_disposition="full_success"), state)

    def success_runner(self, _args, *, progress_sink=None):
        from safe_backup.progress import ProgressEvent
        for index, phase in enumerate((
            "preflight", "inventory", "copy", "sqlite", "archive", "verify", "publish",
        ), 1):
            progress_sink(ProgressEvent(phase, index, 1, 1, "items", "complete", "ok"))
        return self._trusted_success()[0]

    def test_success_renders_all_seven_phases_and_exact_success(self):
        from safe_backup.console_runner import render_backup

        output = io.StringIO()
        _result, state = self._trusted_success()
        with mock.patch("safe_backup.console_runner._trusted_state", return_value=state):
            code = render_backup(self.args, engine_runner=self.success_runner, writer=output,
                                 key_probe=lambda: False, sleep=lambda _: None)
        text = output.getvalue()
        self.assertEqual(code, 0)
        self.assertTrue(all(f"[{index}/7]" in text for index in range(1, 8)))
        self.assertIn("\n备份成功\n", text)

    def test_manual_snapshot_success_does_not_require_or_claim_scheduler_binding(self):
        from safe_backup.console_runner import render_backup

        output = io.StringIO()
        _result, state = self._trusted_success()

        def manual_runner(_args, *, progress_sink=None):
            from safe_backup.progress import ProgressEvent
            for index, phase in enumerate((
                "preflight", "inventory", "copy", "sqlite", "archive", "verify", "publish",
            ), 1):
                progress_sink(ProgressEvent(phase, index, 1, 1, "items", "complete", "ok"))
            result = self._trusted_success()[0]
            result.counts_as_scheduled_success = False
            return result

        manual_args = type("Args", (), {
            "destination": self.destination, "scheduled": False, "manual": True,
        })()
        with mock.patch("safe_backup.console_runner._trusted_state", return_value=state):
            code = render_backup(manual_args, engine_runner=manual_runner, writer=output,
                                 key_probe=lambda: True, sleep=lambda _: None)
        self.assertEqual(code, 0)
        self.assertIn("自动备份周期状态未改变", output.getvalue())
        self.assertIn("\n备份成功\n", output.getvalue())

    def test_failure_is_actionable_and_sanitized(self):
        from safe_backup.console_runner import render_backup

        def running_astrbot(_args, *, progress_sink=None):
            from safe_backup.progress import ProgressEvent
            progress_sink(ProgressEvent("preflight", 1, 1, 0, "items", "failed", "process_running"))
            return Result(1, message=f"AstrBot is running at {self.destination}")

        output = io.StringIO()
        code = render_backup(self.args, engine_runner=running_astrbot, writer=output,
                             key_probe=lambda: False, sleep=lambda _: None)
        text = output.getvalue()
        self.assertNotEqual(code, 0)
        self.assertIn("备份未完成", text)
        self.assertIn("未发布正式 ZIP", text)
        self.assertIn("未删除历史归档", text)
        self.assertNotIn(str(self.destination), text)

    def test_noop_is_silent_and_does_not_wait(self):
        from safe_backup.console_runner import render_backup

        output = io.StringIO()
        waits: list[int] = []
        code = render_backup(self.args, engine_runner=lambda _args, **_: Result(0, noop=True),
                             writer=output, key_probe=lambda: False,
                             sleep=lambda seconds: waits.append(seconds))
        self.assertEqual(code, 0)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(waits, [])

    def test_progress_event_is_immutable_and_rejects_path_tokens(self):
        from safe_backup.progress import ProgressEvent

        event = ProgressEvent("copy", 3, 10, 2, "bytes", "progress", "item")
        with self.assertRaises((AttributeError, TypeError)):
            event.phase = "publish"
        with self.assertRaises(ValueError):
            ProgressEvent("copy", 3, 1, 1, "bytes", "progress", r"C:\\private")
        with self.assertRaises(ValueError):
            ProgressEvent("copy", 3, 0, 1, "bytes", "progress", "item")

    def test_wait_uses_bounded_success_and_failure_ticks(self):
        from safe_backup.console_runner import render_backup

        success_waits: list[int] = []
        _result, state = self._trusted_success()
        with mock.patch("safe_backup.console_runner._trusted_state", return_value=state):
            render_backup(self.args, engine_runner=self.success_runner, writer=io.StringIO(),
                          key_probe=lambda: False, sleep=lambda seconds: success_waits.append(seconds))
        self.assertEqual(success_waits, [1] * 30)
        failure_waits: list[int] = []
        render_backup(self.args, engine_runner=lambda _args, **_: Result(1), writer=io.StringIO(),
                      key_probe=lambda: False, sleep=lambda seconds: failure_waits.append(seconds))
        self.assertEqual(failure_waits, [1] * 120)

    def test_real_engine_emits_ordered_redacted_seven_stage_events(self):
        from safe_backup import engine
        from safe_backup.progress import ProgressEvent
        import sqlite3

        astrbot = Path(self.temp.name) / "astrbot"
        data = astrbot / "data"
        (data / "config").mkdir(parents=True)
        for name in ("cmd_config.json", "plugins.json", "mcp_server.json", "skills.json"):
            (data / name).write_text("{}", encoding="utf-8")
        database = sqlite3.connect(data / "sample.db")
        database.execute("create table t(value text)")
        database.commit()
        database.close()
        args = engine.parse_args(["--astrbot-root", str(astrbot), "--destination", str(self.destination)])
        events: list[ProgressEvent] = []
        result = engine.run(args, process_probe=lambda _root: False, progress_sink=events.append)
        self.assertEqual(result.code, 0, result.message)
        completed = [event.phase for event in events if event.status == "complete"]
        self.assertEqual(completed, [
            "preflight", "inventory", "copy", "sqlite", "archive", "verify", "publish",
        ])
        self.assertTrue(all(str(astrbot) not in event.detail_token for event in events))
        self.assertEqual([event.index for event in events], sorted(event.index for event in events))
        copy_items = [event for event in events if event.phase == "copy" and event.unit == "items"]
        self.assertTrue(copy_items)
        self.assertEqual(copy_items[-1].current, copy_items[-1].total)

    def test_successful_managed_target_gets_bounded_redacted_jsonl_log(self):
        from safe_backup import engine
        from safe_backup.console_runner import render_backup
        import sqlite3

        astrbot = Path(self.temp.name) / "秘密-AstrBot"
        data = astrbot / "data"
        (data / "config").mkdir(parents=True)
        for name in ("cmd_config.json", "plugins.json", "mcp_server.json", "skills.json"):
            (data / name).write_text("{}", encoding="utf-8")
        con = sqlite3.connect(data / "main.db")
        con.execute("create table t(value text)")
        con.commit()
        con.close()
        args = engine.parse_args(["--astrbot-root", str(astrbot), "--destination", str(self.destination)])
        code = render_backup(args,
                             engine_runner=lambda value, **kwargs: engine.run(value, process_probe=lambda _: False, **kwargs),
                             writer=io.StringIO(), key_probe=lambda: True, sleep=lambda _: None)
        self.assertEqual(code, 0)
        logs = list((self.destination / "logs").glob("visible-run-*.jsonl"))
        self.assertEqual(len(logs), 1)
        raw = logs[0].read_text(encoding="utf-8")
        self.assertNotIn(str(astrbot), raw)
        self.assertNotIn("main.db", raw)
        self.assertLess(len(raw.encode("utf-8")), 4 * 1024 * 1024)

    def test_writer_failure_and_progress_callback_failure_do_not_change_result(self):
        from safe_backup.console_runner import render_backup
        from safe_backup.progress import ProgressEvent

        class BrokenWriter:
            def write(self, _text):
                raise UnicodeError("synthetic console")
            def flush(self):
                raise OSError("synthetic console")

        _result, state = self._trusted_success()
        def runner(_args, *, progress_sink=None):
            progress_sink(ProgressEvent("preflight", 1, 1, 1, "items", "complete", "ok"))
            return self._trusted_success()[0]

        with mock.patch("safe_backup.console_runner._trusted_state", return_value=state):
            self.assertEqual(render_backup(self.args, engine_runner=runner, writer=BrokenWriter(),
                                           key_probe=lambda: True, sleep=lambda _: None), 0)

    def test_none_stdout_and_closed_writer_never_change_renderer_code(self):
        from safe_backup.console_runner import render_backup

        class ClosedWriter:
            def write(self, _text):
                raise ValueError("closed")
            def flush(self):
                raise AttributeError("closed")

        original = sys.stdout
        try:
            sys.stdout = None
            _result, state = self._trusted_success()
            with mock.patch("safe_backup.console_runner._trusted_state", return_value=state):
                self.assertEqual(render_backup(self.args, engine_runner=self.success_runner,
                                               key_probe=lambda: True, sleep=lambda _: None), 0)
        finally:
            sys.stdout = original
        _result, state = self._trusted_success()
        with mock.patch("safe_backup.console_runner._trusted_state", return_value=state):
            self.assertEqual(render_backup(self.args, engine_runner=self.success_runner,
                                           writer=ClosedWriter(), key_probe=lambda: True,
                                           sleep=lambda _: None), 0)

    def test_missing_trusted_state_cannot_claim_success(self):
        from safe_backup.console_runner import render_backup

        output = io.StringIO()
        with mock.patch("safe_backup.console_runner._trusted_state", return_value=None):
            code = render_backup(self.args, engine_runner=self.success_runner, writer=output,
                                 key_probe=lambda: True, sleep=lambda _: None)
        self.assertNotEqual(code, 0)
        self.assertNotIn("备份成功", output.getvalue())

    def test_engine_base_exception_uses_quarantine_message(self):
        from safe_backup.console_runner import render_backup

        output = io.StringIO()
        code = render_backup(self.args,
                             engine_runner=lambda _args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
                             writer=output, key_probe=lambda: True, sleep=lambda _: None)
        self.assertEqual(code, 3)
        self.assertNotIn("未发布正式 ZIP", output.getvalue())
        self.assertIn("可能保留隔离产物", output.getvalue())

    def test_non_strict_archive_cannot_claim_success_or_echo_name(self):
        from safe_backup.console_runner import render_backup

        output = io.StringIO()
        code = render_backup(self.args,
                             engine_runner=lambda _args, **_: Result(0, archive=Path("API_TOKEN_SECRET.zip"),
                                                                       publication_disposition="full_success"),
                             writer=output, key_probe=lambda: True, sleep=lambda _: None)
        self.assertNotEqual(code, 0)
        self.assertNotIn("API_TOKEN_SECRET", output.getvalue())
        self.assertNotIn("备份成功", output.getvalue())

    def test_quarantine_disposition_never_claims_no_formal_archive(self):
        from safe_backup.console_runner import render_backup

        output = io.StringIO()
        code = render_backup(self.args,
                             engine_runner=lambda _args, **_: Result(1, publication_disposition="quarantine_possible"),
                             writer=output, key_probe=lambda: True, sleep=lambda _: None)
        self.assertEqual(code, 1)
        self.assertNotIn("未发布正式 ZIP", output.getvalue())
        self.assertIn("可能保留隔离产物", output.getvalue())

    def test_engine_progress_sink_exception_does_not_change_archive_transaction(self):
        from safe_backup import engine
        import sqlite3

        astrbot = Path(self.temp.name) / "AstrBot"
        data = astrbot / "data"
        (data / "config").mkdir(parents=True)
        for name in ("cmd_config.json", "plugins.json", "mcp_server.json", "skills.json"):
            (data / name).write_text("{}", encoding="utf-8")
        database = sqlite3.connect(data / "main.db")
        database.execute("create table t(value text)")
        database.commit()
        database.close()
        args = engine.parse_args(["--astrbot-root", str(astrbot), "--destination", str(self.destination)])
        result = engine.run(args, process_probe=lambda _root: False,
                            progress_sink=lambda _event: (_ for _ in ()).throw(RuntimeError("UI failed")))
        self.assertEqual(result.code, 0, result.message)
        self.assertTrue(result.archive.is_file())

    def test_task_artifact_digest_binds_visible_renderer_and_progress_module(self):
        from safe_backup.setup import artifact_digest

        project = Path(__file__).resolve().parents[1]
        isolated = Path(self.temp.name) / "plugin"
        shutil.copytree(project / "safe_backup", isolated / "safe_backup")
        shutil.copytree(project / "scripts", isolated / "scripts")
        initial = artifact_digest(isolated)
        with (isolated / "safe_backup" / "console_runner.py").open("a", encoding="utf-8") as handle:
            handle.write("\n# synthetic change\n")
        self.assertNotEqual(artifact_digest(isolated), initial)

    def test_log_no_replace_race_preserves_foreign_target(self):
        from safe_backup import console_runner, engine
        import sqlite3

        astrbot = Path(self.temp.name) / "AstrBot"
        data = astrbot / "data"
        (data / "config").mkdir(parents=True)
        for name in ("cmd_config.json", "plugins.json", "mcp_server.json", "skills.json"):
            (data / name).write_text("{}", encoding="utf-8")
        con = sqlite3.connect(data / "main.db")
        con.execute("create table t(value text)")
        con.commit()
        con.close()
        args = engine.parse_args(["--astrbot-root", str(astrbot), "--destination", str(self.destination)])
        result = engine.run(args, process_probe=lambda _: False)
        self.assertEqual(result.code, 0, result.message)
        original_link = os.link
        seen: list[Path] = []
        def race(source, target, *extra, **kwargs):
            target = Path(target)
            target.write_bytes(b"FOREIGN")
            seen.append(target)
            return original_link(source, target, *extra, **kwargs)
        event = __import__("safe_backup.progress", fromlist=["ProgressEvent"]).ProgressEvent
        with mock.patch.object(console_runner.os, "link", side_effect=race):
            self.assertFalse(console_runner._write_redacted_log(
                self.destination, [event("preflight", 1, 1, 1, "items", "complete", "ok")], 0, "success"))
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].read_bytes(), b"FOREIGN")

    def test_log_event_count_is_capped_at_ten_thousand(self):
        from safe_backup import console_runner, engine
        import sqlite3

        astrbot = Path(self.temp.name) / "AstrBot"
        data = astrbot / "data"
        (data / "config").mkdir(parents=True)
        for name in ("cmd_config.json", "plugins.json", "mcp_server.json", "skills.json"):
            (data / name).write_text("{}", encoding="utf-8")
        con = sqlite3.connect(data / "main.db")
        con.execute("create table t(value text)")
        con.commit()
        con.close()
        args = engine.parse_args(["--astrbot-root", str(astrbot), "--destination", str(self.destination)])
        self.assertEqual(engine.run(args, process_probe=lambda _: False).code, 0)
        Event = __import__("safe_backup.progress", fromlist=["ProgressEvent"]).ProgressEvent
        events = [Event("copy", 3, 1, 1, "items", "complete", "item") for _ in range(10_000)]
        self.assertTrue(console_runner._write_redacted_log(self.destination, events, 0, "success"))
        self.assertFalse(console_runner._write_redacted_log(self.destination, events + events[:1], 0, "success"))

    def test_system_exit_progress_sink_cannot_interrupt_engine_cleanup(self):
        from safe_backup import engine
        import sqlite3

        astrbot = Path(self.temp.name) / "AstrBot"
        data = astrbot / "data"
        (data / "config").mkdir(parents=True)
        for name in ("cmd_config.json", "plugins.json", "mcp_server.json", "skills.json"):
            (data / name).write_text("{}", encoding="utf-8")
        con = sqlite3.connect(data / "main.db")
        con.execute("create table t(value text)")
        con.commit()
        con.close()
        args = engine.parse_args(["--astrbot-root", str(astrbot), "--destination", str(self.destination)])
        result = engine.run(args, process_probe=lambda _: False,
                            progress_sink=lambda _event: (_ for _ in ()).throw(SystemExit(91)))
        self.assertEqual(result.code, 0, result.message)
        self.assertTrue(result.archive.is_file())

    def test_post_publish_failure_reports_quarantine_when_owned_final_cleanup_refuses(self):
        from safe_backup import engine
        import sqlite3

        astrbot = Path(self.temp.name) / "AstrBot"
        data = astrbot / "data"
        (data / "config").mkdir(parents=True)
        for name in ("cmd_config.json", "plugins.json", "mcp_server.json", "skills.json"):
            (data / name).write_text("{}", encoding="utf-8")
        con = sqlite3.connect(data / "main.db")
        con.execute("create table t(value text)")
        con.commit()
        con.close()
        args = engine.parse_args(["--astrbot-root", str(astrbot), "--destination", str(self.destination)])
        def fail_after_publish(phase, *_args):
            if phase == "final-verify":
                raise engine.BackupError("synthetic final verification failure", 1)
        original_unlink = engine._safe_unlink_owned
        def refuse_final(path, token):
            if path is not None and str(path).endswith(".zip") and ".partial." not in str(path):
                return False
            return original_unlink(path, token)
        with mock.patch.object(engine, "_safe_unlink_owned", side_effect=refuse_final):
            result = engine.run(args, process_probe=lambda _: False, phase_hook=fail_after_publish)
        self.assertEqual(result.code, 1)
        self.assertEqual(result.publication_disposition, "quarantine_possible")


if __name__ == "__main__":
    unittest.main()
