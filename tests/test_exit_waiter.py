from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from safe_backup.exit_waiter import (
    PROCESS_QUERY_LIMITED_INFORMATION,
    SYNCHRONIZE,
    WAIT_OBJECT_0,
    ProcessIdentity,
    WaitResult,
    wait_for_astrbot_exit,
)
from safe_backup.task_control import TaskOperationResult
from safe_backup.setup import InitializationLedger, SetupConfig
from safe_backup.engine import _path_token


class FakeWinApi:
    def __init__(self, *, creation=100, executable=r"C:\\Synthetic\\venv\\Scripts\\python.exe",
                 wait_result=WAIT_OBJECT_0, logged_on=True):
        self.creation = creation
        self.executable = executable
        self.wait_result = wait_result
        self.logged_on = logged_on
        self.requested_access = None
        self.closed = []

    def open_process(self, access, pid):
        self.requested_access = access
        return 7

    def get_process_creation_time(self, handle):
        return self.creation

    def query_full_process_image_name(self, handle):
        return self.executable

    def wait_for_single_object(self, handle, timeout_ms):
        return self.wait_result

    def close_handle(self, handle):
        self.closed.append(handle)

    def process_session_id(self, pid):
        return 9

    def is_interactive_user_logged_on(self, session_id):
        return self.logged_on


class FakeTasks:
    def __init__(self, *, exact=True):
        self.exact = exact
        self.triggered = []
        self.inspected = []

    def inspect(self, spec):
        self.inspected.append(spec)
        return TaskOperationResult(0 if self.exact else 1, "inspected" if self.exact else "failed", "a" * 12)

    def trigger(self, spec):
        self.triggered.append(spec)
        return TaskOperationResult(0 if self.exact else 1, "triggered" if self.exact else "failed", "a" * 12)


class ExitWaiterTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(r"C:\\Synthetic")
        self.identity = ProcessIdentity(
            pid=42,
            creation_time_100ns=100,
            executable_key=r"c:\\synthetic\\venv\\scripts\\python.exe",
            session_id=9,
        )
        self.task = SimpleNamespace(name="AstrBot Safe Backup " + "a" * 12)

    @staticmethod
    def ledger_for(config, owner, state):
        return InitializationLedger(
            destination_token=_path_token(config.destination, directory=True),
            managed_token=_path_token(config.destination / "managed", directory=True),
            owner_token=_path_token(config.destination / "managed" / owner, directory=True),
            owner_uuid=owner, state=state,
        )

    def test_waiter_requests_only_wait_and_query_access_then_triggers(self):
        api = FakeWinApi()
        tasks = FakeTasks()
        result = wait_for_astrbot_exit(
            self.identity, self.root, self.task, win_api=api,
            process_probe=lambda _root: False, task_adapter=tasks, sleep=lambda _seconds: None,
        )
        self.assertEqual(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, api.requested_access)
        self.assertTrue(result.triggered)
        self.assertEqual([7], api.closed)
        self.assertEqual([self.task], tasks.triggered)

    def test_ready_hook_runs_only_after_original_process_identity_is_verified(self):
        events = []
        class OrderedApi(FakeWinApi):
            def wait_for_single_object(self, handle, timeout_ms):
                events.append("wait")
                return super().wait_for_single_object(handle, timeout_ms)
        ok = wait_for_astrbot_exit(
            self.identity, self.root, self.task, win_api=OrderedApi(), process_probe=lambda _root: False,
            task_adapter=FakeTasks(), sleep=lambda _seconds: None, on_verified_wait=lambda: events.append("ready"),
        )
        self.assertTrue(ok.triggered)
        self.assertEqual(["ready", "wait"], events)
        rejected_events = []
        rejected = wait_for_astrbot_exit(
            self.identity, self.root, self.task, win_api=FakeWinApi(creation=101),
            process_probe=lambda _root: False, task_adapter=FakeTasks(), sleep=lambda _seconds: None,
            on_verified_wait=lambda: rejected_events.append("ready"),
        )
        self.assertFalse(rejected.triggered)
        self.assertEqual([], rejected_events)

    def test_cli_wiring_uses_original_identity_for_wait_and_helper_identity_for_probe(self):
        from safe_backup import exit_waiter
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            owner = "11111111-1111-4111-8111-111111111111"
            destination = base / "target"
            (destination / "managed" / owner).mkdir(parents=True)
            config = SetupConfig(base / "source", destination, None, base, base / "python.exe", 5, 6,
                                 "12:00", "a" * 64, {}, "b" * 64)
            authority = exit_waiter._WaiterAuthority(config, owner, _path_token(destination, directory=True),
                _path_token(destination / "managed", directory=True), _path_token(destination / "managed" / owner, directory=True))
            original = self.identity
            helper = ProcessIdentity(84, 200, r"c:\\synthetic\\venv\\scripts\\python.exe", 9)
            lease = mock.Mock(path=destination / "managed" / owner / "lease.active", token=object())
            lease.release.return_value = True
            observed = {}
            def fake_wait(identity, root, _task, **kwargs):
                observed["wait_identity"] = identity
                observed["probe_identity"] = kwargs["process_probe"](root)
                kwargs["on_verified_wait"]()
                return exit_waiter.WaitResult(False, "synthetic")
            with mock.patch.object(exit_waiter, "_consume_nonce", return_value=(config, original, object(), authority)), \
                 mock.patch.object(exit_waiter, "acquire_nonce_lease", return_value=lease), \
                 mock.patch.object(exit_waiter, "CtypesWinApi", return_value=FakeWinApi()), \
                 mock.patch.object(exit_waiter, "current_process_identity", return_value=helper), \
                 mock.patch.object(exit_waiter, "waiter_process_probe", side_effect=lambda _root, identity: identity), \
                 mock.patch.object(exit_waiter, "wait_for_astrbot_exit", side_effect=fake_wait), \
                 mock.patch.object(exit_waiter, "task_spec", return_value=self.task), \
                 mock.patch.object(exit_waiter, "_write_ready", return_value=object()), \
                 mock.patch.object(exit_waiter, "_safe_unlink_owned", return_value=True):
                self.assertEqual(0, exit_waiter.main(["--nonce", str(destination / "managed" / owner / "setup-wait-11111111-1111-4111-8111-111111111111.json")]))
            self.assertEqual(original, observed["wait_identity"])
            self.assertEqual(helper, observed["probe_identity"])

    def test_missing_or_foreign_state_refuses_before_nonce_open(self):
        from safe_backup import exit_waiter
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            owner = "11111111-1111-4111-8111-111111111111"
            nonce = base / "source-like" / "managed" / owner / "setup-wait-11111111-1111-4111-8111-111111111111.json"
            nonce.parent.mkdir(parents=True)
            nonce.write_text("not read", encoding="utf-8")
            with mock.patch.object(exit_waiter, "_read_nonce_stably", wraps=exit_waiter._read_nonce_stably) as opener:
                with self.assertRaises(RuntimeError):
                    exit_waiter._consume_nonce(nonce)
            opener.assert_not_called()

    def test_pid_reuse_never_triggers(self):
        api = FakeWinApi(creation=101)
        tasks = FakeTasks()
        result = wait_for_astrbot_exit(
            self.identity, self.root, self.task, win_api=api,
            process_probe=lambda _root: False, task_adapter=tasks, sleep=lambda _seconds: None,
        )
        self.assertFalse(result.triggered)
        self.assertEqual("identity_mismatch", result.reason)
        self.assertFalse(tasks.triggered)
        self.assertEqual([7], api.closed)

    def test_automatic_restart_or_indeterminate_probe_never_triggers(self):
        for probe in (lambda _root: True, lambda _root: None):
            with self.subTest(probe=probe):
                api = FakeWinApi()
                tasks = FakeTasks()
                result = wait_for_astrbot_exit(
                    self.identity, self.root, self.task, win_api=api,
                    process_probe=probe, task_adapter=tasks, sleep=lambda _seconds: None,
                )
                self.assertFalse(result.triggered)
                self.assertEqual("process_active_or_indeterminate", result.reason)
                self.assertFalse(tasks.triggered)

    def test_logoff_task_replacement_or_duplicate_waiter_never_triggers(self):
        api = FakeWinApi(logged_on=False)
        tasks = FakeTasks()
        logged_off = wait_for_astrbot_exit(
            self.identity, self.root, self.task, win_api=api,
            process_probe=lambda _root: False, task_adapter=tasks, sleep=lambda _seconds: None,
        )
        self.assertEqual("user_not_logged_on", logged_off.reason)
        replaced = wait_for_astrbot_exit(
            self.identity, self.root, self.task, win_api=FakeWinApi(),
            process_probe=lambda _root: False, task_adapter=FakeTasks(exact=False), sleep=lambda _seconds: None,
        )
        self.assertEqual("task_identity_changed", replaced.reason)
        duplicate = wait_for_astrbot_exit(
            self.identity, self.root, self.task, win_api=FakeWinApi(),
            process_probe=lambda _root: False, task_adapter=FakeTasks(), sleep=lambda _seconds: None,
            already_running=lambda: True,
        )
        self.assertEqual("waiter_already_running", duplicate.reason)

    def test_waiter_has_no_source_reader_or_sqlite_surface(self):
        names = set(wait_for_astrbot_exit.__code__.co_names)
        self.assertFalse({"open", "sqlite3", "read_text", "read_bytes", "glob", "rglob"} & names)

    def test_detached_launcher_creates_nonce_only_under_run_owned_setup_area(self):
        from safe_backup.exit_waiter import launch_exit_waiter
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            owner = "11111111-1111-4111-8111-111111111111"
            destination = base / "target"
            (destination / "managed" / owner).mkdir(parents=True)
            config = SetupConfig(
                astrbot_root=base / "source", destination=destination, napcat_root=None,
                plugin_dir=base, python_path=base / "python.exe", retention=5, week_start=6,
                schedule_time="12:00", source_fingerprint="a" * 64,
                source_fingerprints={"astrbot_root": "a" * 64, "napcat_root": ""},
                config_fingerprint="b" * 64,
            )
            calls = []
            def fake_popen(argv, **kwargs):
                calls.append((argv, kwargs))
                return object()
            identity_api = FakeWinApi(executable=r"C:\\Synthetic\\venv\\Scripts\\python.exe")
            state = {"owner_uuid": owner, "last_result": "INITIALIZED"}
            ledger = self.ledger_for(config, owner, state)
            with mock.patch("safe_backup.exit_waiter.os.getpid", return_value=42):
                launch_exit_waiter(config, state, ledger, win_api=identity_api, popen=fake_popen,
                                   ready_waiter=lambda _nonce, _authority: None)
            nonce = next((destination / "managed" / owner).iterdir())
            self.assertRegex(nonce.name, r"^setup-wait-[0-9a-f-]{36}\.json$")
            self.assertEqual([str(config.python_path), "-m", "safe_backup.exit_waiter", "--nonce", str(nonce)], calls[0][0])
            self.assertFalse(calls[0][1]["shell"])
            self.assertTrue(calls[0][1]["close_fds"])
            self.assertEqual(str(config.plugin_dir), calls[0][1]["cwd"])

    def test_nonce_lease_refuses_a_second_waiter_without_removing_the_nonce(self):
        from safe_backup.exit_waiter import acquire_nonce_lease, _WaiterAuthority
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "target"
            owner = "11111111-1111-4111-8111-111111111111"
            nonce = destination / "managed" / owner / "setup-wait-11111111-1111-4111-8111-111111111111.json"
            nonce.parent.mkdir(parents=True)
            nonce.write_text("{}", encoding="utf-8")
            config = SetupConfig(Path(temporary) / "source", destination, None, Path(temporary), Path(temporary) / "py", 5, 6, "12:00", "a" * 64, {}, "b" * 64)
            authority = _WaiterAuthority(config, owner, _path_token(destination, directory=True),
                                         _path_token(destination / "managed", directory=True),
                                         _path_token(nonce.parent, directory=True))
            first = acquire_nonce_lease(nonce, authority)
            self.assertIsNotNone(first)
            self.assertIsNone(acquire_nonce_lease(nonce, authority))
            self.assertTrue(nonce.exists())
            first.release()

    def test_launcher_rejects_replaced_owner_before_any_nonce_write(self):
        from safe_backup.exit_waiter import launch_exit_waiter
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            owner = "11111111-1111-4111-8111-111111111111"
            destination = base / "target"
            owner_dir = destination / "managed" / owner
            owner_dir.mkdir(parents=True)
            config = SetupConfig(base / "source", destination, None, base, base / "python.exe", 5, 6,
                                 "12:00", "a" * 64, {"astrbot_root": "a" * 64, "napcat_root": ""}, "b" * 64)
            state = {"owner_uuid": owner, "last_result": "INITIALIZED"}
            ledger = self.ledger_for(config, owner, state)
            owner_dir.rmdir()
            owner_dir.mkdir()
            with self.assertRaisesRegex(RuntimeError, "waiter target"):
                launch_exit_waiter(config, state, ledger, win_api=FakeWinApi(), popen=mock.Mock())
            self.assertEqual([], list(owner_dir.iterdir()))

    def test_post_exit_probe_excludes_only_exact_waiter_identity(self):
        from safe_backup.exit_waiter import waiter_process_probe
        helper = {"ProcessId": 42, "CreationTime100ns": 100,
                  "ExecutablePath": r"C:\\Synthetic\\venv\\Scripts\\python.exe",
                  "CommandLine": 'python -m safe_backup.exit_waiter'}
        self.assertFalse(waiter_process_probe(self.root, self.identity, rows_provider=lambda: [helper]))
        restarted = {"ProcessId": 43, "CreationTime100ns": 101,
                     "ExecutablePath": r"C:\\Synthetic\\venv\\Scripts\\python.exe",
                     "CommandLine": 'python main.py'}
        self.assertTrue(waiter_process_probe(self.root, self.identity, rows_provider=lambda: [helper, restarted]))
        ambiguous = {"ProcessId": 43, "CreationTime100ns": 101,
                     "ExecutablePath": r"C:\\Synthetic\\tool.exe", "CommandLine": '"unterminated'}
        self.assertIsNone(waiter_process_probe(self.root, self.identity, rows_provider=lambda: [helper, ambiguous]))
        impostor = dict(helper, CreationTime100ns=101)
        self.assertIsNone(waiter_process_probe(self.root, self.identity, rows_provider=lambda: [impostor]))
        self.assertFalse(waiter_process_probe(self.root, self.identity, rows_provider=lambda: [
            {"ProcessId": 0, "CreationTime100ns": None, "ExecutablePath": None, "CommandLine": None},
            {"ProcessId": 4, "CreationTime100ns": None, "ExecutablePath": None, "CommandLine": None}, helper,
        ]))
        root_ambiguous = {"ProcessId": 43, "CreationTime100ns": 101,
                          "ExecutablePath": r"C:\\Synthetic\\tool.exe", "CommandLine": '"unterminated'}
        self.assertIsNone(waiter_process_probe(self.root, self.identity, rows_provider=lambda: [root_ambiguous]))
        no_executable_astrbot = {"ProcessId": 43, "CreationTime100ns": 101,
                                 "ExecutablePath": None, "CommandLine": "python .\\main.py"}
        self.assertTrue(waiter_process_probe(self.root, self.identity, rows_provider=lambda: [no_executable_astrbot]))
        no_executable_absolute = {"ProcessId": 43, "CreationTime100ns": 101,
                                  "ExecutablePath": None, "CommandLine": r"python C:\Synthetic\main.py"}
        self.assertTrue(waiter_process_probe(self.root, self.identity, rows_provider=lambda: [no_executable_absolute]))

    def test_launcher_requires_a_bounded_ready_handshake_after_spawn(self):
        from safe_backup.exit_waiter import launch_exit_waiter
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            owner = "11111111-1111-4111-8111-111111111111"
            destination = base / "target"
            (destination / "managed" / owner).mkdir(parents=True)
            config = SetupConfig(base / "source", destination, None, base, base / "python.exe", 5, 6,
                                 "12:00", "a" * 64, {"astrbot_root": "a" * 64, "napcat_root": ""}, "b" * 64)
            state = {"owner_uuid": owner, "last_result": "INITIALIZED"}
            ledger = self.ledger_for(config, owner, state)
            with self.assertRaisesRegex(RuntimeError, "readiness"):
                launch_exit_waiter(config, state, ledger, win_api=FakeWinApi(), popen=lambda *_a, **_k: object(),
                                   ready_waiter=lambda _nonce, _authority: (_ for _ in ()).throw(RuntimeError("not ready")))

    def test_nonce_replacement_after_stable_validation_refuses_before_trigger(self):
        """The main wiring rechecks the stable nonce token immediately before start."""
        from safe_backup import exit_waiter
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            nonce = base / "setup-wait-11111111-1111-4111-8111-111111111111.json"
            lease_path = base / "setup-wait-11111111-1111-4111-8111-111111111111.active"
            nonce.write_text("original", encoding="utf-8")
            lease_path.write_text("lease", encoding="utf-8")
            config = SimpleNamespace(astrbot_root=self.root, plugin_dir=base, python_path=base / "python.exe")
            authority = object()
            original_token = object()
            lease_token = object()
            lease = mock.Mock(path=lease_path, token=lease_token)
            lease.release.return_value = True
            tasks = FakeTasks()
            changed_token = object()

            def token_for(path, **_kwargs):
                if Path(path) == lease_path:
                    return SimpleNamespace(same_content_identity=lambda value: value is lease_token)
                if Path(path) == nonce:
                    return SimpleNamespace(same_content_identity=lambda value: value is changed_token)
                raise AssertionError(path)

            with (
                mock.patch.object(exit_waiter, "_consume_nonce", return_value=(config, self.identity, original_token, authority)),
                mock.patch.object(exit_waiter, "acquire_nonce_lease", return_value=lease),
                mock.patch.object(exit_waiter, "CtypesWinApi", return_value=FakeWinApi()),
                mock.patch.object(exit_waiter, "current_process_identity", return_value=self.identity),
                mock.patch.object(exit_waiter, "waiter_process_probe", return_value=False),
                mock.patch.object(exit_waiter, "PowerShellTaskAdapter", return_value=tasks),
                mock.patch.object(exit_waiter, "task_spec", return_value=self.task),
                mock.patch.object(exit_waiter, "_verify_authority", return_value=None),
                mock.patch.object(exit_waiter, "_write_ready", return_value=object()),
                mock.patch.object(exit_waiter, "_path_token", side_effect=token_for),
                mock.patch.object(exit_waiter, "_safe_unlink_owned", return_value=False),
            ):
                self.assertEqual(1, exit_waiter.main(["--nonce", str(nonce)]))
            self.assertEqual([self.task], tasks.inspected)
            self.assertEqual([], tasks.triggered)
            self.assertTrue(nonce.exists())
