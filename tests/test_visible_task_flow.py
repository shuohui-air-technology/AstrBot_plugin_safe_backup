from __future__ import annotations

import ast
import datetime as dt
import asyncio
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zipfile
import re
from pathlib import Path
from unittest import mock

STUBS = Path(__file__).resolve().parent / "stubs"
import sys
if str(STUBS) not in sys.path:
    sys.path.insert(0, str(STUBS))
if str(ROOT := Path(__file__).resolve().parents[1]) not in sys.path:
    sys.path.insert(0, str(ROOT))

from astrbot.api import AstrBotConfig
from astrbot.api.event import AstrMessageEvent
from astrbot.api.star import Context
import main as plugin_main
from safe_backup import engine
from safe_backup import console_runner
from safe_backup import exit_waiter
from safe_backup.setup import artifact_digest
from safe_backup.task_control import TaskDiscovery, TaskOperationResult


SCRIPTS = ROOT / "scripts"


def powershells() -> list[str]:
    return [name for name in ("powershell.exe", "pwsh") if shutil.which(name)]


def run_ps(command: str, executable: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [executable, "-NoProfile", "-Command", command],
        capture_output=True, text=True, check=False,
    )


class ScheduleProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="safe-backup-visible-")
        self.root = Path(self.temporary.name)
        self.astrbot = self.root / "AstrBot"
        data = self.astrbot / "data"
        (data / "config").mkdir(parents=True)
        for name in ("cmd_config.json", "plugins.json", "mcp_server.json", "skills.json"):
            (data / name).write_text("{}", encoding="utf-8")
        database = sqlite3.connect(data / "main.db")
        database.execute("create table synthetic (value text)")
        database.commit()
        database.close()
        self.destination = self.root / "backups"
        self.now = dt.datetime(2026, 8, 5, 12, tzinfo=dt.timezone(dt.timedelta(hours=8)))
        self.artifact = "a" * 64

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def args(self):
        return engine.parse_args([
            "--astrbot-root", str(self.astrbot), "--destination", str(self.destination),
            "--scheduled", "--week-start", "0", "--artifact-digest", self.artifact,
        ])

    def snapshot_destination(self):
        return {
            path.relative_to(self.destination).as_posix(): (
                path.is_dir(), path.stat().st_size if path.is_file() else 0,
                path.stat().st_mtime_ns,
                path.read_bytes() if path.is_file() else b"",
            )
            for path in self.destination.rglob("*")
        }

    def probe_args(self):
        args = self.args()
        args.probe_source_fingerprints = engine.source_fingerprints(args.astrbot_root, args.napcat_root)
        args.probe_config_fingerprint = engine.configuration_fingerprint(
            args.astrbot_root, args.napcat_root, args.destination, args.keep, args.week_start, args.schedule_time)
        args.artifact_digest = self.artifact
        return args

    def test_probe_successful_cycle_is_read_only_silent_noop(self):
        initial = engine.run(self.args(), process_probe=lambda _root: False, now=self.now)
        self.assertEqual(initial.code, 0, initial.message)
        before = self.snapshot_destination()
        with mock.patch.object(engine, "default_instance_guard", side_effect=AssertionError("guard")), \
                mock.patch.object(engine, "default_astrbot_offline_guard", side_effect=AssertionError("guard")), \
                mock.patch.object(engine, "check_process", side_effect=AssertionError("source process")), \
                mock.patch.object(engine, "walk_files", side_effect=AssertionError("source data")):
            result = engine.scheduled_probe(self.probe_args(), now=self.now + dt.timedelta(hours=1))
        self.assertEqual(result.code, 0, result.message)
        self.assertTrue(result.noop)
        self.assertEqual(self.snapshot_destination(), before)

    def test_probe_new_cycle_is_due_without_source_read_or_destination_write(self):
        initial = engine.run(self.args(), process_probe=lambda _root: False, now=self.now)
        self.assertEqual(initial.code, 0, initial.message)
        before = self.snapshot_destination()
        with mock.patch.object(engine, "check_process", side_effect=AssertionError("source process")), \
                mock.patch.object(engine, "walk_files", side_effect=AssertionError("source data")):
            result = engine.scheduled_probe(self.probe_args(), now=self.now + dt.timedelta(days=7))
        self.assertEqual(result.code, 10, result.message)
        self.assertFalse(result.noop)
        self.assertEqual(self.snapshot_destination(), before)

    def test_probe_corrupt_state_fails_closed_without_creating_anything(self):
        self.destination.mkdir()
        (self.destination / "state.json").write_text("{invalid", encoding="utf-8")
        before = self.snapshot_destination()
        result = engine.scheduled_probe(self.probe_args(), now=self.now)
        self.assertEqual(result.code, 3)
        self.assertEqual(self.snapshot_destination(), before)

    def test_probe_requires_the_published_archive_digest_and_required_members(self):
        initial = engine.run(self.args(), process_probe=lambda _root: False, now=self.now)
        self.assertEqual(initial.code, 0, initial.message)
        state = json.loads((self.destination / "state.json").read_text(encoding="utf-8"))
        self.assertRegex(state["last_successful_archive_sha256"], r"^[0-9a-f]{64}$")
        archive = initial.archive
        state["last_successful_archive_sha256"] = "0" * 64
        state["last_success_archive_sha256"] = "0" * 64
        for state_path in [self.destination / "state.json", *(self.destination / "state-journal").glob("*.json")]:
            state_path.write_text(json.dumps(state), encoding="utf-8")
        self.assertEqual(engine.scheduled_probe(self.probe_args(), now=self.now).code, 3)

    def test_probe_rejects_missing_required_archive_members_even_if_digest_is_rebound(self):
        initial = engine.run(self.args(), process_probe=lambda _root: False, now=self.now)
        self.assertEqual(initial.code, 0, initial.message)
        archive = initial.archive
        replacement = archive.with_suffix(".replacement.zip")
        with zipfile.ZipFile(archive) as source, zipfile.ZipFile(replacement, "w") as output:
            for info in source.infolist():
                if info.filename in {"RESTORE-NOTES.txt", "AstrBot/data/cmd_config.json"}:
                    continue
                output.writestr(info, source.read(info.filename))
        replacement.replace(archive)
        digest = engine._hash_regular(archive)[0]
        state_path = self.destination / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["last_success_archive_sha256"] = digest
        state["last_successful_archive_sha256"] = digest
        state_path.write_text(json.dumps(state), encoding="utf-8")
        self.assertEqual(engine.scheduled_probe(self.probe_args(), now=self.now).code, 3)

    def test_probe_parser_never_resolves_or_stats_source_roots(self):
        original_lstat = Path.lstat
        source_key = str(self.astrbot).casefold()
        def reject_source_stat(path):
            if str(path).casefold().startswith(source_key):
                raise AssertionError("source stat")
            return original_lstat(path)
        with mock.patch.object(engine, "resolve_safe_source", side_effect=AssertionError("source resolve")), \
                mock.patch.object(engine.Path, "lstat", reject_source_stat):
            parsed = engine.parse_args([
                "--astrbot-root", str(self.astrbot), "--destination", str(self.destination),
                "--scheduled", "--scheduled-probe", "--artifact-digest", self.artifact,
            ])
        self.assertTrue(parsed.scheduled_probe)

    def test_probe_parser_rejects_zero_artifact_digest(self):
        with self.assertRaises(SystemExit):
            engine.parse_args([
                "--astrbot-root", str(self.astrbot), "--destination", str(self.destination),
                "--scheduled", "--scheduled-probe", "--artifact-digest", "0" * 64,
            ])

    def test_scheduled_normal_run_requires_a_nonzero_artifact_digest(self):
        with self.assertRaises(SystemExit):
            engine.parse_args([
                "--astrbot-root", str(self.astrbot), "--destination", str(self.destination),
                "--scheduled",
            ])

    def test_direct_scheduled_run_without_digest_fails_before_source_access(self):
        args = engine.parse_args([
            "--astrbot-root", str(self.astrbot), "--destination", str(self.destination),
        ])
        args.scheduled = True
        args.artifact_digest = None
        with mock.patch.object(engine, "source_fingerprints", side_effect=AssertionError("source")):
            result = engine._run(args, process_probe=lambda _root: False, now=self.now)
        self.assertEqual(result.code, 3)

    def test_public_probe_without_prebound_context_fails_before_source_access(self):
        with mock.patch.object(engine, "source_fingerprints", side_effect=AssertionError("source")), \
                mock.patch.object(engine, "configuration_fingerprint", side_effect=AssertionError("source")):
            result = engine.scheduled_probe(self.args(), now=self.now)
        self.assertEqual(result.code, 3)


class VisibleLauncherTests(unittest.TestCase):
    @unittest.skipUnless(powershells(), "PowerShell unavailable")
    def test_trusted_script_gate_rejects_hardlinks_and_reparse_points(self):
        common = str(SCRIPTS / "task_common.ps1").replace("'", "''")
        with tempfile.TemporaryDirectory(prefix="safe-backup-script-gate-") as raw:
            root = Path(raw)
            regular = root / "regular.ps1"
            linked_source = root / "linked-source.ps1"
            hardlink = root / "hardlink.ps1"
            regular.write_text("# synthetic", encoding="utf-8")
            linked_source.write_text("# synthetic", encoding="utf-8")
            try:
                os.link(linked_source, hardlink)
            except OSError:
                self.skipTest("hard links unavailable")
            target_dir = root / "target"
            target_dir.mkdir()
            (target_dir / "child.ps1").write_text("# synthetic", encoding="utf-8")
            reparse_dir = root / "reparse-dir"
            try:
                os.symlink(target_dir, reparse_dir, target_is_directory=True)
            except OSError:
                reparse_dir = None
            reparse_check = ""
            if reparse_dir is not None:
                reparse = reparse_dir / "child.ps1"
                reparse_check = (
                    f"try{{Assert-TrustedPluginFile '{str(reparse).replace("'", "''")}' '{str(reparse).replace("'", "''")}'|Out-Null}}catch{{$reparse=$true}};"
                )
            command = (
                f". '{common}';$good=$false;$hard=$false;$reparse=$false;"
                f"try{{Assert-TrustedPluginFile '{str(regular).replace("'", "''")}' '{str(regular).replace("'", "''")}'|Out-Null;$good=$true}}catch{{}};"
                f"try{{Assert-TrustedPluginFile '{str(hardlink).replace("'", "''")}' '{str(hardlink).replace("'", "''")}'|Out-Null}}catch{{$hard=$true}};"
                + reparse_check
                + "[pscustomobject]@{good=$good;hard=$hard;reparse=$reparse}|ConvertTo-Json -Compress"
            )
            result = run_ps(command, powershells()[0])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["good"])
        self.assertTrue(report["hard"])
        if reparse_dir is not None:
            self.assertTrue(report["reparse"])

    @unittest.skipUnless(powershells(), "PowerShell unavailable")
    def test_hidden_launcher_stays_silent_for_noop_and_starts_one_visible_runner_when_due_or_unsafe(self):
        launcher = str(SCRIPTS / "task_launcher.ps1").replace("'", "''")
        fake_python = ROOT / "tests" / "visible-probe-fixture.cmd"
        self.addCleanup(lambda: fake_python.unlink(missing_ok=True))
        source = ROOT / "tests" / "synthetic-source"
        destination = ROOT / "tests" / "synthetic-destination"
        arguments = (
            "--astrbot-root", str(source), "--destination", str(destination),
            "--python-path", str(fake_python), "--keep", "5", "--week-start", "0",
            "--schedule-time", "12:00", "--artifact-digest", artifact_digest(ROOT), "--scheduled",
        )
        for expected_probe, expected_starts in ((0, 0), (10, 1), (3, 1)):
            with self.subTest(probe=expected_probe):
                fake_python.write_text(
                    "@echo off\r\n"
                    "setlocal\r\n"
                    "echo %* | findstr /C:\"--scheduled-probe\" >nul\r\n"
                    f"if not errorlevel 1 exit /b {expected_probe}\r\n"
                    "exit /b 71\r\n",
                    encoding="ascii",
                )
                quoted = " ".join('"' + value.replace('"', '\\\"') + '"' for value in arguments)
                command = (
                    "$global:visible=0;$global:captured='';"
                    "function Start-Process { param($FilePath,$ArgumentList,$WindowStyle,[switch]$Wait,[switch]$PassThru) "
                    "$global:visible++;$global:captured=[string]$ArgumentList;return [pscustomobject]@{ExitCode=47} };"
                    f"& '{launcher}' {quoted};"
                    "[pscustomobject]@{code=$LASTEXITCODE;visible=$global:visible;captured=$global:captured}|ConvertTo-Json -Compress"
                )
                result = run_ps(command, powershells()[0])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                report = json.loads(result.stdout.strip())
                self.assertEqual(report["visible"], expected_starts)
                self.assertEqual(report["code"], 0 if expected_starts == 0 else 47)
                if expected_starts:
                    self.assertIn("run_backup_visible.ps1", report["captured"])
                    self.assertNotIn("--scheduled-probe", report["captured"])
                    self.assertIn(f"-ProbeCode\" \"{expected_probe}", report["captured"])

    @unittest.skipUnless(powershells(), "PowerShell unavailable")
    def test_visible_runner_propagates_engine_exit_code(self):
        runner = str(SCRIPTS / "run_backup_visible.ps1").replace("'", "''")
        fake_python = ROOT / "tests" / "visible-runner-fixture.cmd"
        self.addCleanup(lambda: fake_python.unlink(missing_ok=True))
        fake_python.write_text("@echo off\r\nexit /b 29\r\n", encoding="ascii")
        command = (
            f"& '{runner}' -PythonPath '{str(fake_python).replace("'", "''")}' "
            f"-EnginePath '{str(ROOT / 'safe_backup' / 'engine.py').replace("'", "''")}' -ProbeCode 10 "
            "--astrbot-root 'C:\\synthetic source' --destination 'C:\\synthetic destination' "
            "--python-path '" + str(fake_python).replace("'", "''") + "' --keep 5 --week-start 0 --schedule-time 12:00 --artifact-digest " + artifact_digest(ROOT) + " --scheduled;"
            "$global:LASTEXITCODE"
        )
        result = run_ps(command, powershells()[0])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(int(result.stdout.strip()), 29)

    @unittest.skipUnless(powershells(), "PowerShell unavailable")
    def test_scripts_parse_in_both_powershell_engines(self):
        for executable in powershells():
            for name in ("task_launcher.ps1", "run_backup_visible.ps1"):
                path = str(SCRIPTS / name).replace("'", "''")
                command = (
                    "$errors=$null;$tokens=$null;[void][Management.Automation.Language.Parser]::ParseFile("
                    f"'{path}',[ref]$tokens,[ref]$errors);if($errors.Count){{$errors|% Message;exit 1}}"
                )
                result = run_ps(command, executable)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_launcher_and_runner_do_not_contain_process_kill_or_shell_string_execution(self):
        for name in ("task_launcher.ps1", "run_backup_visible.ps1"):
            text = (SCRIPTS / name).read_text(encoding="utf-8-sig")
            for forbidden in ("Stop-Process", "taskkill", "Invoke-Expression", "-NoExit"):
                self.assertNotIn(forbidden, text)
        launcher = (SCRIPTS / "task_launcher.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("--scheduled-probe", launcher)
        self.assertIn("Start-Process -Wait -PassThru", launcher)
        runner = (SCRIPTS / "run_backup_visible.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("& $PythonPath", runner)
        self.assertIn("console_runner.py", runner)
        self.assertIn("OutputEncoding", runner)


async def _collect_command(generator):
    return [item async for item in generator]


class _SyntheticTaskAdapter:
    """A no-host Task Scheduler boundary used only by the end-to-end test."""

    def __init__(self) -> None:
        self.spec = None
        self.calls: list[str] = []
        self.trigger_hook = None

    @staticmethod
    def _result(status, spec, code=0):
        return TaskOperationResult(code, status, spec.name.rsplit(" ", 1)[-1])

    def inspect_by_fingerprint(self, _fingerprint):
        self.calls.append("discover")
        return TaskDiscovery("missing", None) if self.spec is None else TaskDiscovery("exact", self.spec)

    def install(self, spec):
        self.calls.append("install")
        if self.spec is not None:
            return self._result("failed", spec, 1)
        self.spec = spec
        return self._result("installed", spec)

    def inspect(self, spec):
        self.calls.append("inspect")
        return self._result("inspected", spec) if self.spec == spec else self._result("failed", spec, 1)

    def trigger(self, spec):
        self.calls.append("trigger")
        if self.spec != spec:
            return self._result("failed", spec, 1)
        if callable(self.trigger_hook):
            self.trigger_hook(spec)
        return self._result("triggered", spec)

    def remove(self, spec):
        self.calls.append("remove")
        if self.spec != spec:
            return self._result("failed", spec, 1)
        self.spec = None
        return self._result("removed", spec)


class EndToEndSyntheticTransactionTests(unittest.TestCase):
    """A full cold-run path made solely from temporary source and output trees."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="safe-backup-e2e-")
        self.root = Path(self.temporary.name)
        self.astrbot = self.root / "SyntheticAstrBot"
        data = self.astrbot / "data"
        (data / "config").mkdir(parents=True)
        (data / "plugins" / "third_party").mkdir(parents=True)
        (data / "empty-directory").mkdir(parents=True)
        for name in ("cmd_config.json", "plugins.json", "mcp_server.json", "skills.json"):
            (data / name).write_text("{}", encoding="utf-8")
        (data / "plugins" / "third_party" / "plugin.txt").write_text("synthetic", encoding="utf-8")
        (data / "配置-测试.txt").write_text("unicode", encoding="utf-8")
        # Keep WAL mode alive long enough for a real sidecar to be produced.
        database = sqlite3.connect(data / "synthetic.db")
        database.execute("pragma journal_mode=wal")
        database.execute("create table entries (value text)")
        database.execute("insert into entries values ('safe')")
        database.commit()
        self.database = database
        self.destination = self.root / "output"
        self.profile = self.root / "profile"
        self.profile.mkdir()
        self.adapter = _SyntheticTaskAdapter()
        self.event = AstrMessageEvent()
        self.visible = io.StringIO()
        # Setup stamps the authoritative INITIALIZED state with the real local
        # clock, so the synthetic cold run deliberately follows it.
        self.now = dt.datetime.now().astimezone() + dt.timedelta(minutes=1)

    def tearDown(self):
        self.database.close()
        self.temporary.cleanup()

    @staticmethod
    def _release_guard():
        class Guard:
            def release(self):
                return None
        return Guard()

    def _exited_win_api(self, identity):
        test_case = self
        class ExitedWinApi:
            def open_process(self, access, pid):
                if test_case is not None:
                    test_case.assertEqual(access, exit_waiter.SYNCHRONIZE | exit_waiter.PROCESS_QUERY_LIMITED_INFORMATION)
                    test_case.assertEqual(pid, identity.pid)
                return 41

            def get_process_creation_time(self, handle):
                if test_case is not None: test_case.assertEqual(handle, 41)
                return identity.creation_time_100ns

            def query_full_process_image_name(self, handle):
                if test_case is not None: test_case.assertEqual(handle, 41)
                return identity.executable_key

            def wait_for_single_object(self, handle, timeout_ms):
                if test_case is not None:
                    test_case.assertEqual(handle, 41)
                    test_case.assertEqual(timeout_ms, exit_waiter.INFINITE)
                return exit_waiter.WAIT_OBJECT_0

            def close_handle(self, handle):
                if test_case is not None: test_case.assertEqual(handle, 41)

            def is_interactive_user_logged_on(self, session_id):
                if test_case is not None: test_case.assertEqual(session_id, identity.session_id)
                return True
        return ExitedWinApi()

    def _plugin(self):
        config = AstrBotConfig(
            destination_path=str(self.destination), retention_count=5,
            schedule_weekday="Sunday", schedule_time="12:00",
            napcat_enabled=False, napcat_root="",
        )
        triggered: list[int] = []
        outcomes = []

        def engine_runner(args, *, progress_sink):
            with mock.patch.object(engine.os, "name", "nt"):
                outcome = engine._run(
                    args, process_probe=lambda _root: False, now=self.now,
                    progress_sink=progress_sink,
                )
                outcomes.append(outcome)
                return outcome

        def launch_from_exact_trigger(spec):
            """Model the PowerShell launcher: consume its interpreter pair only."""
            launcher_args = list(spec.arguments)
            python_index = launcher_args.index("--python-path")
            del launcher_args[python_index:python_index + 2]
            args = engine.parse_args(launcher_args)
            result = console_runner.render_backup(
                args, engine_runner=engine_runner, writer=self.visible,
                key_probe=lambda: True, sleep=lambda _seconds: None,
            )
            self.assertEqual(result, 0, self.visible.getvalue() + repr(outcomes[-1]))

        self.adapter.trigger_hook = launch_from_exact_trigger

        def waiter(setup_config, _state):
            """Use the real wait/identity/trigger boundary with a fake OS handle."""
            spec = self.adapter.spec
            self.assertIsNotNone(spec)
            identity = exit_waiter.ProcessIdentity(
                pid=4242, creation_time_100ns=987654321,
                executable_key=r"c:\\synthetic\\python.exe", session_id=1,
            )
            outcome = exit_waiter.wait_for_astrbot_exit(
                identity, setup_config.astrbot_root, spec,
                win_api=self._exited_win_api(identity), process_probe=lambda _root: False,
                task_adapter=self.adapter, sleep=lambda _seconds: None,
                before_trigger=lambda: True, grace_seconds=0,
            )
            self.assertTrue(outcome.triggered, outcome)
            triggered.append(0 if outcome.reason == "triggered" else 1)

        plugin = plugin_main.SafeBackupPlugin(
            Context(), config, task_adapter=self.adapter, waiter_launcher=waiter,
            user_profile=self.profile, plugin_dir=ROOT, python_path=Path(sys.executable),
            compatibility_gate=lambda: None,
        )
        patcher = mock.patch.object(plugin, "_infer_astrbot_root", return_value=self.astrbot)
        patcher.start()
        self.addCleanup(patcher.stop)
        return plugin, triggered

    def test_complete_first_backup(self):
        """setup → verified natural-exit trigger → real archive/renderer succeeds."""
        plugin, triggered = self._plugin()
        messages = asyncio.run(_collect_command(plugin.setup(self.event)))
        self.assertEqual(len(messages), 1)
        self.assertIn("初始化完成", messages[0])
        self.assertEqual(triggered, [0])
        self.assertEqual(self.adapter.calls, ["discover", "install", "inspect", "inspect", "trigger"])

        state = engine.load_state(self.destination)
        self.assertEqual(state["last_result"], "FULL_SUCCESS")
        self.assertFalse(state["napcat_enabled"])
        archive = self.destination / "managed" / state["owner_uuid"] / state["last_successful_archive"]
        self.assertTrue(archive.is_file())
        self.assertTrue(engine.verify_archive(archive, state["owner_uuid"], state["source_fingerprints"]))
        with zipfile.ZipFile(archive) as package:
            names = set(package.namelist())
        self.assertIn("AstrBot/data/empty-directory/", names)
        self.assertIn("AstrBot/data/配置-测试.txt", names)
        self.assertIn("AstrBot/data/synthetic.db", names)
        self.assertFalse(any(name.startswith("NapCat/") for name in names))
        terminal = self.visible.getvalue()
        self.assertEqual(terminal.count("备份成功"), 1)
        self.assertTrue(all(f"[{index}/7]" in terminal for index in range(1, 8)))


class IsolationPolicyTests(unittest.TestCase):
    RELEASE_ROOT_FILES = frozenset({
        ".gitignore", "CHANGELOG.md", "CONTRIBUTING.md", "LICENSE", "PUBLISHING_AGENT_PROMPT.md",
        "README.md", "README_EN.md", "SECURITY.md", "_conf_schema.json", "logo.svg", "main.py",
        "metadata.yaml", "requirements.txt",
    })
    RELEASE_GLOBS = ("safe_backup/*.py", "scripts/*.ps1", ".github/workflows/*.yml")

    @classmethod
    def _release_files(cls, root=ROOT):
        files = {root / name for name in cls.RELEASE_ROOT_FILES}
        for glob in cls.RELEASE_GLOBS:
            files.update(root.glob(glob))
        if any(not path.is_file() for path in files):
            raise AssertionError("release allowlist is incomplete")
        return sorted(files)

    @staticmethod
    def _folded_python_strings(text):
        tree = ast.parse(text)

        def fold(node):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return node.value
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                left, right = fold(node.left), fold(node.right)
                return left + right if left is not None and right is not None else None
            return None

        return [value for node in ast.walk(tree) if (value := fold(node)) is not None]

    @staticmethod
    def _scheduler_calls(text):
        return re.findall(r"(?im)\bget-scheduledtask\b([^\r\n;]*)", text)

    @classmethod
    def _assert_release_tree_safe(cls, root):
        files = cls._release_files(root)
        for path in root.rglob("*"):
            if path.name == "__pycache__" or path.suffix.casefold() in {".pyc", ".pyo"}:
                if path in files or any(parent in files for parent in path.parents):
                    raise AssertionError("bytecode must never be a release entry")
        legacy = "AstrBot" + " NapCat " + "Read-Only" + " Backup"
        prohibited = (legacy, "D:" + "\\qq", "\\AstrBotBackups", "17029", "44498", "old-data_v4")
        for path in files:
            if path.suffix.casefold() == ".py":
                values = cls._folded_python_strings(path.read_text(encoding="utf-8"))
            else:
                values = [path.read_text(encoding="utf-8-sig", errors="replace")]
            for value in values:
                for token in prohibited:
                    if token.casefold() in value.casefold():
                        raise AssertionError(f"private release token in {path.name}")
            if path.suffix.casefold() == ".ps1":
                calls = cls._scheduler_calls(path.read_text(encoding="utf-8-sig"))
                for tail in calls:
                    compact = re.sub(r"\s+", "", tail).casefold()
                    if not re.search(r"-taskname\$(?:resolved\.identity\.name|identity\.name)\b", compact):
                        raise AssertionError(f"unscoped scheduler query in {path.name}")

    def test_release_allowlist_is_private_and_disallows_bytecode(self):
        self._assert_release_tree_safe(ROOT)
        release = self._release_files()
        self.assertFalse(any(path.name == "__pycache__" or path.suffix == ".pyc" for path in release))
        # The packager's bytecode policy must be proved in a disposable exact
        # source copy, not by depending on a cache that happens to exist in the
        # live repository after a prior test run.
        with tempfile.TemporaryDirectory(prefix="safe-backup-release-cache-") as raw:
            fixture = Path(raw) / "source"
            shutil.copytree(
                ROOT, fixture,
                ignore=shutil.ignore_patterns("__pycache__", ".git", ".superpowers"),
            )
            cache = fixture / "safe_backup" / "__pycache__"
            cache.mkdir()
            (cache / "dummy.pyc").write_bytes(b"synthetic-bytecode")
            result = subprocess.run(
                [
                    sys.executable, "-B", str(fixture / "scripts" / "release_packager.py"),
                    "--source", str(fixture), "--output", str(Path(raw) / "output"),
                    "--validate-only",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((Path(raw) / "output").exists())

    def test_release_scanner_folds_python_literals_and_rejects_unscoped_scheduler_forms(self):
        legacy = "AstrBot" + " NapCat " + "Read-Only" + " Backup"
        values = self._folded_python_strings('value = "AstrBot" + " NapCat Read-Only Backup"')
        self.assertIn(legacy, values)
        for text in (
            "Get-ScheduledTask -TaskName $other -ErrorAction SilentlyContinue",
            "GET-SCHEDULEDTASK    -TASKNAME    $resolved.Identity.Name\nGet-ScheduledTask",
            "Get-ScheduledTask -ErrorAction SilentlyContinue",
        ):
            calls = self._scheduler_calls(text)
            self.assertTrue(calls)
            self.assertFalse(all(re.search(r"-taskname\$(?:resolved\.identity\.name|identity\.name)\b", re.sub(r"\s+", "", tail).casefold()) for tail in calls))

    def test_production_tree_does_not_reference_legacy_identity_or_private_machine_data(self):
        self._assert_release_tree_safe(ROOT)
        legacy = "AstrBot" + " NapCat " + "Read-Only" + " Backup"
        prohibited = (legacy, "D:" + "\\qq", "\\AstrBotBackups", "17029", "44498", "old-data_v4")
        for path in self._release_files():
            text = path.read_text(encoding="utf-8-sig", errors="replace")
            for token in prohibited:
                self.assertNotIn(token.casefold(), text.casefold(), path)

    def test_task_control_uses_one_exact_fingerprint_name_without_host_enumeration(self):
        text = (ROOT / "safe_backup" / "task_control.py").read_text(encoding="utf-8")
        scripts = "\n".join(path.read_text(encoding="utf-8-sig") for path in (ROOT / "scripts").glob("*.ps1"))
        self.assertIn('name = f"AstrBot Safe Backup {fingerprint}"', text)
        self.assertNotIn("Get-ScheduledTask |", scripts)
        self.assertNotIn("Get-ScheduledTask -TaskName '*'", scripts)


class DestructiveMatrixInventoryTests(unittest.TestCase):
    """Every published Task 7 adversarial claim must name a runnable test."""

    MATRIX = {
        "task replacement": "tests.test_exit_waiter.ExitWaiterTests.test_logoff_task_replacement_or_duplicate_waiter_never_triggers",
        "setup journal hardlink": "tests.test_setup.SetupFixture.test_setup_journal_hardlink_fails_closed_without_deleting_the_alias",
        "setup journal reparse": "tests.test_setup.SetupFixture.test_setup_journal_junction_fails_closed_and_preserves_original_journal",
        "destination ancestor junction": "tests.test_setup.SetupFixture.test_real_temporary_junction_in_destination_ancestor_is_rejected_without_output",
        "nonce replacement": "tests.test_exit_waiter.ExitWaiterTests.test_nonce_replacement_after_stable_validation_refuses_before_trigger",
        "PID reuse": "tests.test_exit_waiter.ExitWaiterTests.test_pid_reuse_never_triggers",
        "launcher replacement": "tests.test_visible_task_flow.VisibleLauncherTests.test_trusted_script_gate_rejects_hardlinks_and_reparse_points",
        "progress sink": "tests.test_console_runner.ConsoleRunnerTests.test_engine_progress_sink_exception_does_not_change_archive_transaction",
        "foreign staging": "tests.test_fail_safe_hardening.TaskSevenTransactionMatrixTests.test_archive_state_and_staging_faults_preserve_verified_history",
        "SQLite sidecar drift": "tests.test_fail_safe_hardening.TaskSevenTransactionMatrixTests.test_source_wal_sidecar_drift_fails_without_replacing_verified_history",
        "archive replacement": "tests.test_engine_regressions.PublicationCleanupRetentionTests.test_publish_no_replace_preserves_existing_final",
        "state commit": "tests.test_engine_regressions.PublicationCleanupRetentionTests.test_state_commit_failure_removes_uncommitted_final",
        "cleanup refusal": "tests.test_engine_regressions.PublicationCleanupRetentionTests.test_cleanup_refuses_replacement_identity",
            "retention quarantine": "tests.test_fail_safe_hardening.AutomaticRetentionTests.test_retention_verification_cleanup_failure_preserves_all_archives",
    }

    def test_each_adversarial_claim_resolves_to_one_real_test(self):
        for boundary, qualified_name in self.MATRIX.items():
            with self.subTest(boundary=boundary):
                suite = unittest.defaultTestLoader.loadTestsFromName(qualified_name)
                self.assertEqual(suite.countTestCases(), 1, qualified_name)
                self.assertNotIn("_FailedTest", repr(suite))


if __name__ == "__main__":
    unittest.main()
