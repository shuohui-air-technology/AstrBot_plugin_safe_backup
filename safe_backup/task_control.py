"""Typed, local adapter for the scheduled-task PowerShell scripts."""
from __future__ import annotations

from dataclasses import dataclass
import getpass
import json
import ntpath
from pathlib import Path
import subprocess
import re
import threading
import time
from typing import Literal

from .setup import SetupConfig, artifact_digest


MAX_OUTPUT_BYTES = 16 * 1024
PROCESS_TIMEOUT_SECONDS = 30
WINDOWS_POWERSHELL = Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
_SCRIPT_DIRECTORY = Path(__file__).resolve().parents[1] / "scripts"
_STATUS_BY_OPERATION = {
    "install": frozenset(("installed", "validated", "failed")),
    "update": frozenset(("updated", "validated", "failed")),
    "remove": frozenset(("removed", "validated", "failed")),
    "inspect": frozenset(("inspected", "failed")),
    "trigger": frozenset(("triggered", "failed")),
}


class TaskControlError(RuntimeError):
    """A non-sensitive failure reported by the task-control boundary."""


@dataclass(frozen=True)
class TaskSpec:
    name: str
    description: str
    launcher: Path
    arguments: tuple[str, ...]
    user_id: str
    run_level: Literal["Limited"] = "Limited"
    logon_type: Literal["Interactive"] = "Interactive"


@dataclass(frozen=True)
class TaskOperationResult:
    code: int
    status: str
    fingerprint: str


@dataclass(frozen=True)
class TaskDiscovery:
    """Exact-name task discovery; it never lists unrelated host tasks."""
    status: Literal["missing", "exact"]
    spec: TaskSpec | None


def task_spec(config: SetupConfig, plugin_dir: Path, python_path: Path) -> TaskSpec:
    """Build the immutable, launcher-only scheduled-task specification."""
    fingerprint = config.source_fingerprint[:12]
    arguments = [
        "--astrbot-root", str(config.astrbot_root),
        "--destination", str(config.destination),
        "--python-path", str(python_path),
        "--keep", str(config.retention),
        "--week-start", str(config.week_start),
        "--schedule-time", config.schedule_time,
    ]
    if config.napcat_root is not None:
        arguments.extend(("--napcat-root", str(config.napcat_root)))
    arguments.extend(("--artifact-digest", config.artifact_digest))
    arguments.append("--scheduled")
    return TaskSpec(
        name=f"AstrBot Safe Backup {fingerprint}",
        description=f"AstrBotSafeBackup:v1:{fingerprint}",
        launcher=Path(plugin_dir) / "scripts" / "task_launcher.ps1",
        arguments=tuple(arguments),
        user_id=getpass.getuser(),
    )


class PowerShellTaskAdapter:
    """Run fixed PowerShell task scripts without a shell or path-bearing output."""

    def __init__(self) -> None:
        self._executable = WINDOWS_POWERSHELL
        self._script_directory = _SCRIPT_DIRECTORY

    def install(self, spec: TaskSpec) -> TaskOperationResult:
        return self._operate("install", spec)

    def update(self, expected_old: TaskSpec, new: TaskSpec | None = None) -> TaskOperationResult:
        """Replace a task only if the process re-proves the complete old spec."""
        new = new or expected_old
        # An old task is allowed to carry the prior trusted artifact digest so
        # that an explicit update can move it forward.  Only the new admission
        # must match the files installed right now.
        old_fingerprint = self._validate_spec(expected_old)
        if old_fingerprint != self._validate_spec(new, require_current_artifact=True):
            raise TaskControlError("invalid task specification")
        command = [
            str(self._executable), "-NoProfile", "-NonInteractive", "-File",
            str(self._script_directory / "update_task.ps1"),
            "-TaskName", new.name, "-Description", new.description,
            "-TaskFingerprint", old_fingerprint,
            "-ExpectedLauncherPath", str(expected_old.launcher),
            "-ExpectedLauncherArgumentsJson", json.dumps(list(expected_old.arguments), ensure_ascii=False),
            "-LauncherPath", str(new.launcher),
            "-LauncherArgumentsJson", json.dumps(list(new.arguments), ensure_ascii=False),
            "-OutputJson",
        ]
        return_code, stdout, _stderr = self._run_bounded(command)
        result = self._parse_result(stdout, "update", new)
        if return_code != result.code:
            raise TaskControlError("invalid task response")
        return result

    def remove(self, spec: TaskSpec) -> TaskOperationResult:
        return self._operate("remove", spec)

    def trigger(self, spec: TaskSpec) -> TaskOperationResult:
        """Request one run only after the external script re-proves ownership."""
        return self._operate("trigger", spec)

    def inspect(self, spec: TaskSpec) -> TaskOperationResult:
        return self._operate("inspect", spec)

    def inspect_by_fingerprint(self, fingerprint: str) -> TaskDiscovery:
        """Discover one source-derived task name and recover only trusted arguments."""
        if re.fullmatch(r"[0-9a-f]{12}", fingerprint) is None:
            raise TaskControlError("invalid task specification")
        name = f"AstrBot Safe Backup {fingerprint}"
        description = f"AstrBotSafeBackup:v1:{fingerprint}"
        command = [
            str(self._executable), "-NoProfile", "-NonInteractive", "-File",
            str(self._script_directory / "update_task.ps1"),
            "-TaskName", name, "-Description", description,
            "-TaskFingerprint", fingerprint, "-Discover", "-OutputJson",
        ]
        return_code, stdout, _stderr = self._run_bounded(command)
        discovery = self._parse_discovery_result(stdout, fingerprint)
        if return_code not in {0, 3}:
            raise TaskControlError("invalid task response")
        return discovery

    def _operate(self, operation: Literal["install", "update", "remove", "inspect"],
                 spec: TaskSpec) -> TaskOperationResult:
        fingerprint = self._validate_spec(spec, require_current_artifact=operation == "install")
        script_operation = "update" if operation == "inspect" else (
            "start" if operation == "trigger" else operation
        )
        command = [
            str(self._executable), "-NoProfile", "-NonInteractive", "-File",
            str(self._script_directory / f"{script_operation}_task.ps1"),
            "-TaskName", spec.name,
            "-Description", spec.description,
            "-TaskFingerprint", fingerprint,
            "-LauncherPath", str(spec.launcher),
            "-LauncherArgumentsJson", json.dumps(list(spec.arguments), ensure_ascii=False),
            "-OutputJson",
        ]
        if operation == "inspect":
            command.extend(("-ValidateOnly", "-Operation", "inspect"))
        return_code, stdout, _stderr = self._run_bounded(command)
        result = self._parse_result(stdout, operation, spec)
        if return_code != result.code:
            raise TaskControlError("invalid task response")
        return result

    @staticmethod
    def _run_bounded(command: list[str]) -> tuple[int, str, str]:
        try:
            process = subprocess.Popen(
                command, shell=False, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        except Exception:
            raise TaskControlError("task process failed") from None
        captures = {"stdout": bytearray(), "stderr": bytearray()}
        overflow = threading.Event()
        read_error = threading.Event()

        def read_stream(stream, key):
            try:
                while True:
                    chunk = stream.read(4096)
                    if not chunk:
                        break
                    if len(captures[key]) + len(chunk) > MAX_OUTPUT_BYTES:
                        overflow.set()
                        break
                    captures[key].extend(chunk)
            except Exception:
                read_error.set()

        readers = [
            threading.Thread(target=read_stream, args=(process.stdout, "stdout"), daemon=True),
            threading.Thread(target=read_stream, args=(process.stderr, "stderr"), daemon=True),
        ]
        for reader in readers:
            reader.start()
        deadline = time.monotonic() + PROCESS_TIMEOUT_SECONDS
        error = None
        code = None
        try:
            while code is None:
                if overflow.is_set():
                    error = TaskControlError("task response too large")
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    error = TaskControlError("task operation timed out")
                    break
                try:
                    code = process.wait(timeout=min(0.1, remaining))
                except subprocess.TimeoutExpired:
                    continue
        except Exception as exc:
            error = TaskControlError("task process failed")
        finally:
            if error is not None:
                try:
                    process.terminate()
                except (OSError, ValueError, subprocess.SubprocessError):
                    pass
            for reader in readers:
                reader.join(timeout=1)
        if error is not None:
            raise error
        if read_error.is_set() or any(reader.is_alive() for reader in readers):
            raise TaskControlError("task process failed")
        try:
            return int(code), captures["stdout"].decode("utf-8", "replace"), captures["stderr"].decode("utf-8", "replace")
        except (TypeError, ValueError, UnicodeError):
            raise TaskControlError("task process failed") from None

    @staticmethod
    def _capped(value: object) -> str:
        if not isinstance(value, str):
            raise TaskControlError("invalid task response")
        if len(value.encode("utf-8", "replace")) > MAX_OUTPUT_BYTES:
            raise TaskControlError("task response too large")
        return value

    @staticmethod
    def _fingerprint(spec: TaskSpec) -> str:
        prefix = "AstrBot Safe Backup "
        if not spec.name.startswith(prefix) or len(spec.name) != len(prefix) + 12:
            raise TaskControlError("invalid task specification")
        return spec.name[len(prefix):]

    def _validate_spec(self, spec: TaskSpec, *, require_current_artifact: bool = False) -> str:
        if not isinstance(spec, TaskSpec):
            raise TaskControlError("invalid task specification")
        fingerprint = self._fingerprint(spec)
        expected_launcher = self._script_directory / "task_launcher.ps1"
        if (
            re.fullmatch(r"[0-9a-f]{12}", fingerprint) is None
            or spec.description != f"AstrBotSafeBackup:v1:{fingerprint}"
            or spec.launcher.name != "task_launcher.ps1"
            or spec.launcher.parent.name != "scripts"
            or not ntpath.isabs(str(spec.launcher))
            or str(spec.launcher).startswith("\\\\")
            or ntpath.normcase(ntpath.normpath(str(spec.launcher)))
            != ntpath.normcase(ntpath.normpath(str(expected_launcher)))
            or not isinstance(spec.arguments, tuple)
            or any(not isinstance(value, str) for value in spec.arguments)
        ):
            raise TaskControlError("invalid task specification")
        args = spec.arguments
        required = ("--astrbot-root", "--destination", "--python-path", "--keep", "--week-start", "--schedule-time")
        if len(args) not in (15, 17) or tuple(args[index] for index in range(0, 12, 2)) != required:
            raise TaskControlError("invalid task specification")
        if args[-1] != "--scheduled" or args[-3] != "--artifact-digest" or re.fullmatch(r"[0-9a-f]{64}", args[-2]) is None or args[-2] == "0" * 64 or (len(args) == 17 and args[-5] != "--napcat-root"):
            raise TaskControlError("invalid task specification")
        paths = [args[1], args[3], args[5]] + ([args[13]] if len(args) == 17 else [])
        if any(not value or value.startswith("\\\\") or not ntpath.isabs(value) for value in paths):
            raise TaskControlError("invalid task specification")
        if not re.fullmatch(r"(?:[1-9]|[12][0-9]|30)", args[7]) or args[9] not in "0 1 2 3 4 5 6".split():
            raise TaskControlError("invalid task specification")
        if re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", args[11]) is None:
            raise TaskControlError("invalid task specification")
        if require_current_artifact:
            # The task adapter is the final Python-side admission boundary.  A
            # caller-supplied non-zero digest is insufficient: recompute it
            # from the complete local, trusted runtime artifact set.
            current = artifact_digest(expected_launcher.parents[1])
            if current == "0" * 64 or args[-2] != current:
                raise TaskControlError("artifact digest does not match local plugin files")
        return fingerprint

    def _parse_result(self, stdout: str, operation: str, spec: TaskSpec) -> TaskOperationResult:
        try:
            record = json.loads(stdout)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise TaskControlError("invalid task response") from exc
        expected_fingerprint = self._fingerprint(spec)
        if (
            not isinstance(record, dict)
            or set(record) != {"operation", "fingerprint", "status", "code"}
            or record.get("operation") != operation
            or record.get("fingerprint") != expected_fingerprint
            or not isinstance(record.get("status"), str)
            or record["status"] not in _STATUS_BY_OPERATION[operation]
            or not isinstance(record.get("code"), int)
            or isinstance(record["code"], bool)
            or record["code"] < 0 or record["code"] > 255
        ):
            raise TaskControlError("invalid task response")
        return TaskOperationResult(record["code"], record["status"], record["fingerprint"])

    def _parse_discovery_result(self, stdout: str, fingerprint: str) -> TaskDiscovery:
        try:
            record = json.loads(stdout)
        except (TypeError, ValueError, json.JSONDecodeError):
            raise TaskControlError("invalid task response") from None
        if (not isinstance(record, dict) or record.get("operation") != "discover"
                or record.get("fingerprint") != fingerprint
                or not isinstance(record.get("code"), int)
                or isinstance(record.get("code"), bool)
                or record["code"] < 0 or record["code"] > 255):
            raise TaskControlError("invalid task response")
        status = record.get("status")
        if status == "missing" and set(record) == {"operation", "fingerprint", "status", "code"} and record["code"] == 0:
            return TaskDiscovery("missing", None)
        if status == "foreign" and set(record) == {"operation", "fingerprint", "status", "code"} and record["code"] == 3:
            raise TaskControlError("foreign task")
        arguments = record.get("arguments")
        if (status != "exact" or record.get("code") != 0
                or set(record) != {"operation", "fingerprint", "status", "code", "arguments"}
                or not isinstance(arguments, list) or any(not isinstance(value, str) for value in arguments)):
            raise TaskControlError("invalid task response")
        spec = TaskSpec(
            name=f"AstrBot Safe Backup {fingerprint}",
            description=f"AstrBotSafeBackup:v1:{fingerprint}",
            launcher=self._script_directory / "task_launcher.ps1",
            arguments=tuple(arguments), user_id=getpass.getuser(),
        )
        self._validate_spec(spec)
        return TaskDiscovery("exact", spec)
