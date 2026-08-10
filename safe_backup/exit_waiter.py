"""One-shot, fail-closed helper for the first AstrBot cold backup.

The helper observes the *current* AstrBot Python process.  It never opens an
AstrBot data file, sends a process-control request, or attempts to make the
process exit.  It only waits for a naturally terminating process handle.
"""
from __future__ import annotations

from dataclasses import dataclass
import ctypes
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
import stat
from typing import Any, Callable, Mapping, Protocol

from .engine import BackupError, _key, _parse_process_commandline, _path_token, _safe_unlink_owned, _token_from_stat, alternate_data_streams, assert_local_path, assert_safe_output_path, default_process_probe, load_state, process_command_matches
from .setup import InitializationLedger, SetupConfig, build_setup_config
from .task_control import PowerShellTaskAdapter, TaskOperationResult, task_spec


SYNCHRONIZE = 0x00100000
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
WAIT_OBJECT_0 = 0x00000000
WAIT_FAILED = 0xFFFFFFFF
INFINITE = 0xFFFFFFFF
GRACE_SECONDS = 5.0
CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008
_NONCE_PREFIX = "setup-wait-"
_NONCE_SUFFIX = ".json"
READY_TIMEOUT_SECONDS = 8.0


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    creation_time_100ns: int
    executable_key: str
    session_id: int | None = None


@dataclass(frozen=True)
class WaitResult:
    triggered: bool
    reason: str


@dataclass
class _NonceLease:
    path: Path
    token: object

    def release(self) -> bool:
        return _safe_unlink_owned(self.path, self.token)


@dataclass(frozen=True)
class _WaiterAuthority:
    config: SetupConfig
    owner: str
    destination_token: object
    managed_token: object
    owner_token: object


class WinApi(Protocol):
    def open_process(self, access: int, pid: int) -> int | None: ...
    def get_process_creation_time(self, handle: int) -> int: ...
    def query_full_process_image_name(self, handle: int) -> str: ...
    def wait_for_single_object(self, handle: int, timeout_ms: int) -> int: ...
    def close_handle(self, handle: int) -> None: ...
    def is_interactive_user_logged_on(self, session_id: int | None) -> bool | None: ...


def _windows_key(value: str | Path) -> str:
    return str(value).replace("/", "\\").rstrip("\\").casefold()


class CtypesWinApi:
    """Small typed wrapper around the only Windows process APIs this helper needs."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise RuntimeError("Windows process APIs are unavailable")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._open = kernel32.OpenProcess
        self._open.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
        self._open.restype = ctypes.c_void_p
        self._times = kernel32.GetProcessTimes
        self._times.argtypes = (
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_void_p,
        )
        self._times.restype = ctypes.c_int
        self._image = kernel32.QueryFullProcessImageNameW
        self._image.argtypes = (ctypes.c_void_p, ctypes.c_uint32, ctypes.c_wchar_p,
                                ctypes.POINTER(ctypes.c_uint32))
        self._image.restype = ctypes.c_int
        self._wait = kernel32.WaitForSingleObject
        self._wait.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
        self._wait.restype = ctypes.c_uint32
        self._close = kernel32.CloseHandle
        self._close.argtypes = (ctypes.c_void_p,)
        self._close.restype = ctypes.c_int
        self._pid_to_session = kernel32.ProcessIdToSessionId
        self._pid_to_session.argtypes = (ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32))
        self._pid_to_session.restype = ctypes.c_int
        self._active_session = kernel32.WTSGetActiveConsoleSessionId
        self._active_session.argtypes = ()
        self._active_session.restype = ctypes.c_uint32

    def open_process(self, access: int, pid: int) -> int | None:
        if access != SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION or pid <= 0:
            return None
        handle = self._open(access, False, pid)
        return int(handle) if handle else None

    def get_process_creation_time(self, handle: int) -> int:
        creation = ctypes.c_uint64()
        exit_time = ctypes.c_uint64()
        kernel = ctypes.c_uint64()
        user = ctypes.c_uint64()
        if not self._times(ctypes.c_void_p(handle), ctypes.byref(creation), ctypes.byref(exit_time),
                           ctypes.byref(kernel), ctypes.byref(user)):
            raise OSError("cannot read process creation time")
        return int(creation.value)

    def query_full_process_image_name(self, handle: int) -> str:
        size = ctypes.c_uint32(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not self._image(ctypes.c_void_p(handle), 0, buffer, ctypes.byref(size)):
            raise OSError("cannot read process image")
        return buffer.value

    def wait_for_single_object(self, handle: int, timeout_ms: int) -> int:
        return int(self._wait(ctypes.c_void_p(handle), ctypes.c_uint32(timeout_ms)))

    def close_handle(self, handle: int) -> None:
        self._close(ctypes.c_void_p(handle))

    def process_session_id(self, pid: int) -> int | None:
        result = ctypes.c_uint32()
        if not self._pid_to_session(ctypes.c_uint32(pid), ctypes.byref(result)):
            return None
        return int(result.value)

    def is_interactive_user_logged_on(self, session_id: int | None) -> bool | None:
        # A console-session mismatch is intentionally treated as a refusal.
        # RDP-only installations may therefore require the daily task retry,
        # which is safer than starting a task after a user logged out.
        if session_id is None or session_id < 0:
            return None
        active = int(self._active_session())
        if active == 0xFFFFFFFF:
            return False
        return active == session_id


def current_process_identity(win_api: WinApi | None = None) -> ProcessIdentity:
    api = win_api or CtypesWinApi()
    handle = api.open_process(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, os.getpid())
    if not handle:
        raise RuntimeError("cannot identify current process")
    try:
        creation = api.get_process_creation_time(handle)
        executable = api.query_full_process_image_name(handle)
    finally:
        api.close_handle(handle)
    if creation <= 0 or not executable:
        raise RuntimeError("cannot identify current process")
    session = getattr(api, "process_session_id", lambda _pid: None)(os.getpid())
    if not isinstance(session, int) or session < 0:
        raise RuntimeError("cannot identify current process session")
    return ProcessIdentity(os.getpid(), creation, _windows_key(executable), session)


def _exact_task_result(result: object, status: str, task_identity: object) -> bool:
    name = getattr(task_identity, "name", "")
    expected = name.rsplit(" ", 1)[-1] if isinstance(name, str) else ""
    return (
        isinstance(result, TaskOperationResult)
        and result.code == 0 and result.status == status
        and bool(expected) and result.fingerprint == expected
    )


def waiter_process_probe(root: Path, self_identity: ProcessIdentity, *,
                         rows_provider: Callable[[], object] | None = None) -> bool | None:
    """Engine-equivalent post-exit probe that excludes only this helper itself."""
    try:
        if rows_provider is None:
            command = ("Get-CimInstance Win32_Process | Select-Object ProcessId,ExecutablePath,CommandLine,"
                       "@{n='CreationTime100ns';e={$_.CreationDate.ToUniversalTime().ToFileTimeUtc()}} | "
                       "ConvertTo-Json -Compress")
            completed = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                                       capture_output=True, text=True, timeout=20, check=True)
            rows = json.loads(completed.stdout or "[]")
        else:
            rows = rows_provider()
        if isinstance(rows, dict):
            rows = [rows]
        if not isinstance(rows, list):
            return None
        target = root / "venv" / "Scripts" / "python.exe"
        root_main = root / "main.py"
        root_key = _windows_key(root).rstrip("\\")
        for row in rows:
            if not isinstance(row, dict):
                return None
            pid, creation, executable, commandline = (row.get("ProcessId"), row.get("CreationTime100ns"),
                                                       row.get("ExecutablePath"), row.get("CommandLine"))
            if (pid == self_identity.pid and creation == self_identity.creation_time_100ns
                    and isinstance(executable, str) and _windows_key(executable) == self_identity.executable_key):
                continue
            executable_path = Path(executable) if isinstance(executable, str) and executable else None
            executable_key = _windows_key(executable_path) if executable_path is not None else ""
            under_root = bool(executable_key) and (executable_key == root_key or executable_key.startswith(root_key + "\\"))
            if not isinstance(commandline, str):
                if under_root or executable_key == _windows_key(target): return None
                continue
            normalized = commandline.replace("/", "\\").casefold()
            words = _parse_process_commandline(commandline)
            if words is None:
                if under_root or root_key in normalized: return None
                continue
            interpreter = words[0].replace("/", "\\").casefold() if words else ""
            pythonish = (interpreter in {"python", "python.exe", "py", "py.exe"}
                         or executable_key == _windows_key(target))
            for word in words[1:]:
                candidate = word.replace("/", "\\")
                if candidate.casefold() in {"main.py", ".\\main.py"} and pythonish:
                    return True
                try:
                    if Path(candidate).is_absolute() and _windows_key(Path(candidate)) == _windows_key(root_main):
                        return True
                except OSError:
                    return None
            if executable_path is None:
                if root_key in normalized: return None
                continue
            if executable_key == _windows_key(target):
                if process_command_matches(executable_path, commandline, target):
                    return True
            if any(word.replace("/", "\\").casefold() == "main.py" for word in words[1:]):
                return True if under_root else None
            if under_root:
                return None
            if root_key in normalized:
                return None
        return False
    except Exception:
        return None


def wait_for_astrbot_exit(identity: ProcessIdentity, root: Path, task_identity: object, *,
                          win_api: WinApi, process_probe: Callable[[Path], bool | None],
                          task_adapter: object, sleep: Callable[[float], None] = time.sleep,
                          already_running: Callable[[], bool] | None = None,
                          before_trigger: Callable[[], bool] | None = None,
                          on_verified_wait: Callable[[], None] | None = None,
                          grace_seconds: float = GRACE_SECONDS) -> WaitResult:
    """Wait for exactly one observed process, then trigger an exact task once.

    Every uncertainty intentionally turns into a non-triggering result.  This
    function takes no source file opener and performs no source filesystem IO.
    """
    if already_running is not None and already_running():
        return WaitResult(False, "waiter_already_running")
    if (not isinstance(identity, ProcessIdentity) or identity.pid <= 0
            or identity.creation_time_100ns <= 0 or not identity.executable_key
            or not isinstance(root, Path) or grace_seconds < 0):
        return WaitResult(False, "invalid_identity")
    handle: int | None = None
    try:
        handle = win_api.open_process(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, identity.pid)
        if not handle:
            return WaitResult(False, "process_unavailable")
        if (win_api.get_process_creation_time(handle) != identity.creation_time_100ns
                or _windows_key(win_api.query_full_process_image_name(handle)) != identity.executable_key):
            return WaitResult(False, "identity_mismatch")
        if on_verified_wait is not None:
            on_verified_wait()
        if win_api.wait_for_single_object(handle, INFINITE) != WAIT_OBJECT_0:
            return WaitResult(False, "wait_failed")
    except Exception:
        return WaitResult(False, "process_check_failed")
    finally:
        if handle:
            try:
                win_api.close_handle(handle)
            except Exception:
                pass
    try:
        sleep(grace_seconds)
        if win_api.is_interactive_user_logged_on(identity.session_id) is not True:
            return WaitResult(False, "user_not_logged_on")
        if process_probe(root) is not False:
            return WaitResult(False, "process_active_or_indeterminate")
        inspected = getattr(task_adapter, "inspect")(task_identity)
        if not _exact_task_result(inspected, "inspected", task_identity):
            return WaitResult(False, "task_identity_changed")
        if before_trigger is not None and before_trigger() is not True:
            return WaitResult(False, "waiter_lease_changed")
        triggered = getattr(task_adapter, "trigger")(task_identity)
        if not _exact_task_result(triggered, "triggered", task_identity):
            return WaitResult(False, "task_trigger_failed")
        return WaitResult(True, "triggered")
    except Exception:
        return WaitResult(False, "post_exit_check_failed")


def _nonce_path(config: SetupConfig, owner: str) -> Path:
    if re.fullmatch(r"[0-9a-f-]{36}", owner, re.I) is None:
        raise RuntimeError("invalid setup owner")
    return config.destination / "managed" / owner / f"{_NONCE_PREFIX}{uuid.uuid4()}{_NONCE_SUFFIX}"


def _ready_path(nonce: Path) -> Path:
    return nonce.with_name(nonce.stem + ".ready")


def _authority_from_ledger(config: SetupConfig, state: Mapping[str, Any], ledger: InitializationLedger) -> _WaiterAuthority:
    """Bind target writes to the exact setup objects, not just path strings."""
    owner = state.get("owner_uuid")
    if (not isinstance(owner, str) or state.get("last_result") != "INITIALIZED"
            or ledger.state != state or ledger.owner_uuid != owner
            or ledger.destination_token is None or ledger.managed_token is None
            or ledger.owner_token is None):
        raise RuntimeError("untrusted initialization authority")
    authority = _WaiterAuthority(config, owner, ledger.destination_token,
                                 ledger.managed_token, ledger.owner_token)
    _verify_authority(authority)
    return authority


def _verify_authority(authority: _WaiterAuthority) -> None:
    config = authority.config
    destination = config.destination
    if not destination.is_absolute() or str(destination).startswith(("\\\\", "//")):
        raise RuntimeError("unsafe waiter target")
    try:
        assert_local_path(destination)
        assert_safe_output_path(destination)
        destination_token = _path_token(destination, directory=True)
        managed_token = _path_token(destination / "managed", directory=True)
        owner_token = _path_token(destination / "managed" / authority.owner, directory=True)
    except (BackupError, OSError, ValueError):
        raise RuntimeError("unsafe waiter target") from None
    if (not destination_token.same_object(authority.destination_token)
            or not managed_token.same_object(authority.managed_token)
            or not owner_token.same_object(authority.owner_token)):
        raise RuntimeError("waiter target identity changed")


def _assert_plain_target_chain(path: Path, destination: Path) -> None:
    """Reject a target nonce or its owned parents if any is a reparse point."""
    current = path
    while True:
        info = current.lstat()
        attrs = getattr(info, "st_file_attributes", 0)
        if stat.S_ISLNK(info.st_mode) or attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            raise RuntimeError("unsafe waiter nonce path")
        if current == destination:
            return
        if current.parent == current:
            raise RuntimeError("unsafe waiter nonce path")
        current = current.parent


def acquire_nonce_lease(nonce: Path, authority: _WaiterAuthority) -> _NonceLease | None:
    """Claim one nonce once, using a target-only exact-token marker."""
    try:
        _verify_authority(authority)
        if nonce.parent != authority.config.destination / "managed" / authority.owner:
            return None
        nonce_token = _path_token(nonce, regular=True, single_link=True)
        if alternate_data_streams(nonce):
            return None
    except (BackupError, OSError, ValueError):
        return None
    lease = nonce.with_name(nonce.stem + ".active")
    try:
        with lease.open("x", encoding="ascii", newline="\n") as handle:
            handle.write("one-shot\n")
        lease_token = _path_token(lease, regular=True, single_link=True)
        _verify_authority(authority)
        if not _path_token(nonce, regular=True, single_link=True).same_content_identity(nonce_token):
            return None
        return _NonceLease(lease, lease_token)
    except FileExistsError:
        return None
    except (BackupError, OSError, ValueError):
        return None


def _write_nonce(authority: _WaiterAuthority, state: Mapping[str, Any], identity: ProcessIdentity) -> tuple[Path, object]:
    config = authority.config
    owner = authority.owner
    _verify_authority(authority)
    path = _nonce_path(config, owner)
    record = {
        "schema": 1, "owner_uuid": owner, "source_fingerprint": config.source_fingerprint,
        "config_fingerprint": config.config_fingerprint, "pid": identity.pid,
        "creation_time_100ns": identity.creation_time_100ns,
        "executable_key": identity.executable_key,
        "session_id": identity.session_id,
        "astrbot_root": str(config.astrbot_root), "destination": str(config.destination),
        "plugin_dir": str(config.plugin_dir), "python_path": str(config.python_path),
        "retention": config.retention, "week_start": config.week_start,
        "schedule_time": config.schedule_time,
        "napcat_root": str(config.napcat_root) if config.napcat_root is not None else None,
    }
    try:
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(record, handle, sort_keys=True, separators=(",", ":"))
        _verify_authority(authority)
    except Exception:
        raise RuntimeError("cannot create waiter nonce") from None
    return path, _path_token(path, regular=True, single_link=True)


def _write_ready(nonce: Path, nonce_token: object, authority: _WaiterAuthority) -> object:
    """Publish a small target-only handshake after nonce validation and lease."""
    _verify_authority(authority)
    if not _path_token(nonce, regular=True, single_link=True).same_content_identity(nonce_token):
        raise RuntimeError("waiter nonce changed before ready")
    ready = _ready_path(nonce)
    record = {"schema": 1, "owner_uuid": authority.owner,
              "source_fingerprint": authority.config.source_fingerprint,
              "config_fingerprint": authority.config.config_fingerprint}
    try:
        with ready.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(record, handle, sort_keys=True, separators=(",", ":"))
        token = _path_token(ready, regular=True, single_link=True)
        _verify_authority(authority)
        return token
    except Exception:
        raise RuntimeError("cannot publish waiter ready") from None


def _wait_for_ready(nonce: Path, authority: _WaiterAuthority, *,
                    sleep: Callable[[float], None] = time.sleep,
                    monotonic: Callable[[], float] = time.monotonic) -> None:
    deadline = monotonic() + READY_TIMEOUT_SECONDS
    ready = _ready_path(nonce)
    while monotonic() < deadline:
        try:
            _verify_authority(authority)
            if ready.exists():
                record, _token = _read_nonce_stably(ready)
                if (record == {"schema": 1, "owner_uuid": authority.owner,
                               "source_fingerprint": authority.config.source_fingerprint,
                               "config_fingerprint": authority.config.config_fingerprint}):
                    return
                raise RuntimeError("invalid waiter ready")
        except FileNotFoundError:
            pass
        sleep(0.05)
    raise RuntimeError("waiter did not become ready")


def launch_exit_waiter(config: SetupConfig, state: Mapping[str, Any], ledger: InitializationLedger, *,
                       win_api: WinApi | None = None, popen=subprocess.Popen,
                       ready_waiter: Callable[[Path, _WaiterAuthority], None] | None = None) -> None:
    """Start the detached one-shot helper; failure leaves a diagnostic nonce."""
    authority = _authority_from_ledger(config, state, ledger)
    identity = current_process_identity(win_api)
    nonce, _token = _write_nonce(authority, state, identity)
    command = [str(config.python_path), "-m", "safe_backup.exit_waiter", "--nonce", str(nonce)]
    flags = CREATE_NO_WINDOW | DETACHED_PROCESS if os.name == "nt" else 0
    try:
        popen(command, shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
              stderr=subprocess.DEVNULL, close_fds=True, cwd=str(config.plugin_dir), creationflags=flags)
    except Exception:
        # Do not remove a nonce after a spawn uncertainty: retaining it is the
        # fail-closed, auditable choice.
        raise RuntimeError("cannot launch exit waiter") from None
    try:
        (ready_waiter or _wait_for_ready)(nonce, authority)
    except Exception:
        raise RuntimeError("waiter readiness failed") from None


def _read_nonce_stably(path: Path) -> tuple[dict[str, Any], object]:
    """Read one small nonce through a non-following, identity-checked handle."""
    try:
        pre = _path_token(path, regular=True, single_link=True)
        if alternate_data_streams(path):
            raise RuntimeError("unsafe waiter nonce")
        descriptor = _open_nofollow_read(path)
        try:
            opened = _token_from_stat(os.fstat(descriptor))
            if not opened.same_content_identity(pre) or opened.nlink != 1:
                raise RuntimeError("waiter nonce changed while opening")
            chunks: list[bytes] = []
            remaining = 32 * 1024
            while remaining:
                chunk = os.read(descriptor, min(4096, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            if remaining == 0 and os.read(descriptor, 1):
                raise RuntimeError("waiter nonce too large")
        finally:
            os.close(descriptor)
        post = _path_token(path, regular=True, single_link=True)
        if not post.same_content_identity(pre) or not post.same_content_identity(opened):
            raise RuntimeError("waiter nonce changed while reading")
        record = json.loads(b"".join(chunks).decode("utf-8"))
        if not isinstance(record, dict):
            raise RuntimeError("invalid waiter nonce")
        return record, pre
    except (BackupError, OSError, UnicodeError, ValueError, TypeError):
        raise RuntimeError("invalid waiter nonce") from None


def _open_nofollow_read(path: Path) -> int:
    """Open only a leaf object, never following its reparse target."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is not None:
        return os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | nofollow)
    if os.name != "nt":
        raise RuntimeError("nonce no-follow access unavailable")
    try:
        import msvcrt
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create = kernel32.CreateFileW
        create.argtypes = (ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                           ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p)
        create.restype = ctypes.c_void_p
        handle = create(str(path), 0x80000000, 0x00000001 | 0x00000002 | 0x00000004, None,
                        3, 0x00000080 | 0x00200000, None)
        if not handle or int(handle) == -1:
            raise OSError("cannot open waiter nonce")
        return msvcrt.open_osfhandle(int(handle), os.O_RDONLY | getattr(os, "O_BINARY", 0))
    except Exception:
        raise RuntimeError("nonce no-follow access unavailable") from None


def _consume_nonce(path: Path) -> tuple[SetupConfig, ProcessIdentity, object, _WaiterAuthority]:
    if (path.name.startswith(_NONCE_PREFIX) is False or not path.name.endswith(_NONCE_SUFFIX)
            or re.fullmatch(r"setup-wait-[0-9a-f-]{36}\.json", path.name, re.I) is None):
        raise RuntimeError("invalid waiter nonce path")
    destination = path.parents[2]
    owner_dir = path.parent
    managed_dir = owner_dir.parent
    # This pre-read path gate only permits the fixed run-owned shape.  It does
    # not write anything; a later authority is created only after state binding.
    try:
        if not path.is_absolute() or str(path).startswith(("\\\\", "//")):
            raise RuntimeError("invalid waiter nonce path")
        if (path.parent != owner_dir or managed_dir.name != "managed"
                or managed_dir.parent != destination
                or owner_dir != destination / "managed" / owner_dir.name):
            raise RuntimeError("invalid waiter nonce path")
        assert_local_path(path)
        _assert_plain_target_chain(path, destination)
        _path_token(destination, directory=True)
        _path_token(managed_dir, directory=True)
        _path_token(owner_dir, directory=True)
        state = load_state(destination)
        state_owner = state.get("owner_uuid") if isinstance(state, dict) else None
        if (not isinstance(state, dict) or state.get("last_result") != "INITIALIZED"
                or state.get("managed_by") != "astrbot_plugin_safe_backup"
                or state.get("state_namespace") != "community-v1"
                or not isinstance(state_owner, str)
                or owner_dir != destination / "managed" / state_owner
                or managed_dir != destination / "managed"):
            raise RuntimeError("untrusted waiter state")
        record, nonce_token = _read_nonce_stably(path)
    except (BackupError, OSError, RuntimeError, ValueError):
        raise RuntimeError("invalid waiter nonce") from None
    if not isinstance(record, dict) or set(record) != {
        "schema", "owner_uuid", "source_fingerprint", "config_fingerprint", "pid",
        "creation_time_100ns", "executable_key", "session_id",
        "astrbot_root", "destination", "plugin_dir", "python_path", "retention", "week_start",
        "schedule_time", "napcat_root",
    } or record.get("schema") != 1:
        raise RuntimeError("invalid waiter nonce")
    # CLI keeps all potentially private root/configuration values inside the
    # target state and nonce directory; it never accepts them on the command line.
    owner = record.get("owner_uuid")
    if not isinstance(owner, str) or owner_dir.name != owner or owner_dir.parent.name != "managed":
        raise RuntimeError("invalid waiter nonce")
    if (state.get("owner_uuid") != owner or state.get("last_result") != "INITIALIZED"
            or state.get("source_fingerprints", {}).get("astrbot_root") != record.get("source_fingerprint")
            or state.get("config_fingerprint") != record.get("config_fingerprint")):
        raise RuntimeError("untrusted waiter nonce")
    expected_text = ("astrbot_root", "destination", "plugin_dir", "python_path", "schedule_time")
    if any(not isinstance(record.get(key), str) or not record[key] for key in expected_text):
        raise RuntimeError("invalid waiter nonce")
    if record.get("napcat_root") is not None and not isinstance(record["napcat_root"], str):
        raise RuntimeError("invalid waiter nonce")
    weekday = str(record.get("week_start"))
    if weekday not in {str(value) for value in range(7)}:
        raise RuntimeError("invalid waiter nonce")
    try:
        config = build_setup_config(
            astrbot_root=record["astrbot_root"], destination_text=record["destination"],
            user_profile=Path(record["destination"]).parent, plugin_dir=record["plugin_dir"],
            python_path=record["python_path"], retention=record["retention"], weekday={
                0: "Monday", 1: "Tuesday", 2: "Wednesday", 3: "Thursday", 4: "Friday",
                5: "Saturday", 6: "Sunday",
            }[int(weekday)], schedule_time=record["schedule_time"], napcat_root=record["napcat_root"],
        )
    except (BackupError, OSError, TypeError, ValueError, KeyError):
        raise RuntimeError("invalid waiter nonce") from None
    if (config.source_fingerprint != record["source_fingerprint"]
            or config.config_fingerprint != record["config_fingerprint"]
            or config.destination != destination):
        raise RuntimeError("untrusted waiter nonce")
    try:
        identity = ProcessIdentity(
            pid=record["pid"], creation_time_100ns=record["creation_time_100ns"],
            executable_key=record["executable_key"], session_id=record["session_id"],
        )
    except TypeError:
        raise RuntimeError("invalid waiter nonce") from None
    if (identity.pid <= 0 or identity.creation_time_100ns <= 0
            or not isinstance(identity.executable_key, str) or not identity.executable_key
            or not isinstance(identity.session_id, int) or identity.session_id < 0):
        raise RuntimeError("invalid waiter nonce")
    authority = _WaiterAuthority(
        config, owner, _path_token(destination, directory=True),
        _path_token(destination / "managed", directory=True),
        _path_token(owner_dir, directory=True),
    )
    _verify_authority(authority)
    if not _path_token(path, regular=True, single_link=True).same_content_identity(nonce_token):
        raise RuntimeError("waiter nonce changed after validation")
    return config, identity, nonce_token, authority


def main(argv: list[str] | None = None) -> int:
    """Strict CLI: it only accepts one run-owned, short-lived nonce path."""
    import argparse
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--nonce", required=True)
    lease: _NonceLease | None = None
    ready_token: object | None = None
    ready_path: Path | None = None
    consumed = False
    try:
        namespace = parser.parse_args(argv)
        nonce = Path(namespace.nonce)
        config, identity, token, authority = _consume_nonce(nonce)
        lease = acquire_nonce_lease(nonce, authority)
        if lease is None:
            return 1
        api = CtypesWinApi()
        helper_identity = current_process_identity(api)
        ready_path = _ready_path(nonce)
        def lease_is_current() -> bool:
            try:
                _verify_authority(authority)
                return (_path_token(lease.path, regular=True, single_link=True).same_content_identity(lease.token)
                        and _path_token(nonce, regular=True, single_link=True).same_content_identity(token))
            except (BackupError, OSError, ValueError):
                return False
        spec = task_spec(config, config.plugin_dir, config.python_path)
        def publish_ready() -> None:
            nonlocal ready_token
            ready_token = _write_ready(nonce, token, authority)
        wait_for_astrbot_exit(
            identity, config.astrbot_root, spec, win_api=api,
            process_probe=lambda root: waiter_process_probe(root, helper_identity), task_adapter=PowerShellTaskAdapter(),
            before_trigger=lease_is_current,
            on_verified_wait=publish_ready,
        )
        consumed = _safe_unlink_owned(nonce, token)
    except Exception:
        consumed = False
    if lease is None or not lease.release():
        return 1
    if ready_path is None or ready_token is None or not _safe_unlink_owned(ready_path, ready_token):
        return 1
    return 0 if consumed else 1


if __name__ == "__main__":
    raise SystemExit(main())
