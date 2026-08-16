#!/usr/bin/env python3
"""Strict, read-only AstrBot + NapCat backup tool (Python standard library)."""
from __future__ import annotations

import argparse
import ctypes
import contextlib
import datetime as dt
import errno
import hashlib
import json
import logging
import ntpath
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

try:  # Keep the historic ``python safe_backup/engine.py`` command usable.
    from .progress import ProgressEvent, ProgressSink
except ImportError:  # pragma: no cover - exercised by the PowerShell wrapper.
    from progress import ProgressEvent, ProgressSink

SCHEMA = 1
GENERATOR = "astrbot_plugin_safe_backup"
GENERATOR_VERSION = "0.1.0"
DISABLED_NAPCAT = "disabled"
WEEKDAYS = {
    "monday": 0, "tuesday": 1, "wednesday": 2, "thursday": 3,
    "friday": 4, "saturday": 5, "sunday": 6,
}
WEEKDAY_NAMES = {value: key for key, value in WEEKDAYS.items()}
NONCRITICAL = {"temp", "logs", "dist", "site-packages", "sowing_discord_cache"}
DB_SUFFIXES = (".db", ".sqlite", ".sqlite3")
SIDECARS = ("-wal", "-shm", "-journal")
HARD_MAX_ARCHIVE_ENTRY = 2 * 1024 * 1024 * 1024
HARD_MAX_ARCHIVE_ENTRIES = 50_000
HARD_MAX_ARCHIVE_TOTAL = 64 * 1024 * 1024 * 1024
HARD_MAX_COMPRESSION_RATIO = 500
# Compatibility names remain hard verifier ceilings. Per-run limits are lower and
# are recorded in the manifest by archive_budget().
MAX_ARCHIVE_ENTRY = HARD_MAX_ARCHIVE_ENTRY
MAX_ARCHIVE_ENTRIES = HARD_MAX_ARCHIVE_ENTRIES
MAX_ARCHIVE_TOTAL = HARD_MAX_ARCHIVE_TOTAL
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_METADATA_JSON_BYTES = 4 * 1024 * 1024
MAX_STATE_BYTES = 1024 * 1024
ARCHIVE_EXCLUSIONS = ["QQ AppData", "NapCat binaries/cache/log/temp/plugin code"]
CAPABILITIES = {
    "source_read_only": True,
    "sqlite_integrity_check": True,
    "plugin_business_semantics": False,
    "automatic_restore": False,
}
STATE_RESULTS = {"INITIALIZED", "FULL_SUCCESS", "FAILED", "DEGRADED"}
PUBLICATION_DISPOSITIONS = {
    "never_published", "cleaned", "quarantine_possible", "full_success",
}
FAILURE_PHASES = {
    "output-gate", "state-load", "schedule-check", "process-check", "astrbot-inventory",
    "napcat-inventory", "layout-check", "staging-create", "copy", "post-process-check",
    "post-copy-check", "post-inventory", "normalize", "archive-write", "archive-verify",
    "staging-cleanup", "publish", "final-verify", "state-commit", "retention",
}
NAPCAT_VERSION_JSON_SUFFIXES = (
    "version.json",
    "resources/app/application.json",
    "resources/app/package.json",
    "resources/app/napcat/package.json",
    "resources/app/napcat/qqnt.json",
)
ASTRBOT_REQUIRED_ANCHORS = (
    "AstrBot/data/config/",
    "AstrBot/data/cmd_config.json",
    "AstrBot/data/plugins.json",
    "AstrBot/data/mcp_server.json",
    "AstrBot/data/skills.json",
)


class BackupError(RuntimeError):
    def __init__(self, message: str, code: int = 1):
        super().__init__(message)
        self.code = code


class VerificationCleanupError(BackupError):
    """A verified distinction from an ordinary invalid archive."""

    def __init__(self):
        super().__init__(
            "archive verification cleanup failed; sensitive quarantine preserved", 1
        )


@dataclass
class Result:
    code: int
    noop: bool = False
    archive: Optional[Path] = None
    message: str = ""
    retention_candidates: Optional[list[dict[str, object]]] = None
    publication_disposition: str = "never_published"
    archive_sha256: str | None = None
    # Manual snapshots are fully verified publications, but they must not
    # advance the scheduler's cycle-bound success pointer.
    counts_as_scheduled_success: bool = True

    def __post_init__(self):
        if self.publication_disposition not in PUBLICATION_DISPOSITIONS:
            raise ValueError("invalid publication disposition")
        if self.archive_sha256 is not None and re.fullmatch(r"[0-9a-f]{64}", self.archive_sha256) is None:
            raise ValueError("invalid archive digest")


@dataclass
class Item:
    disk: Path
    archive: str
    area: str
    size: int
    mtime_ns: int
    dev: int
    ino: int
    attrs: int
    sha256: str
    kind: str = "file"
    reparse: bool = False


@dataclass(frozen=True)
class FileToken:
    """A path-independent token for one filesystem object and its verified bytes."""
    dev: int
    ino: int
    mode: int
    size: int
    mtime_ns: int
    attrs: int
    nlink: int

    def same_object(self, other) -> bool:
        return isinstance(other, FileToken) and (self.dev, self.ino) == (other.dev, other.ino)

    def same_content_identity(self, other) -> bool:
        return self.same_object(other) and (
            stat.S_IFMT(self.mode), self.size, self.mtime_ns, self.attrs
        ) == (stat.S_IFMT(other.mode), other.size, other.mtime_ns, other.attrs)


@dataclass(frozen=True)
class RetentionPlanEntry:
    """One old archive proven by both authoritative state and archive bytes."""

    path: Path
    token: FileToken
    sha256: str


class StageLedger:
    """Exact identity inventory for objects created inside one run UUID directory."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.root_token = _path_token(self.root, directory=True)
        self.entries: dict[str, tuple[str, FileToken]] = {}

    def _relative(self, path: Path) -> str:
        try:
            relative = Path(path).relative_to(self.root).as_posix()
        except ValueError as exc:
            raise BackupError("staging ledger path escaped run root", 3) from exc
        if not relative or not safe_zip_name(relative):
            raise BackupError("invalid staging ledger path", 3)
        return relative

    def register(self, path: Path, *, kind: str) -> FileToken:
        token = _path_token(
            Path(path), regular=kind == "file", directory=kind == "directory",
            single_link=kind == "file",
        )
        return self.register_token(path, kind=kind, token=token)

    def register_token(self, path: Path, *, kind: str, token: FileToken) -> FileToken:
        if kind not in {"file", "directory"}:
            raise BackupError("invalid staging ledger kind", 3)
        relative = self._relative(Path(path))
        existing = self.entries.get(relative)
        unchanged = (
            existing is None
            or (
                existing[0] == kind
                and (
                    existing[1].same_object(token)
                    if kind == "directory"
                    else _same_verified_token(existing[1], token)
                )
            )
        )
        if not unchanged:
            raise BackupError("staging ledger identity changed", 3)
        self.entries[relative] = (kind, token)
        return token

    def refresh(self, path: Path, *, kind: str) -> FileToken:
        relative = self._relative(Path(path))
        prior = self.entries.get(relative)
        token = _path_token(
            Path(path), regular=kind == "file", directory=kind == "directory",
            single_link=kind == "file",
        )
        if prior is None or prior[0] != kind or not prior[1].same_object(token):
            raise BackupError("staging object replaced before ledger refresh", 3)
        self.entries[relative] = (kind, token)
        return token

    def replace_with_created(self, path: Path, created: FileToken) -> FileToken:
        relative = self._relative(Path(path))
        prior = self.entries.get(relative)
        current = _path_token(Path(path), regular=True, single_link=True)
        if prior is None or prior[0] != "file" or not current.same_object(created):
            raise BackupError("staging replacement did not preserve created identity", 3)
        self.entries[relative] = ("file", current)
        return current

    def forget_verified_removed(self, path: Path, removed: FileToken) -> None:
        relative = self._relative(Path(path))
        prior = self.entries.get(relative)
        if (_lexists(Path(path)) or prior is None or prior[0] != "file"
                or not _same_verified_token(prior[1], removed)):
            raise BackupError("removed staging object did not match ledger", 3)
        del self.entries[relative]

    def seal(self) -> None:
        inventory = _registered_stage_inventory(self.root)
        if set(inventory) != set(self.entries):
            raise BackupError("staging contains unregistered or missing objects", 3)
        current_root = _path_token(self.root, directory=True)
        if not current_root.same_object(self.root_token):
            raise BackupError("staging root identity changed before seal", 3)
        self.root_token = current_root
        for relative, (kind, token) in list(self.entries.items()):
            current_kind, current = inventory[relative]
            if current_kind != kind or not current.same_object(token):
                raise BackupError("staging identity changed before seal", 3)
            if kind == "file" and current.nlink != 1:
                raise BackupError("staging file gained a hard link", 3)
            self.entries[relative] = (kind, current)


def _token_from_stat(st) -> FileToken:
    return FileToken(
        st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns,
        getattr(st, "st_file_attributes", 0), getattr(st, "st_nlink", 0),
    )


def _path_token(path: Path, *, regular=False, directory=False, single_link=False) -> FileToken:
    try:
        st = path.lstat()
    except OSError as exc:
        raise BackupError("filesystem object is missing or unreadable", 3) from exc
    token = _token_from_stat(st)
    if is_reparse(path, st):
        raise BackupError("reparse point refused", 3)
    if regular and not stat.S_ISREG(st.st_mode):
        raise BackupError("ordinary file required", 3)
    if directory and not stat.S_ISDIR(st.st_mode):
        raise BackupError("ordinary directory required", 3)
    if single_link and st.st_nlink != 1:
        raise BackupError("single-link file required", 3)
    return token


def _path_token_if_present(path: Path, **kwargs):
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    return _path_token(path, **kwargs)


def _same_verified_token(current: FileToken, expected: FileToken) -> bool:
    return current.same_content_identity(expected) and current.nlink == expected.nlink


@contextlib.contextmanager
def _stable_source_reader(path: Path, opener, change_code=1):
    before = _path_token(path, regular=True)
    if before.nlink > 1:
        raise BackupError("source ordinary file has multiple hard links", change_code)
    try:
        handle = opener(path)
    except OSError as exc:
        raise BackupError("source file cannot be opened read-only", change_code) from exc
    try:
        try:
            opened = _token_from_stat(os.fstat(handle.fileno()))
        except (AttributeError, OSError, ValueError) as exc:
            raise BackupError("source opener did not provide a verifiable handle", 3) from exc
        if not opened.same_object(before):
            raise BackupError("source handle identity does not match requested path", 3)
        if not opened.same_content_identity(before):
            raise BackupError("source changed while being opened", change_code)
        yield handle
    finally:
        with contextlib.suppress(Exception):
            handle.close()
    after = _path_token(path, regular=True)
    if not after.same_object(before):
        raise BackupError("source identity changed while open", 3)
    if not _same_verified_token(after, before):
        raise BackupError("source changed while being read", change_code)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--astrbot-root")
    parser.add_argument("--napcat-root", help="optional NapCat installation root")
    parser.add_argument("--destination")
    parser.add_argument("--keep", type=int, default=5)
    parser.add_argument("--week-start", type=int, choices=range(7), default=6,
                        help="0=Monday ... 6=Sunday")
    parser.add_argument("--schedule-time", default="12:00", metavar="HH:MM",
                        help="scheduled trigger identity (24-hour local time)")
    parser.add_argument("--scheduled", action="store_true")
    parser.add_argument("--scheduled-probe", action="store_true",
                        help="read-only scheduler decision; internal launcher use only")
    parser.add_argument("--artifact-digest", metavar="SHA256")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--manual", action="store_true",
                        help="publish a verified manual snapshot without advancing the scheduled cycle")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--verify", metavar="ARCHIVE")
    ns = parser.parse_args(argv)
    if not 1 <= ns.keep <= 30:
        parser.error("--keep must be between 1 and 30")
    if (not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", ns.schedule_time)
            or ns.schedule_time != ns.schedule_time.strip()):
        parser.error("--schedule-time must be HH:MM in 24-hour local time")
    if ns.preflight and (ns.scheduled or ns.scheduled_probe or ns.force or ns.verify):
        parser.error("--preflight conflicts with scheduled, scheduled-probe, force, and verify")
    if ns.manual and (ns.scheduled or ns.scheduled_probe or ns.preflight or ns.verify):
        parser.error("--manual conflicts with scheduled, scheduled-probe, preflight, and verify")
    if ns.verify and (ns.scheduled or ns.scheduled_probe or ns.force):
        parser.error("--verify conflicts with scheduled, scheduled-probe, and force")
    if ns.scheduled_probe and (not ns.scheduled or ns.force):
        parser.error("--scheduled-probe requires --scheduled and conflicts with --force")
    if (ns.scheduled
            and (not isinstance(ns.artifact_digest, str)
                 or re.fullmatch(r"[0-9a-f]{64}", ns.artifact_digest) is None
                 or ns.artifact_digest == "0" * 64)):
        parser.error("--scheduled requires a non-zero --artifact-digest")
    if ns.verify:
        ns.verify = checked_absolute(ns.verify)
        assert_local_path(ns.verify)
        return ns
    if not ns.astrbot_root or not ns.destination:
        parser.error("--astrbot-root and --destination are required")
    if ns.scheduled_probe:
        # Do not touch AstrBot/NapCat paths here.  The hidden launcher is only
        # deciding from target state; normal run later performs all source
        # resolution/reparse/local-volume gates again.
        ns.astrbot_root = _lexical_windows_absolute(ns.astrbot_root)
        ns.napcat_root = _lexical_windows_absolute(ns.napcat_root) if ns.napcat_root else None
        ns.week_start_index = ns.week_start
        ns.destination = checked_absolute(ns.destination)
        assert_local_path(ns.destination)
        assert_safe_output_path(ns.destination)
        source_keys = _probe_fingerprints(ns.astrbot_root, ns.napcat_root)
        ns.probe_source_fingerprints = source_keys
        ns.probe_config_fingerprint = hashlib.sha256(json.dumps({
            "astrbot_root": _lexical_key(ns.astrbot_root),
            "napcat_root": _lexical_key(ns.napcat_root) if ns.napcat_root is not None else "",
            "destination": _key(ns.destination), "keep": ns.keep,
            "week_start": ns.week_start, "schedule_time": ns.schedule_time,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        if (not isinstance(ns.artifact_digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", ns.artifact_digest) is None
                or ns.artifact_digest == "0" * 64):
            parser.error("--scheduled-probe requires --artifact-digest")
        return ns
    ns.astrbot_root = resolve_safe_source(ns.astrbot_root)
    ns.napcat_root = resolve_safe_source(ns.napcat_root) if ns.napcat_root else None
    ns.week_start_index = ns.week_start
    assert_safe_output_path(Path(ns.destination))
    ns.destination = checked_absolute(ns.destination)
    assert_local_path(ns.astrbot_root)
    if ns.napcat_root is not None:
        assert_local_path(ns.napcat_root)
    assert_local_path(ns.destination)
    reject_overlap(ns.astrbot_root, ns.napcat_root, ns.destination)
    if (ns.artifact_digest is not None
            and (re.fullmatch(r"[0-9a-f]{64}", ns.artifact_digest) is None
                 or ns.artifact_digest == "0" * 64)):
        parser.error("--artifact-digest must be SHA-256")
    return ns


def checked_absolute(value) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise BackupError("all paths must be absolute", 3)
    return path.resolve(strict=False)


def _lexical_windows_absolute(value) -> Path:
    """Pure lexical canonicalization for the target-only scheduled probe."""
    raw = str(value)
    if raw.startswith(("\\\\", "//")) or not ntpath.isabs(raw):
        raise BackupError("all paths must be local absolute paths", 3)
    return Path(ntpath.normpath(raw))


def _lexical_key(path: Path) -> str:
    return ntpath.normcase(ntpath.normpath(str(path))).casefold()


def _probe_fingerprints(astrbot: Path, napcat: Optional[Path]) -> dict[str, str]:
    return {
        "astrbot_root": hashlib.sha256(_lexical_key(astrbot).encode("utf-8")).hexdigest(),
        "napcat_root": (hashlib.sha256(_lexical_key(napcat).encode("utf-8")).hexdigest()
                        if napcat is not None else "0" * 64),
    }


def windows_drive_type(path: Path) -> int:
    """Return Win32 drive type; 4 is a mapped/network drive."""
    if os.name != "nt":
        return 3
    drive, _ = ntpath.splitdrive(str(path))
    root = drive + "\\" if drive else str(path.anchor)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
    kernel.GetDriveTypeW.restype = ctypes.c_uint32
    return int(kernel.GetDriveTypeW(root))


def assert_local_path(path: Path, drive_type_probe=None) -> None:
    raw = str(path)
    drive, _ = ntpath.splitdrive(raw)
    if raw.startswith(("\\\\", "//")) or drive.startswith(("\\\\", "//")):
        raise BackupError("UNC paths are not supported", 3)
    drive_type = (drive_type_probe or windows_drive_type)(path)
    if drive_type == 4:
        raise BackupError("mapped network drives are not supported", 3)
    if os.name == "nt" and drive_type in {0, 1}:
        raise BackupError("local drive type cannot be verified", 3)


def _lexists(path: Path) -> bool:
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def assert_safe_output_path(value, reparse_probe=None):
    raw = Path(value)
    probe = reparse_probe or is_reparse
    current = raw
    while True:
        if (reparse_probe is not None or _lexists(current)) and probe(current):
            raise BackupError("output path contains a reparse point", 3)
        if current.parent == current:
            return raw
        current = current.parent

def assert_no_reparse_chain(value: Path):
    current = value
    while True:
        if _lexists(current) and is_reparse(current):
            raise BackupError("source path contains a reparse point", 3)
        if current.parent == current: return
        current = current.parent


def resolve_safe_source(value, reparse_probe=is_reparse if "is_reparse" in globals() else None) -> Path:
    """Reject a source root whose lexical chain contains a link/reparse point before resolving."""
    raw = Path(value)
    if not raw.is_absolute():
        raise BackupError("all paths must be absolute", 3)
    probe = reparse_probe or is_reparse
    chain = []
    current = raw
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    for part in reversed(chain):
        if _lexists(part) and probe(part):
            raise BackupError("source root parent is a reparse point", 3)
    return raw.resolve(strict=False)


def _key(path: Path) -> str:
    return os.path.normpath(str(path.resolve(strict=False))).casefold()


def configuration_fingerprint(astrbot_root: Path, napcat_root: Optional[Path],
                              destination: Path, keep: int, week_start: int,
                              schedule_time: str = "12:00") -> str:
    public_configuration = {
        "astrbot_root": _key(astrbot_root),
        "napcat_root": _key(napcat_root) if napcat_root is not None else "",
        "destination": _key(destination),
        "keep": keep,
        "week_start": week_start,
        "schedule_time": schedule_time,
    }
    encoded = json.dumps(public_configuration, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def source_fingerprints(astrbot_root: Path, napcat_root: Optional[Path]) -> dict[str, str]:
    return {
        "astrbot_root": hashlib.sha256(_key(astrbot_root).encode("utf-8")).hexdigest(),
        "napcat_root": (hashlib.sha256(_key(napcat_root).encode("utf-8")).hexdigest()
                        if napcat_root is not None else "0" * 64),
    }


def _inside(a: Path, b: Path) -> bool:
    aa, bb = _key(a), _key(b)
    return aa == bb or aa.startswith(bb + os.sep.casefold())


def reject_overlap(astr: Path, nap: Optional[Path], destination: Path) -> None:
    nap_overlap = nap is not None and (_inside(destination, nap) or _inside(nap, destination))
    if _inside(destination, astr) or _inside(astr, destination) or nap_overlap:
        raise BackupError("destination must not overlap either source", 3)


def windows_shared_read(path: Path):
    """Open source files with read/write/delete sharing on Windows, never write them."""
    if os.name != "nt":
        return open(path, "rb")
    import msvcrt
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                       ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    create.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_bool
    kernel.GetFileInformationByHandleEx.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    kernel.GetFileInformationByHandleEx.restype = ctypes.c_bool
    class FILE_ATTRIBUTE_TAG_INFO(ctypes.Structure):
        _fields_ = [("FileAttributes", ctypes.c_uint32), ("ReparseTag", ctypes.c_uint32)]
    handle = create(str(path), 0x80000000, 0x00000001 | 0x00000002 | 0x00000004, None,
                    3, 0x00000080 | 0x00200000, None)  # NORMAL | OPEN_REPARSE_POINT
    if handle == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "CreateFileW shared read failed", str(path))
    tag_info = FILE_ATTRIBUTE_TAG_INFO()
    if not kernel.GetFileInformationByHandleEx(handle, 9, ctypes.byref(tag_info), ctypes.sizeof(tag_info)):
        error = ctypes.get_last_error()
        kernel.CloseHandle(handle)
        raise OSError(error, "GetFileInformationByHandleEx failed", str(path))
    if tag_info.FileAttributes & (0x00000400 | 0x00000010):
        kernel.CloseHandle(handle)
        raise OSError("source handle is a reparse point or directory")
    fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    return os.fdopen(fd, "rb", closefd=True)


def sha256_file(path: Path, opener: Callable[[Path], object] = windows_shared_read, change_code=1) -> str:
    digest = hashlib.sha256()
    with _stable_source_reader(path, opener, change_code) as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def safe_component(name: str) -> bool:
    return bool(name) and name not in {".", ".."} and ":" not in name and "\\" not in name and "/" not in name


def is_reparse(path: Path, st=None) -> bool:
    st = st or path.lstat()
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & 0x400)


def alternate_data_streams(path: Path) -> list[str]:
    """Return named NTFS streams without opening their contents."""
    if os.name != "nt":
        return []
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)

    class WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [("StreamSize", ctypes.c_int64), ("cStreamName", ctypes.c_wchar * 296)]

    first = kernel.FindFirstStreamW
    first.argtypes = [ctypes.c_wchar_p, ctypes.c_int, ctypes.POINTER(WIN32_FIND_STREAM_DATA), ctypes.c_uint32]
    first.restype = ctypes.c_void_p
    next_stream = kernel.FindNextStreamW
    next_stream.argtypes = [ctypes.c_void_p, ctypes.POINTER(WIN32_FIND_STREAM_DATA)]
    next_stream.restype = ctypes.c_bool
    kernel.FindClose.argtypes = [ctypes.c_void_p]
    invalid = ctypes.c_void_p(-1).value
    data = WIN32_FIND_STREAM_DATA()
    handle = first(str(path), 0, ctypes.byref(data), 0)
    if handle == invalid:
        error = ctypes.get_last_error()
        if error in {2, 38}:  # no file / end of stream enumeration
            return []
        raise BackupError("alternate data streams cannot be enumerated", 1)
    names = []
    try:
        while True:
            name = data.cStreamName
            if name and name != "::$DATA":
                names.append(name)
            if not next_stream(handle, ctypes.byref(data)):
                error = ctypes.get_last_error()
                if error != 38:
                    raise BackupError("alternate data streams changed or became unreadable", 1)
                break
    finally:
        kernel.FindClose(handle)
    return names


def assert_safe_source_streams(path: Path) -> None:
    streams = alternate_data_streams(path)
    unsupported = [name for name in streams if name.casefold() != ":zone.identifier:$data"]
    if unsupported:
        raise BackupError("source file contains an unsupported alternate data stream", 1)


def walk_files(root: Path, archive_root: str, opener=windows_shared_read):
    _path_token(root, directory=True)
    items = []
    def visit(directory: Path, rel_parts: tuple[str, ...]):
        directory_before = _path_token(directory, directory=True)
        assert_safe_source_streams(directory)
        directory_archive = "/".join((archive_root, *rel_parts)) + "/"
        directory_area = rel_parts[0].casefold() if rel_parts else ""
        items.append(Item(directory, directory_archive, directory_area, 0, directory_before.mtime_ns,
                          directory_before.dev, directory_before.ino, directory_before.attrs, "", "directory"))
        with os.scandir(directory) as listing:
            for entry in listing:
                if not safe_component(entry.name):
                    if entry.name.endswith(":Zone.Identifier"):
                        continue
                    raise BackupError("unsafe source/archive name", 3)
                item_path = Path(entry.path)
                est = entry.stat(follow_symlinks=False)
                if is_reparse(item_path, est):
                    raise BackupError("source reparse point refused", 3)
                parts = rel_parts + (entry.name,)
                if stat.S_ISDIR(est.st_mode):
                    visit(item_path, parts)
                elif stat.S_ISREG(est.st_mode):
                    before = _path_token(item_path, regular=True)
                    assert_safe_source_streams(item_path)
                    entry_token = _token_from_stat(est)
                    # Some Windows Python builds return zero identity/link fields from
                    # DirEntry.stat(); compare them only when the API supplied identity.
                    if entry_token.dev and entry_token.ino and not before.same_content_identity(entry_token):
                        raise BackupError("source identity changed during traversal", 3)
                    area = parts[0].casefold() if parts else ""
                    code = classify_drift([area])
                    digest = sha256_file(item_path, opener, code)
                    archive = "/".join((archive_root, *parts))
                    items.append(Item(item_path, archive, area, before.size, before.mtime_ns,
                                      before.dev, before.ino, before.attrs, digest))
                else:
                    raise BackupError("unsupported source entry", 3)
        directory_after = _path_token(directory, directory=True)
        assert_safe_source_streams(directory)
        if not _same_verified_token(directory_after, directory_before):
            code = classify_drift([rel_parts[0] if rel_parts else ""])
            raise BackupError("source directory changed during traversal", code)
    visit(root, ())
    return sorted(items, key=lambda x: x.archive.casefold())


def _source_json(path: Path, opener):
    try:
        with _stable_source_reader(path, opener, 1) as f:
            value = json.loads(f.read().decode("utf-8"))
        if not isinstance(value, dict):
            raise TypeError("JSON object required")
        return value
    except BackupError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, AttributeError) as exc:
        raise BackupError("required NapCat JSON is unreadable", 1) from exc


def _source_json_any(path: Path, opener):
    try:
        with _stable_source_reader(path, opener, 1) as handle:
            raw = handle.read(MAX_METADATA_JSON_BYTES + 1)
        if len(raw) > MAX_METADATA_JSON_BYTES:
            raise ValueError("JSON exceeds safe metadata limit")
        return json.loads(raw.decode("utf-8"))
    except BackupError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, AttributeError) as exc:
        raise BackupError("required NapCat JSON is unreadable", 1) from exc


def _safe_metadata_string(value) -> bool:
    return (isinstance(value, str) and 0 < len(value) <= 4096
            and value == value.strip()
            and all(ord(character) >= 32 and ord(character) != 127 for character in value))


def _metadata_build(value):
    if type(value) is int and value >= 0:
        return str(value)
    if isinstance(value, str) and re.fullmatch(r"\d+", value):
        return value
    return None


def valid_napcat_metadata(suffix: str, data, current: str) -> bool:
    if not isinstance(data, dict):
        return False
    current_match = re.fullmatch(r"(\d+\.\d+\.\d+)-(\d+)", current)
    if current_match is None:
        return False
    if suffix == "version.json":
        return _safe_metadata_string(data.get("QQNT.dll"))
    if suffix == "resources/app/application.json":
        return (bool(data) and _safe_metadata_string(data.get("package.json"))
                and all(_safe_metadata_string(value) for value in data.values()))
    if suffix == "resources/app/package.json":
        return (data.get("name") == "qq-chat" and data.get("version") == current
                and _metadata_build(data.get("buildVersion")) == current_match.group(2))
    if suffix == "resources/app/napcat/package.json":
        return (data.get("name") == "napcat" and isinstance(data.get("version"), str)
                and re.fullmatch(
                    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
                    r"(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z.-]+)?",
                    data["version"],
                ) is not None)
    if suffix == "resources/app/napcat/qqnt.json":
        compatible = data.get("version")
        match = re.fullmatch(r"(\d+\.\d+\.\d+)-(\d+)", compatible) if isinstance(compatible, str) else None
        return (data.get("name") == "qq-chat" and match is not None and compatible != current
                and _metadata_build(data.get("buildVersion")) == match.group(2))
    return False


def valid_napcat_version_relation(base, current, compatible) -> bool:
    """Accept the two observed safe Shell layouts, reject a third version.

    Some OneKey Shell releases record ``baseVersion`` as the active/current
    QQ build, while older layouts record the compatibility build carried by
    ``napcat/qqnt.json``.  The active package and qqnt metadata are validated
    independently; baseVersion must bind to one of those two proven values.
    """
    return (
        valid_registered_napcat_version(base)
        and valid_registered_napcat_version(current)
        and valid_registered_napcat_version(compatible)
        and compatible != current
        and base in {current, compatible}
    )


def napcat_items(root: Path, opener):
    if re.fullmatch(r"NapCat\.[A-Za-z0-9._-]+\.Shell", root.name):
        shells = [root]
    else:
        _path_token(root, directory=True)
        shells = []
        with os.scandir(root) as listing:
            for entry in listing:
                if re.fullmatch(r"NapCat\.[A-Za-z0-9._-]+\.Shell", entry.name):
                    candidate = Path(entry.path)
                    if entry.is_dir(follow_symlinks=False) and not is_reparse(candidate):
                        shells.append(candidate)
    if len(shells) != 1:
        raise BackupError("NapCat root must contain exactly one safe Shell directory", 1)
    shell = shells[0]
    config = shell / "versions" / "config.json"
    for path in (root, shell, shell / "versions", config): assert_no_reparse_chain(path)
    data = _source_json(config, opener)
    base, current = data.get("baseVersion"), data.get("curVersion")
    if (not isinstance(base, str) or not re.fullmatch(r"[0-9.]+-[0-9]+", base)
            or not isinstance(current, str) or not re.fullmatch(r"[0-9.]+-[0-9]+", current)
            or not safe_component(current)):
        raise BackupError("NapCat version metadata is invalid", 1)
    version = current
    active = shell / "versions" / current
    for path in (active, active / "resources", active / "resources" / "app", active / "resources" / "app" / "napcat"):
        assert_no_reparse_chain(path)
    if is_reparse(active) or not active.is_dir():
        raise BackupError("unsafe/missing NapCat version directory", 3)
    wanted = [shell / x for x in ("napcat.bat", "napcat.quick.bat", "napcat.kill.qq.bat", "ReadMe.txt")]
    wanted += [config] + [active / suffix for suffix in NAPCAT_VERSION_JSON_SUFFIXES]
    for required in wanted:
        if not required.is_file() or is_reparse(required):
            raise BackupError("missing or unsafe required NapCat file", 1)
    parsed_metadata = {}
    for suffix, required in zip(NAPCAT_VERSION_JSON_SUFFIXES, wanted[5:]):
        meta = _source_json(required, opener)
        if not valid_napcat_metadata(suffix, meta, version):
            raise BackupError("invalid NapCat metadata: " + suffix, 1)
        parsed_metadata[suffix] = meta
    if not valid_napcat_version_relation(
            base, current,
            parsed_metadata["resources/app/napcat/qqnt.json"].get("version")):
        raise BackupError("NapCat baseVersion contradicts qqnt compatibility metadata", 1)
    config_dir = active / "resources" / "app" / "napcat" / "config"
    additional = walk_files(config_dir, "NapCat/versions/" + current + "/resources/app/napcat/config", opener)
    for item in additional:
        if item.kind == "file" and item.disk.suffix.casefold() == ".json":
            _source_json_any(item.disk, opener)
    items = []
    def add_file(file: Path, archive: str):
        assert_safe_source_streams(file)
        digest = sha256_file(file, opener)
        st = file.stat(follow_symlinks=False)
        items.append(Item(file, archive, "napcat", st.st_size, st.st_mtime_ns,
                          st.st_dev, st.st_ino, getattr(st, "st_file_attributes", 0), digest))
    for file in wanted[:4]:
        add_file(file, "NapCat/" + file.name)
    add_file(config, "NapCat/versions/config.json")
    for file in wanted[5:]:
        rel = file.relative_to(shell / "versions")
        add_file(file, "NapCat/versions/" + rel.as_posix())
    items.extend(additional)
    archives = [x.archive.casefold() for x in items]
    if len(archives) != len(set(archives)):
        raise BackupError("duplicate NapCat archive name", 3)
    items = sorted(items, key=lambda x: x.archive.casefold())
    whitelist = [item.archive for item in items]
    return items, current, whitelist


def compatible_napcat_whitelist_transition(previous, current, version: str) -> bool:
    """Allow only additive JSON config files within the same active version."""
    if previous == current:
        return True
    if not isinstance(previous, list) or not isinstance(current, list) or not isinstance(version, str):
        return False
    old = {name.casefold() for name in previous}
    new = {name.casefold() for name in current}
    if not old or not old <= new:
        return False
    added = new - old
    if not added:
        return False
    prefix = f"napcat/versions/{version.casefold()}/resources/app/napcat/config/"
    return all(name.startswith(prefix) and name.endswith(".json") for name in added)


def database_layout(items, opener=windows_shared_read):
    mains = []
    for item in items:
        if item.kind != "file":
            continue
        lowered = item.archive.casefold()
        magic = False
        try:
            with _stable_source_reader(item.disk, opener, classify_drift([item.area])) as f:
                magic = f.read(16) == b"SQLite format 3\x00"
        except BackupError:
            raise
        except OSError as exc:
            raise BackupError("database candidate cannot be read", 1) from exc
        if lowered.endswith(DB_SUFFIXES) or magic:
            mains.append(item.archive)
    sidecars = [x.archive for x in items if x.kind == "file" and x.archive.casefold().endswith(SIDECARS)]
    main_keys = {name.casefold() for name in mains}
    for item in items:
        if item.kind != "file":
            continue
        lowered = item.archive.casefold()
        if lowered in main_keys or lowered.endswith(SIDECARS):
            continue
        if (re.search(r"-mj(?:\s|[0-9a-f])", lowered)
                or any(lowered.startswith(main + "-") for main in main_keys)):
            raise BackupError("unknown SQLite sidecar or super-journal candidate", 1)
    return {"mains": sorted(mains), "sidecars": sorted(sidecars)}


# A database layout is part of the trust boundary, but some applications keep
# a bounded rolling set of SQLite snapshots.  The transition checker is
# generic: it learns no machine-specific directory or filename.  It only
# admits a balanced rename within the same directory and filename template
# when a single date/time token is replaced.  Missing/added static databases,
# sidecar changes, and arbitrary renames remain fail-closed.
_ROTATION_TOKEN = re.compile(
    r"(?<!\d)(?:19|20|21)\d{2}(?:[-_.]?\d{2}){1,2}"
    r"(?:[-_.T]?\d{2}(?:[-_:]?\d{2}){0,2})?(?!\d)",
    re.IGNORECASE,
)


def _rotation_signature(name: str):
    if not isinstance(name, str) or "/" not in name:
        return None
    parent, _, leaf = name.rpartition("/")
    matches = list(_ROTATION_TOKEN.finditer(leaf))
    if len(matches) != 1:
        return None
    match = matches[0]
    token = match.group(0)
    if len(re.sub(r"\D", "", token)) < 8:
        return None
    template = leaf[:match.start()] + "{rotation}" + leaf[match.end():]
    return parent.casefold(), template.casefold()


def compatible_database_layout_transition(previous, current) -> bool:
    """Return whether *current* is a safe rolling SQLite-name transition.

    This does not inspect or adopt files.  The normal inventory, identity,
    post-copy stability, SQLite integrity, and archive verification gates still
    run after this compatibility check.
    """
    if previous == current:
        return True
    if not isinstance(previous, dict) or not isinstance(current, dict):
        return False
    if set(previous) != {"mains", "sidecars"} or set(current) != {"mains", "sidecars"}:
        return False
    old_sidecars = {name.casefold() for name in previous["sidecars"]}
    new_sidecars = {name.casefold() for name in current["sidecars"]}
    if old_sidecars != new_sidecars:
        return False
    old_mains = {name.casefold() for name in previous["mains"]}
    new_mains = {name.casefold() for name in current["mains"]}
    removed = old_mains - new_mains
    added = new_mains - old_mains
    if not removed or not added:
        return False
    groups = {}
    for kind, names in (("removed", removed), ("added", added)):
        for name in names:
            signature = _rotation_signature(name)
            if signature is None:
                return False
            groups.setdefault(signature, {"removed": set(), "added": set()})[kind].add(name)
    return bool(groups) and all(
        bucket["removed"] and bucket["added"]
        and len(bucket["removed"]) == len(bucket["added"])
        for bucket in groups.values()
    )


def required_free_space(source_bytes: int, database_family_bytes: int, napcat_bytes: int) -> int:
    return 2 * source_bytes + 2 * database_family_bytes + napcat_bytes + 512 * 1024 * 1024


def archive_budget(source_bytes: int, source_entries: int) -> dict[str, int]:
    """Return a bounded expansion budget derived from this run's source inventory."""
    if type(source_bytes) is not int or source_bytes < 0 or type(source_entries) is not int or source_entries < 0:
        raise BackupError("invalid archive budget input", 3)
    allowance = 64 * 1024 * 1024
    total = min(HARD_MAX_ARCHIVE_TOTAL, max(allowance, source_bytes * 3 + allowance))
    return {
        "max_archive_entry": min(HARD_MAX_ARCHIVE_ENTRY, total),
        "max_archive_entries": min(HARD_MAX_ARCHIVE_ENTRIES, max(16, source_entries + 2)),
        "max_archive_total": total,
        "max_compression_ratio": HARD_MAX_COMPRESSION_RATIO,
    }


def _zip_info_within_budget(info, limits: dict[str, int]) -> bool:
    try:
        if info.file_size < 0 or info.compress_size < 0:
            return False
        if info.file_size > limits["max_archive_entry"]:
            return False
        if info.file_size and info.file_size > max(1, info.compress_size) * limits["max_compression_ratio"]:
            return False
        return True
    except (KeyError, TypeError, AttributeError, OverflowError):
        return False


def available_space_without_creating(path: Path) -> int:
    probe = path
    while not _lexists(probe):
        if probe.parent == probe:
            raise BackupError("no existing local ancestor for destination", 3)
        probe = probe.parent
    _path_token(probe, directory=True)
    return shutil.disk_usage(probe).free


def ensure_unique_archive_names(names):
    folded = [name.casefold() for name in names]
    if len(folded) != len(set(folded)):
        raise BackupError("case-insensitive archive-name collision", 3)


def classify_drift(relative_names):
    return 2 if relative_names and all(name.replace("\\", "/").split("/")[0].casefold() in NONCRITICAL for name in relative_names) else 1


def _state_path(destination: Path) -> Path:
    return destination / "state.json"


@contextlib.contextmanager
def _stable_regular_reader(path: Path, expected: Optional[FileToken] = None, *, single_link=True):
    before = _path_token(path, regular=True, single_link=single_link)
    if expected is not None and not _same_verified_token(before, expected):
        raise BackupError("file identity changed before read", 3)
    try:
        handle = open(path, "rb")
    except OSError as exc:
        raise BackupError("file cannot be opened", 3) from exc
    try:
        opened = _token_from_stat(os.fstat(handle.fileno()))
        if not opened.same_content_identity(before):
            raise BackupError("opened handle identity does not match path", 3)
        yield handle
    finally:
        handle.close()
    after = _path_token(path, regular=True, single_link=single_link)
    if not _same_verified_token(after, before):
        raise BackupError("file identity changed during read", 3)


def _read_stable_regular(path: Path):
    with _stable_regular_reader(path) as handle:
        content = handle.read()
    return content, _path_token(path, regular=True, single_link=True), hashlib.sha256(content).hexdigest()


@contextlib.contextmanager
def _exclusive_output(path: Path):
    """Create one new ordinary output without following an existing leaf."""
    assert_safe_output_path(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        code = 1 if exc.errno == errno.ENOSPC or getattr(exc, "winerror", None) == 112 else 3
        raise BackupError("exclusive output creation failed", code) from exc
    handle = os.fdopen(fd, "wb", closefd=True)
    owned = _token_from_stat(os.fstat(handle.fileno()))
    try:
        leaf = _path_token(path, regular=True, single_link=True)
        if not leaf.same_object(owned):
            raise BackupError("exclusive output path changed", 3)
        yield handle, owned
        handle.flush()
        os.fsync(handle.fileno())
    finally:
        handle.close()


def _safe_unlink_owned(path: Optional[Path], owned: Optional[FileToken]) -> bool:
    if path is None or owned is None:
        return False
    try:
        current = _path_token(path, regular=True)
        if not current.same_object(owned):
            return False
        path.unlink()
        return True
    except (OSError, BackupError):
        return False


def load_state(destination: Path):
    if _lexists(destination):
        _path_token(destination, directory=True)
    state_file = _state_path(destination)
    journal_dir = destination / "state-journal"
    candidate_paths = []
    if _lexists(state_file):
        candidate_paths.append(state_file)
    if _lexists(journal_dir):
        _path_token(journal_dir, directory=True)
        journal_paths = []
        for entry in journal_dir.iterdir():
            if (not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json", entry.name)
                    or is_reparse(entry)):
                raise BackupError("state journal contains a foreign entry", 3)
            _path_token(entry, regular=True, single_link=True)
            journal_paths.append(entry)
        if journal_paths:
            # A present compatibility cache remains part of the trust boundary:
            # never hide a corrupt/replaced state.json behind an older valid
            # journal.  When it is valid, the newest timestamped candidate still
            # lets the journal recover a cache refresh failure.
            candidate_paths.extend(journal_paths)
    if not candidate_paths:
        if _lexists(destination) and any(destination.iterdir()):
            raise BackupError("initial destination must be completely empty", 3)
        return None
    try:
        candidates = []
        for candidate_path in candidate_paths:
            token = _path_token(candidate_path, regular=True, single_link=True)
            if token.size > MAX_STATE_BYTES:
                raise ValueError("state candidate too large")
            raw, _, _ = _read_stable_regular(candidate_path)
            candidate = json.loads(raw.decode("utf-8"))
            if not isinstance(candidate, dict):
                raise TypeError("state object required")
            attempt = dt.datetime.fromisoformat(candidate.get("last_attempt_time_utc", ""))
            if attempt.tzinfo is None:
                raise ValueError("state attempt time")
            revision = candidate.get("state_revision")
            if type(revision) is not int or revision < 0:
                raise ValueError("state revision")
            candidates.append((
                revision,
                attempt.astimezone(dt.timezone.utc),
                candidate_path.parent == journal_dir,
                candidate_path.name,
                hashlib.sha256(raw).hexdigest(),
                candidate,
            ))
        by_revision = {}
        journal_bindings = {}
        cache_bindings = {}
        for revision, _attempt, is_journal, _name, digest, candidate in candidates:
            existing = by_revision.get(revision)
            if existing is not None and existing[0] != digest:
                raise ValueError("conflicting state revision")
            by_revision[revision] = (digest, candidate)
            bindings = journal_bindings if is_journal else cache_bindings
            existing_binding = bindings.get(revision)
            if existing_binding is not None and existing_binding != digest:
                raise ValueError("conflicting state revision")
            bindings[revision] = digest
        if journal_bindings:
            newest_journal_revision = max(journal_bindings)
            for revision, digest in cache_bindings.items():
                if revision > newest_journal_revision:
                    raise ValueError("state cache revision exceeds journal")
                if revision == newest_journal_revision and journal_bindings[revision] != digest:
                    raise ValueError("state cache is not journal-bound")
        # Revisions are the authority order.  The cache is valid only when it
        # is byte-identical to a journal at the same revision; otherwise the
        # disagreement is an unsafe state rather than an ordering tie.
        _digest, state = by_revision[max(by_revision)]
        required = {"schema", "schema_version", "managed_by", "state_namespace",
                    "owner_uuid", "source_fingerprint", "state_revision",
                    "config_fingerprint", "artifact_digest", "source_fingerprints", "database_layout", "napcat_enabled",
                    "napcat_version", "napcat_whitelist", "week_start", "schedule_time",
                    "timezone", "last_cycle", "last_success_cycle", "last_success_archive", "last_success_archive_sha256",
                    "last_successful_cycle", "last_successful_archive", "last_successful_archive_sha256", "last_result",
                    "last_attempt_time_utc", "last_attempt_time_local"}
        failure_optional = {"last_failure_code", "last_failure_phase"}
        optional = failure_optional | {"retention_candidates"}
        initialized_required = {
            "schema", "schema_version", "managed_by", "state_namespace", "owner_uuid", "state_revision",
            "source_fingerprint", "config_fingerprint", "artifact_digest", "source_fingerprints", "week_start",
            "schedule_time", "last_result", "last_attempt_time_utc", "last_attempt_time_local",
        }
        initialized = state.get("last_result") == "INITIALIZED"
        if ((initialized and set(state) != initialized_required)
                or (not initialized and (not required <= set(state) or not set(state) <= required | optional))
                or state.get("schema") != SCHEMA or state.get("schema_version") != SCHEMA
                or state.get("managed_by") != GENERATOR
                or state.get("state_namespace") != "community-v1"
                or type(state.get("state_revision")) is not int or state["state_revision"] < 0):
            raise ValueError("schema")
        owner = state["owner_uuid"]
        if not isinstance(owner, str) or str(uuid.UUID(owner)) != owner or "/" in owner or "\\" in owner:
            raise ValueError("owner")
        allowed_top = {"state.json", "state-journal", "managed", "diagnostics", "logs", "staging"}
        top_entries = list(destination.iterdir())
        if any(entry.name not in allowed_top or is_reparse(entry) for entry in top_entries):
            raise ValueError("foreign destination artifact")
        for directory_name in ("managed", "diagnostics", "logs", "staging", "state-journal"):
            candidate = destination / directory_name
            if _lexists(candidate):
                _path_token(candidate, directory=True)
        managed = destination / "managed"
        if not _lexists(managed):
            raise ValueError("managed directory missing")
        managed_entries = list(managed.iterdir())
        if (len(managed_entries) != 1 or managed_entries[0].name != owner
                or is_reparse(managed_entries[0])):
            raise ValueError("foreign managed owner")
        _path_token(managed_entries[0], directory=True)
        fp = state["source_fingerprints"]
        if not isinstance(fp, dict) or set(fp) != {"astrbot_root", "napcat_root"} or not all(isinstance(x, str) and re.fullmatch(r"[0-9a-f]{64}", x) for x in fp.values()): raise ValueError("fingerprints")
        if (state["source_fingerprint"] != fp["astrbot_root"]
                or not isinstance(state["config_fingerprint"], str)
                or re.fullmatch(r"[0-9a-f]{64}", state["config_fingerprint"]) is None
                or not isinstance(state["artifact_digest"], str)
                or re.fullmatch(r"[0-9a-f]{64}", state["artifact_digest"]) is None):
            raise ValueError("compatibility aliases")
        if initialized:
            attempt_utc = dt.datetime.fromisoformat(state["last_attempt_time_utc"])
            attempt_local = dt.datetime.fromisoformat(state["last_attempt_time_local"])
            if (state["week_start"] not in WEEKDAYS
                    or re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", state["schedule_time"]) is None
                    or attempt_utc.tzinfo is None or attempt_local.tzinfo is None
                    or attempt_utc.utcoffset() != dt.timedelta(0)):
                raise ValueError("initialized state")
            return state
        if (state["last_success_cycle"] != state["last_successful_cycle"]
                or state["last_success_archive"] != state["last_successful_archive"]
                or state["last_success_archive_sha256"] != state["last_successful_archive_sha256"]):
            raise ValueError("compatibility aliases")
        layout = state["database_layout"]
        if not isinstance(layout, dict) or set(layout) != {"mains", "sidecars"} or not all(isinstance(layout[k], list) and all(isinstance(x, str) for x in layout[k]) for k in layout): raise ValueError("layout")
        whitelist = state["napcat_whitelist"]
        if (not isinstance(whitelist, list)
                or not all(isinstance(path, str) and safe_zip_name(path)
                           and path.startswith("NapCat/") for path in whitelist)
                or len(whitelist) != len({path.casefold() for path in whitelist})
                or type(state["napcat_enabled"]) is not bool
                or (state["napcat_enabled"] and not valid_registered_napcat_version(state["napcat_version"]))
                or (not state["napcat_enabled"] and state["napcat_version"] != DISABLED_NAPCAT)
                or (state["napcat_enabled"] and not whitelist)
                or (not state["napcat_enabled"] and whitelist)
                or state["week_start"] not in WEEKDAYS
                or re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", state["schedule_time"]) is None
                or not isinstance(state["timezone"], str)):
            raise ValueError("napcat/schedule")
        if (state["last_result"] not in STATE_RESULTS
                or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", state["last_cycle"])
                or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", state["last_successful_cycle"])
                or not is_strict_archive_name(state["last_successful_archive"])
                or not isinstance(state["last_successful_archive_sha256"], str)
                or re.fullmatch(r"[0-9a-f]{64}", state["last_successful_archive_sha256"]) is None):
            raise ValueError("cycle")
        if state["last_result"] == "FULL_SUCCESS":
            if failure_optional & set(state):
                raise ValueError("unexpected failure fields")
        elif (type(state.get("last_failure_code")) is not int
                or state["last_failure_code"] not in {1, 2}
                or state.get("last_failure_phase") not in FAILURE_PHASES):
            raise ValueError("failure fields")
        retention_candidates = state.get("retention_candidates", [])
        if (not isinstance(retention_candidates, list)
                or not all(
                    isinstance(item, dict)
                    and set(item) == {"archive", "action", "sha256", "verified"}
                    and is_strict_archive_name(item.get("archive"))
                    and item.get("action") in {"report-only", "auto-delete-authorized"}
                    and isinstance(item.get("sha256"), str)
                    and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None
                    and item.get("verified") is True
                    for item in retention_candidates
                )
                or len(retention_candidates) > 100):
            raise ValueError("retention candidates")
        state["retention_candidates"] = retention_candidates
        attempt_utc = dt.datetime.fromisoformat(state["last_attempt_time_utc"])
        attempt_local = dt.datetime.fromisoformat(state["last_attempt_time_local"])
        if attempt_utc.tzinfo is None or attempt_local.tzinfo is None or attempt_utc.utcoffset() != dt.timedelta(0):
            raise ValueError("attempt time")
        return state
    except BackupError:
        raise
    except (OSError, ValueError, UnicodeError, TypeError, AttributeError, json.JSONDecodeError) as exc:
        raise BackupError("state is corrupt; refusing to adopt artifacts", 3) from exc


def atomic_json(path: Path, value):
    assert_safe_output_path(path.parent)
    original = _path_token_if_present(path, regular=True, single_link=True)
    tmp = path.parent / (path.name + "." + str(uuid.uuid4()) + ".partial")
    tmp_owned = None
    encoded = json.dumps(value, sort_keys=True, indent=2).encode("utf-8")
    try:
        with _exclusive_output(tmp) as (handle, tmp_owned):
            handle.write(encoded)
        tmp_verified = _path_token(tmp, regular=True, single_link=True)
        if not tmp_verified.same_object(tmp_owned):
            raise BackupError("temporary state identity changed", 3)
        current = _path_token_if_present(path, regular=True, single_link=True)
        if (original is None) != (current is None) or (original is not None and not _same_verified_token(current, original)):
            raise BackupError("state target changed before commit", 3)
        try:
            if original is None:
                # Bootstrap is a no-replace link publication. A concurrently
                # created/hard-linked state entry makes link() fail instead of
                # allowing rename-to-same-object semantics to report success.
                os.link(tmp, path, follow_symlinks=False)
                linked = _path_token(path, regular=True)
                tmp_linked = _path_token(tmp, regular=True)
                if (not linked.same_content_identity(tmp_verified) or not tmp_linked.same_content_identity(tmp_verified)
                        or linked.nlink != 2 or tmp_linked.nlink != 2):
                    raise BackupError("initial state link identity mismatch", 3)
                if not _safe_unlink_owned(tmp, tmp_owned):
                    raise BackupError("initial state temporary unlink failed", 3)
            else:
                os.replace(tmp, path)
        except BackupError:
            raise
        except OSError as exc:
            raise BackupError("atomic state replace failed", 3) from exc
        committed = _path_token(path, regular=True, single_link=True)
        if not committed.same_content_identity(tmp_verified):
            raise BackupError("atomic state replace did not commit expected object", 3)
        raw, stable, digest = _read_stable_regular(path)
        if not stable.same_content_identity(committed) or raw != encoded or digest != hashlib.sha256(encoded).hexdigest():
            raise BackupError("committed state verification failed", 3)
    finally:
        _safe_unlink_owned(tmp, tmp_owned)


def commit_state(destination: Path, value, writer=None) -> bool:
    """Durably append state before best-effort refresh of the compatibility cache."""
    write = writer or atomic_json
    journal_dir = destination / "state-journal"
    if not _lexists(_state_path(destination)) and not _lexists(journal_dir):
        prior_revision = -1
    else:
        prior = load_state(destination)
        if prior is None:
            raise BackupError("state transition requires initialized state", 3)
        prior_revision = prior.get("state_revision")
        if type(prior_revision) is not int or prior_revision < 0:
            raise BackupError("state revision is unsafe", 3)
    value = dict(value)
    value["state_revision"] = prior_revision + 1
    created = False
    journal_token = None
    if not _lexists(journal_dir):
        journal_dir.mkdir(exist_ok=False)
        created = True
        journal_token = _path_token(journal_dir, directory=True)
    else:
        _path_token(journal_dir, directory=True)
    record = journal_dir / (str(uuid.uuid4()) + ".json")
    try:
        write(record, value)
    except Exception:
        if created:
            _safe_rmdir_owned(journal_dir, journal_token)
        raise
    try:
        write(_state_path(destination), value)
        return True
    except (OSError, BackupError, ValueError, TypeError):
        # The immutable record is authoritative and load_state() can recover it.
        return False


def initial_state(*, owner_uuid: str, source_fingerprints: dict[str, str],
                  config_fingerprint: str, week_start: int, schedule_time: str,
                  artifact_digest: str = "0" * 64, now: Optional[dt.datetime] = None) -> dict[str, object]:
    """Build the deliberately small, trusted state before a first cold backup."""
    moment = now or dt.datetime.now().astimezone()
    if moment.tzinfo is None:
        raise BackupError("initial state time must be timezone-aware", 3)
    if not _canonical_uuid(owner_uuid):
        raise BackupError("invalid initial state owner", 3)
    if (not isinstance(source_fingerprints, dict)
            or set(source_fingerprints) != {"astrbot_root", "napcat_root"}
            or not all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
                       for value in source_fingerprints.values())):
        raise BackupError("invalid initial state fingerprints", 3)
    if (not isinstance(config_fingerprint, str)
            or re.fullmatch(r"[0-9a-f]{64}", config_fingerprint) is None
            or not isinstance(artifact_digest, str) or re.fullmatch(r"[0-9a-f]{64}", artifact_digest) is None
            or week_start not in WEEKDAY_NAMES
            or re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", schedule_time) is None):
        raise BackupError("invalid initial state configuration", 3)
    return {
        "schema": SCHEMA, "schema_version": SCHEMA, "managed_by": GENERATOR,
        "state_namespace": "community-v1", "owner_uuid": owner_uuid, "state_revision": 0,
        "source_fingerprint": source_fingerprints["astrbot_root"],
        "config_fingerprint": config_fingerprint, "artifact_digest": artifact_digest,
        "source_fingerprints": dict(source_fingerprints),
        "week_start": WEEKDAY_NAMES[week_start], "schedule_time": schedule_time,
        "last_result": "INITIALIZED",
        "last_attempt_time_utc": moment.astimezone(dt.timezone.utc).isoformat(),
        "last_attempt_time_local": moment.isoformat(),
    }


def local_cycle(now: dt.datetime, week_start: int = 6) -> str:
    if week_start not in range(7):
        raise BackupError("invalid week start", 3)
    today = now.date()
    first_day = today - dt.timedelta(days=(today.weekday() - week_start) % 7)
    return first_day.isoformat()


def failed_attempt_state(state, now: dt.datetime, cycle: str, code: int, phase: str):
    if code not in {1, 2} or phase not in FAILURE_PHASES:
        raise BackupError("unsafe failed-attempt state transition", 3)
    updated = dict(state)
    if state.get("last_result") == "INITIALIZED":
        # No archive/layout exists yet, so retain the exact first-run schema.
        updated["last_attempt_time_utc"] = now.astimezone(dt.timezone.utc).isoformat()
        updated["last_attempt_time_local"] = now.isoformat()
        return updated
    updated["timezone"] = str(now.tzinfo)
    updated["last_cycle"] = cycle
    updated["last_attempt_time_utc"] = now.astimezone(dt.timezone.utc).isoformat()
    updated["last_attempt_time_local"] = now.isoformat()
    updated["last_result"] = "DEGRADED" if code == 2 else "FAILED"
    updated["last_failure_code"] = code
    updated["last_failure_phase"] = phase
    return updated


def _trusted_backup_process_commandline(commandline) -> bool:
    words = _parse_process_commandline(commandline)
    if words is None or len(words) < 2:
        return False
    engine_path = Path(__file__).resolve(strict=True)
    expected = {
        _key(engine_path),
        _key(engine_path.with_name("console_runner.py")),
    }
    # The scheduled wrappers may use exactly one ``-B`` before the verified
    # script to prevent runtime bytecode from invalidating the artifact
    # namespace.  No other interpreter option, repeated option, ``-m`` or
    # ``-c`` form is accepted as proof of the current backup process.
    entry_index = 2 if words[1] == "-B" else 1
    if len(words) <= entry_index:
        return False
    candidate = words[entry_index].strip().replace("/", "\\")
    if ntpath.basename(ntpath.normpath(candidate)).casefold() not in {
            "engine.py", "console_runner.py"}:
        return False
    try:
        return Path(candidate).is_absolute() and _key(Path(candidate)) in expected
    except OSError:
        return False


def default_process_probe(root: Path):
    if os.name != "nt":
        return None
    target_path = root / "venv" / "Scripts" / "python.exe"
    target = _key(target_path)
    try:
        command = "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine | ConvertTo-Json -Compress"
        data = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", command], capture_output=True,
                              text=True, timeout=20, check=True)
        rows = json.loads(data.stdout or "[]")
        if isinstance(rows, dict):
            rows = [rows]
        self_pid = os.getpid()
        direct_parent_pid = None
        self_is_trusted_backup = False
        for row in rows:
            if type(row.get("ProcessId")) is int and row.get("ProcessId") == self_pid:
                self_is_trusted_backup = _trusted_backup_process_commandline(row.get("CommandLine"))
                parent = row.get("ParentProcessId")
                if type(parent) is int:
                    direct_parent_pid = parent
                break
        root_main = root / "main.py"
        for row in rows:
            process_id = row.get("ProcessId")
            if (type(process_id) is int and process_id == self_pid
                    and self_is_trusted_backup):
                # The scheduled backup itself normally uses AstrBot's venv
                # interpreter and lives below the AstrBot root.  Exclude only
                # this exact PID after its entry script is bound to this
                # verified package; every other row remains fail-closed.
                continue
            executable = row.get("ExecutablePath") or row.get("Image")
            commandline = row.get("CommandLine")
            if (self_is_trusted_backup and type(process_id) is int
                    and process_id == direct_parent_pid
                    and executable and _key(Path(executable)) == target):
                words = _parse_process_commandline(commandline)
                if words is not None and not process_command_matches(
                        Path(executable), commandline, target_path):
                    # On Windows a venv redirector can remain as the exact
                    # direct parent of the real Python process.  Exclude that
                    # proven launcher only; malformed or main.py parents are
                    # still treated as running/indeterminate.
                    continue
            if executable and _key(Path(executable)) == target:
                if _parse_process_commandline(commandline) is None:
                    return None
                if process_command_matches(Path(executable), commandline, target_path):
                    return True
            words = _parse_process_commandline(commandline)
            executable_path = Path(executable) if isinstance(executable, str) and executable else None
            executable_under_root = False
            if executable_path is not None:
                root_key = _key(root).rstrip("\\")
                executable_key = _key(executable_path)
                executable_under_root = executable_key == root_key or executable_key.startswith(root_key + "\\")
            if words is None:
                if executable_under_root:
                    return None
                continue
            for word in words[1:]:
                candidate = word.strip().replace("/", "\\")
                candidate_is_main = ntpath.basename(ntpath.normpath(candidate)).casefold() == "main.py"
                if candidate_is_main:
                    try:
                        if Path(candidate).is_absolute() and _key(Path(candidate)) == _key(root_main):
                            return True
                    except OSError:
                        return None
                if ntpath.normpath(candidate).casefold() == "main.py":
                    if executable_under_root:
                        return True
                    basename = executable_path.name.casefold() if executable_path is not None else ""
                    if basename in {"python", "python.exe", "pythonw", "pythonw.exe", "py", "py.exe"}:
                        return None
            normalized_command = commandline.replace("/", "\\").casefold()
            basename = executable_path.name.casefold() if executable_path is not None else ""
            python_like = basename in {"python", "python.exe", "pythonw", "pythonw.exe", "py", "py.exe"}
            if _key(root).casefold() in normalized_command and (executable_under_root or python_like):
                return None
        return False
    except Exception:
        return None


def _parse_process_commandline(commandline):
    if not isinstance(commandline, str) or not commandline.strip() or "\x00" in commandline:
        return None
    quoted = False
    for index, character in enumerate(commandline):
        if character != '"':
            continue
        backslashes = 0
        cursor = index - 1
        while cursor >= 0 and commandline[cursor] == "\\":
            backslashes += 1
            cursor -= 1
        if backslashes % 2 == 0:
            quoted = not quoted
    if quoted:
        return None
    tokens = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"|([^\s]+)', commandline)
    words = [a or b for a, b in tokens]
    return words or None


def process_command_matches(executable: Path, commandline: str, target: Path) -> bool:
    """Conservative process matcher: exact interpreter and a quoted/unquoted main.py token only."""
    if _key(executable) != _key(target):
        return False
    words = _parse_process_commandline(commandline)
    if words is None:
        return False
    interpreter = words[0].strip().replace("/", "\\")
    exact_interpreter = _key(Path(interpreter)) == _key(target)
    basename_interpreter = ("\\" not in interpreter and "/" not in words[0]
                            and ntpath.splitdrive(interpreter)[0] == ""
                            and interpreter.casefold() in {"python", "python.exe"})
    if not exact_interpreter and not basename_interpreter:
        return False
    for word in words[1:]:
        candidate = word.strip().replace("/", "\\")
        if ntpath.normpath(candidate).casefold() == "main.py":
            return True
        try:
            if Path(candidate).is_absolute() and _key(Path(candidate)) == _key(target.parent.parent.parent / "main.py"):
                return True
        except OSError:
            return False
    return False


def check_process(probe, root):
    result = probe(root)
    if result is not False:
        raise BackupError("AstrBot process is running or process state is indeterminate", 1)


def compare_post(items, opener):
    changed = []
    for item in items:
        try:
            st = item.disk.stat(follow_symlinks=False)
            current = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, getattr(st, "st_file_attributes", 0))
            expected = (item.dev, item.ino, item.size, item.mtime_ns, item.attrs)
            if item.kind == "directory":
                current = (st.st_dev, st.st_ino, 0, st.st_mtime_ns, getattr(st, "st_file_attributes", 0))
            else:
                assert_safe_source_streams(item.disk)
            if (current != expected or (item.kind == "file"
                    and sha256_file(item.disk, opener, classify_drift([item.area])) != item.sha256)):
                changed.append(item)
        except (OSError, BackupError):
            changed.append(item)
    return changed


def _ensure_stage_directory(path: Path, stage: Path, ledger: StageLedger) -> None:
    missing = []
    current = path
    while current != stage and not _lexists(current):
        missing.append(current)
        current = current.parent
    if current == stage:
        # Creating registered descendants legitimately changes directory
        # metadata on NTFS.  The root gate binds the directory object itself;
        # exact descendant paths and file identities are enforced by seal().
        if not _path_token(stage, directory=True).same_object(ledger.root_token):
            raise BackupError("staging root identity changed", 3)
    elif current != stage:
        relative = ledger._relative(current)
        registered = ledger.entries.get(relative)
        token = _path_token(current, directory=True)
        if registered is None or registered[0] != "directory" or not registered[1].same_object(token):
            raise BackupError("unregistered staging ancestor", 3)
    for directory in reversed(missing):
        directory.mkdir(exist_ok=False)
        ledger.register(directory, kind="directory")


def copy_item(item: Item, stage: Path, opener, ledger: Optional[StageLedger] = None,
              progress_callback=None):
    ledger = ledger or StageLedger(stage)
    relative = item.archive[:-1] if item.kind == "directory" else item.archive
    target = stage.joinpath(*relative.split("/"))
    if item.kind == "directory":
        if _lexists(target):
            relative_key = ledger._relative(target)
            registered = ledger.entries.get(relative_key)
            current = _path_token(target, directory=True)
            if registered is None or registered[0] != "directory" or not registered[1].same_object(current):
                raise BackupError("staging directory already exists", 3)
            # Creating registered children legitimately changes a directory's
            # metadata.  Refresh only after proving it is the same registered
            # directory; replacement and foreign entries remain fail-closed.
            ledger.refresh(target, kind="directory")
        else:
            _ensure_stage_directory(target, stage, ledger)
        if progress_callback is not None:
            progress_callback(item, 0)
        return target
    _ensure_stage_directory(target.parent, stage, ledger)
    assert_safe_source_streams(item.disk)
    digest = hashlib.sha256()
    code = classify_drift([item.area])
    created = None
    try:
        with _stable_source_reader(item.disk, opener, code) as src, _exclusive_output(target) as (dst, created):
            while True:
                block = src.read(1024 * 1024)
                if not block:
                    break
                dst.write(block)
                digest.update(block)
    except BackupError:
        raise
    except OSError as exc:
        raise BackupError("source copy failed", code) from exc
    finally:
        if created is not None:
            try:
                current = _path_token(target, regular=True, single_link=True)
                if current.same_object(created):
                    ledger.register_token(target, kind="file", token=current)
            except BackupError:
                pass
    if digest.hexdigest() != item.sha256:
        raise BackupError("source changed during copy", code)
    assert_safe_source_streams(item.disk)
    if progress_callback is not None:
        progress_callback(item, item.size)
    return target


def _copy_registered_to_workspace(source: Path, target: Path, stage_ledger: StageLedger,
                                  workspace_ledger: StageLedger) -> None:
    relative = stage_ledger._relative(source)
    registered = stage_ledger.entries.get(relative)
    current = _path_token(source, regular=True, single_link=True)
    if (registered is None or registered[0] != "file"
            or not _same_verified_token(current, registered[1])):
        raise BackupError("SQLite family member is not registered or changed", 3)
    created = None
    with _stable_regular_reader(source, current) as src, _exclusive_output(target) as (dst, created):
        shutil.copyfileobj(src, dst, 1024 * 1024)
    copied = _path_token(target, regular=True, single_link=True)
    if created is None or not copied.same_object(created):
        raise BackupError("SQLite workspace copy identity changed", 3)
    workspace_ledger.register_token(target, kind="file", token=copied)


def _seal_sqlite_workspace(workspace: Path, ledger: StageLedger,
                           family_names: tuple[str, ...]) -> None:
    if (not family_names
            or len({name.casefold() for name in family_names}) != len(family_names)):
        raise BackupError("invalid SQLite workspace family names", 3)
    required = {name.casefold() for name in family_names}
    allowed = required | {
        (name + suffix).casefold()
        for name in family_names
        for suffix in SIDECARS
    }
    inventory = _registered_stage_inventory(workspace)
    inventory_names = {relative.casefold() for relative in inventory}
    if (len(inventory_names) != len(inventory)
            or not required.issubset(inventory_names)
            or any(kind != "file" or "/" in relative or relative.casefold() not in allowed
                   for relative, (kind, _token) in inventory.items())):
        raise BackupError("SQLite workspace contains a foreign artifact", 3)
    for relative, (_kind, current) in inventory.items():
        path = workspace / relative
        prior = ledger.entries.get(relative)
        if prior is None:
            ledger.register_token(path, kind="file", token=current)
        else:
            if prior[0] != "file" or not prior[1].same_object(current):
                raise BackupError("SQLite workspace member was replaced", 3)
            ledger.refresh(path, kind="file")
    ledger.seal()


def _publish_normalized_database(source: Path, normalized: Path, normalized_token: FileToken,
                                 stage_ledger: StageLedger) -> None:
    relative = stage_ledger._relative(source)
    registered = stage_ledger.entries.get(relative)
    source_token = _path_token(source, regular=True, single_link=True)
    if (registered is None or registered[0] != "file"
            or not _same_verified_token(source_token, registered[1])):
        raise BackupError("staging database changed before normalized publish", 3)
    if not _safe_unlink_owned(source, source_token):
        raise BackupError("registered staging database unlink failed", 1)
    try:
        os.link(normalized, source, follow_symlinks=False)
    except OSError as exc:
        raise BackupError("normalized database no-replace publish failed", 1) from exc
    linked = _path_token(source, regular=True)
    private_link = _path_token(normalized, regular=True)
    if (not linked.same_content_identity(normalized_token)
            or not private_link.same_content_identity(normalized_token)
            or not linked.same_object(private_link)):
        raise BackupError("normalized database publish identity mismatch", 3)
    if not _safe_unlink_owned(normalized, private_link):
        raise BackupError("normalized private link cleanup failed", 1)
    published = _path_token(source, regular=True, single_link=True)
    if not published.same_content_identity(normalized_token):
        raise BackupError("normalized database changed after publish", 3)
    stage_ledger.replace_with_created(source, normalized_token)


def normalize_databases(stage: Path, layout, ledger: Optional[StageLedger] = None):
    if ledger is None:
        raise BackupError("SQLite normalization requires a staging ledger", 3)
    results, omit = [], set()
    staged_names = {p.relative_to(stage).as_posix(): p for p in _staging_files(stage)}
    normalization_root = stage / ".normalization"
    if _lexists(normalization_root):
        raise BackupError("unexpected staging normalization path", 3)
    normalization_root.mkdir(exist_ok=False)
    normalization_root_token = _path_token(normalization_root, directory=True)
    private_normalization = normalization_root / str(uuid.uuid4())
    private_normalization.mkdir(exist_ok=False)
    private_normalization_token = _path_token(private_normalization, directory=True)
    mains = set(layout["mains"])
    for sidecar in layout["sidecars"]:
        base = next((sidecar[:-len(s)] for s in SIDECARS if sidecar.casefold().endswith(s)), "")
        if base.casefold() not in {x.casefold() for x in mains}:
            results.append({"path": sidecar, "orphan_sidecar": True, "normalized": False})
    for name in sorted(mains):
        source = staged_names.get(name)
        if source is None:
            raise BackupError("database disappeared from staging", 1)
        related = [candidate for candidate in staged_names if sqlite_sidecar_belongs(candidate, [name])]
        try:
            family_workspace = private_normalization / str(uuid.uuid4())
            family_workspace.mkdir(exist_ok=False)
            family_ledger = StageLedger(family_workspace)
            member_names = [name, *related]
            leaf_names = [Path(member).name for member in member_names]
            if len(leaf_names) != len({leaf.casefold() for leaf in leaf_names}):
                raise BackupError("SQLite family workspace name collision", 3)
            for member, leaf in zip(member_names, leaf_names):
                member_source = staged_names[member]
                _copy_registered_to_workspace(
                    member_source, family_workspace / leaf, ledger, family_ledger
                )
            workspace_main = family_workspace / Path(name).name
            normalized = family_workspace / (str(uuid.uuid4()) + ".db")
            with _exclusive_output(normalized) as (_handle, normalized_created):
                pass
            src_uri = workspace_main.resolve().as_uri() + "?mode=ro"
            out_uri = normalized.resolve().as_uri() + "?mode=rw"
            read_con = sqlite3.connect(src_uri, uri=True)
            out_con = sqlite3.connect(out_uri, uri=True)
            try:
                if not _path_token(normalized, regular=True, single_link=True).same_object(normalized_created):
                    raise BackupError("normalization output identity changed after open", 3)
                read_con.backup(out_con)
                check = out_con.execute("PRAGMA integrity_check").fetchone()[0]
                if check != "ok":
                    raise sqlite3.DatabaseError(check)
            finally:
                out_con.close()
                read_con.close()
            normalized_token = _path_token(normalized, regular=True, single_link=True)
            if not normalized_token.same_object(normalized_created):
                raise BackupError("normalization output identity changed", 3)
            _seal_sqlite_workspace(
                family_workspace, family_ledger, (workspace_main.name, normalized.name)
            )
            _publish_normalized_database(source, normalized, normalized_token, ledger)
            family_ledger.forget_verified_removed(normalized, normalized_token)
            if not _safe_rmtree_registered(family_workspace, family_ledger):
                raise BackupError("SQLite family workspace cleanup failed", 1)
        except (sqlite3.Error, OSError, ValueError) as exc:
            raise BackupError("staging SQLite integrity/normalization failed", 1) from exc
        omit.update(related)
        results.append({"path": name, "normalized": True, "integrity_check": "ok",
                        "sidecars_omitted": related})
    if not _safe_rmdir_owned(private_normalization, private_normalization_token):
        raise BackupError("normalization work directory is not empty/safe", 3)
    if not _safe_rmdir_owned(normalization_root, normalization_root_token):
        raise BackupError("normalization root is not empty/safe", 3)
    return results, omit


def safe_zip_name(name: str) -> bool:
    if not isinstance(name, str) or not name or name.startswith(("/", "\\")) or "\\" in name or "\x00" in name:
        return False
    core = name[:-1] if name.endswith("/") else name
    if not core:
        return False
    parts = core.split("/")
    return all(part not in {"", ".", ".."} and ":" not in part for part in parts)

def valid_registered_napcat_version(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9.]+-[0-9]+", value) is not None

def sqlite_sidecar_belongs(sidecar, mains):
    lowered = sidecar.casefold()
    for suffix in SIDECARS:
        if lowered.endswith(suffix):
            return lowered[:-len(suffix)] in {main.casefold() for main in mains}
    return False

STRICT_ARCHIVE_RE = re.compile(
    r"astrbot-safe-backup-\d{8}-\d{6}-(?P<run_id>[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.zip"
)


def is_strict_archive_name(name):
    return isinstance(name, str) and STRICT_ARCHIVE_RE.fullmatch(name) is not None


def archive_run_id(name):
    match = STRICT_ARCHIVE_RE.fullmatch(name) if isinstance(name, str) else None
    return match.group("run_id") if match else None


def archive_manifest(owner, run_id, archive_name, fingerprints, version, cycle, entries,
                     database_results, database_layout, volumes=None, created_at=None,
                     napcat_enabled=True, week_start="sunday", schedule_time="12:00",
                     napcat_whitelist=None, root_config_anchors=None, started_at=None,
                     finished_at=None, limits=None):
    finished = finished_at or created_at or dt.datetime.now().astimezone()
    started = started_at or finished
    return {"schema": 1, "generator": GENERATOR, "generator_version": GENERATOR_VERSION,
            "owner_uuid": owner, "run_id": run_id,
            "result": "FULL_SUCCESS", "status": "FULL_SUCCESS", "source_fingerprints": fingerprints, "napcat_version": version,
            "napcat_enabled": napcat_enabled, "napcat_whitelist": list(napcat_whitelist or []),
            "week_start": week_start, "schedule_time": schedule_time,
            "archive": archive_name,
            "created_at": finished.isoformat(), "started_at": started.isoformat(),
            "finished_at": finished.isoformat(), "timezone": finished.strftime("%z"), "cycle": cycle,
            "volumes": volumes or {},
            "entries": entries, "database_results": database_results, "database_layout": database_layout,
            "astrbot_root_config_anchors": list(root_config_anchors or []),
            "total_files": 0, "total_bytes": 0, "warnings": [],
            "capabilities": dict(CAPABILITIES),
            "exclusions": list(ARCHIVE_EXCLUSIONS),
            "limits": dict(limits or archive_budget(0, len(entries)))}


def _staging_files(stage: Path):
    root_token = _path_token(stage, directory=True)
    files = []
    for root, directories, names in os.walk(stage, topdown=True, followlinks=False):
        root_path = Path(root)
        for name in directories:
            if not safe_component(name):
                raise BackupError("unsafe staging directory name", 3)
            _path_token(root_path / name, directory=True)
        for name in names:
            if not safe_component(name):
                raise BackupError("unsafe staging file name", 3)
            path = root_path / name
            _path_token(path, regular=True, single_link=True)
            files.append(path)
    if not _same_verified_token(_path_token(stage, directory=True), root_token):
        raise BackupError("staging tree changed during static validation", 3)
    return sorted(files, key=lambda path: path.relative_to(stage).as_posix().casefold())


def write_archive(partial: Path, stage: Path, omitted, manifest, output=None):
    stage_files = _staging_files(stage)
    staged_names = {path.relative_to(stage).as_posix() for path in stage_files}
    if (not isinstance(omitted, (set, frozenset)) or not all(isinstance(name, str) and safe_zip_name(name) for name in omitted)
            or not set(omitted) <= staged_names):
        raise BackupError("omitted database sidecar is not an actual safe staging file", 3)
    layout = manifest.get("database_layout") if isinstance(manifest, dict) else None
    if (not isinstance(layout, dict) or set(layout) != {"mains", "sidecars"}
            or not all(isinstance(layout.get(key), list) for key in ("mains", "sidecars"))):
        raise BackupError("archive manifest database layout is missing", 3)
    layout_mains, layout_sidecars = set(layout["mains"]), set(layout["sidecars"])
    if not (layout_mains | layout_sidecars) <= staged_names:
        raise BackupError("database layout does not exist exactly in staging", 3)
    paired_sidecars = {sidecar for sidecar in layout_sidecars if sqlite_sidecar_belongs(sidecar, layout_mains)}
    if set(omitted) != paired_sidecars:
        raise BackupError("omitted sidecars do not exactly match staged database families", 3)
    if output is None:
        owned = None
        try:
            with _exclusive_output(partial) as (created, owned):
                return write_archive(partial, stage, omitted, manifest, created)
        except Exception:
            _safe_unlink_owned(partial, owned)
            raise
    source_entries = manifest.get("entries") if isinstance(manifest, dict) else None
    limits = manifest.get("limits") if isinstance(manifest, dict) else None
    if not _valid_archive_limits(limits):
        raise BackupError("archive manifest budget is invalid", 3)
    if (not isinstance(source_entries, list)
            or any(not isinstance(entry, dict) or set(entry) != {"path", "kind", "mtime_ns"}
                   for entry in source_entries)):
        raise BackupError("archive manifest source inventory is missing", 3)
    source_by_name = {}
    for entry in source_entries:
        name, kind, mtime_ns = entry["path"], entry["kind"], entry["mtime_ns"]
        if (not isinstance(name, str) or name in source_by_name or not safe_zip_name(name)
                or kind not in {"file", "directory"} or type(mtime_ns) is not int
                or (kind == "directory") != name.endswith("/")):
            raise BackupError("archive manifest source inventory is invalid", 3)
        source_by_name[name] = entry
    declared_files = {name for name, entry in source_by_name.items() if entry["kind"] == "file"}
    if declared_files - set(omitted) != staged_names - set(omitted):
        raise BackupError("archive manifest files do not exactly match staging", 3)
    staged_total = sum(path.stat().st_size for path in stage_files if path.relative_to(stage).as_posix() not in omitted)
    if (len(source_by_name) + 2 > limits["max_archive_entries"]
            or staged_total > limits["max_archive_total"]
            or any(path.stat().st_size > limits["max_archive_entry"] for path in stage_files)):
        raise BackupError("staging exceeds the source-bound archive budget", 1)

    def zip_datetime(mtime_ns):
        try:
            value = dt.datetime.fromtimestamp(mtime_ns / 1_000_000_000)
            if 1980 <= value.year <= 2107:
                return (value.year, value.month, value.day, value.hour, value.minute, value.second)
        except (OSError, OverflowError, ValueError):
            pass
        return (1980, 1, 1, 0, 0, 0)

    entries = []
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        for name in sorted(source_by_name, key=str.casefold):
            source_entry = source_by_name[name]
            if name in omitted:
                continue
            if source_entry["kind"] == "directory":
                directory = stage.joinpath(*name[:-1].split("/"))
                _path_token(directory, directory=True)
                info = zipfile.ZipInfo(name, zip_datetime(source_entry["mtime_ns"]))
                info.create_system = 3
                info.external_attr = ((stat.S_IFDIR | 0o755) << 16) | 0x10
                info.compress_type = zipfile.ZIP_STORED
                zf.writestr(info, b"")
                entries.append({"path": name, "kind": "directory", "size": 0,
                                "mtime_ns": source_entry["mtime_ns"], "sha256": ""})
                continue
            path = stage.joinpath(*name.split("/"))
            token = _path_token(path, regular=True, single_link=True)
            info = zipfile.ZipInfo(name, zip_datetime(source_entry["mtime_ns"]))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            digest = hashlib.sha256()
            with _stable_regular_reader(path, token) as source, zf.open(info, "w") as destination:
                while True:
                    block = source.read(1024 * 1024)
                    if not block:
                        break
                    digest.update(block)
                    destination.write(block)
            if not _zip_info_within_budget(zf.getinfo(name), limits):
                raise BackupError("ZIP member exceeds compression budget", 1)
            entries.append({"path": name, "kind": "file", "size": token.size,
                            "mtime_ns": source_entry["mtime_ns"], "sha256": digest.hexdigest()})
        manifest["entries"] = entries
        manifest["total_files"] = sum(entry["kind"] == "file" for entry in entries)
        manifest["total_bytes"] = sum(entry["size"] for entry in entries if entry["kind"] == "file")
        zf.writestr("backup-manifest.json", json.dumps(manifest, sort_keys=True, separators=(",", ":")))
        zf.writestr(
            "RESTORE-NOTES.txt",
            "Status: FULL_SUCCESS\n"
            "This ZIP is not encrypted and may contain secrets.\n"
            "Extract into an isolated restoration directory and verify before any manual restore.\n"
            "Do not start AstrBot, NapCat, or QQ during restoration verification.\n"
            "SQLite integrity checks validate database structure, not third-party plugin business semantics.\n"
            "This tool never performs an automatic restore or overwrites source data.\n",
        )


def _read_zip_limited(zf: zipfile.ZipFile, name: str, limit: int) -> bytes:
    info = zf.getinfo(name)
    if info.file_size > limit:
        raise ValueError("ZIP metadata member exceeds limit")
    chunks, total = [], 0
    with zf.open(info) as source:
        while True:
            block = source.read(min(1024 * 1024, limit + 1 - total))
            if not block:
                break
            total += len(block)
            if total > limit:
                raise ValueError("ZIP metadata member expands beyond limit")
            chunks.append(block)
    if total != info.file_size:
        raise ValueError("ZIP metadata size mismatch")
    return b"".join(chunks)


def _hash_zip_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo, limit=MAX_ARCHIVE_ENTRY) -> str:
    digest, total = hashlib.sha256(), 0
    with zf.open(info) as source:
        while True:
            block = source.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > limit:
                raise ValueError("ZIP member expands beyond per-entry limit")
            digest.update(block)
    if total != info.file_size:
        raise ValueError("ZIP member size mismatch")
    return digest.hexdigest()


def _copy_zip_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo, output, limit=MAX_ARCHIVE_ENTRY) -> None:
    total = 0
    with zf.open(info) as source:
        while True:
            block = source.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > limit:
                raise ValueError("ZIP extraction exceeds per-entry limit")
            output.write(block)
    if total != info.file_size:
        raise ValueError("ZIP extraction size mismatch")


def _canonical_uuid(value) -> bool:
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError, TypeError):
        return False


def _valid_archive_limits(limits) -> bool:
    return (
        isinstance(limits, dict)
        and set(limits) == {
            "max_archive_entry", "max_archive_entries", "max_archive_total",
            "max_compression_ratio",
        }
        and all(type(value) is int and value > 0 for value in limits.values())
        and limits["max_archive_entry"] <= HARD_MAX_ARCHIVE_ENTRY
        and limits["max_archive_entries"] <= HARD_MAX_ARCHIVE_ENTRIES
        and limits["max_archive_total"] <= HARD_MAX_ARCHIVE_TOTAL
        and limits["max_compression_ratio"] <= HARD_MAX_COMPRESSION_RATIO
        and limits["max_archive_entry"] <= limits["max_archive_total"]
    )


def _valid_manifest_contract(manifest) -> bool:
    required = {
        "schema", "generator", "generator_version", "owner_uuid", "run_id", "result", "status", "source_fingerprints",
        "napcat_enabled", "napcat_version", "napcat_whitelist", "week_start", "schedule_time",
        "archive", "created_at", "started_at", "finished_at", "timezone", "cycle", "volumes", "entries",
        "database_results", "database_layout", "exclusions", "limits",
        "astrbot_root_config_anchors", "total_files", "total_bytes", "warnings", "capabilities",
    }
    if not isinstance(manifest, dict) or set(manifest) != required:
        return False
    if (manifest["schema"] != 1 or manifest["generator"] != GENERATOR
            or manifest["generator_version"] != GENERATOR_VERSION
            or manifest["result"] != "FULL_SUCCESS" or manifest["status"] != "FULL_SUCCESS"):
        return False
    if not _canonical_uuid(manifest["owner_uuid"]) or not _canonical_uuid(manifest["run_id"]):
        return False
    if (not is_strict_archive_name(manifest["archive"])
            or archive_run_id(manifest["archive"]) != manifest["run_id"]):
        return False
    fingerprints = manifest["source_fingerprints"]
    if (not isinstance(fingerprints, dict) or set(fingerprints) != {"astrbot_root", "napcat_root"}
            or not all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in fingerprints.values())):
        return False
    version = manifest["napcat_version"]
    napcat_enabled = manifest["napcat_enabled"]
    whitelist = manifest["napcat_whitelist"]
    if (type(napcat_enabled) is not bool
            or not isinstance(whitelist, list)
            or not all(isinstance(path, str) and safe_zip_name(path) and path.startswith("NapCat/")
                       for path in whitelist)
            or len(whitelist) != len({path.casefold() for path in whitelist})
            or (napcat_enabled and not valid_registered_napcat_version(version))
            or (not napcat_enabled and version != DISABLED_NAPCAT)
            or (napcat_enabled and not whitelist) or (not napcat_enabled and whitelist)
            or manifest["week_start"] not in WEEKDAYS
            or not isinstance(manifest["schedule_time"], str)
            or re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", manifest["schedule_time"]) is None):
        return False
    try:
        created = dt.datetime.fromisoformat(manifest["created_at"])
        started = dt.datetime.fromisoformat(manifest["started_at"])
        finished = dt.datetime.fromisoformat(manifest["finished_at"])
        cycle = dt.date.fromisoformat(manifest["cycle"])
    except (TypeError, ValueError):
        return False
    if (created.tzinfo is None or started.tzinfo is None or finished.tzinfo is None
            or started > finished or created != finished
            or not isinstance(manifest["timezone"], str)
            or re.fullmatch(r"[+-]\d{4}", manifest["timezone"]) is None
            or manifest["timezone"] != finished.strftime("%z")
            or cycle.weekday() != WEEKDAYS[manifest["week_start"]]
            or not (cycle <= created.date() <= cycle + dt.timedelta(days=6))):
        return False
    volumes = manifest["volumes"]
    if (not isinstance(volumes, dict) or set(volumes) != {"astrbot_source", "napcat_source", "destination"}
            or not all(isinstance(value, str) and value for value in volumes.values())):
        return False
    if manifest["exclusions"] != ARCHIVE_EXCLUSIONS:
        return False
    anchors = manifest["astrbot_root_config_anchors"]
    if anchors != list(ASTRBOT_REQUIRED_ANCHORS):
        return False
    if (type(manifest["total_files"]) is not int or manifest["total_files"] < 0
            or type(manifest["total_bytes"]) is not int or manifest["total_bytes"] < 0
            or manifest["warnings"] != [] or manifest["capabilities"] != CAPABILITIES):
        return False
    if not _valid_archive_limits(manifest["limits"]):
        return False
    if not isinstance(manifest["entries"], list) or not isinstance(manifest["database_results"], list):
        return False
    layout = manifest["database_layout"]
    if not isinstance(layout, dict) or set(layout) != {"mains", "sidecars"}:
        return False
    for key in ("mains", "sidecars"):
        values = layout[key]
        if (not isinstance(values, list) or not all(isinstance(value, str) and safe_zip_name(value) for value in values)
                or len(values) != len(set(value.casefold() for value in values))):
            return False
    return True


def _zip_member_kind(info: zipfile.ZipInfo):
    dos_attributes = info.external_attr & 0xFFFF
    if dos_attributes & 0x400:
        return None
    kind = None
    if info.create_system == 3:
        unix_mode = (info.external_attr >> 16) & 0xFFFF
        unix_type = stat.S_IFMT(unix_mode)
        if unix_type == stat.S_IFREG:
            kind = "file"
        elif unix_type == stat.S_IFDIR:
            kind = "directory"
        elif unix_type:
            return None
    if kind is None:
        kind = "directory" if dos_attributes & 0x10 or info.is_dir() else "file"
    if info.is_dir() != (kind == "directory"):
        return None
    return kind


def verify_archive(archive: Path, owner_uuid=None, fingerprints=None, expected_token=None,
                   drive_type_probe=None, verification_root=None, verification_hook=None,
                   cleanup_failure_fatal=False) -> bool:
    verification_stage = None
    verification_ledger = None
    cleanup_required = False
    try:
        assert_local_path(checked_absolute(archive), drive_type_probe)
        with _stable_regular_reader(Path(archive), expected_token) as archive_handle:
            with zipfile.ZipFile(archive_handle) as zf:
                infos = zf.infolist()
                if not infos or len(infos) > MAX_ARCHIVE_ENTRIES:
                    return False
                seen = set()
                by_name = {}
                member_kinds = {}
                expanded_total = 0
                for info in infos:
                    name = info.filename
                    key = name.casefold()
                    member_kind = _zip_member_kind(info)
                    expanded_total += info.file_size
                    if (member_kind is None or not safe_zip_name(name) or key in seen or not _zip_info_within_budget(
                            info, {"max_archive_entry": MAX_ARCHIVE_ENTRY,
                                   "max_archive_entries": MAX_ARCHIVE_ENTRIES,
                                   "max_archive_total": MAX_ARCHIVE_TOTAL,
                                   "max_compression_ratio": HARD_MAX_COMPRESSION_RATIO})
                            or expanded_total > MAX_ARCHIVE_TOTAL or info.flag_bits & 0x1):
                        return False
                    seen.add(key)
                    by_name[name] = info
                    member_kinds[name] = member_kind
                if "backup-manifest.json" not in by_name or "RESTORE-NOTES.txt" not in by_name:
                    return False
                if member_kinds["backup-manifest.json"] != "file" or member_kinds["RESTORE-NOTES.txt"] != "file":
                    return False
                manifest = json.loads(_read_zip_limited(zf, "backup-manifest.json", MAX_MANIFEST_BYTES))
                if not _valid_manifest_contract(manifest):
                    return False
                limits = manifest["limits"]
                if (len(infos) > limits["max_archive_entries"]
                        or expanded_total > limits["max_archive_total"]
                        or any(not _zip_info_within_budget(info, limits) for info in infos)):
                    return False
                archive_leaf = Path(archive).name
                permitted_partial = manifest["archive"][:-4] + ".partial.zip"
                if archive_leaf not in {manifest["archive"], permitted_partial}:
                    return False
                if owner_uuid is not None and manifest.get("owner_uuid") != owner_uuid:
                    return False
                if fingerprints is not None and manifest.get("source_fingerprints") != fingerprints:
                    return False
                declared = {}
                for entry in manifest["entries"]:
                    if not isinstance(entry, dict) or set(entry) != {"path", "kind", "size", "mtime_ns", "sha256"}:
                        return False
                    name = entry.get("path")
                    if (not isinstance(name, str) or name in declared or not safe_zip_name(name)
                            or entry.get("kind") not in {"file", "directory"}
                            or (entry["kind"] == "directory") != name.endswith("/")
                            or type(entry.get("size")) is not int or entry["size"] < 0
                            or type(entry.get("mtime_ns")) is not int
                            or not isinstance(entry.get("sha256"), str)):
                        return False
                    if (entry["kind"] == "directory" and (entry["size"] != 0 or entry["sha256"] != "")):
                        return False
                    if entry["kind"] == "file" and not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
                        return False
                    declared[name] = entry
                actual = {info.filename for info in infos if info.filename not in {"backup-manifest.json", "RESTORE-NOTES.txt"}}
                if set(declared) != actual:
                    return False
                if (manifest["total_files"] != sum(entry["kind"] == "file" for entry in declared.values())
                        or manifest["total_bytes"] != sum(
                            entry["size"] for entry in declared.values() if entry["kind"] == "file"
                        )):
                    return False
                for name, entry in declared.items():
                    if name not in by_name or not safe_zip_name(name):
                        return False
                    if member_kinds[name] != entry["kind"]:
                        return False
                    if entry["kind"] == "file" and (_hash_zip_member(zf, by_name[name], limits["max_archive_entry"]) != entry["sha256"]
                            or by_name[name].file_size != entry["size"]):
                        return False
                    if entry["kind"] == "directory" and by_name[name].file_size != 0:
                        return False
                if ("astrbot/data/" not in seen
                        or member_kinds.get("AstrBot/data/") != "directory"):
                    return False
                if any(not (name.startswith("AstrBot/data/") or name.startswith("NapCat/")) for name in actual):
                    return False
                for anchor in ASTRBOT_REQUIRED_ANCHORS:
                    expected_kind = "directory" if anchor.endswith("/") else "file"
                    if anchor not in declared or declared[anchor]["kind"] != expected_kind or anchor not in actual:
                        return False
                notes = _read_zip_limited(zf, "RESTORE-NOTES.txt", MAX_METADATA_JSON_BYTES).decode("utf-8")
                if "FULL_SUCCESS" not in notes:
                    return False
                version = manifest.get("napcat_version")
                napcat_actual = sorted(
                    (name for name in actual if name.startswith("NapCat/")),
                    key=str.casefold,
                )
                if manifest["napcat_whitelist"] != napcat_actual:
                    return False
                if manifest["napcat_enabled"]:
                    if "napcat/versions/config.json" not in seen:
                        return False
                    nap_config = json.loads(_read_zip_limited(zf, "NapCat/versions/config.json", MAX_METADATA_JSON_BYTES))
                    if (not isinstance(nap_config, dict) or not valid_registered_napcat_version(version)
                            or nap_config.get("curVersion") != version
                            or not valid_registered_napcat_version(nap_config.get("baseVersion"))):
                        return False
                    required_json = [f"NapCat/versions/{version}/" + suffix
                                     for suffix in NAPCAT_VERSION_JSON_SUFFIXES]
                    for suffix, name in zip(NAPCAT_VERSION_JSON_SUFFIXES, required_json):
                        data = json.loads(_read_zip_limited(zf, name, MAX_METADATA_JSON_BYTES))
                        if not valid_napcat_metadata(suffix, data, version):
                            return False
                    qqnt = json.loads(_read_zip_limited(
                        zf, f"NapCat/versions/{version}/resources/app/napcat/qqnt.json",
                        MAX_METADATA_JSON_BYTES,
                    ))
                    if not valid_napcat_version_relation(
                            nap_config.get("baseVersion"), version, qqnt.get("version")):
                        return False
                    top = {"NapCat/napcat.bat", "NapCat/napcat.quick.bat", "NapCat/napcat.kill.qq.bat", "NapCat/ReadMe.txt",
                           "NapCat/versions/config.json"}
                    if not top <= actual or not any(name.startswith(f"NapCat/versions/{version}/resources/app/napcat/config/") for name in actual):
                        return False
                    config_prefix = f"NapCat/versions/{version}/resources/app/napcat/config/"
                    allowed_nap = top | set(required_json)
                    if any(name.startswith("NapCat/") and name not in allowed_nap and not name.startswith(config_prefix) for name in actual):
                        return False
                    for name in actual:
                        if (name.startswith(config_prefix) and name.casefold().endswith(".json")
                                and declared[name]["kind"] == "file"):
                            json.loads(_read_zip_limited(zf, name, MAX_METADATA_JSON_BYTES))
                elif any(name.startswith("NapCat/") for name in actual):
                    return False

                # Discover database candidates from the actual ZIP, independently of the manifest results.
                mains, sidecars = set(), set()
                for name in actual:
                    if not name.startswith("AstrBot/data/"):
                        continue
                    if declared[name]["kind"] == "directory":
                        continue
                    lowered = name.casefold()
                    if lowered.endswith(SIDECARS):
                        sidecars.add(name)
                    else:
                        with zf.open(name) as candidate:
                            magic = candidate.read(16) == b"SQLite format 3\x00"
                        if lowered.endswith(DB_SUFFIXES) or magic:
                            mains.add(name)
                layout = manifest["database_layout"]
                layout_mains, layout_sidecars = set(layout["mains"]), set(layout["sidecars"])
                if mains != layout_mains:
                    return False
                paired_by_main = {name: set() for name in mains}
                orphan_layout = set()
                for sidecar in layout_sidecars:
                    family = [main for main in mains if sqlite_sidecar_belongs(sidecar, [main])]
                    if len(family) > 1:
                        return False
                    if family:
                        paired_by_main[family[0]].add(sidecar)
                    else:
                        orphan_layout.add(sidecar)
                if sidecars != orphan_layout:
                    return False
                results = {}
                for result in manifest["database_results"]:
                    if not isinstance(result, dict) or not isinstance(result.get("path"), str) or result["path"] in results:
                        return False
                    results[result["path"]] = result
                if set(results) != mains | orphan_layout:
                    return False
                for name in mains:
                    result = results[name]
                    omitted = result.get("sidecars_omitted")
                    if (set(result) != {"path", "normalized", "integrity_check", "sidecars_omitted"}
                            or result.get("normalized") is not True or result.get("integrity_check") != "ok"
                            or not isinstance(omitted, list) or not all(isinstance(x, str) for x in omitted)):
                        return False
                    if len(omitted) != len(set(x.casefold() for x in omitted)):
                        return False
                    if set(omitted) != paired_by_main[name] or any(x in actual for x in omitted):
                        return False
                for name in orphan_layout:
                    result = results[name]
                    if (set(result) != {"path", "orphan_sidecar", "normalized"} or result.get("orphan_sidecar") is not True
                            or result.get("normalized") is not False):
                        return False

                # Materialize only already validated names on an explicitly checked local volume.
                archive_path = Path(archive)
                if verification_root is None:
                    if (archive_path.parent.parent.name.casefold() == "managed"
                            and _canonical_uuid(archive_path.parent.name)):
                        verification_root = archive_path.parent.parent.parent / "staging"
                    else:
                        verification_root = Path(tempfile.gettempdir())
                verification_root = checked_absolute(verification_root)
                assert_local_path(verification_root, drive_type_probe)
                assert_safe_output_path(verification_root)
                if not verification_root.is_dir() or is_reparse(verification_root):
                    return False
                required_verify_space = sum(by_name[name].file_size for name in mains) + 512 * 1024 * 1024
                if shutil.disk_usage(verification_root).free < required_verify_space:
                    return False
                verification_stage = verification_root / ("backup-verify-" + str(uuid.uuid4()))
                if _lexists(verification_stage):
                    return False
                verification_stage.mkdir(exist_ok=False)
                cleanup_required = True
                verification_ledger = StageLedger(verification_stage)
                for name in sorted(mains, key=lambda value: (value.count("/"), value.casefold())):
                    target = verification_stage.joinpath(*name.split("/"))
                    _ensure_stage_directory(target.parent, verification_stage, verification_ledger)
                    with _exclusive_output(target) as (output, created):
                        _copy_zip_member(zf, by_name[name], output, limits["max_archive_entry"])
                    current = _path_token(target, regular=True, single_link=True)
                    if not current.same_object(created):
                        return False
                    verification_ledger.register_token(target, kind="file", token=current)
                verification_ledger.seal()
                for name in mains:
                    p = verification_stage.joinpath(*name.split("/"))
                    token = _path_token(p, regular=True, single_link=True)
                    con = sqlite3.connect(
                        "file:" + str(p) + "?mode=ro&immutable=1", uri=True
                    )
                    try:
                        if con.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                            return False
                    finally:
                        con.close()
                    if not _same_verified_token(_path_token(p, regular=True, single_link=True), token):
                        return False
                if verification_hook is not None:
                    verification_hook(verification_stage, verification_ledger)
                verification_ledger.seal()
                if not _safe_rmtree_registered(verification_stage, verification_ledger):
                    cleanup_required = False
                    logging.getLogger(__name__).error(
                        "archive verification cleanup failed; sensitive quarantine preserved"
                    )
                    if cleanup_failure_fatal:
                        raise VerificationCleanupError()
                    return False
                cleanup_required = False
                verification_stage = None
                verification_ledger = None
                return True
    except (OSError, ValueError, KeyError, AttributeError, TypeError, zipfile.BadZipFile, sqlite3.Error):
        return False
    except VerificationCleanupError:
        if cleanup_failure_fatal:
            raise
        return False
    except BackupError:
        return False
    finally:
        if cleanup_required and verification_stage is not None and verification_ledger is not None:
            if not _safe_rmtree_registered(verification_stage, verification_ledger):
                logging.getLogger(__name__).error(
                    "archive verification cleanup failed; sensitive quarantine preserved"
                )
                if cleanup_failure_fatal:
                    raise VerificationCleanupError()


def read_verified_manifest(archive: Path, owner_uuid=None, fingerprints=None, expected_token=None):
    """Return a bounded manifest summary only after full archive verification."""
    try:
        token = expected_token or _path_token(Path(archive), regular=True, single_link=True)
        if not verify_archive(archive, owner_uuid, fingerprints, expected_token=token):
            return None
        with _stable_regular_reader(Path(archive), token) as archive_handle:
            with zipfile.ZipFile(archive_handle) as zf:
                manifest = json.loads(_read_zip_limited(zf, "backup-manifest.json", MAX_MANIFEST_BYTES))
        if not _valid_manifest_contract(manifest) or manifest["archive"] != Path(archive).name:
            return None
        return manifest
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, zipfile.BadZipFile, BackupError):
        return None


def _hash_regular(path: Path, expected: Optional[FileToken] = None):
    digest = hashlib.sha256()
    with _stable_regular_reader(path, expected) as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest(), _path_token(path, regular=True, single_link=True)


def publish_no_replace(partial: Path, final: Path, verified_token: FileToken, verified_hash: str):
    if _path_token_if_present(final) is not None:
        raise BackupError("refusing to overwrite final archive", 3)
    current = _path_token(partial, regular=True, single_link=True)
    if not _same_verified_token(current, verified_token):
        raise BackupError("verified partial identity changed before publish", 3)
    current_hash, current = _hash_regular(partial, verified_token)
    if current_hash != verified_hash:
        raise BackupError("verified partial bytes changed before publish", 3)
    linked_token = None
    try:
        os.link(partial, final, follow_symlinks=False)
        linked_token = _path_token(final, regular=True)
        partial_linked = _path_token(partial, regular=True)
        if not linked_token.same_content_identity(verified_token) or not partial_linked.same_content_identity(verified_token):
            raise BackupError("publish link identity mismatch", 3)
        if linked_token.nlink != 2 or partial_linked.nlink != 2:
            raise BackupError("publish link count is unsafe", 3)
        if not _safe_unlink_owned(partial, verified_token):
            raise BackupError("verified partial changed before unlink", 3)
        final_token = _path_token(final, regular=True, single_link=True)
        if not final_token.same_content_identity(verified_token):
            raise BackupError("published final identity mismatch", 3)
        return final_token
    except BackupError:
        _safe_unlink_owned(final, linked_token)
        raise
    except OSError as exc:
        _safe_unlink_owned(final, linked_token)
        raise BackupError("no-replace same-filesystem publish failed", 1) from exc


def _trusted_retention_bindings(destination: Path, owner: str, fingerprints) -> dict[str, str]:
    """Return archive/hash bindings from a complete authoritative journal chain.

    Archive verification alone is intentionally insufficient for deletion: a
    copied or attacker-supplied structurally valid ZIP is preserved unless an
    earlier durable state revision names the same archive and digest.
    """
    latest = load_state(destination)
    if (latest is None or latest.get("owner_uuid") != owner
            or latest.get("source_fingerprints") != fingerprints):
        raise BackupError("retention state binding is unsafe", 3)
    journal_dir = destination / "state-journal"
    if not _lexists(journal_dir):
        return {}
    _path_token(journal_dir, directory=True)
    revisions: set[int] = set()
    bindings: dict[str, str] = {}
    for entry in journal_dir.iterdir():
        if (not re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json",
                entry.name)
                or is_reparse(entry)):
            raise BackupError("state journal contains a foreign entry", 3)
        token = _path_token(entry, regular=True, single_link=True)
        if token.size > MAX_STATE_BYTES:
            raise BackupError("state journal record is too large", 3)
        raw, stable, _ = _read_stable_regular(entry)
        if not _same_verified_token(stable, token):
            raise BackupError("state journal record changed while read", 3)
        try:
            record = json.loads(raw.decode("utf-8"))
            revision = record.get("state_revision")
            attempt = dt.datetime.fromisoformat(record.get("last_attempt_time_utc", ""))
        except (UnicodeError, json.JSONDecodeError, ValueError, TypeError, AttributeError) as exc:
            raise BackupError("state journal record is invalid", 3) from exc
        if (not isinstance(record, dict) or type(revision) is not int or revision < 0
                or attempt.tzinfo is None
                or record.get("schema") != SCHEMA
                or record.get("schema_version") != SCHEMA
                or record.get("managed_by") != GENERATOR
                or record.get("state_namespace") != "community-v1"
                or record.get("owner_uuid") != owner
                or record.get("source_fingerprints") != fingerprints
                or record.get("source_fingerprint") != fingerprints.get("astrbot_root")):
            raise BackupError("state journal chain is unsafe", 3)
        revisions.add(revision)
        if record.get("last_result") == "INITIALIZED":
            continue
        archive = record.get("last_success_archive")
        archive_alias = record.get("last_successful_archive")
        digest = record.get("last_success_archive_sha256")
        digest_alias = record.get("last_successful_archive_sha256")
        if (archive != archive_alias or digest != digest_alias
                or not is_strict_archive_name(archive)
                or not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None):
            raise BackupError("state journal archive binding is unsafe", 3)
        existing = bindings.get(archive)
        if existing is not None and existing != digest:
            raise BackupError("state journal archive binding conflicts", 3)
        bindings[archive] = digest
    latest_revision = latest.get("state_revision")
    if (type(latest_revision) is not int or latest_revision < 0
            or revisions != set(range(latest_revision + 1))):
        raise BackupError("state journal revision chain is incomplete", 3)
    return bindings


def retain(owner_dir: Path, keep: int, owner: str, fingerprints, current: Path):
    """Plan deletion only for old archives proven by state and full verification."""
    if keep < 1 or keep > 30:
        raise BackupError("retention count is unsafe", 3)
    owner_token = _path_token(owner_dir, directory=True)
    if is_reparse(owner_dir):
        raise BackupError("managed owner is a reparse point", 3)
    destination = owner_dir.parent.parent
    bindings = _trusted_retention_bindings(destination, owner, fingerprints)
    current_binding = bindings.get(current.name)
    current_token = _path_token(current, regular=True, single_link=True)
    current_hash, current_token = _hash_regular(current, current_token)
    if current_binding != current_hash:
        raise BackupError("current archive is not bound to authoritative state", 3)
    candidates: list[RetentionPlanEntry] = []
    for candidate in owner_dir.iterdir():
        if candidate == current or not is_strict_archive_name(candidate.name):
            continue
        bound_hash = bindings.get(candidate.name)
        if bound_hash is None:
            continue
        try:
            # A named NTFS stream is an unmodeled part of the archive object.
            # It must never be silently carried into an ownership proof.
            if alternate_data_streams(candidate):
                continue
            token = _path_token(candidate, regular=True, single_link=True)
            before_hash, token = _hash_regular(candidate, token)
        except BackupError:
            continue
        if before_hash != bound_hash:
            continue
        if verify_archive(
            candidate,
            owner,
            fingerprints,
            expected_token=token,
            cleanup_failure_fatal=True,
        ):
            try:
                after_hash, after_token = _hash_regular(candidate, token)
                if after_hash == bound_hash and _same_verified_token(after_token, token):
                    candidates.append(RetentionPlanEntry(candidate, after_token, after_hash))
            except BackupError:
                continue
    if not _path_token(owner_dir, directory=True).same_object(owner_token):
        raise BackupError("managed owner changed during retention planning", 3)
    candidates.sort(key=lambda candidate: candidate.path.name, reverse=True)
    return candidates[keep - 1:]


def _retention_report(plan: list[RetentionPlanEntry]) -> list[dict[str, object]]:
    return [{
        "archive": candidate.path.name,
        "action": "auto-delete-authorized",
        "sha256": candidate.sha256,
        "verified": True,
    } for candidate in plan]


def _apply_retention_plan(owner_dir: Path, plan: list[RetentionPlanEntry]) -> int:
    """Delete a pre-authorized plan with a final identity/hash recheck."""
    owner_token = _path_token(owner_dir, directory=True)
    deleted = 0
    for candidate in plan:
        if candidate.path.parent != owner_dir or not is_strict_archive_name(candidate.path.name):
            raise BackupError("retention candidate escaped managed owner", 3)
        if not _path_token(owner_dir, directory=True).same_object(owner_token):
            raise BackupError("managed owner changed before retention delete", 3)
        try:
            if alternate_data_streams(candidate.path):
                raise BackupError("retention candidate has alternate data streams", 3)
        except BackupError:
            raise
        digest, token = _hash_regular(candidate.path, candidate.token)
        if digest != candidate.sha256 or not _same_verified_token(token, candidate.token):
            raise BackupError("retention candidate changed before delete", 3)
        if not _safe_unlink_owned(candidate.path, token):
            raise BackupError("retention candidate delete was refused", 1)
        if _lexists(candidate.path):
            raise BackupError("retention candidate path reappeared", 3)
        if not _path_token(owner_dir, directory=True).same_object(owner_token):
            raise BackupError("managed owner changed after retention delete", 3)
        deleted += 1
    return deleted


def write_diagnostic(destination: Path, code: int, message: str, reparse_probe=None):
    try:
        assert_safe_output_path(destination, reparse_probe)
        diagnostics = destination / "diagnostics"
        assert_safe_output_path(diagnostics, reparse_probe)
        diagnostics.mkdir(parents=True, exist_ok=True)
        assert_safe_output_path(diagnostics, reparse_probe)
        name = f"diagnostic-{uuid.uuid4()}.json"
        encoded = json.dumps({"code": code, "message": re.sub(r"[\r\n]", " ", message)[:300]}).encode("utf-8")
        with _exclusive_output(diagnostics / name) as (handle, _):
            handle.write(encoded)
    except (OSError, BackupError):
        pass


def _registered_stage_inventory(path: Path) -> dict[str, tuple[str, FileToken]]:
    inventory: dict[str, tuple[str, FileToken]] = {}
    for root, directories, files in os.walk(path, topdown=True, followlinks=False):
        root_path = Path(root)
        for name in directories:
            child = root_path / name
            token = _path_token(child, directory=True)
            relative = child.relative_to(path).as_posix()
            if not safe_zip_name(relative):
                raise BackupError("unsafe staging inventory path", 3)
            inventory[relative] = ("directory", token)
        for name in files:
            child = root_path / name
            token = _path_token(child, regular=True, single_link=True)
            relative = child.relative_to(path).as_posix()
            if not safe_zip_name(relative):
                raise BackupError("unsafe staging inventory path", 3)
            inventory[relative] = ("file", token)
    return inventory


def _safe_rmtree_registered(path: Optional[Path], ledger: Optional[StageLedger],
                            between_rounds=None) -> bool:
    """Delete only an exactly registered run tree after two identical inventories."""
    if path is None or ledger is None or Path(path) != ledger.root:
        return False
    try:
        first_root = _path_token(path, directory=True)
        if not first_root.same_object(ledger.root_token):
            return False
        first = _registered_stage_inventory(path)
        if set(first) != set(ledger.entries):
            return False
        for relative, expected in ledger.entries.items():
            actual = first.get(relative)
            if (actual is None or actual[0] != expected[0]
                    or (not actual[1].same_object(expected[1]) if actual[0] == "directory"
                        else not _same_verified_token(actual[1], expected[1]))):
                return False
        if between_rounds is not None:
            between_rounds()
        second_root = _path_token(path, directory=True)
        second = _registered_stage_inventory(path)
        if not second_root.same_object(first_root) or set(second) != set(first):
            return False
        for relative, first_value in first.items():
            second_value = second[relative]
            if (second_value[0] != first_value[0]
                    or (not second_value[1].same_object(first_value[1]) if second_value[0] == "directory"
                        else not _same_verified_token(second_value[1], first_value[1]))):
                return False
        shutil.rmtree(path)
        return True
    except (OSError, BackupError):
        return False


def _safe_rmdir_owned(path: Optional[Path], owned: Optional[FileToken]) -> bool:
    if path is None or owned is None:
        return False
    try:
        current = _path_token(path, directory=True)
        if not current.same_object(owned) or any(path.iterdir()):
            return False
        path.rmdir()
        return True
    except (OSError, BackupError):
        return False


def _read_bound_manifest_read_only(archive: Path, owner_uuid: str, fingerprints: dict[str, str],
                                   expected_token: FileToken, expected_sha256: str) -> Optional[dict]:
    """Read enough of a published archive to bind it to trusted state.

    Unlike ``verify_archive`` this never materializes SQLite members, so it is
    safe for the scheduler's no-op decision.  Publication already performed
    the full SQLite/extraction verification; a real run repeats its normal
    verification independently.
    """
    try:
        with _stable_regular_reader(archive, expected_token) as handle:
            digest = hashlib.sha256()
            while True:
                block = handle.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
            if digest.hexdigest() != expected_sha256:
                return None
            handle.seek(0)
            with zipfile.ZipFile(handle) as zf:
                infos = zf.infolist()
                if not infos or len(infos) > MAX_ARCHIVE_ENTRIES:
                    return None
                seen, actual, total = set(), {}, 0
                for info in infos:
                    key = info.filename.casefold()
                    kind = _zip_member_kind(info)
                    total += info.file_size
                    if (kind is None or not safe_zip_name(info.filename) or key in seen
                            or info.flag_bits & 0x1 or total > MAX_ARCHIVE_TOTAL
                            or not _zip_info_within_budget(info, {
                                "max_archive_entry": MAX_ARCHIVE_ENTRY,
                                "max_archive_entries": MAX_ARCHIVE_ENTRIES,
                                "max_archive_total": MAX_ARCHIVE_TOTAL,
                                "max_compression_ratio": HARD_MAX_COMPRESSION_RATIO,
                            })):
                        return None
                    seen.add(key)
                    actual[info.filename] = (info, kind)
                if ("backup-manifest.json" not in actual or "RESTORE-NOTES.txt" not in actual
                        or actual["backup-manifest.json"][1] != "file"
                        or actual["RESTORE-NOTES.txt"][1] != "file"):
                    return None
                manifest = json.loads(_read_zip_limited(zf, "backup-manifest.json", MAX_MANIFEST_BYTES))
                if (not _valid_manifest_contract(manifest)
                        or manifest.get("owner_uuid") != owner_uuid
                        or manifest.get("source_fingerprints") != fingerprints
                        or manifest.get("archive") != archive.name):
                    return None
                if any(anchor not in actual for anchor in ASTRBOT_REQUIRED_ANCHORS):
                    return None
                notes = _read_zip_limited(zf, "RESTORE-NOTES.txt", MAX_METADATA_JSON_BYTES)
                if b"FULL_SUCCESS" not in notes:
                    return None
                return manifest
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, zipfile.BadZipFile, BackupError):
        return None


def scheduled_probe(args, now=None, state_loader=load_state) -> Result:
    """Decide whether a scheduled attempt is needed without touching source data.

    This is intentionally not a lightweight backup run.  It only reads the
    already-managed destination state and, for an in-cycle success, the bound
    archive manifest.  It never obtains either runtime mutex, checks a source
    process, opens a source path, creates a directory, or refreshes attempt
    timestamps.  ``run()`` repeats every state/schedule check before a real
    backup so this decision cannot authorize a later race.
    """
    try:
        if os.name != "nt":
            return Result(3, message="scheduled probe is unavailable")
        if not getattr(args, "scheduled", False):
            return Result(3, message="invalid scheduled probe request")
        destination = Path(args.destination)
        assert_local_path(destination)
        assert_safe_output_path(destination)
        week_start_index = getattr(args, "week_start_index", getattr(args, "week_start", 6))
        if week_start_index not in WEEKDAY_NAMES:
            return Result(3, message="invalid scheduled probe state")
        schedule_time = getattr(args, "schedule_time", "12:00")
        if (not isinstance(schedule_time, str)
                or re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", schedule_time) is None):
            return Result(3, message="invalid scheduled probe state")
        state = state_loader(destination)
        if state is None:
            return Result(3, message="scheduled probe state is unsafe")
        current = now or dt.datetime.now().astimezone()
        cycle = local_cycle(current, week_start_index)
        fingerprints = getattr(args, "probe_source_fingerprints", None)
        config_fp = getattr(args, "probe_config_fingerprint", None)
        artifact_digest = getattr(args, "artifact_digest", None)
        if (not isinstance(fingerprints, dict) or set(fingerprints) != {"astrbot_root", "napcat_root"}
                or not all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in fingerprints.values())
                or not isinstance(config_fp, str) or re.fullmatch(r"[0-9a-f]{64}", config_fp) is None
                or not isinstance(artifact_digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", artifact_digest) is None
                or artifact_digest == "0" * 64):
            return Result(3, message="scheduled probe context is unsafe")
        if state.get("source_fingerprints") != fingerprints:
            return Result(3, message="scheduled probe state is unsafe")
        if state.get("artifact_digest") != artifact_digest:
            return Result(3, message="scheduled probe state is unsafe")
        initialized = state.get("last_result") == "INITIALIZED"
        config_changed = state.get("config_fingerprint") != config_fp
        if initialized and config_changed:
            return Result(3, message="scheduled probe state is unsafe")
        if not initialized and state.get("napcat_enabled") != (args.napcat_root is not None):
            return Result(10, message="scheduled backup is due")
        last_utc = dt.datetime.fromisoformat(state["last_attempt_time_utc"])
        last_local = dt.datetime.fromisoformat(state["last_attempt_time_local"])
        if current.astimezone(dt.timezone.utc) < last_utc or current.astimezone(last_local.tzinfo) < last_local:
            return Result(3, message="scheduled probe state is unsafe")
        if initialized or config_changed:
            return Result(10, message="scheduled backup is due")
        prior = state.get("last_successful_cycle")
        if prior and prior > cycle:
            return Result(3, message="scheduled probe state is unsafe")
        if prior != cycle:
            return Result(10, message="scheduled backup is due")
        archive = destination / "managed" / state["owner_uuid"] / state["last_successful_archive"]
        token = _path_token(archive, regular=True, single_link=True)
        manifest = _read_bound_manifest_read_only(
            archive, state["owner_uuid"], state["source_fingerprints"], token,
            state["last_successful_archive_sha256"],
        )
        if manifest is None:
            return Result(3, message="scheduled probe state is unsafe")
        created = dt.datetime.fromisoformat(manifest["created_at"])
        cycle_date = dt.date.fromisoformat(cycle)
        if (manifest.get("cycle") != cycle
                or manifest.get("archive") != state["last_successful_archive"]
                or manifest.get("run_id") != archive_run_id(state["last_successful_archive"])
                or not (cycle_date <= created.date() <= cycle_date + dt.timedelta(days=6))):
            return Result(3, message="scheduled probe state is unsafe")
        return Result(0, noop=True)
    except (BackupError, OSError, ValueError, TypeError, KeyError, AttributeError):
        return Result(3, message="scheduled probe state is unsafe")


def _run(args, process_probe=default_process_probe, source_opener=windows_shared_read, now=None,
         archive_writer=None, state_writer=None, retention_runner=None, phase_hook=None,
         progress_sink: ProgressSink | None = None):
    if os.name != "nt":
        raise BackupError("this beta supports Windows only", 3)
    if getattr(args, "scheduled", False):
        bound_artifact = getattr(args, "artifact_digest", None)
        if (not isinstance(bound_artifact, str)
                or re.fullmatch(r"[0-9a-f]{64}", bound_artifact) is None
                or bound_artifact == "0" * 64):
            return Result(3, message="scheduled artifact binding is unsafe")
    if args.verify:
        return Result(0 if verify_archive(args.verify) else 1)
    supplied_now = now is not None
    now = now or dt.datetime.now().astimezone()
    started_at = now
    stage = None
    current_partial = None
    current_partial_owned = None
    current_final = None
    current_final_owned = None
    publish_attempted = False
    state_committed = False
    owner_dir = None
    owner_dir_owned = None
    owner_dir_created = False
    stage_owned = None
    stage_ledger = None
    destination_created = False
    destination_owned = None
    managed_created = False
    managed_owned = None
    logs_created = False
    logs_owned = None
    staging_created = False
    staging_owned = None
    destination = args.destination
    manual_mode = bool(getattr(args, "manual", False))
    napcat_enabled = args.napcat_root is not None
    week_start_index = getattr(args, "week_start_index", getattr(args, "week_start", 6))
    week_start_name = WEEKDAY_NAMES.get(week_start_index)
    schedule_time = getattr(args, "schedule_time", "12:00")
    if week_start_name is None:
        return Result(3, message="invalid week start")
    if not isinstance(schedule_time, str) or re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", schedule_time) is None:
        return Result(3, message="invalid schedule time")
    fingerprints = source_fingerprints(args.astrbot_root, args.napcat_root)
    config_fp = configuration_fingerprint(
        args.astrbot_root, args.napcat_root, destination, args.keep,
        week_start_index, schedule_time,
    )
    state = None
    state_trusted = False
    cycle = None
    phase = "output-gate"
    display_phase = "preflight"
    copied_items = 0
    copied_bytes = 0
    progress_started: set[str] = set()
    progress_completed: set[str] = set()
    last_progress_index = 0

    def emit_progress(display, status, total=0, current=0, unit="items", detail=""):
        """Progress is informational only: a bad UI callback cannot alter safety."""
        nonlocal last_progress_index
        if progress_sink is None:
            return
        index = ("preflight", "inventory", "copy", "sqlite", "archive", "verify", "publish").index(display) + 1
        # A display observer receives a finite state machine: never regress
        # indices, never restart a completed stage, and synthesize a redacted
        # start for an early failure that occurred before normal entry.
        if display in progress_completed or index < last_progress_index:
            return
        if status != "started" and display not in progress_started:
            try:
                progress_sink(ProgressEvent(display, index, 0, 0, "items", "started", ""))
            except BaseException:
                pass
            progress_started.add(display)
            last_progress_index = index
        if status == "started" and display in progress_started:
            return
        try:
            event = ProgressEvent(
                display, index,
                int(total), int(current), unit, status, detail,
            )
            progress_sink(event)
        except BaseException:
            pass
        if status == "started":
            progress_started.add(display)
        if status == "complete":
            progress_completed.add(display)
        last_progress_index = max(last_progress_index, index)

    def enter_phase(name):
        nonlocal phase
        phase = name
        if phase_hook is not None:
            phase_hook(name, stage, stage_ledger)

    def persist_failed_attempt(code):
        # A manual snapshot must not turn an automatic FULL_SUCCESS/INITIALIZED
        # state into FAILED/DEGRADED.  Its failure is reported by the visible
        # runner, while the scheduler's authoritative cycle remains untouched.
        if (manual_mode or not state_trusted or state is None
                or cycle is None or code not in {1, 2}):
            return True
        try:
            assert_safe_output_path(destination)
            commit_state(destination, failed_attempt_state(state, now, cycle, code, phase), state_writer)
            return True
        except (OSError, BackupError, ValueError, TypeError):
            return False

    def cleanup_empty_scaffolding():
        ok = True
        for path, created, token in (
            (destination / "staging", staging_created, staging_owned),
            (destination / "logs", logs_created, logs_owned),
            (destination / "managed", managed_created, managed_owned),
            (destination, destination_created, destination_owned),
        ):
            if created and token is not None:
                ok = _safe_rmdir_owned(path, token) and ok
        return ok

    try:
        enter_phase("output-gate")
        assert_local_path(args.astrbot_root)
        if args.napcat_root is not None:
            assert_local_path(args.napcat_root)
        assert_local_path(destination)
        assert_safe_output_path(destination)
        enter_phase("state-load")
        state = load_state(destination)
        state_trusted = state is not None
        cycle = local_cycle(now, week_start_index)
        initialized_state = state is not None and state.get("last_result") == "INITIALIZED"
        config_changed = state is not None and state["config_fingerprint"] != config_fp
        if state:
            if state.get("source_fingerprints") != fingerprints:
                raise BackupError("source fingerprint changed", 3)
            supplied_artifact = getattr(args, "artifact_digest", None)
            if supplied_artifact is not None and state.get("artifact_digest") != supplied_artifact:
                raise BackupError("plugin artifact binding changed", 3)
            if initialized_state and config_changed:
                raise BackupError("initial setup configuration changed", 3)
            if not initialized_state and state.get("napcat_enabled") != napcat_enabled:
                raise BackupError("NapCat enablement changed", 1)
            last_utc = dt.datetime.fromisoformat(state["last_attempt_time_utc"])
            last_local = dt.datetime.fromisoformat(state["last_attempt_time_local"])
            if now.astimezone(dt.timezone.utc) < last_utc or now.astimezone(last_local.tzinfo) < last_local:
                raise BackupError("state time rollback", 3)
        enter_phase("schedule-check")
        if state and not initialized_state and args.scheduled:
            prior = state.get("last_successful_cycle")
            if prior and prior > cycle and not config_changed:
                raise BackupError("scheduled time/cycle rollback", 3)
        if state and not initialized_state and args.scheduled and not args.force and not config_changed:
            owner_file = destination / "managed" / state["owner_uuid"] / state["last_successful_archive"]
            if prior == cycle:
                try:
                    owner_file_token = _path_token(owner_file, regular=True, single_link=True)
                except BackupError as exc:
                    raise BackupError("scheduled state/archive is inconsistent", 3) from exc
                noop_hash, owner_file_token = _hash_regular(owner_file, owner_file_token)
                verified_manifest = read_verified_manifest(
                    owner_file, state["owner_uuid"], state["source_fingerprints"], expected_token=owner_file_token
                )
                if verified_manifest is None:
                    raise BackupError("scheduled state/archive is inconsistent", 3)
                created = dt.datetime.fromisoformat(verified_manifest["created_at"])
                cycle_date = dt.date.fromisoformat(cycle)
                if (verified_manifest["cycle"] != cycle or state["last_successful_cycle"] != cycle
                        or verified_manifest["archive"] != state["last_successful_archive"]
                        or verified_manifest["run_id"] != archive_run_id(state["last_successful_archive"])
                        or not (cycle_date <= created.date() <= cycle_date + dt.timedelta(days=6))):
                    raise BackupError("scheduled manifest/state/cycle mismatch", 3)
                after_noop_hash, after_noop_token = _hash_regular(owner_file, owner_file_token)
                if noop_hash != after_noop_hash or not _same_verified_token(after_noop_token, owner_file_token):
                    raise BackupError("scheduled archive changed during verification", 3)
                updated_state = dict(state)
                updated_state["timezone"] = str(now.tzinfo)
                updated_state["last_attempt_time_utc"] = now.astimezone(dt.timezone.utc).isoformat()
                updated_state["last_attempt_time_local"] = now.isoformat()
                commit_state(destination, updated_state, state_writer)
                return Result(0, noop=True, message="weekly cycle already successful")
        enter_phase("process-check")
        display_phase = "preflight"
        emit_progress("preflight", "started", 1, 0)
        check_process(process_probe, args.astrbot_root)
        emit_progress("preflight", "complete", 1, 1)
        enter_phase("astrbot-inventory")
        display_phase = "inventory"
        emit_progress("inventory", "started")
        astr = walk_files(args.astrbot_root / "data", "AstrBot/data", source_opener)
        astr_by_name = {item.archive: item for item in astr}
        for anchor in ASTRBOT_REQUIRED_ANCHORS:
            item = astr_by_name.get(anchor)
            expected_kind = "directory" if anchor.endswith("/") else "file"
            if item is None or item.kind != expected_kind:
                raise BackupError("required AstrBot configuration anchor is missing", 1)
        enter_phase("napcat-inventory")
        nap, version, napcat_whitelist = (
            napcat_items(args.napcat_root, source_opener)
            if napcat_enabled else ([], DISABLED_NAPCAT, [])
        )
        all_items = astr + nap
        ensure_unique_archive_names([item.archive for item in all_items])
        directory_count = sum(1 for item in all_items if item.kind == "directory")
        emit_progress("inventory", "progress", directory_count, directory_count, "directories")
        emit_progress("inventory", "complete", len(all_items), len(all_items), "items")
        enter_phase("layout-check")
        layout = database_layout(astr, source_opener)
        if state and not initialized_state:
            if not compatible_database_layout_transition(state.get("database_layout"), layout):
                raise BackupError("SQLite candidate layout drift", 1)
            if state.get("napcat_version") != version:
                raise BackupError("NapCat version layout drift", 1)
            if not compatible_napcat_whitelist_transition(
                    state.get("napcat_whitelist"), napcat_whitelist, version):
                raise BackupError("NapCat whitelist layout drift; use a new empty destination", 1)
            registered = destination / "managed" / state["owner_uuid"] / state["last_successful_archive"]
            registered_token = _path_token(registered, regular=True, single_link=True)
            if not verify_archive(
                registered, state["owner_uuid"], fingerprints, expected_token=registered_token
            ):
                raise BackupError("registered successful archive is missing or invalid", 3)
        source_bytes = sum(x.size for x in all_items)
        db_bytes = sum(x.size for x in astr if x.archive in layout["mains"] or x.archive.casefold().endswith(SIDECARS))
        required_space = required_free_space(source_bytes, db_bytes, sum(x.size for x in nap))
        if available_space_without_creating(destination) < required_space:
            raise BackupError("insufficient free space", 1)
        if args.preflight:
            return Result(0, message="preflight passed")
        enter_phase("staging-create")
        if not _lexists(destination):
            _path_token(destination.parent, directory=True)
            destination.mkdir(exist_ok=False)
            destination_created = True
            destination_owned = _path_token(destination, directory=True)
        else:
            _path_token(destination, directory=True)
            if state is None and any(destination.iterdir()):
                raise BackupError("initial destination changed and is no longer empty", 3)
        free = shutil.disk_usage(destination).free
        if free < required_space:
            raise BackupError("insufficient free space", 1)
        owner = state["owner_uuid"] if state else str(uuid.uuid4())
        assert_safe_output_path(destination)
        managed = destination / "managed"
        if _lexists(managed) and is_reparse(managed):
            raise BackupError("managed directory is a reparse point", 3)
        if not _lexists(managed):
            managed.mkdir()
            managed_created = True
            managed_owned = _path_token(managed, directory=True)
        else:
            _path_token(managed, directory=True)
        owner_dir = managed / owner
        if _lexists(owner_dir) and is_reparse(owner_dir):
            raise BackupError("managed owner is a reparse point", 3)
        owner_dir_created = not _lexists(owner_dir)
        owner_dir.mkdir(exist_ok=True)
        owner_dir_owned = _path_token(owner_dir, directory=True)
        logs_dir = destination / "logs"
        if not _lexists(logs_dir):
            logs_dir.mkdir()
            logs_created = True
            logs_owned = _path_token(logs_dir, directory=True)
        else:
            _path_token(logs_dir, directory=True)
        staging_dir = destination / "staging"
        if not _lexists(staging_dir):
            staging_dir.mkdir()
            staging_created = True
            staging_owned = _path_token(staging_dir, directory=True)
        else:
            _path_token(staging_dir, directory=True)
        for output in (managed, owner_dir, destination / "logs", destination / "staging", destination / "diagnostics"):
            assert_safe_output_path(output)
        run_id = str(uuid.uuid4())
        stage = staging_dir / run_id
        if _lexists(stage):
            raise BackupError("run staging UUID path already exists", 3)
        stage.mkdir()
        stage_owned = _path_token(stage, directory=True)
        stage_ledger = StageLedger(stage)
        enter_phase("copy")
        display_phase = "copy"
        emit_progress("copy", "started", source_bytes, 0, "bytes")
        def copied(_item, copied):
            nonlocal copied_items, copied_bytes
            copied_items += 1
            copied_bytes += copied
            emit_progress("copy", "progress", source_bytes, copied_bytes, "bytes", "item")
            emit_progress("copy", "progress", len(all_items), copied_items, "items", "item")
        for item in all_items:
            copy_item(item, stage, source_opener, stage_ledger, copied)
        emit_progress("copy", "complete", source_bytes, copied_bytes, "bytes")
        enter_phase("post-process-check")
        check_process(process_probe, args.astrbot_root)
        enter_phase("post-copy-check")
        changed = compare_post(all_items, source_opener)
        if changed:
            code = classify_drift([item.area for item in changed])
            raise BackupError("source drift detected after copying", code)
        enter_phase("post-inventory")
        post_astr = walk_files(args.astrbot_root / "data", "AstrBot/data", source_opener)
        post_nap, post_version, post_whitelist = (
            napcat_items(args.napcat_root, source_opener)
            if napcat_enabled else ([], DISABLED_NAPCAT, [])
        )
        before_by_name = {x.archive: x for x in all_items}
        after_by_name = {x.archive: x for x in post_astr + post_nap}
        differing = {name for name in set(before_by_name) | set(after_by_name)
                     if before_by_name.get(name) != after_by_name.get(name)}
        if differing or post_version != version or post_whitelist != napcat_whitelist:
            napcat_changed = (post_version != version or post_whitelist != napcat_whitelist
                              or any(not name.startswith("AstrBot/data/") for name in differing))
            areas = [name.split("/")[2] for name in differing
                     if name.startswith("AstrBot/data/") and len(name.split("/")) > 2]
            raise BackupError("source post-enumeration drift detected after copying", 1 if napcat_changed else classify_drift(areas))
        if database_layout(post_astr, source_opener) != layout:
            raise BackupError("SQLite candidate layout changed during backup", 1)
        check_process(process_probe, args.astrbot_root)
        enter_phase("normalize")
        display_phase = "sqlite"
        family_count = len(layout.get("mains", []))
        emit_progress("sqlite", "started", family_count, 0, "families")
        database_results, omitted = normalize_databases(stage, layout, stage_ledger)
        emit_progress("sqlite", "complete", family_count, family_count, "families")
        stage_ledger.seal()
        volumes = {"astrbot_source": args.astrbot_root.drive or args.astrbot_root.anchor,
                   "napcat_source": ((args.napcat_root.drive or args.napcat_root.anchor)
                                      if napcat_enabled else DISABLED_NAPCAT),
                   "destination": destination.drive or destination.anchor}
        name = "astrbot-safe-backup-" + now.strftime("%Y%m%d-%H%M%S") + "-" + run_id + ".zip"
        source_entries = [{"path": item.archive, "kind": item.kind, "mtime_ns": item.mtime_ns}
                          for item in all_items]
        root_config_anchors = list(ASTRBOT_REQUIRED_ANCHORS)
        finished_at = now if supplied_now else dt.datetime.now().astimezone()
        manifest = archive_manifest(owner, run_id, name, fingerprints, version, cycle,
                                    source_entries, database_results, layout, volumes, now,
                                    napcat_enabled=napcat_enabled, week_start=week_start_name,
                                    schedule_time=schedule_time,
                                    napcat_whitelist=napcat_whitelist,
                                    root_config_anchors=root_config_anchors,
                                    started_at=started_at, finished_at=finished_at,
                                    limits=archive_budget(source_bytes, len(source_entries)))
        partial = owner_dir / (name[:-4] + ".partial.zip")
        current_partial = partial
        final = owner_dir / name
        current_final = final
        enter_phase("archive-write")
        display_phase = "archive"
        emit_progress("archive", "started", 0, 0, "archive")
        with _exclusive_output(partial) as (partial_output, current_partial_owned):
            (archive_writer or write_archive)(partial, stage, omitted, manifest, partial_output)
        partial_token = _path_token(partial, regular=True, single_link=True)
        if not partial_token.same_object(current_partial_owned):
            raise BackupError("partial archive identity changed while writing", 3)
        partial_hash_before, partial_token = _hash_regular(partial, partial_token)
        emit_progress("archive", "complete", partial_token.size, partial_token.size, "bytes", "archive")
        enter_phase("archive-verify")
        display_phase = "verify"
        emit_progress("verify", "started", len(source_entries), 0, "entries")
        if not verify_archive(partial, owner, fingerprints, expected_token=partial_token):
            raise BackupError("archive verification failed", 1)
        after_verify = _path_token(partial, regular=True, single_link=True)
        if not _same_verified_token(after_verify, partial_token):
            raise BackupError("verified partial identity changed", 3)
        partial_hash, after_verify = _hash_regular(partial, after_verify)
        if partial_hash != partial_hash_before:
            raise BackupError("partial archive bytes changed during verification", 3)
        emit_progress("verify", "progress", len(source_entries), len(source_entries), "entries")
        emit_progress("verify", "complete", len(source_entries), len(source_entries), "entries")
        enter_phase("staging-cleanup")
        if not _safe_rmtree_registered(stage, stage_ledger):
            raise BackupError("verified staging cleanup failed", 1)
        stage = None
        stage_owned = None
        stage_ledger = None
        check_process(process_probe, args.astrbot_root)
        enter_phase("publish")
        display_phase = "publish"
        emit_progress("publish", "started", 1, 0)
        publish_attempted = True
        current_final_owned = publish_no_replace(partial, final, after_verify, partial_hash)
        enter_phase("final-verify")
        if not verify_archive(final, owner, fingerprints, expected_token=current_final_owned):
            raise BackupError("published final verification failed", 1)
        final_after_verify = _path_token(final, regular=True, single_link=True)
        if not _same_verified_token(final_after_verify, current_final_owned):
            raise BackupError("published final identity changed after verification", 3)
        final_hash, final_after_verify = _hash_regular(final, final_after_verify)
        if final_hash != partial_hash:
            raise BackupError("published final bytes differ from verified partial", 3)
        current_final_owned = final_after_verify
        emit_progress("publish", "progress", 1, 1, "items", "final_verified")
        check_process(process_probe, args.astrbot_root)
        if manual_mode:
            # Keep the scheduled state exactly as it was.  If a user selected
            # a brand-new empty manual destination, create only the normal
            # INITIALIZED ledger so a second manual run can reuse that target;
            # INITIALIZED has no successful cycle/archive and therefore cannot
            # satisfy the scheduler's success probe.
            if state is None:
                manual_state = initial_state(
                    owner_uuid=owner,
                    source_fingerprints=fingerprints,
                    config_fingerprint=config_fp,
                    week_start=week_start_index,
                    schedule_time=schedule_time,
                    artifact_digest=(getattr(args, "artifact_digest", None)
                                     or "0" * 64),
                    now=now,
                )
                enter_phase("state-commit")
                commit_state(destination, manual_state, state_writer)
                state_committed = True
                state = load_state(destination)
                if (state is None or state.get("last_result") != "INITIALIZED"
                        or state.get("owner_uuid") != owner):
                    raise BackupError("manual initialization state could not be proven", 3)
            emit_progress("publish", "complete", 1, 1)
            return Result(
                0, archive=final, retention_candidates=[],
                message="manual snapshot completed; scheduled cycle unchanged",
                publication_disposition="full_success", archive_sha256=final_hash,
                counts_as_scheduled_success=False,
            )
        retention_candidates = []
        new_state = {"schema": SCHEMA, "schema_version": SCHEMA, "managed_by": GENERATOR,
                     "state_namespace": "community-v1", "owner_uuid": owner,
                     "source_fingerprint": fingerprints["astrbot_root"], "config_fingerprint": config_fp,
                     "artifact_digest": getattr(args, "artifact_digest", None) or (state.get("artifact_digest", "0" * 64) if state else "0" * 64),
                     "source_fingerprints": fingerprints, "database_layout": layout,
                     "napcat_enabled": napcat_enabled, "napcat_version": version,
                     "napcat_whitelist": napcat_whitelist, "week_start": week_start_name,
                     "schedule_time": schedule_time,
                     "timezone": str(now.tzinfo), "last_cycle": cycle,
                     "last_success_cycle": cycle, "last_success_archive": name, "last_success_archive_sha256": final_hash,
                     "last_successful_cycle": cycle, "last_successful_archive": name, "last_successful_archive_sha256": final_hash, "last_result": "FULL_SUCCESS",
                     "last_attempt_time_utc": now.astimezone(dt.timezone.utc).isoformat(),
                     "last_attempt_time_local": now.isoformat(),
                     "retention_candidates": retention_candidates}
        enter_phase("state-commit")
        commit_state(destination, new_state, state_writer)
        state_committed = True
        state = load_state(destination)
        if state is None or state.get("last_success_archive_sha256") != final_hash:
            raise BackupError("committed success state could not be proven", 3)
        state_trusted = True
        retention_warning = ""
        try:
            enter_phase("retention")
            retention_plan = (retention_runner or retain)(
                owner_dir, args.keep, owner, fingerprints, final
            )
            if (not isinstance(retention_plan, list)
                    or not all(isinstance(item, RetentionPlanEntry) for item in retention_plan)
                    or len(retention_plan) > 100):
                raise BackupError("invalid automatic retention plan", 3)
            retention_candidates = _retention_report(retention_plan)
            if retention_candidates:
                authorized_state = dict(state)
                authorized_state["retention_candidates"] = retention_candidates
                commit_state(destination, authorized_state, state_writer)
                authorized = load_state(destination)
                if (authorized is None
                        or authorized.get("retention_candidates") != retention_candidates
                        or authorized.get("last_success_archive_sha256") != final_hash):
                    raise BackupError("retention authorization state could not be proven", 3)
                state = authorized
                _apply_retention_plan(owner_dir, retention_plan)
        except BackupError:
            # The new archive and success state are already durable.  Retention
            # is best-effort after that point: never roll back a valid backup or
            # delete an unproven object merely to force the configured count.
            retention_warning = "backup succeeded; automatic retention was safely skipped"
            write_diagnostic(destination, 1, retention_warning)
        emit_progress("publish", "complete", 1, 1)
        return Result(0, archive=final, retention_candidates=retention_candidates,
                      message=retention_warning,
                      publication_disposition="full_success", archive_sha256=final_hash)
    except BackupError as exc:
        emit_progress(display_phase, "failed", 1, 0, "items", "failed")
        stage_cleanup_ok = (
            stage is None or stage_ledger is None
            or _safe_rmtree_registered(stage, stage_ledger)
        )
        _safe_unlink_owned(current_partial, current_partial_owned)
        final_cleanup_ok = True
        if not state_committed and current_final is not None:
            final_cleanup_ok = _safe_unlink_owned(current_final, current_final_owned)
        if owner_dir_created:
            _safe_rmdir_owned(owner_dir, owner_dir_owned)
        scaffolding_ok = True if state_committed else cleanup_empty_scaffolding()
        failure_code = exc.code
        failure_message = str(exc)
        if not stage_cleanup_ok:
            failure_message += "; staging cleanup failed; quarantine preserved"
        elif not scaffolding_ok:
            failure_message += "; output cleanup failed; quarantine preserved"
        state_updated = persist_failed_attempt(failure_code)
        if not state_updated:
            failure_message += "; failed-attempt state update failed"
        if not args.preflight and state_trusted:
            write_diagnostic(destination, failure_code, failure_message)
        publication = (
            ("quarantine_possible" if publish_attempted else "never_published") if current_final_owned is None
            else ("cleaned" if final_cleanup_ok else "quarantine_possible")
        )
        return Result(failure_code, message=failure_message,
                      publication_disposition=publication)
    except (OSError, ValueError, TypeError, AttributeError, KeyError, UnicodeError, json.JSONDecodeError, sqlite3.Error, zipfile.BadZipFile) as exc:
        emit_progress(display_phase, "failed", 1, 0, "items", "failed")
        stage_cleanup_ok = (
            stage is None or stage_ledger is None
            or _safe_rmtree_registered(stage, stage_ledger)
        )
        _safe_unlink_owned(current_partial, current_partial_owned)
        final_cleanup_ok = True
        if not state_committed and current_final is not None:
            final_cleanup_ok = _safe_unlink_owned(current_final, current_final_owned)
        if owner_dir_created:
            _safe_rmdir_owned(owner_dir, owner_dir_owned)
        scaffolding_ok = True if state_committed else cleanup_empty_scaffolding()
        state_updated = persist_failed_attempt(1)
        failure_message = "I/O failure"
        if not stage_cleanup_ok:
            failure_message += "; staging cleanup failed; quarantine preserved"
        elif not scaffolding_ok:
            failure_message += "; output cleanup failed; quarantine preserved"
        if not state_updated:
            failure_message += "; failed-attempt state update failed"
        if not args.preflight and state_trusted:
            write_diagnostic(destination, 1, failure_message)
        publication = (
            ("quarantine_possible" if publish_attempted else "never_published") if current_final_owned is None
            else ("cleaned" if final_cleanup_ok else "quarantine_possible")
        )
        return Result(1, message=failure_message, publication_disposition=publication)


_LOCAL_MUTEXES = set()

class _Guard:
    def __init__(self, name): self.name = name
    def release(self): _LOCAL_MUTEXES.discard(self.name)


class _WinMutexGuard:
    def __init__(self, kernel, handle):
        self.kernel = kernel
        self.handle = handle

    def release(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def runtime_mutex_name(root: Path) -> str:
    digest = hashlib.sha256(_key(root).encode("utf-8")).hexdigest()
    return "Local\\AstrBotSafeBackup-Running-" + digest


def _create_runtime_mutex(root: Path):
    if os.name != "nt":
        return None, None, None
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
    kernel.CreateMutexW.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_bool
    handle = kernel.CreateMutexW(None, False, runtime_mutex_name(root))
    if not handle:
        return kernel, None, None
    return kernel, handle, ctypes.get_last_error() == 183


def acquire_runtime_marker(root: Path):
    """Hold the AstrBot-running marker for the plugin lifetime."""
    kernel, handle, _already_exists = _create_runtime_mutex(root)
    if handle is None:
        return None
    return _WinMutexGuard(kernel, handle)


def default_astrbot_offline_guard(root: Path):
    """Acquire the running marker only when no AstrBot plugin instance holds it."""
    kernel, handle, already_exists = _create_runtime_mutex(root)
    if handle is None or already_exists is None:
        return None
    if already_exists:
        kernel.CloseHandle(handle)
        return False
    return _WinMutexGuard(kernel, handle)

def default_instance_guard(destination: Path):
    name = "Local\\AstrBotSafeBackup-" + hashlib.sha256(_key(destination).encode()).hexdigest()
    if os.name != "nt":
        if name in _LOCAL_MUTEXES:
            return False
        _LOCAL_MUTEXES.add(name)
        return _Guard(name)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
    kernel.CreateMutexW.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_bool
    kernel.GetLastError.argtypes = []
    kernel.GetLastError.restype = ctypes.c_uint32
    handle = kernel.CreateMutexW(None, False, name)
    if not handle:
        return False
    if kernel.GetLastError() == 183:
        kernel.CloseHandle(handle)
        return False
    guard = _Guard(name)
    guard.release = lambda: kernel.CloseHandle(handle)
    return guard

def run(args, process_probe=default_process_probe, source_opener=windows_shared_read, now=None,
        instance_guard=None, archive_writer=None, state_writer=None, retention_runner=None,
        phase_hook=None, offline_guard=None, progress_sink: ProgressSink | None = None):
    try:
        if getattr(args, "scheduled_probe", False):
            return scheduled_probe(args, now=now)
        if os.name != "nt":
            return Result(3, message="this beta supports Windows only")
        if args.verify:
            return _run(args, process_probe, source_opener, now, archive_writer, state_writer,
                        retention_runner, phase_hook, progress_sink)
        guard = (instance_guard or default_instance_guard)(args.destination)
        if guard is False or guard is None:
            return Result(3, message="another backup instance is active")
        try:
            runtime_guard = (offline_guard or default_astrbot_offline_guard)(args.astrbot_root)
            if runtime_guard is False or runtime_guard is None:
                return Result(1, message="AstrBot runtime mutex is held or indeterminate")
            try:
                return _run(args, process_probe, source_opener, now, archive_writer, state_writer,
                            retention_runner, phase_hook, progress_sink)
            finally:
                runtime_release = getattr(runtime_guard, "release", None)
                if callable(runtime_release):
                    runtime_release()
        finally:
            release = getattr(guard, "release", None)
            if callable(release):
                release()
    except BackupError as exc:
        return Result(exc.code, message=str(exc))


def main(argv=None):
    try:
        result = run(parse_args(argv))
        if result.message:
            print(result.message, file=sys.stderr if result.code else sys.stdout)
        return result.code
    except BackupError as exc:
        print(str(exc), file=sys.stderr)
        return exc.code


if __name__ == "__main__":
    raise SystemExit(main())
