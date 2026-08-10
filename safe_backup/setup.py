"""Safe, local-only setup helpers for the community backup plugin."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import ntpath
import os
import re
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .engine import (
    BackupError,
    WEEKDAYS,
    _lexists,
    _path_token,
    _safe_rmdir_owned,
    _safe_unlink_owned,
    assert_local_path,
    assert_safe_output_path,
    checked_absolute,
    commit_state,
    configuration_fingerprint,
    initial_state,
    reject_overlap,
    resolve_safe_source,
    source_fingerprints,
)


SETUP_FREE_SPACE_FLOOR = 512 * 1024 * 1024


@dataclass(frozen=True)
class SetupConfig:
    astrbot_root: Path
    destination: Path
    napcat_root: Path | None
    plugin_dir: Path
    python_path: Path
    retention: int
    week_start: int
    schedule_time: str
    source_fingerprint: str
    source_fingerprints: dict[str, str]
    config_fingerprint: str
    artifact_digest: str = "0" * 64


@dataclass
class InitializationLedger:
    """Per-call ownership proof used only for transactional rollback."""
    parent_created: bool = False
    destination_created: bool = False
    parent_token: object | None = None
    destination_token: object | None = None
    managed_token: object | None = None
    owner_token: object | None = None
    owner_uuid: str | None = None
    state: dict[str, object] | None = None


def resolved_default_destination(root: Path, user_profile: Path) -> Path:
    """Return the per-source default without inspecting source contents."""
    fingerprint = source_fingerprints(root, None)["astrbot_root"][:12]
    return Path(user_profile) / "AstrBotSafeBackups" / fingerprint


def artifact_digest(plugin_dir: Path) -> str:
    """Bind the executable plugin surface used by the scheduled task."""
    paths = (
        plugin_dir / "scripts" / "task_launcher.ps1",
        plugin_dir / "scripts" / "run_backup_visible.ps1",
        plugin_dir / "safe_backup" / "engine.py",
        plugin_dir / "safe_backup" / "console_runner.py",
        plugin_dir / "safe_backup" / "progress.py",
        plugin_dir / "scripts" / "task_common.ps1",
    )
    records = {}
    try:
        for path in paths:
            _path_token(path, regular=True, single_link=True)
            records[path.name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    except (OSError, BackupError):
        # Unit-only bare setup construction does not imply a deployable plugin;
        # the host compatibility gate rejects that package before setup writes.
        return "0" * 64
    return hashlib.sha256(json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _checked_local_absolute(value: Path | str, *, source: bool = False) -> Path:
    path = resolve_safe_source(value) if source else checked_absolute(value)
    assert_local_path(path)
    return path


def _checked_output_absolute(value: Path | str) -> Path:
    """Gate the lexical output chain before ``resolve`` can hide a junction."""
    raw = Path(value)
    if not raw.is_absolute():
        raise BackupError("all paths must be absolute", 3)
    raw_text = str(raw)
    drive, tail = ntpath.splitdrive(raw_text)
    # NTFS alternate streams may only use a colon after the drive designator;
    # accepting one would make the output boundary ambiguous.  A volume root
    # is likewise never a dedicated, setup-owned destination.
    if ":" in tail or raw == Path(raw.anchor):
        raise BackupError("output path must be a dedicated local directory", 3)
    assert_local_path(raw)
    assert_safe_output_path(raw)
    # ``..`` segments can make a non-root lexical path resolve to a volume
    # root.  Re-check the resolved value too: the lexical checks above remain
    # necessary because resolve() would otherwise hide a junction in the raw
    # ancestor chain.
    resolved = raw.resolve(strict=False)
    if not resolved.is_absolute():
        raise BackupError("all paths must be absolute", 3)
    resolved_text = str(resolved)
    _resolved_drive, resolved_tail = ntpath.splitdrive(resolved_text)
    if ":" in resolved_tail or resolved == Path(resolved.anchor):
        raise BackupError("output path must be a dedicated local directory", 3)
    assert_local_path(resolved)
    return resolved


def build_setup_config(*, astrbot_root: Path | str, destination_text: str,
                       user_profile: Path | str, plugin_dir: Path | str,
                       python_path: Path | str, retention: int, weekday: str,
                       schedule_time: str, napcat_root: Path | str | None) -> SetupConfig:
    """Validate setup inputs without walking a source tree or opening SQLite."""
    astrbot = _checked_local_absolute(astrbot_root, source=True)
    napcat = _checked_local_absolute(napcat_root, source=True) if napcat_root else None
    profile = _checked_output_absolute(user_profile)
    plugin = _checked_local_absolute(plugin_dir, source=True)
    python = _checked_local_absolute(python_path, source=True)
    if not isinstance(destination_text, str):
        raise BackupError("destination must be text", 3)
    destination = (
        _checked_output_absolute(resolved_default_destination(astrbot, profile))
        if not destination_text.strip() else _checked_output_absolute(destination_text)
    )
    reject_overlap(astrbot, napcat, destination)
    if not isinstance(retention, int) or isinstance(retention, bool) or not 1 <= retention <= 30:
        raise BackupError("retention must be between 1 and 30", 3)
    if not isinstance(weekday, str) or weekday.casefold() not in WEEKDAYS:
        raise BackupError("invalid schedule weekday", 3)
    if (not isinstance(schedule_time, str)
            or re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", schedule_time) is None):
        raise BackupError("schedule time must be HH:MM", 3)
    fingerprints = source_fingerprints(astrbot, napcat)
    week_start = WEEKDAYS[weekday.casefold()]
    return SetupConfig(
        astrbot_root=astrbot,
        destination=destination,
        napcat_root=napcat,
        plugin_dir=plugin,
        python_path=python,
        retention=retention,
        week_start=week_start,
        schedule_time=schedule_time,
        source_fingerprint=fingerprints["astrbot_root"],
        source_fingerprints=fingerprints,
        config_fingerprint=configuration_fingerprint(
            astrbot, napcat, destination, retention, week_start, schedule_time
        ), artifact_digest=artifact_digest(plugin),
    )


def _probe_free_space(path: Path, probe: Optional[Callable[[Path], int]]) -> int:
    return int((probe or (lambda value: shutil.disk_usage(value).free))(path))


def _volume_supports_hardlinks(path: Path, probe: Optional[Callable[[Path], object]]) -> bool:
    if probe is None:
        return True
    result = probe(path)
    return result is True or (isinstance(result, str) and result.casefold() == "ntfs")


def _verify_hardlink_capability(destination: Path,
                                volume_probe: Optional[Callable[[Path], object]]) -> None:
    """Prove hard-link support using only two registered, run-owned leaf files."""
    if not _volume_supports_hardlinks(destination, volume_probe):
        raise BackupError("destination volume must support NTFS hard links", 3)
    run_id = str(uuid.uuid4())
    probe = destination / f".safe-backup-setup-{run_id}.probe"
    alias = destination / f".safe-backup-setup-{run_id}.link"
    probe_token = alias_token = None
    try:
        with open(probe, "xb"):
            pass
        probe_token = _path_token(probe, regular=True, single_link=True)
        os.link(probe, alias, follow_symlinks=False)
        probe_after_link = _path_token(probe, regular=True)
        alias_token = _path_token(alias, regular=True)
        if (not probe_after_link.same_object(probe_token)
                or not alias_token.same_object(probe_token)
                or probe_after_link.nlink != 2 or alias_token.nlink != 2):
            raise BackupError("destination hard-link capability verification failed", 3)
        if not _safe_unlink_owned(alias, alias_token):
            raise BackupError("setup hard-link probe cleanup failed", 3)
        alias_token = None
        probe_token = _path_token(probe, regular=True, single_link=True)
        if not _safe_unlink_owned(probe, probe_token):
            raise BackupError("setup hard-link probe cleanup failed", 3)
        probe_token = None
    except OSError as exc:
        raise BackupError("destination volume must support NTFS hard links", 3) from exc
    finally:
        # Exact-identity cleanup only: leave a partially-created link pair for
        # inspection rather than risking deletion after an uncertain failure.
        if alias_token is None and not _lexists(alias):
            _safe_unlink_owned(probe, probe_token)


def initialize_destination(config: SetupConfig, *, now: Optional[dt.datetime] = None,
                           writer=None, free_space_probe: Optional[Callable[[Path], int]] = None,
                           volume_probe: Optional[Callable[[Path], object]] = None,
                           ledger: InitializationLedger | None = None) -> dict[str, object]:
    """Create the authoritative first-run journal; never inspect backup sources."""
    destination = config.destination
    parent_created = destination_created = managed_created = owner_created = False
    parent_token = destination_token = managed_token = owner_token = None
    owner = None
    try:
        assert_local_path(config.astrbot_root)
        if config.napcat_root is not None:
            assert_local_path(config.napcat_root)
        assert_local_path(destination)
        assert_safe_output_path(destination)
        reject_overlap(config.astrbot_root, config.napcat_root, destination)
        parent = destination.parent
        if not _lexists(parent):
            _path_token(parent.parent, directory=True)
            parent.mkdir(exist_ok=False)
            parent_created = True
            parent_token = _path_token(parent, directory=True)
        else:
            _path_token(parent, directory=True)
        if _probe_free_space(parent, free_space_probe) < SETUP_FREE_SPACE_FLOOR:
            raise BackupError("insufficient free space for setup", 1)
        if _lexists(destination):
            _path_token(destination, directory=True)
            if any(destination.iterdir()):
                raise BackupError("initial destination must be completely empty", 3)
        else:
            destination.mkdir(exist_ok=False)
            destination_created = True
            destination_token = _path_token(destination, directory=True)
        _verify_hardlink_capability(destination, volume_probe)
        managed = destination / "managed"
        managed.mkdir(exist_ok=False)
        managed_created = True
        managed_token = _path_token(managed, directory=True)
        owner = str(uuid.uuid4())
        owner_dir = managed / owner
        owner_dir.mkdir(exist_ok=False)
        owner_created = True
        owner_token = _path_token(owner_dir, directory=True)
        timestamp = now or dt.datetime.now().astimezone()
        if timestamp.tzinfo is None:
            raise BackupError("setup time must be timezone-aware", 3)
        state = initial_state(
            owner_uuid=owner,
            source_fingerprints=config.source_fingerprints,
            config_fingerprint=config.config_fingerprint,
            week_start=config.week_start,
            schedule_time=config.schedule_time,
            artifact_digest=config.artifact_digest,
            now=timestamp,
        )
        def guarded_writer(path: Path, value):
            try:
                return writer(path, value)
            except Exception as exc:
                raise BackupError("setup state write failed", 1) from exc

        commit_state(destination, state, guarded_writer if writer is not None else None)
        if ledger is not None:
            ledger.parent_created = parent_created
            ledger.destination_created = destination_created
            ledger.parent_token = parent_token
            ledger.destination_token = destination_token or _path_token(destination, directory=True)
            ledger.managed_token = managed_token or _path_token(managed, directory=True)
            ledger.owner_token = owner_token or _path_token(owner_dir, directory=True)
            ledger.owner_uuid = owner
            ledger.state = state
        return state
    except Exception as exc:
        if owner_created:
            _safe_rmdir_owned(destination / "managed" / str(owner), owner_token)
        if managed_created:
            _safe_rmdir_owned(destination / "managed", managed_token)
        if destination_created:
            _safe_rmdir_owned(destination, destination_token)
        if parent_created:
            _safe_rmdir_owned(destination.parent, parent_token)
        if isinstance(exc, BackupError):
            raise
        raise BackupError("setup initialization failed", 1) from exc


def rollback_initialized_destination(config: SetupConfig, state: dict[str, object],
                                    ledger: InitializationLedger | None = None) -> bool:
    """Remove only a just-created, still-pristine initialization ledger.

    This is deliberately conservative.  A caller must have retained the exact
    state returned by :func:`initialize_destination`; any changed state, extra
    journal entry, archive, or identity mismatch leaves all evidence in place.
    """
    from .engine import load_state

    destination = config.destination
    try:
        if (ledger is None or ledger.state != state or not isinstance(state, dict)
                or state.get("last_result") != "INITIALIZED"):
            return False
        owner = state.get("owner_uuid")
        if not isinstance(owner, str) or load_state(destination) != state:
            return False
        expected = {"managed", "state-journal", "state.json"}
        entries = list(destination.iterdir())
        if {entry.name for entry in entries} != expected:
            return False
        managed = destination / "managed"
        owner_dir = managed / owner
        journal = destination / "state-journal"
        records = list(journal.iterdir())
        if (len(records) != 1 or any(owner_dir.iterdir())
                or [entry.name for entry in managed.iterdir()] != [owner]):
            return False
        destination_token = _path_token(destination, directory=True)
        if (ledger.destination_token is None
                or not destination_token.same_object(ledger.destination_token)):
            return False
        managed_token = _path_token(managed, directory=True)
        owner_token = _path_token(owner_dir, directory=True)
        journal_token = _path_token(journal, directory=True)
        record_token = _path_token(records[0], regular=True, single_link=True)
        state_path = destination / "state.json"
        state_token = _path_token(state_path, regular=True, single_link=True)
        if not _safe_unlink_owned(state_path, state_token):
            return False
        if not _safe_unlink_owned(records[0], record_token):
            return False
        if not _safe_rmdir_owned(journal, journal_token):
            return False
        if not _safe_rmdir_owned(owner_dir, owner_token):
            return False
        if not _safe_rmdir_owned(managed, managed_token):
            return False
        if not ledger.destination_created:
            return True
        if not _safe_rmdir_owned(destination, destination_token):
            return False
        if ledger.parent_created and ledger.parent_token is not None:
            parent_token = _path_token(destination.parent, directory=True)
            if not parent_token.same_object(ledger.parent_token):
                return False
            return _safe_rmdir_owned(destination.parent, parent_token)
        return True
    except (BackupError, OSError, ValueError, TypeError):
        return False
