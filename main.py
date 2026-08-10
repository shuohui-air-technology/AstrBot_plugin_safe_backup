"""AstrBot control plane for safe, offline backups.

This module exposes explicit administrator actions for the local backup task.  It
never starts a backup itself and keeps task, archive, and filesystem details out
of chat responses.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import stat
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Mapping

from astrbot.api import AstrBotConfig
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, register
if __package__:
    # AstrBot imports plugins as ``data.plugins.<plugin_dir>.main``.  Keep all
    # bundled modules inside that package namespace; they are not third-party
    # top-level dependencies.
    from .safe_backup.engine import (
        BackupError,
        acquire_runtime_marker,
        assert_local_path,
        configuration_fingerprint,
        commit_state,
        load_state,
        source_fingerprints,
        verify_archive,
    )
    from .safe_backup.setup import (
        SetupConfig,
        InitializationLedger,
        build_setup_config,
        artifact_digest,
        initialize_destination,
        rollback_initialized_destination,
    )
    from .safe_backup.task_control import (
        PowerShellTaskAdapter,
        TaskOperationResult,
        task_spec,
    )
    from .safe_backup.exit_waiter import launch_exit_waiter
else:
    # Direct repository imports are retained for the isolated unit-test and
    # development entry point only.
    from safe_backup.engine import (
        BackupError,
        acquire_runtime_marker,
        assert_local_path,
        configuration_fingerprint,
        commit_state,
        load_state,
        source_fingerprints,
        verify_archive,
    )
    from safe_backup.setup import (
        SetupConfig,
        InitializationLedger,
        build_setup_config,
        artifact_digest,
        initialize_destination,
        rollback_initialized_destination,
    )
    from safe_backup.task_control import (
        PowerShellTaskAdapter,
        TaskOperationResult,
        task_spec,
    )
    from safe_backup.exit_waiter import launch_exit_waiter


PLUGIN_ID = "astrbot_plugin_safe_backup"
PLUGIN_VERSION = "v0.1.0-beta"
STATE_MANAGER = "astrbot_plugin_safe_backup"
STATE_NAMESPACE = "community-v1"
MAX_STATE_BYTES = 1_048_576
WEEKDAYS = {
    "sunday": "Sunday",
    "monday": "Monday",
    "tuesday": "Tuesday",
    "wednesday": "Wednesday",
    "thursday": "Thursday",
    "friday": "Friday",
    "saturday": "Saturday",
}
WEEKDAY_INDEX = {
    "Monday": 0,
    "Tuesday": 1,
    "Wednesday": 2,
    "Thursday": 3,
    "Friday": 4,
    "Saturday": 5,
    "Sunday": 6,
}


class ControlError(RuntimeError):
    """A deliberately non-sensitive configuration or status error."""


class TaskStateUncertain(ControlError):
    """A task may have changed while its authoritative state could not be proved."""


def _is_relative_to(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
        return True
    except ValueError:
        return False


def _windows_key(path: Path) -> str:
    return str(path.resolve(strict=False)).replace("/", "\\").rstrip("\\").casefold()


def _paths_overlap(first: Path, second: Path) -> bool:
    first_key = _windows_key(first)
    second_key = _windows_key(second)
    return (
        first_key == second_key
        or first_key.startswith(second_key + "\\")
        or second_key.startswith(first_key + "\\")
    )


def _is_reparse_point(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        raise ControlError("无法可靠检查路径重解析属性，已失败关闭。") from None
    attributes = getattr(info, "st_file_attributes", 0)
    return stat.S_ISLNK(info.st_mode) or bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _assert_no_existing_reparse_ancestor(path: Path) -> None:
    current = path
    while True:
        if _is_reparse_point(current):
            raise ControlError("路径或其父目录包含重解析点，已拒绝继续。")
        parent = current.parent
        if parent == current:
            return
        current = parent


def _local_absolute_path(raw: str, label: str) -> Path:
    value = raw.strip()
    if not value:
        raise ControlError(f"{label}尚未配置。")
    if value.startswith("\\\\") or value.startswith("//"):
        raise ControlError(f"{label}必须是本地路径，不能使用 UNC 或网络路径。")
    path = Path(value)
    if not path.is_absolute():
        raise ControlError(f"{label}必须是绝对路径。")
    try:
        assert_local_path(path)
    except BackupError:
        raise ControlError(f"{label}必须位于可验证的本地磁盘，不能使用网络驱动器。") from None
    _assert_no_existing_reparse_ancestor(path)
    return path.resolve(strict=False)


def _display_token(value: Any, fallback: str = "未知", limit: int = 64) -> str:
    """Return only a conservative status token, never arbitrary state text."""
    text = str(value)
    if len(text) > limit or not re.fullmatch(r"[A-Za-z0-9_.:+TZ-]+", text):
        return fallback
    return text


@register(
    PLUGIN_ID,
    "shuohui-air-technology",
    "Windows 严格只读冷备份控制层（NapCat 可选）",
    PLUGIN_VERSION,
)
class SafeBackupPlugin(Star):
    """Read-only control plane. No method in this class performs a backup."""

    def __init__(self, context: Context, config: AstrBotConfig, *,
                 task_adapter=None, waiter_launcher: Callable[[SetupConfig, Mapping[str, Any]], None] | None = None,
                 archive_verifier: Callable[[Path, str, Mapping[str, str]], bool] | None = None,
                 user_profile: Path | None = None, plugin_dir: Path | None = None,
                 python_path: Path | None = None, compatibility_gate=None):
        super().__init__(context)
        self.config = config
        self._runtime_marker = None
        self.task_adapter = task_adapter or PowerShellTaskAdapter()
        self._waiter_launcher = waiter_launcher or self._default_waiter_launcher
        self._waiter_uses_ledger = waiter_launcher is None
        self._archive_verifier = archive_verifier or verify_archive
        self._user_profile = user_profile or Path(os.environ.get("USERPROFILE", Path.home()))
        self._plugin_dir = plugin_dir or Path(__file__).resolve(strict=False).parent
        self._python_path = python_path or Path(sys.executable)
        self._compatibility_gate = compatibility_gate or self._default_compatibility_gate

    @staticmethod
    def _default_waiter_launcher(config: SetupConfig, state: Mapping[str, Any], ledger: InitializationLedger) -> None:
        """Use the one-shot natural-exit helper, never a process-control action."""
        launch_exit_waiter(config, state, ledger)

    def _default_compatibility_gate(self) -> None:
        """Side-effect-free host/package gate before any target creation."""
        if os.name != "nt":
            raise ControlError("仅支持 Windows 主机。")
        try:
            from astrbot import __version__ as version
        except ImportError:
            version = None
        if not isinstance(version, str):
            raise ControlError("无法验证 AstrBot 运行时版本。")
        version = str(version)
        match = re.fullmatch(r"(\d+)\.(\d+)(?:\.\d+)?", version)
        if match is None or not (4, 26) <= tuple(map(int, match.groups())) < (5, 0):
            raise ControlError("AstrBot 版本不受支持。")
        required = (
            self._plugin_dir / "safe_backup" / "__init__.py",
            self._plugin_dir / "scripts" / "task_launcher.ps1",
            self._plugin_dir / "scripts" / "run_backup_visible.ps1",
            self._plugin_dir / "scripts" / "install_task.ps1",
            self._plugin_dir / "scripts" / "update_task.ps1",
            self._plugin_dir / "scripts" / "remove_task.ps1",
        )
        def trusted_regular(path: Path) -> bool:
            try:
                current = path
                leaf = True
                while True:
                    info = current.lstat()
                    if _is_reparse_point(current):
                        return False
                    if leaf and not stat.S_ISREG(info.st_mode):
                        return False
                    parent = current.parent
                    if parent == current:
                        return True
                    current, leaf = parent, False
            except OSError:
                return False
        if not trusted_regular(self._python_path) or any(not trusted_regular(path) for path in required):
            raise ControlError("插件包或解释器不完整。")

    async def initialize(self):
        root = self._infer_astrbot_root()
        marker = acquire_runtime_marker(root)
        if marker is None:
            raise RuntimeError("无法建立 AstrBot 运行状态互斥量；插件失败关闭。")
        self._runtime_marker = marker

    def _get(self, key: str, default: Any = None) -> Any:
        getter = getattr(self.config, "get", None)
        return getter(key, default) if callable(getter) else default

    def _infer_astrbot_root(self) -> Path:
        plugin_file = Path(__file__).resolve(strict=False)
        for ancestor in plugin_file.parents:
            if (
                ancestor.name.casefold() == "plugins"
                and ancestor.parent.name.casefold() == "data"
            ):
                return ancestor.parent.parent.resolve(strict=False)
        raise ControlError("无法从插件安装位置确定 AstrBot 根目录。")

    def _setup_config(self) -> SetupConfig:
        """Resolve setup inputs through the single setup validation boundary."""
        try:
            self._compatibility_gate()
            return build_setup_config(
                astrbot_root=self._infer_astrbot_root(),
                destination_text=str(self._get("destination_path", "")),
                user_profile=self._user_profile,
                plugin_dir=self._plugin_dir,
                python_path=self._python_path,
                retention=self._get("retention_count", 5),
                weekday=str(self._get("schedule_weekday", "Sunday")),
                schedule_time=str(self._get("schedule_time", "12:00")),
                napcat_root=(str(self._get("napcat_root", ""))
                             if self._get("napcat_enabled", False) else None),
            )
        except (BackupError, OSError, TypeError, ValueError):
            raise ControlError("配置无效或路径不安全，已拒绝操作。") from None

    @staticmethod
    def _setup_mapping(config: SetupConfig) -> dict[str, Any]:
        return {
            "astrbot_root": config.astrbot_root,
            "destination": config.destination,
            "retention": config.retention,
            "weekday": next(name for name, index in WEEKDAY_INDEX.items()
                            if index == config.week_start),
            "schedule_time": config.schedule_time,
            "napcat_enabled": config.napcat_root is not None,
            "napcat_root": config.napcat_root,
            "source_fingerprint": config.source_fingerprint,
            "source_fingerprints": config.source_fingerprints,
            "config_fingerprint": config.config_fingerprint,
            "artifact_digest": config.artifact_digest,
        }

    def _setup_config_from_task_spec(self, spec) -> SetupConfig:
        """Rebuild old setup input only after task_control proved its full grammar."""
        values = dict(zip(spec.arguments[::2], spec.arguments[1::2]))
        current_root = self._infer_astrbot_root().resolve(strict=False)
        task_root = Path(values["--astrbot-root"]).resolve(strict=False)
        if _windows_key(current_root) != _windows_key(task_root):
            raise ControlError("发现的计划任务不属于当前 AstrBot 实例。")
        if _windows_key(Path(values["--python-path"])) != _windows_key(self._python_path):
            raise ControlError("发现的计划任务解释器不受当前实例信任。")
        rebuilt = build_setup_config(
            astrbot_root=task_root,
            destination_text=values["--destination"],
            user_profile=self._user_profile,
            plugin_dir=self._plugin_dir,
            python_path=values["--python-path"],
            retention=int(values["--keep"]),
            weekday=next(name for name, index in WEEKDAY_INDEX.items()
                         if str(index) == values["--week-start"]),
            schedule_time=values["--schedule-time"],
            napcat_root=values.get("--napcat-root"),
        )
        # Discovery proves an historic task specification.  Do not silently
        # substitute today's plugin digest while validating its state: only an
        # explicit task update is permitted to advance this binding.
        return replace(rebuilt, artifact_digest=values["--artifact-digest"])

    @staticmethod
    def _task_succeeded(result: TaskOperationResult, status: str, spec) -> bool:
        return (
            isinstance(result, TaskOperationResult)
            and result.code == 0
            and result.status == status
            and result.fingerprint == spec.name.rsplit(" ", 1)[-1]
        )

    @staticmethod
    def _same_task_immutables(actual, desired) -> bool:
        return (
            actual.name == desired.name and actual.description == desired.description
            and actual.launcher == desired.launcher
            and actual.user_id == desired.user_id
            and actual.run_level == desired.run_level
            and actual.logon_type == desired.logon_type
            and actual.arguments[1] == desired.arguments[1]
            and actual.arguments[5] == desired.arguments[5]
        )

    def _finalize_same_destination_update(self, old_spec, new_spec, state,
                                          config: SetupConfig) -> None:
        """Re-prove a possibly output-lost update before advancing its state binding."""
        try:
            result = self.task_adapter.update(old_spec, new_spec)
            update_confirmed = self._task_succeeded(result, "updated", new_spec)
        except (ControlError, BackupError, OSError, RuntimeError, TypeError, ValueError):
            # An exception can occur after Set-ScheduledTask but before the
            # script has restored/proved the prior Disabled state.  The action
            # shape alone cannot prove that it is safe to bind the new state.
            raise TaskStateUncertain("计划任务结果不确定，已隔离保留现场。") from None
        if not update_confirmed:
            try:
                old_task = self.task_adapter.inspect(old_spec)
            except (ControlError, BackupError, OSError, RuntimeError, TypeError, ValueError):
                old_task = None
            if self._task_succeeded(old_task, "inspected", old_spec):
                raise ControlError("计划任务更新失败，原任务保持不变。")
            raise TaskStateUncertain("计划任务结果不确定，已隔离保留现场。")
        try:
            new_task = self.task_adapter.inspect(new_spec)
        except (ControlError, BackupError, OSError, RuntimeError, TypeError, ValueError):
            new_task = None
        if self._task_succeeded(new_task, "inspected", new_spec):
            refreshed = dict(state)
            # Task arguments carry the schedule/configuration binding used by
            # scheduled_probe() and _run().  Advance that whole binding in the
            # same journal-first state transition as the task update; updating
            # only the executable digest would leave an INITIALIZED state
            # permanently unsafe after a schedule/retention change.
            refreshed["config_fingerprint"] = config.config_fingerprint
            refreshed["artifact_digest"] = config.artifact_digest
            refreshed["week_start"] = next(
                name.casefold()
                for name, index in WEEKDAY_INDEX.items()
                if index == config.week_start
            )
            refreshed["schedule_time"] = config.schedule_time
            prior_revision = state.get("state_revision")
            try:
                commit_state(config.destination, refreshed)
                recovered = load_state(config.destination)
            except (BackupError, OSError, RuntimeError, TypeError, ValueError):
                raise TaskStateUncertain("计划任务已更新但状态账本未同步，已隔离。") from None
            if (
                not isinstance(recovered, dict)
                or recovered.get("config_fingerprint") != config.config_fingerprint
                or recovered.get("artifact_digest") != config.artifact_digest
                or recovered.get("week_start") != refreshed["week_start"]
                or recovered.get("schedule_time") != config.schedule_time
                or type(prior_revision) is not int
                or recovered.get("state_revision") != prior_revision + 1
                or recovered.get("owner_uuid") != state.get("owner_uuid")
                or recovered.get("source_fingerprints") != state.get("source_fingerprints")
                or recovered.get("last_success_archive") != state.get("last_success_archive")
                or recovered.get("last_successful_archive") != state.get("last_successful_archive")
            ):
                raise TaskStateUncertain("计划任务已更新但状态账本未同步，已隔离。")
            return
        try:
            old_task = self.task_adapter.inspect(old_spec)
        except (ControlError, BackupError, OSError, RuntimeError, TypeError, ValueError):
            old_task = None
        if self._task_succeeded(old_task, "inspected", old_spec) and not update_confirmed:
            raise ControlError("计划任务更新失败，原任务保持不变。")
        raise TaskStateUncertain("计划任务结果不确定，已隔离保留现场。")

    def _validated_config(self) -> dict[str, Any]:
        if not str(self._get("destination_path", "")).strip():
            return self._setup_mapping(self._setup_config())
        root = self._infer_astrbot_root()
        _assert_no_existing_reparse_ancestor(root)
        destination = _local_absolute_path(
            str(self._get("destination_path", "")), "备份目标目录"
        )
        if _paths_overlap(root, destination):
            raise ControlError("备份目标目录不能与 AstrBot 根目录相同或互相包含。")

        try:
            retention = int(self._get("retention_count", 5))
        except (TypeError, ValueError) as exc:
            raise ControlError("保留数量必须是 1 到 30 的整数。") from exc
        if not 1 <= retention <= 30:
            raise ControlError("保留数量必须是 1 到 30 的整数。")

        weekday_raw = str(self._get("schedule_weekday", "Sunday")).casefold()
        if weekday_raw not in WEEKDAYS:
            raise ControlError("计划星期值无效。")
        weekday = WEEKDAYS[weekday_raw]

        schedule_time = str(self._get("schedule_time", "12:00")).strip()
        if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", schedule_time):
            raise ControlError("计划时间必须采用 24 小时 HH:MM 格式。")

        napcat_value = self._get("napcat_enabled", False)
        if type(napcat_value) is not bool:
            raise ControlError("NapCat 开关必须是布尔值。")
        napcat_enabled = napcat_value
        napcat_root: Path | None = None
        if napcat_enabled:
            napcat_root = _local_absolute_path(
                str(self._get("napcat_root", "")), "NapCat 根目录"
            )
            if _paths_overlap(napcat_root, destination):
                raise ControlError("备份目标目录不能与 NapCat 根目录互相包含。")

        fingerprints = source_fingerprints(root, napcat_root)
        source_fingerprint = fingerprints["astrbot_root"]
        napcat_fingerprint = fingerprints["napcat_root"]
        config_fingerprint = configuration_fingerprint(
            root,
            napcat_root,
            destination,
            retention,
            WEEKDAY_INDEX[weekday],
            schedule_time,
        )
        return {
            "astrbot_root": root,
            "destination": destination,
            "retention": retention,
            "weekday": weekday,
            "schedule_time": schedule_time,
            "napcat_enabled": napcat_enabled,
            "napcat_root": napcat_root,
            "source_fingerprint": source_fingerprint,
            "source_fingerprints": {
                "astrbot_root": source_fingerprint,
                "napcat_root": napcat_fingerprint,
            },
            "config_fingerprint": config_fingerprint,
            "artifact_digest": artifact_digest(self._plugin_dir),
        }

    def _read_state(self, destination: Path) -> Mapping[str, Any] | None:
        try:
            return load_state(destination)
        except (BackupError, OSError):
            raise ControlError("目标目录中的状态不可信或不可读，拒绝接管。") from None

    def _inspect_destination(
        self, config: Mapping[str, Any]
    ) -> tuple[str, Mapping[str, Any] | None]:
        destination: Path = config["destination"]
        if _is_reparse_point(destination):
            raise ControlError("备份目标不是安全的普通目录。")
        if not destination.exists():
            return "尚未初始化（目标目录不存在）", None
        if not destination.is_dir():
            raise ControlError("备份目标不是安全的普通目录。")
        state = self._read_state(destination)
        if state is None:
            try:
                nonempty = next(destination.iterdir(), None) is not None
            except OSError as exc:
                raise ControlError(f"无法检查目标目录（{type(exc).__name__}）。") from None
            if nonempty:
                raise ControlError("目标目录非空且没有本插件状态，拒绝初始化或接管。")
            return "尚未初始化（目标目录为空）", None
        allowed = {"state.json", "state-journal", "managed", "diagnostics", "logs", "staging"}
        try:
            if any(child.name not in allowed for child in destination.iterdir()):
                raise ControlError("目标目录包含陌生顶层产物，拒绝接管。")
            managed = destination / "managed"
            if managed.exists():
                if not managed.is_dir() or _is_reparse_point(managed):
                    raise ControlError("受管归档目录不安全。")
                owner = str(state["owner_uuid"]).casefold()
                if any(child.name.casefold() != owner for child in managed.iterdir()):
                    raise ControlError("受管目录包含其他 owner，拒绝接管。")
        except ControlError:
            raise
        except OSError as exc:
            raise ControlError(f"无法检查受管目录（{type(exc).__name__}）。") from None
        if state.get("source_fingerprint") != config["source_fingerprint"]:
            raise ControlError("状态中的源目录指纹不匹配，拒绝接管。")
        if state.get("source_fingerprints") != config["source_fingerprints"]:
            raise ControlError("状态中的 AstrBot/NapCat 源指纹不匹配，拒绝接管。")
        drift = (state.get("config_fingerprint") != config["config_fingerprint"]
                 or state.get("artifact_digest") != config["artifact_digest"])
        return (
            "配置已变化：请显式更新计划任务，并等待下一次成功冷备刷新状态"
            if drift
            else "配置与状态一致"
        ), state

    def _task_name(self, config: Mapping[str, Any]) -> str:
        token = config["source_fingerprint"][:12]
        return f"AstrBot Safe Backup {token}"

    def _latest_archive(self, config: Mapping[str, Any], state: Mapping[str, Any]) -> Path:
        raw = state.get("last_success_archive")
        if not isinstance(raw, str) or not raw.strip():
            raise ControlError("尚无成功归档可供验证。")
        candidate = Path(raw)
        if not candidate.is_absolute():
            owner = str(state.get("owner_uuid", ""))
            if not re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                owner,
                re.I,
            ):
                raise ControlError("状态中的 owner UUID 无效。")
            candidate = config["destination"] / "managed" / owner / candidate
        _assert_no_existing_reparse_ancestor(candidate)
        candidate = candidate.resolve(strict=False)
        destination = config["destination"].resolve(strict=False)
        if not _is_relative_to(candidate, destination):
            raise ControlError("最近归档路径越出受管目录或包含重解析点。")
        if not candidate.is_file():
            raise ControlError("最近成功归档当前不存在。")
        return candidate

    @filter.command_group("safe_backup")
    def safe_backup(self):
        """安全冷备份控制命令组。"""

    @filter.permission_type(filter.PermissionType.ADMIN)
    @safe_backup.command("setup")
    async def setup(self, event: AstrMessageEvent):
        """Initialize a destination and install exactly one verified task."""
        initialized_state = None
        initialization_ledger = None
        transaction_spec = None
        transaction_config = None
        created_task = False
        rollback_failed = False
        try:
            setup_config = self._setup_config()
            transaction_config = setup_config
            config = self._setup_mapping(setup_config)
            spec = task_spec(setup_config, self._plugin_dir, self._python_path)
            transaction_spec = spec
            discover = getattr(self.task_adapter, "inspect_by_fingerprint", None)
            if not callable(discover):
                raise ControlError("计划任务发现接口不可用，已拒绝操作。")
            discovery = discover(setup_config.source_fingerprint[:12])
            destination_status, existing_state = self._inspect_destination(config)
            if discovery.status == "missing":
                exact_task = False
            elif discovery.status == "exact":
                if discovery.spec is not None and discovery.spec != spec:
                    if not self._same_task_immutables(discovery.spec, spec):
                        raise ControlError("发现同名非受管计划任务，拒绝操作。")
                    if existing_state is None:
                        raise ControlError("计划任务与初始化账本不完整或不匹配，拒绝接管。")
                    yield event.plain_result("配置已变化；请使用 /safe_backup task update。")
                    return
                exact_task = True
            else:
                raise ControlError("发现同名非受管计划任务，拒绝操作。")
            if existing_state is not None:
                if destination_status.startswith("配置已变化"):
                    yield event.plain_result("配置已变化；请使用 /safe_backup task update。")
                    return
                if exact_task:
                    yield event.plain_result("备份已经初始化，计划任务与初始化账本一致。")
                    return
                raise ControlError("初始化账本与计划任务不完整或不匹配，拒绝接管。")
            if exact_task:
                raise ControlError("发现没有初始化账本的同名计划任务，拒绝接管。")
            initialization_ledger = InitializationLedger()
            initialized_state = initialize_destination(setup_config, ledger=initialization_ledger)
            installed = self.task_adapter.install(spec)
            if not self._task_succeeded(installed, "installed", spec):
                raise ControlError("计划任务安装未得到可信确认。")
            created_task = True
            reinspected = self.task_adapter.inspect(spec)
            if not self._task_succeeded(reinspected, "inspected", spec):
                raise ControlError("计划任务安装后复核失败。")
            if self._waiter_uses_ledger:
                self._waiter_launcher(setup_config, initialized_state, initialization_ledger)
            else:
                self._waiter_launcher(setup_config, initialized_state)
            yield event.plain_result("初始化完成。没有立即启动备份；首次冷备将在 AstrBot 停止后等待器确认时执行。")
        except (ControlError, BackupError, OSError, RuntimeError, TypeError, ValueError):
            if initialized_state is not None:
                absence_proven = False
                if created_task:
                    try:
                        current = self.task_adapter.inspect(transaction_spec)
                        if not self._task_succeeded(current, "inspected", transaction_spec):
                            rollback_failed = True
                        else:
                            removed = self.task_adapter.remove(transaction_spec)
                            if not self._task_succeeded(removed, "removed", transaction_spec):
                                rollback_failed = True
                    except (ControlError, BackupError, OSError, RuntimeError, TypeError, ValueError):
                        rollback_failed = True
                try:
                    discovery = self.task_adapter.inspect_by_fingerprint(
                        transaction_spec.name.rsplit(" ", 1)[-1]
                    )
                    absence_proven = discovery.status == "missing"
                except (ControlError, BackupError, OSError, RuntimeError, TypeError, ValueError):
                    rollback_failed = True
                if not absence_proven:
                    rollback_failed = True
                if not rollback_failed and not rollback_initialized_destination(
                        transaction_config, initialized_state, initialization_ledger):
                    rollback_failed = True
            warning = " 已隔离保留现场，请勿重试或手工接管。" if rollback_failed else ""
            yield event.plain_result("初始化失败，未执行备份。" + warning)

    @filter.permission_type(filter.PermissionType.ADMIN)
    @safe_backup.command("status")
    async def status(self, event: AstrMessageEvent):
        """Show sanitized configuration and last-run status."""
        try:
            config = self._validated_config()
            destination_status, state = self._inspect_destination(config)
            lines = [
                f"安全冷备份控制层 {PLUGIN_VERSION}",
                f"任务标识：{self._task_name(config)}",
                f"目标状态：{destination_status}",
                f"NapCat：{'已启用' if config['napcat_enabled'] else '未启用'}",
                "计划任务管理：仅显式 setup/task 命令可修改；插件加载或卸载不会修改。",
                (
                    "备份执行：初始化后由计划任务按配置自动尝试。"
                    if state is not None
                    else "备份执行：尚未初始化，不会按计划运行。"
                ),
            ]
            if state:
                lines.extend(
                    [
                        "最近结果："
                        + _display_token(state.get("last_result", "未知")),
                        "最近成功周期："
                        + _display_token(state.get("last_success_cycle", "无"), "无"),
                        "自动清理授权数量："
                + str(len(state.get("retention_candidates", [])))
                + "（最近一次已授权的自动清理项；不确定项会保留）",
                    ]
                )
            yield event.plain_result("\n".join(lines))
        except ControlError as exc:
            yield event.plain_result(f"配置/状态检查失败：{exc}")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @safe_backup.command("check")
    async def check(self, event: AstrMessageEvent):
        """Perform static, read-only path and state checks."""
        try:
            config = self._validated_config()
            destination_status, _ = self._inspect_destination(config)
            if not config["astrbot_root"].is_dir():
                raise ControlError("AstrBot 根目录不存在。")
            if config["napcat_enabled"] and not config["napcat_root"].is_dir():
                raise ControlError("NapCat 根目录不存在。")
            yield event.plain_result(
                "静态只读检查通过。\n"
                f"目标状态：{destination_status}\n"
                "本命令未读取数据库、未创建目录、未执行备份、未修改计划任务。"
            )
        except ControlError as exc:
            yield event.plain_result(f"静态只读检查失败：{exc}")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @safe_backup.command("history")
    async def history(self, event: AstrMessageEvent):
        """Read sanitized history from the authoritative journal-backed state."""
        try:
            config = self._validated_config()
            _, state = self._inspect_destination(config)
            if not state:
                raise ControlError("备份尚未初始化，没有历史记录。")
            runs = state.get("recent_runs")
            if runs is None:
                runs = [
                    {
                        "time": state.get("last_attempt_time_local", "未知"),
                        "result": state.get("last_result", "未知"),
                        "stage": state.get("last_failure_phase", "state"),
                    }
                ]
            if not isinstance(runs, list):
                raise ControlError("历史记录格式无效。")
            lines = [
                "状态中可用的运行记录（最多 10 条，仅显示状态字段）：",
            "自动清理授权数量："
            + str(len(state.get("retention_candidates", [])))
            + "（外来、损坏或无法证明归属的归档不会自动删除）",
            ]
            for item in runs[-10:]:
                if not isinstance(item, dict):
                    continue
                when = _display_token(
                    item.get("time", item.get("started_at", "未知")), limit=40
                )
                result = _display_token(item.get("result", "未知"), limit=32)
                stage = _display_token(item.get("stage", "未知"), limit=32)
                lines.append(f"- {when} | {result} | {stage}")
            if len(lines) == 2:
                lines.append("- 暂无记录")
            yield event.plain_result("\n".join(lines))
        except ControlError as exc:
            yield event.plain_result(f"无法读取历史：{exc}")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @safe_backup.command("verify")
    async def verify(self, event: AstrMessageEvent, target: str = "latest"):
        """Verify one trusted archive off the AstrBot event loop."""
        if target.casefold() != "latest":
            yield event.plain_result("当前只支持：/safe_backup verify latest")
            return
        try:
            config = self._validated_config()
            _, state = self._inspect_destination(config)
            if not state:
                raise ControlError("备份尚未初始化。")
            archive = self._latest_archive(config, state)
            verified = await asyncio.to_thread(
                self._archive_verifier,
                archive,
                str(state["owner_uuid"]),
                state["source_fingerprints"],
            )
            yield event.plain_result(
                "最近归档验证通过。" if verified else "最近归档验证未通过。"
            )
        except (ControlError, BackupError, OSError, RuntimeError, TypeError, ValueError):
            yield event.plain_result("最近归档验证失败或状态不可信。")

    @filter.permission_type(filter.PermissionType.ADMIN)
    @safe_backup.command("task")
    async def task(self, event: AstrMessageEvent, action: str = ""):
        """Explicitly update or remove an exact, trusted scheduled task."""
        normalized = action.casefold().strip()
        if normalized not in {"update", "remove"}:
            yield event.plain_result("用法：/safe_backup task update|remove")
            return
        quarantined = False
        try:
            setup_config = self._setup_config()
            config = self._setup_mapping(setup_config)
            destination_status, state = self._inspect_destination(config)
            spec = task_spec(setup_config, self._plugin_dir, self._python_path)
            active_spec = spec
            if state is not None:
                current = self.task_adapter.inspect(spec)
                if not self._task_succeeded(current, "inspected", spec):
                    discover = getattr(self.task_adapter, "inspect_by_fingerprint", None)
                    if not callable(discover):
                        raise ControlError("计划任务不存在或与受管规格不匹配。")
                    discovery = discover(setup_config.source_fingerprint[:12])
                    if discovery.status != "exact" or discovery.spec is None:
                        raise ControlError("计划任务不存在或与受管规格不匹配。")
                    active_spec = discovery.spec
                    old_config = self._setup_config_from_task_spec(active_spec)
                    old_status, old_state = self._inspect_destination(self._setup_mapping(old_config))
                    if old_state is None or old_status.startswith("配置已变化"):
                        raise ControlError("旧初始化账本不可信或不完整。")
                    if normalized == "update" and old_config.destination == setup_config.destination:
                        self._finalize_same_destination_update(active_spec, spec, state, setup_config)
                        yield event.plain_result("计划任务与状态绑定已更新；不会立即启动备份。")
                        return
            if state is None:
                discover = getattr(self.task_adapter, "inspect_by_fingerprint", None)
                if not callable(discover):
                    raise ControlError("没有可信初始化账本。")
                discovery = discover(setup_config.source_fingerprint[:12])
                if discovery.status != "exact" or discovery.spec is None:
                    raise ControlError("计划任务不存在或与受管规格不匹配。")
                active_spec = discovery.spec
                old_config = self._setup_config_from_task_spec(active_spec)
                old_status, state = self._inspect_destination(self._setup_mapping(old_config))
                if state is None or old_status.startswith("配置已变化"):
                    raise ControlError("旧初始化账本不可信或不完整。")
                if normalized == "update":
                    new_ledger = InitializationLedger()
                    new_state = initialize_destination(setup_config, ledger=new_ledger)
                    try:
                        result = self.task_adapter.update(active_spec, spec)
                        reinspected = self.task_adapter.inspect(spec)
                        if (not self._task_succeeded(result, "updated", spec)
                                or not self._task_succeeded(reinspected, "inspected", spec)):
                            raise ControlError("计划任务更新未得到可信确认。")
                    except (ControlError, BackupError, OSError, RuntimeError, TypeError, ValueError):
                        try:
                            after = self.task_adapter.inspect_by_fingerprint(
                                spec.name.rsplit(" ", 1)[-1]
                            )
                        except (ControlError, BackupError, OSError, RuntimeError, TypeError, ValueError):
                            quarantined = True
                            raise ControlError("计划任务结果不确定，已隔离保留新初始化账本。") from None
                        if (after.status != "exact" or after.spec is None
                                or after.spec.arguments != active_spec.arguments):
                            quarantined = True
                            raise ControlError("计划任务结果不确定，已隔离保留新初始化账本。") from None
                        if not rollback_initialized_destination(setup_config, new_state, new_ledger):
                            raise ControlError("新初始化账本回滚未得到证明。") from None
                        raise
                    yield event.plain_result("计划任务已更新；新目标已初始化且未迁移旧归档。")
                    return
            inspected = self.task_adapter.inspect(active_spec)
            if not self._task_succeeded(inspected, "inspected", active_spec):
                raise ControlError("计划任务不存在或与受管规格不匹配。")
            if normalized == "update":
                if state is None:
                    raise ControlError("初始化账本不可信或不完整。")
                self._finalize_same_destination_update(active_spec, spec, state, setup_config)
                yield event.plain_result("计划任务与状态绑定已更新；不会立即启动备份。")
                return
            result = self.task_adapter.remove(active_spec)
            if not self._task_succeeded(result, "removed", active_spec):
                raise ControlError("计划任务移除未得到可信确认。")
            yield event.plain_result("计划任务已移除；初始化账本和归档文件均未删除。")
        except (ControlError, BackupError, OSError, RuntimeError, TypeError, ValueError) as exc:
            quarantined = quarantined or isinstance(exc, TaskStateUncertain)
            yield event.plain_result(
                "计划任务结果不确定，已隔离保留新初始化账本。"
                if quarantined else "计划任务操作失败或状态不可信。"
            )

    async def terminate(self):
        """Release the process-lifetime running marker."""
        marker, self._runtime_marker = self._runtime_marker, None
        release = getattr(marker, "release", None)
        if callable(release):
            release()
        return None
