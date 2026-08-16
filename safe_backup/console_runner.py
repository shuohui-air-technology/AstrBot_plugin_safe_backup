"""Chinese visible-terminal renderer for redacted cold-backup progress."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Callable, TextIO

try:  # The visible PowerShell runner invokes this file by its verified path.
    from . import engine
    from .progress import PHASES, ProgressEvent
except ImportError:  # pragma: no cover - direct-script Windows entry point.
    import engine
    from progress import PHASES, ProgressEvent


MAX_EVENTS = 10_000
MAX_LOG_BYTES = 4 * 1024 * 1024
PHASE_TITLES = {
    "preflight": "安全预检",
    "inventory": "AstrBot 数据清点",
    "copy": "数据复制",
    "sqlite": "SQLite 隔离副本处理",
    "archive": "ZIP 生成",
    "verify": "归档完整验证",
    "publish": "正式发布",
}
HELP = {
    "process": "请先正常退出 AstrBot，随后会在下一次计划窗口重试。",
    "state": "备份目标状态无法安全确认，请检查插件专用目标目录。",
    "space": "请确认备份目标有足够的本地可用空间。",
    "source": "源数据在备份期间发生变化，请在 AstrBot 停止后重试。",
    "default": "请查看插件的状态检查结果后再重试。",
}


def _safe_message_token(message: str) -> str:
    text = (message or "").casefold()
    if "process" in text or "running" in text or "astrbot runtime" in text:
        return "process"
    if "state" in text or "destination" in text or "output" in text:
        return "state"
    if "space" in text:
        return "space"
    if "source" in text or "drift" in text or "sqlite" in text:
        return "source"
    return "default"


def _bar(event: ProgressEvent) -> str:
    if event.total <= 0:
        return "[--------------------]"
    ratio = min(1.0, event.current / event.total)
    filled = int(ratio * 20)
    return "[" + "#" * filled + "-" * (20 - filled) + "]"


class _DiscardWriter:
    def write(self, _text: str) -> int:
        return 0

    def flush(self) -> None:
        return None


def _default_key_probe() -> bool:
    """Consume one console key without blocking; redirected/no-console is false."""
    if os.name != "nt":
        return False
    try:
        import msvcrt
        if not msvcrt.kbhit():
            return False
        msvcrt.getwch()
        return True
    except BaseException:
        return False


def _write(writer: TextIO, text: str) -> None:
    try:
        writer.write(text + "\n")
        flush = getattr(writer, "flush", None)
        if callable(flush):
            flush()
    except BaseException:
        # Rendering cannot alter the cold-backup decision or transaction.
        return


def _trusted_state(destination: Path) -> dict[str, object] | None:
    try:
        state = engine.load_state(destination)
        if not isinstance(state, dict):
            return None
        if (state.get("managed_by") != engine.GENERATOR
                or state.get("state_namespace") != "community-v1"
                or not isinstance(state.get("owner_uuid"), str)):
            return None
        return state
    except (OSError, ValueError, TypeError, KeyError, engine.BackupError):
        return None


def _recheck_log_directories(destination: Path, logs: Path, destination_token, logs_token) -> bool:
    try:
        engine.assert_safe_output_path(destination)
        engine.assert_safe_output_path(logs)
        return (engine._path_token(destination, directory=True).same_object(destination_token)
                and engine._path_token(logs, directory=True).same_object(logs_token)
                and not engine.is_reparse(logs))
    except (OSError, ValueError, TypeError, engine.BackupError):
        return False


def _write_redacted_log(destination: Path, events: list[ProgressEvent], code: int,
                        result_token: str) -> bool:
    """Best-effort output-only log.  The caller has already proved state trust."""
    try:
        if (len(events) > MAX_EVENTS
                or any(not isinstance(event, ProgressEvent) for event in events)):
            return False
        logs = destination / "logs"
        engine.assert_safe_output_path(logs)
        if not logs.is_dir() or engine.is_reparse(logs):
            return False
        destination_token = engine._path_token(destination, directory=True)
        logs_token = engine._path_token(logs, directory=True)
        if not _recheck_log_directories(destination, logs, destination_token, logs_token):
            return False
        name = "visible-run-" + uuid.uuid4().hex + ".jsonl"
        target = logs / name
        temporary = logs / ("." + name + ".tmp")
        # Event validation prevents messages, paths, secrets and exception text
        # from crossing this boundary.
        records = [event.record() for event in events]
        records.append({"result": result_token, "code": int(code)})
        raw = "".join(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
                      for record in records).encode("utf-8")
        if len(raw) > MAX_LOG_BYTES:
            return False
        temporary_token = None
        with engine._exclusive_output(temporary) as (handle, temporary_token):
            handle.write(raw)
        if not _recheck_log_directories(destination, logs, destination_token, logs_token):
            return False
        current_temp = engine._path_token(temporary, regular=True, single_link=True)
        if (temporary_token is None or not current_temp.same_object(temporary_token)
                or current_temp.size != len(raw)):
            return False
        digest, current_temp = engine._hash_regular(temporary, current_temp)
        if digest != hashlib.sha256(raw).hexdigest():
            return False
        if engine._path_token_if_present(target) is not None:
            return False
        if not _recheck_log_directories(destination, logs, destination_token, logs_token):
            return False
        # Hard-link publication is no-replace on supported local NTFS volumes.
        os.link(temporary, target, follow_symlinks=False)
        if not _recheck_log_directories(destination, logs, destination_token, logs_token):
            return False
        target_token = engine._path_token(target, regular=True)
        temporary_linked = engine._path_token(temporary, regular=True)
        if (not target_token.same_content_identity(current_temp)
                or not temporary_linked.same_content_identity(current_temp)
                or target_token.nlink != 2 or temporary_linked.nlink != 2):
            return False
        if not _recheck_log_directories(destination, logs, destination_token, logs_token):
            return False
        if not engine._safe_unlink_owned(temporary, temporary_linked):
            return False
        final_token = engine._path_token(target, regular=True, single_link=True)
        final_digest, final_token = engine._hash_regular(target, final_token)
        if (final_digest != digest or final_token.size != len(raw)
                or not _recheck_log_directories(destination, logs, destination_token, logs_token)):
            return False
        final_recheck = engine._path_token(target, regular=True, single_link=True)
        if not final_recheck.same_content_identity(final_token):
            return False
        return True
    except (OSError, ValueError, TypeError, engine.BackupError):
        # A failed optional log is deliberately preserved for inspection rather
        # than deleting a path whose identity can no longer be proved here.
        return False


def _wait(seconds: int, writer: TextIO, key_probe: Callable[[], bool],
          sleep: Callable[[float], None]) -> None:
    for remaining in range(seconds, 0, -1):
        try:
            if key_probe():
                return
        except BaseException:
            pass
        _write(writer, f"窗口将在 {remaining} 秒后自动关闭；按任意键可提前关闭。")
        sleep(1)


def render_backup(args, *, engine_runner: Callable = engine.run, writer: TextIO | None = None,
                  key_probe: Callable[[], bool] | None = None,
                  sleep: Callable[[float], None] = time.sleep) -> int:
    """Run one actual attempt and show only fixed/redacted user-facing data."""
    writer = writer if writer is not None else (sys.stdout if sys.stdout is not None else _DiscardWriter())
    key_probe = key_probe or _default_key_probe
    events: list[ProgressEvent] = []
    started = False

    def sink(event: ProgressEvent) -> None:
        nonlocal started
        if not isinstance(event, ProgressEvent):
            return
        if len(events) < MAX_EVENTS:
            events.append(event)
        if not started:
            started = True
            _write(writer, "AstrBot 自动化安全冷备份")
            if getattr(args, "manual", False):
                attempt = "手动快照（不计入自动备份周期）"
            else:
                attempt = "计划任务" if getattr(args, "scheduled", False) else "首次或手动"
            _write(writer, f"尝试类型：{attempt}；源数据只读。")
        title = PHASE_TITLES[event.phase]
        value = f"{event.current}/{event.total}" if event.total else "进行中"
        _write(writer, f"[{event.index}/7] {title} {_bar(event)} {value} {event.unit}")

    try:
        result = engine_runner(args, progress_sink=sink)
    except BaseException:  # Engine API boundary: renderer never exposes exception text.
        result = engine.Result(3, message="renderer_engine_failure",
                               publication_disposition="quarantine_possible")
    if result.noop:
        return int(result.code)
    if not started:
        # State/process failures can occur before the engine has a stage event.
        sink(ProgressEvent("preflight", 1, 1, 0, "items", "failed", "precheck_failed"))
    try:
        code = int(result.code)
    except (TypeError, ValueError):
        code = 3
    archive_name = Path(result.archive).name if result.archive is not None else ""
    destination = Path(args.destination)
    trusted = _trusted_state(destination)
    state_matches = False
    manual_archive_matches = False
    if isinstance(trusted, dict) and engine.is_strict_archive_name(archive_name):
        owner = trusted.get("owner_uuid")
        state_digest = trusted.get("last_successful_archive_sha256")
        result_digest = getattr(result, "archive_sha256", None)
        try:
            uuid.UUID(owner)
            expected = destination / "managed" / owner / archive_name
            path_matches = engine._key(Path(result.archive)) == engine._key(expected)
            digest_matches = (
                isinstance(state_digest, str) and isinstance(result_digest, str)
                and engine.re.fullmatch(r"[0-9a-f]{64}", state_digest) is not None
                and state_digest == result_digest
            )
            if (trusted.get("last_result") == "FULL_SUCCESS"
                    and trusted.get("last_successful_archive") == archive_name
                    and path_matches and digest_matches):
                archive_token = engine._path_token(expected, regular=True, single_link=True)
                actual_digest, archive_token = engine._hash_regular(expected, archive_token)
                state_matches = actual_digest == state_digest
        except (OSError, ValueError, TypeError, engine.BackupError):
            state_matches = False
    if (not getattr(result, "counts_as_scheduled_success", True)
            and isinstance(trusted, dict)
            and engine.is_strict_archive_name(archive_name)):
        try:
            owner = trusted.get("owner_uuid")
            uuid.UUID(owner)
            expected = destination / "managed" / owner / archive_name
            path_matches = engine._key(Path(result.archive)) == engine._key(expected)
            result_digest = getattr(result, "archive_sha256", None)
            if path_matches and isinstance(result_digest, str) and engine.re.fullmatch(
                    r"[0-9a-f]{64}", result_digest):
                archive_token = engine._path_token(expected, regular=True, single_link=True)
                actual_digest, archive_token = engine._hash_regular(expected, archive_token)
                final_token = engine._path_token(expected, regular=True, single_link=True)
                manual_archive_matches = (
                    actual_digest == result_digest
                    and final_token.same_content_identity(archive_token)
                )
        except (OSError, ValueError, TypeError, engine.BackupError):
            manual_archive_matches = False
    counts_as_scheduled_success = getattr(result, "counts_as_scheduled_success", True)
    valid_success = (
        code == 0 and result.publication_disposition == "full_success"
        and engine.is_strict_archive_name(archive_name)
        and (state_matches if counts_as_scheduled_success else manual_archive_matches)
    )
    if valid_success:
        _write(writer, f"归档已验证：{archive_name}")
        if not counts_as_scheduled_success:
            _write(writer, "本次为手动快照：自动备份周期状态未改变。")
        _write(writer, "备份成功")
        logged = _write_redacted_log(destination, events, code, "success")
        if trusted is not None and not logged:
            _write(writer, "本次进度日志未保存；归档结果不受影响。")
        _wait(30, writer, key_probe, sleep)
        return code
    if code == 0:
        code = 3
    token = _safe_message_token(getattr(result, "message", ""))
    _write(writer, "备份未完成")
    _write(writer, HELP[token])
    disposition = getattr(result, "publication_disposition", "quarantine_possible")
    if disposition in {"never_published", "cleaned"}:
        _write(writer, "未发布正式 ZIP。")
    else:
        _write(writer, "可能保留隔离产物或正式归档；请勿手工接管或删除。")
    _write(writer, "未删除历史归档。")
    logged = trusted is not None and _write_redacted_log(destination, events, code, "failure")
    if trusted is not None and not logged:
        _write(writer, "本次进度日志未保存；已保留现有归档。")
    _wait(120, writer, key_probe, sleep)
    return code


def main(argv: list[str] | None = None) -> int:
    return render_backup(engine.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
