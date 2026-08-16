# AstrBot Automated Safe Cold Backup Plugin

`astrbot_plugin_safe_backup` is a Windows cold-backup plugin for AstrBot users who put safety first. It backs up sensitive data efficiently and cautiously.

“Safety first” is a design direction, not an impossible absolute guarantee. If the required safety conditions cannot be proved, the plugin refuses the run rather than weakening a check to make a backup appear successful.

> `v0.1.0-beta`: currently supports AstrBot `>=4.26,<5` on local Windows only. Test it before using it for important data.

## Install and initialize

1. Install **AstrBot Automated Safe Cold Backup Plugin** from the AstrBot marketplace, or install the plugin ZIP provided with a project Release through AstrBot's plugin installer.
2. Reload the plugin or restart AstrBot. Loading it does not create a backup, Scheduled Task, or destination directory.
3. As an AstrBot administrator, send:

   ```text
   /safe_backup setup
   ```

No path is required for first-time use. The plugin derives a separate local default destination for this AstrBot instance and accepts only a missing or completely empty directory. Foreign files, old state, or unknown archives cause a fail-closed stop; they are never adopted or cleaned.

Setup verifies compatibility, destination safety, and task identity before creating one dedicated task. It then launches a one-shot helper that only waits for AstrBot to exit naturally. It never stops, pauses, restarts, or kills AstrBot.

Continue using AstrBot normally. After you close AstrBot in the ordinary way, the helper confirms that exit and automatically starts the first visible backup. There is no vague fixed delay to wait through.

Every **actual backup attempt** opens a visible terminal with fixed, redacted progress for preflight, inventory, copying, SQLite isolation, ZIP creation, archive verification, and publication. A successful run displays:

```text
备份成功
```

This literal Chinese terminal text means “Backup successful.”

The success window closes after 30 seconds; a failure window remains for 120 seconds. Press any key to close either window early. A scheduled trigger that only checks an already-successful weekly state remains silent.

### Local visible manual console

To start one manual backup or inspect the next scheduled time in a local terminal, run the script included in the plugin package:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<PLUGIN_DIR>\scripts\manual_backup.ps1"
```

The panel shows whether the exact task is still owned, its next run time, the scheduled and manual targets, ZIP count and total size, whether the newest archive SHA-256 matches authoritative state, state revision, staging/log/diagnostic counts, and free space on the destination volume. It also states that this release is a Windows cold backup and AstrBot must be closed normally first.

The **run now** menu entry opens the same seven-stage visible renderer and uses a one-shot force flag. Repeating it in the same cycle therefore does not get stuck behind the scheduled silent no-op; the second attempt still performs a complete verification. A manual snapshot is published and verified separately: it does not advance the automatic cycle, state pointer, or next scheduled time. The tool never stops, pauses, or kills AstrBot. If the process is still running, the backup fails safely.

Manual snapshots also do not trigger automatic retention cleanup, so the actual ZIP count may temporarily exceed `retention_count`; manual snapshots and scheduled cycles are tracked separately.

**Change manual target** saves a local preference bound to the current task fingerprint. It does not modify the Scheduled Task and never adopts a non-empty foreign directory. A new target must be missing or completely empty, and the panel keeps the scheduled target and manual target visibly separate. To permanently change the scheduled destination, edit `destination_path` in the plugin settings and explicitly run `/safe_backup task update`; do not edit task arguments directly.

Non-interactive examples:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<PLUGIN_DIR>\scripts\manual_backup.ps1" -Action Status -NoPause
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<PLUGIN_DIR>\scripts\manual_backup.ps1" -Action Run -NoPause
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<PLUGIN_DIR>\scripts\manual_backup.ps1" -Action SetDestination -Destination "D:\SafeBackups\AstrBot" -NoPause
```

The last command only saves the manual target; it does not start a backup. Run `-Action Run` afterwards. Use these commands only in a local terminal; do not paste commands containing real paths into chat or public issues.

## Main features

- Source data receives ordinary shared reads only: no source file is modified, moved, deleted, repaired, unlocked, or timestamp-restored.
- AstrBot is never controlled by the backup. If it is running or its process state cannot be proved, the run fails closed.
- The complete AstrBot `data` tree is attempted, including configuration, plugins, plugin data, knowledge bases, attachments, indexes, databases, empty directories, and future ordinary files.
- Source SQLite is read as files only. Normalization and `integrity_check` run solely on target-side isolated copies.
- Two inventories plus identity, size, mtime, and SHA-256 checks catch source changes. After a trusted baseline exists, a balanced SQLite rotation within one directory and filename template may be recognized; other layout changes still fail closed and cannot silently publish a formal archive.
- Before publication, the ZIP passes path, CRC, manifest SHA256, database-integrity, and restore-layout checks.
- No network upload, telemetry, NAS/UNC target, automatic restore, or automatic deletion of historical archives is provided.

### Optional NapCat configuration package

NapCat support is disabled by default. Normal AstrBot users do not need to configure it. When explicitly enabled with a local root, only a version-validated configuration allowlist is included. Binaries, caches, logs, temporary files, runtime databases, and account runtime data are excluded. Additions of validated JSON files inside the controlled config directory are accepted for the same active version; version changes, removals, and other layout changes pause backup for manual review.

## Settings

Defaults are sufficient for the first setup. Optional settings are:

| Setting | Default | Meaning |
| --- | --- | --- |
| `destination_path` | blank | Use the derived local destination, or a local absolute empty directory outside the source. |
| `retention_count` | `5` | Maximum number of trusted archives to retain. Only journal-bound archives that pass full verification again are eligible for cleanup. |
| `schedule_weekday` | `Sunday` | First weekly attempt day. |
| `schedule_time` | `12:00` | Local time in `HH:MM`. |
| `napcat_enabled` | `false` | Enable the optional NapCat package. |
| `napcat_root` | blank | Required only when NapCat is enabled. |

Configuration changes never automatically alter a Windows task. Updating or replacing plugin code can also change the artifact digest bound to the task. Run `/safe_backup status`; if it reports artifact drift, deliberately run `/safe_backup task update` after reviewing the result. After exact task re-inspection it immediately synchronizes the schedule/configuration state binding, but does not start a backup or fabricate an archive success. An identity/state mismatch fails closed; an uncertain or quarantined result should be reviewed with `/safe_backup status`, not retried repeatedly.

## Schedule, commands, and uninstall

The task runs as the current Windows user with limited privileges, ignores overlapping starts, does not wake the computer, and has no forced execution timeout. It attempts on the configured weekday, retries once daily through the rest of that weekly cycle after a failure, and becomes a quiet state check after a full success. It never stops AstrBot to improve its success rate.

| Command | Action |
| --- | --- |
| `/safe_backup status` | Shows redacted state and configuration drift. |
| `/safe_backup check` | Checks paths, configuration, and state ownership only. |
| `/safe_backup history` | Shows small redacted run records. |
| `/safe_backup verify latest` | Verifies the latest managed archive without reading sources. |
| `/safe_backup task update` | Explicitly updates an exactly identified plugin task. |
| `/safe_backup task remove` | Explicitly removes that task; archives, state, and plugin files remain untouched. |

Before uninstalling the plugin, explicitly send `/safe_backup task remove`. Uninstall never removes a task automatically.

## Archives and manual recovery

Archives are not encrypted and may contain API keys, tokens, passkeys, plugin configuration, and chat data. Keep them in a private local location; do not upload or commit them.

There is deliberately no automatic restore code. Verify the archive first, extract it to a new empty directory, inspect `backup-manifest.json` and `RESTORE-NOTES.txt`, test a compatible AstrBot installation in isolation, then have an administrator manually replace data only after related processes have exited. Keep a separate pre-recovery copy for rollback.

## Known issues that can make a backup fail

- AstrBot is still running or Windows cannot prove its process state;
- source files, SQLite/WAL families, plugin data, or configuration change between inventories;
- a source file cannot be opened with shared read access;
- destination state, ownership, reparse points, or filesystem capabilities are not safe;
- optional NapCat metadata or configuration changes during a run;
- destination space is insufficient, or final archive verification fails;
- a path, plugin artifact, task, or state identity cannot be verified.

These conditions do not silently count as success. Preserve the scene, check `/safe_backup status` and the fixed terminal guidance, and do not take over or delete quarantine content manually. Extreme same-account malicious-attack cases are recorded in [SECURITY.md](SECURITY.md); that document is not used to hide ordinary user-facing defects.

## Privacy, development, and status

The source-read-only boundary applies to AstrBot and optional NapCat data; archives, state, logs, and isolated copies are written only to the backup destination. Same-disk local backup cannot protect against disk failure, formatting, ransomware, or malicious software under the same Windows account.

Automatic retention defaults to five archives. Cleanup is considered only after a new formal ZIP has passed full verification and its successful state is durably committed. Before removing an older archive, the plugin rechecks its owner, authoritative journal binding, source fingerprints, SHA-256, file identity, single-link status, and complete ZIP contents. Any uncertainty stops cleanup and preserves the file. Foreign, corrupt, replaced, hard-linked, or unprovable ZIP files are never automatically removed, so the physical ZIP count may temporarily exceed the configured limit.

Staging for the current run is cleaned only when two directory inventories match its complete identity registration: the run record, random UUID path, and object-identity token. A mismatch or cleanup failure fails closed; a sensitive quarantine is preserved and reported. Historical, foreign, or unprovable content is never cleaned.

Ordinary identity mismatches, malformed state, and benign concurrency fail closed. In the extreme, a malicious process under the same Windows account can perform a precise TOCTOU or replace an ancestor junction after validation. That is outside the normal-use boundary documented in SECURITY. Setup and update/remove are explicit user action.

All tests use synthetic directories only. Development, testing, and publishing must not access a real AstrBot/NapCat installation, Scheduled Task, or backup destination.

```powershell
python -B -m unittest discover -s tests -v
```

`v0.1.0-beta` currently supports AstrBot `>=4.26,<5` and local Windows cold backup only. Hot backup, automatic restore, network targets, uploads, and telemetry are out of scope. See [SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md). MIT licensed.
