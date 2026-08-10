# Contributing

Thank you for helping improve AstrBot Safe Backup. Safety takes precedence over convenience and compatibility.

## Before changing code

- Open an issue describing the behavior and its effect on the source-read-only boundary.
- Never use a real AstrBot, NapCat, QQ, backup directory, Scheduled Task, account identifier, or secret as a fixture.
- Do not add process-stop, unlock, online-backup, automatic-restore, upload, telemetry, UNC/NAS, or broad cleanup behavior.
- Do not weaken failure-closed handling to support an unknown version or layout.

## Development checks

Use Python 3.12 or 3.13 on Windows:

```powershell
python -m unittest discover -s tests -v
python -m compileall -q .
```

PowerShell changes must support Windows PowerShell 5.1 and PowerShell 7, expose `-ValidateOnly`, and use synthetic names during testing. No test may register or remove a real task.

## Pull-request requirements

- Explain the safety effect and new failure modes.
- Add synthetic tests for success, access denial, drift, reparse points, identity mismatch, and interrupted output as applicable.
- Confirm that plugin load/unload performs no filesystem or task mutation.
- Confirm that no local paths, account names, tokens, archive contents, or configuration values were committed.
- Update Chinese and English documentation together.
- Obtain independent specification/safety review and destructive-operation review before release.

Changes that can write source data, interfere with source processes, adopt foreign state, or delete an unverified file will not be accepted.
