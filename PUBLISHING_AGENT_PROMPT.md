# Prompt for the publishing Agent

Copy the prompt below into a separate Agent only after all implementation reviews and tests have passed.

---

You are publishing the already completed AstrBot community plugin `astrbot_plugin_safe_backup`. Work **only inside the repository directory explicitly supplied by the user**. Do not inspect, stage, copy, upload, or modify its parent directory, any real AstrBot/NapCat/QQ installation, any backup destination, or any Windows Scheduled Task.

Your tasks are:

1. Build a clean release repository from an explicit allowlist of public source, synthetic tests, documentation, CI, and release assets. Do not copy or commit `.superpowers/` or `docs/superpowers/`; they are local implementation/audit material and may contain machine-specific paths. Do not use `git add .`. Refuse publication if the resulting allowlist contains backups, databases, configuration dumps, logs, state files, ZIP partials, credentials, local account identifiers, machine-specific absolute paths, or private task names.
2. Ask the user for the final GitHub owner and repository URL. If either identity is unknown, stop and ask the user; do not infer an owner, organization, visibility, or repository name. Replace every `shuohui-air-technology` placeholder in `metadata.yaml`, `main.py`, `LICENSE`, and documentation as applicable. Confirm `metadata.yaml` has:
   - name `astrbot_plugin_safe_backup`;
   - display name `AstrBot 自动化安全冷备份插件`;
   - version `v0.1.0-beta`;
   - AstrBot compatibility `>=4.26,<5`;
   - a repository URL belonging to the supplied owner.
3. Run all tests on Windows with Python 3.12 and, when available, Python 3.13. Run compile checks, PowerShell 5.1/7 parse and `-ValidateOnly` tests, metadata checks, package-size checks, and privacy/secret scans. Do not run the engine against real paths and do not register a task.
4. Require the two independent reviews described in `SECURITY.md`: specification/source-read-only review and destructive-operation/privacy review. Do not publish if either review reports a blocker, severe data-integrity risk, source-process interference, foreign-file deletion risk, or `REJECT`.
5. Initialize Git only at the supplied clean release repository root. Before the first commit, print and manually inspect the complete staged allowlist. Never use `git add .` or `git add` on a parent directory. Make a clean initial commit without rewriting unrelated history.
6. Create or connect the repository requested by the user. Do not infer an organization, visibility, branch-protection policy, or marketplace identity. Do not force-push or overwrite an existing remote.
7. Build `astrbot_plugin_safe_backup-v0.1.0-beta.zip` and its `.sha256` sidecar using the repository's narrow release-packaging allowlist. Its archive root must directly contain `main.py`, `metadata.yaml`, `_conf_schema.json`, `safe_backup`, and `scripts`—not an extra parent directory. Exclude `.git`, tests, caches, diagnostics, state, logs, partial files, and every backup archive. Confirm the ZIP is below the AstrBot marketplace size limit.
8. Create a prerelease/tag `v0.1.0-beta` with concise notes that clearly state: Windows-only beta; AstrBot must be stopped for backup; NapCat is optional; ZIPs are unencrypted and potentially sensitive; no automatic restore, upload, telemetry, or network target.
9. If the user requests marketplace submission, follow the current official AstrBot publishing instructions and submit the exact final repository identity. Do not claim approval until the marketplace confirms it.
10. Return the repository URL, commit hash, tag, release URL, ZIP filename, SHA-256, test results, review verdicts, secret-scan result, and marketplace submission status.

At every stage, fail closed instead of weakening a safety check. Publication authority does not authorize access to any local production installation or backup.

---
