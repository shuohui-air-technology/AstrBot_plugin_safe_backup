# Changelog

All notable changes are documented here. Versions follow Semantic Versioning where practical.

## [0.1.0-beta] - Unreleased

### Added

- One-click `/safe_backup setup` initialization with a derived local destination, an exact identity-gated Scheduled Task, and a natural-exit first-run waiter.
- Read-only AstrBot administrator control plane for configuration checks, sanitized status, history, and archive verification.
- Windows cold-backup engine with full source-tree stability checks and target-side SQLite verification.
- Optional, version-validated NapCat configuration bundle.
- Explicit identity-gated Scheduled Task update and remove commands; plugin load/unload never mutates tasks.
- Visible terminal progress for every actual attempt, including the exact Chinese success message `备份成功`.
- Manifested ZIP verification, weekly retry scheduling, synthetic tests, bilingual documentation, and manual verified-archive retention guidance.

### Security

- Plugin load/unload never mutates a task and the plugin never performs an online backup. After an administrator explicitly runs setup, the identity-gated Windows daily schedule automatically attempts a cold backup when due; every actual attempt is visible in a terminal.
- Added fail-closed automatic retention. `retention_count` defaults to five and only verified, journal-bound, single-link archives can be removed after a newer success is durably committed; foreign, corrupt, or uncertain ZIP files are preserved.
- Current-run staging cleanup requires complete run identity; cleanup failures are preserved and reported as sensitive quarantine rather than broad-cleaned.
- Operator mistakes and benign races fail closed. Precise same-account TOCTOU, ancestor-junction replacement, and malicious task replacement are documented threat-model exclusions.
- Backup archives remain unencrypted; see `SECURITY.md` and both READMEs.
- The release package is generated through a narrow allowlist with `astrbot_plugin_safe_backup-v0.1.0-beta.zip` and SHA-256 sidecar; it excludes tests, state, logs, archives, caches, and machine-specific material.
