# Security Policy

## Supported version

Security fixes are considered for the latest published release. `v0.1.0-beta` currently supports local Windows cold backup with AstrBot `>=4.26,<5` only.

## Release-blocking invariants

Every release must preserve these rules:

1. AstrBot source data, and optional NapCat source data, are never opened for write, delete, rename, metadata mutation, exclusive locking, repair, or SQLite access.
2. No source process is stopped, paused, restarted, killed, unlocked, or sent an exit signal.
3. Only an explicit administrator command (`/safe_backup setup`, `/safe_backup task update`, or `/safe_backup task remove`) may change a Scheduled Task. Plugin load and unload do not.
4. Foreign destinations, owner IDs, state, archives, and tasks are never adopted or deleted.
5. A formal ZIP is published only after path checks, streaming CRC and manifest SHA256 verification, and `integrity_check` for recognized SQLite main databases materialized in a registered target-side directory. This does not claim that an entire archive tree is materialized.
6. Automatic retention is fail-closed. It runs only after a newer verified archive and success state are durably committed. An older archive must be bound by the authoritative journal and match the owner, source fingerprints, SHA-256, strict filename, regular-file type, single-link identity, and a fresh complete archive verification. Any mismatch preserves the archive and stops cleanup; foreign, corrupt, or unprovable ZIP files are never adopted or deleted.
7. Current-run staging cleanup requires a matching run record, UUID path, and object identity. A mismatch or cleanup failure preserves a sensitive quarantine instead of broad cleanup.
8. Logs and chat replies never include configuration values, database rows, secrets, cookies, passkeys, tokens, unfiltered exceptions, or real paths.
9. Tests, CI, documentation examples, release packaging, and reviews use synthetic paths only.

Any violation is a release blocker.

## Reporting a vulnerability

Use the repository host's private security-advisory feature. Do not put archive contents, configuration files, state files, logs, database samples, account identifiers, or real filesystem paths in a public issue.

Provide the smallest sanitized reproduction and say whether source data could have changed, a foreign file could have been deleted, or a secret could have been exposed.

## Extreme security scenarios recorded here

The cases in this section are extreme or malicious-attack scenarios. **而这些问题被认为不会在主要使用场景中出现。** They are recorded here so that maintainers and advanced users can assess the boundary; this document **不会用来隐藏普通用户容易遇到的功能缺陷**. Conditions that can normally make a backup fail belong in README's “已知问题：可能导致备份失败” section and must remain fail-closed.

### Same Windows account can defeat normal user-mode trust

A malicious program running as the same Windows account can perform a precise TOCTOU race during validation, replace an ancestor junction after a check, or replace task/code/target material after it was inspected. It can also directly alter files owned by that account. In particular, a same-account attacker can make an apparent last-instruction/task/code self-proof unreliable by replacing the object after its final check but before Windows consumes it.

Ordinary identity mismatches, malformed state, and benign races fail closed. Fully defending against a hostile same-account principal would require stronger account/ACL isolation or a different service architecture, not a normal user-mode plugin. Use restrictive local ACLs and do not run untrusted same-account programs while using the backup.

### Untrusted external ZIP verification has bounded resource cost

The verifier rejects path traversal and enforces entry-count, expanded-size, per-entry, and compression-ratio ceilings. Nevertheless, a deliberately constructed external ZIP near those ceilings can consume noticeable CPU, disk I/O, and temporary target-side space before rejection. Verify external ZIP files only when they came from a trusted source. The verifier never writes to AstrBot or optional NapCat source paths.

### Non-encrypted local copies remain sensitive

Archives and a preserved quarantine are not encrypted. This project does not defend against disk failure, volume loss, formatting, ransomware, or a compromised same Windows account. These are deployment risks, not a reason to weaken the source-read-only or fail-closed rules above.

The plugin provides no uploads, network destinations, or automatic restore.
