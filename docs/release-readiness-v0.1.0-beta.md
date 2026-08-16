# v0.1.0-beta release-readiness evidence

Status: PASS for the frozen, synthetic-only implementation workspace (2026-08-10).

## Verification

- `PYTHONDONTWRITEBYTECODE=1 python -B -m unittest discover -s tests -q`: **254 passed** in 84.129s.
- In-memory `compile()` of `main.py`, every `safe_backup/**/*.py`, `scripts/**/*.py`, and `tests/**/*.py`: **25 files passed**; it did not create bytecode.
- PowerShell parsing: **8/8** scripts passed in PowerShell 7 and **8/8** passed in Windows PowerShell 5.1.
- Metadata, schema defaults, release allowlist, and privacy-pattern scan: **26/26 release entries passed**.
- A fresh isolated `build_release_package.ps1` build passed after the automatic-retention and empty-description migration fixes, with 26 allowlisted entries and full extraction/hash comparison against the source allowlist. The ZIP was 99,549 bytes; SHA-256 `7b951d59868440cfe9af7dc134767dd4286d922d5ec0ad8b27a78d852fb2659c`.

The two release outputs contained only the ZIP and its matching `.sha256` sidecar. No `.partial` output remained in either output directory.

## Release allowlist hashes

| Entry | SHA-256 |
| --- | --- |
| `main.py` | `7aa12984776f8a8411e4b62ab735889be821f7aec67548eeae7cf9dcab568000` |
| `metadata.yaml` | `9ed84d4db5c6ae41a91c03b65cb96f125a40f8efe95b8d9b0ca9199dc6ac9bf8` |
| `_conf_schema.json` | `acf962e690051bc798b85d7d72602b1a65a75498882634a3d6aa83410b5723f3` |
| `README.md` | `35c925407777a66192fb179c1cbf36b99dea157966f62259a87e07cf32b20a23` |
| `README_EN.md` | `9cb79fc4ed397092c3752cd8e8eaa0b59aa0cfd97ed4d1bf1246ded6497e586d` |
| `SECURITY.md` | `72145437f5866844508fc0ec7566bf2d16c48ca591e5dc724f9594ace7704b83` |
| `safe_backup/engine.py` | `9fcb338431a8c99d59057a7154504789409372de51d2c0bc6825b6bcba0681d8` |
| `safe_backup/setup.py` | `758b1e7aa8bd6dda2a9b8c22f51887639be8ae918e23f96d57296bb90beff4e4` |
| `safe_backup/task_control.py` | `2a5219e12cb05a0cc066a30b2e3ab01bf9d1d99708ae756ec573f5e103445192` |
| `safe_backup/exit_waiter.py` | `da8b47a1fee9090e046dbf6521c677cc0b6d5d5132be594927d6f2e1ff6ac993` |
| `safe_backup/progress.py` | `665953ae125bbe4197f72bf2c9b859aa4b2e62addd5223ac1bcfe25aa9bfed88` |
| `safe_backup/console_runner.py` | `61e38496facff85156cb370356eaa58ae839b974d3ef5786493e1673d2ab7dde` |
| `scripts/*.ps1` (7 allowlisted runtime files) | individually verified in the deterministic ZIP/extraction comparison |
| Remaining root documentation/runtime files (12) | individually verified in the deterministic ZIP/extraction comparison; updated `CHANGELOG.md` SHA-256 `4d1f9479649c6840b50b00a9678718d74fca4d4f7241fa78d27d28485e23eb23`; updated `PUBLISHING_AGENT_PROMPT.md` SHA-256 `47f38ba1f6a822f64527216b411ddcd1cd63c67cfbccbe5b772f8f27639fffee` |

## Residual security boundaries

The approved `SECURITY.md` boundaries remain: a same-Windows-account adversary can attempt last-instruction/task/code self-proof races; deliberately supplied untrusted external ZIPs can consume bounded resources during verification; and same-disk, unencrypted local archives do not provide disaster recovery or encryption. These are not treated as normal-use backup failures and are documented in `SECURITY.md`.

## Scope declaration

This evidence used only the isolated workspace and synthetic tests. It did **not** access a D-drive source, the original backup directory, Task Scheduler, Desktop delivery tree, Git/GitHub remote, release endpoint, network service, or real AstrBot/NapCat data. No real task was registered.

The live packaged namespace has no cache/bytecode, database, log, state, ZIP, or partial artifacts. Historical `.pyc` files remain only under `.superpowers` SDD baseline snapshots; those snapshots are outside the release allowlist and were deliberately preserved as audit records.
