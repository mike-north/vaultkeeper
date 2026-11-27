---
'vaultkeeper': patch
'@vaultkeeper/wasm': patch
---

Keep YubiKey inventory consistent with encrypted records after concurrent stores or legacy index failures.
Older versions that share this storage still rely on the legacy index and may not see changes made by upgraded versions.
Report TypeScript inventory directory failures as typed filesystem errors.
List YubiKey records by envelope, including legacy records reachable through case aliases or links to regular files. Publish stores as regular files through their canonical paths, even at the macOS path limit. New IDs that previously shared a UTF-8 filename use distinct paths and authenticated version 2 envelopes. Keep IDs listed during upgrades and require matching legacy filenames before using index spellings to retire records. Keep legacy records accessible where their exact filenames would exceed the path limit. Report a typed error when a lossy legacy filename cannot identify the original ID. Older readers need an upgrade to find version 2 records.

Allow fresh stores and legacy overwrites at the macOS path limit using compact exact filenames. Keep truncated legacy and compact records in inventory when their version markers survive. Resolve only the requested legacy filename during point operations, and surface unreadable record candidates during inventory.

Report a typed decryption error with the affected path when a recognized hashed YubiKey record loses its verifiable ID. Rust hosts using the default lookup resolve reachable case aliases and skip confirmed directories.
