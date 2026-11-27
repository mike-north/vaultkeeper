---
'vaultkeeper': patch
'@vaultkeeper/wasm': patch
---

Keep YubiKey inventory consistent with encrypted records after concurrent stores or legacy index failures.
Older versions that share this storage still rely on the legacy index and may not see changes made by upgraded versions.
Report TypeScript inventory directory failures as typed filesystem errors.
List YubiKey records by envelope, including legacy records reachable through case aliases or links to regular files. Publish stores as regular files through their canonical paths, even at the macOS path limit. New IDs that previously shared a UTF-8 filename use distinct paths and authenticated version 2 envelopes. Keep IDs listed during upgrades and require matching legacy filenames before using index spellings to retire records. Keep legacy records accessible where their exact filenames would exceed the path limit. Report a typed error when a lossy legacy filename cannot identify the original ID. Older readers need an upgrade to find version 2 records.

Allow overwrites of confirmed legacy credentials when their exact filenames exceed filesystem limits. Filter record names before following links so unreadable legacy metadata cannot block ordinary inventory.
