---
'vaultkeeper': patch
'@vaultkeeper/wasm': patch
---

Keep YubiKey inventory consistent with encrypted records after concurrent stores or legacy index failures.
Older versions that share this storage still rely on the legacy index and may not see changes made by upgraded versions.
Report TypeScript inventory directory failures as typed filesystem errors.
List YubiKey records by envelope so co-located file-backend records and directories stay out of the inventory. Publish stores as regular files at their canonical names, including on case-insensitive volumes. New IDs that previously shared a UTF-8 filename use distinct paths and authenticated version 2 envelopes. Upgrading a uniquely indexed legacy ID replaces its old record. Report a typed error when a lossy legacy filename cannot identify the original ID. Older readers need an upgrade to find version 2 records.
