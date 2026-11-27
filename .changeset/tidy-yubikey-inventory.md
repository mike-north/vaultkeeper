---
'vaultkeeper': patch
'@vaultkeeper/wasm': patch
---

Keep YubiKey inventory consistent with encrypted records after concurrent stores or legacy index failures.
Older versions that share this storage still rely on the legacy index and may not see changes made by upgraded versions.
Report TypeScript inventory directory failures as typed filesystem errors.
List YubiKey records by envelope so co-located file-backend records and directories stay out of the inventory. Recover unambiguous legacy TypeScript IDs when their original spelling is available. New IDs that previously shared a UTF-8 filename use distinct paths and authenticated version 2 envelopes. Older readers need an upgrade to find these records.
