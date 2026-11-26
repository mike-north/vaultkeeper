---
'vaultkeeper': patch
'@vaultkeeper/wasm': patch
---

Keep YubiKey inventory consistent with encrypted records after concurrent stores or legacy index failures.
Older versions that share this storage still rely on the legacy index and may not see changes made by upgraded versions.
