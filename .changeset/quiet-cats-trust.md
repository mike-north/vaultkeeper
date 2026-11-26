---
'vaultkeeper': patch
'@vaultkeeper/cli': patch
'@vaultkeeper/wasm': patch
---

Serialize trust-manifest updates across processes so independent approvals survive and conflicting first-use approvals require explicit reapproval.
Resolve WASM manifest locks through filesystem aliases and create native approval directories with owner-only permissions.
