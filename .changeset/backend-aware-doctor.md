---
'vaultkeeper': minor
---

Scope doctor checks to configured backends: system dependency checks (secret-tool, security, powershell) are only required when the corresponding backend is enabled, reducing false negatives on systems that only use the file backend.
