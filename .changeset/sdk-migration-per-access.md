---
"vaultkeeper": major
---

Migrate 1Password backend from `op` CLI to `@1password/sdk`

Breaking change: the 1Password backend now requires the `@1password/sdk` package and either the 1Password desktop app (for biometric auth via `DesktopAuth`) or a service account token (for headless CI/CD). The `op` CLI is no longer used.

New per-credential access modes:
- **Session mode** (default): SDK client is created once on first use and cached for the lifetime of the process. A 30-second timeout guards against the SDK hanging during authentication (known beta bug).
- **Per-access mode**: fresh biometric prompt for every secret retrieval via child process isolation. Only available with desktop auth (not service account tokens).

Setup now collects account name, vault, and access mode preference.
