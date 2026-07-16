---
'vaultkeeper': patch
'@vaultkeeper/cli': patch
---

Wrap config-directory CREATION failures in a typed `FilesystemError` instead of leaking a raw Node error.

`vaultkeeper config init` (and the first `store`, which persists key state before writing any secret) against a config directory whose parent is read-only previously aborted with the raw, unwrapped `Error: EACCES: permission denied, mkdir '<path>'` — no error class, no plain-English description, no fix hint. Only the config-directory READ paths had been wrapped previously.

The directory-creation path now surfaces a typed `FilesystemError` (with the path and the underlying errno code) rendered through the CLI's error formatter with directory-specific wording and a parent-directory fix hint (check that the parent directory is writable, or choose a writable location with `--config-dir`). The raw `EACCES`/`mkdir` errno text no longer reaches the user, and the command still exits non-zero. The key-state write path is likewise wrapped.
