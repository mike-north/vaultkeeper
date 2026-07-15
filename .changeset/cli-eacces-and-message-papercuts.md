---
'@vaultkeeper/cli': patch
---

Route the shared config-file presence check through the typed `FilesystemError` path, and fix three CLI message papercuts.

- `store`, `config show`, `delete`, and `exec` against a config directory the process cannot read (e.g. `chmod 000`) no longer leak a raw Node `EACCES: permission denied, access '.../config.json'` string. They now render the same typed `FilesystemError` with a permissions remediation that `doctor` already produced — a human message naming the file and pointing at the file's permissions, with a non-zero exit.
- `delete`'s "secret not found" message no longer tells the user to run `store` to *create* the secret they are trying to delete. It keeps the shared diagnostic line but gives a neutral, delete-appropriate hint. `exec` (an access path) still suggests creating the secret.
- `exec`'s required-flags validation error now includes the standard `Usage:` line, matching every sibling validation error (exit code 2).
- `vaultkeeper approve --help` now states that `approve` is a required first step for a new caller in non-interactive/CI contexts (non-TTY stdin), where there is no prompt to grant trust — not merely an optional prompt-avoidance convenience.
