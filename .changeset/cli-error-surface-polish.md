---
'vaultkeeper': minor
'@vaultkeeper/cli': minor
---

Uniform CLI exit-code taxonomy (0 success / 1 runtime failure / 2 usage error) applied everywhere: a top-level typo like `vaultkeeper --bogus` now exits 2 with an error instead of silently exiting 0, and an unrecognized flag on `store`, `delete`, `exec`, `approve`, `dev-mode`, or `doctor` now exits 2 instead of a bare fatal error (exit 1).

`store` (and `delete`, for consistency) now reject an empty or whitespace-only `--name` with exit 2 and the same error style as a missing flag, instead of persisting a near-unreachable secret or surfacing a generic runtime error. Allowed `--name` characters (letters, digits, `.`, `_`, `-`, `/`) are documented in `--help`.

`exec` now validates that the secret exists before the caller-approval/TTY gate, so `exec --secret <nonexistent> ...` reports a clear `SecretNotFoundError` regardless of TTY, instead of being masked by the generic "requires interactive approval" message. This is backed by a new public `VaultKeeper.secretExists(name)` method — a side-effect-free existence check that never touches the TOFU trust manifest.

`config init --help` and `config show --help` now print help for that subcommand instead of the parent `config` help. `exec --help` includes a worked `--caller` example.
