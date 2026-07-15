# @vaultkeeper/cli

Command-line interface for [vaultkeeper](https://www.npmjs.com/package/vaultkeeper) — store,
retrieve, and inject secrets with policy-enforced access control. Secrets are kept in a portable,
self-contained encrypted `file` backend by default; your OS credential store (macOS Keychain,
Windows DPAPI) is available as an explicit opt-in.

## Installation

```sh
pnpm add -g @vaultkeeper/cli
# or
npm install -g @vaultkeeper/cli
```

**Requirements:** Node >= 20

## Quick start

All state (config, keys, the default `file` backend's secrets) lives under a config directory
that defaults to `~/.config/vaultkeeper`. Override it with the global `--config-dir <path>` flag
or the `VAULTKEEPER_CONFIG_DIR` environment variable — useful for CI runs and sandboxed/isolated
test environments that shouldn't touch a developer's real config:

```sh
vaultkeeper --config-dir /tmp/ci-vault doctor
# or
VAULTKEEPER_CONFIG_DIR=/tmp/ci-vault vaultkeeper doctor
```

```sh
# Run preflight checks
vaultkeeper doctor

# Initialize configuration. With no --backend this writes the safe, portable
# `file` backend — never your real OS keychain. Opt into the native store
# explicitly with --backend, e.g. `vaultkeeper config init --backend keychain`.
vaultkeeper config init

# Store a secret (reads from stdin)
echo "my-secret-value" | vaultkeeper store --name MY_API_KEY

# Pre-approve an executable (TOFU) so it isn't prompted on first use
vaultkeeper approve --script /usr/local/bin/my-tool

# Run a command with the secret injected as an env var. By default the secret
# value is redacted from the command's stdout/stderr as `[REDACTED]` — pass
# --no-redact if you need to see the real output while debugging.
vaultkeeper exec --secret MY_API_KEY --env MY_API_TOKEN --caller /usr/local/bin/my-tool -- my-tool --flag

# Toggle development mode for a script under active development
vaultkeeper dev-mode enable --script /path/to/script

# Delete a secret
vaultkeeper delete --name MY_API_KEY
```

Run `vaultkeeper <command> --help` for full flag reference on any subcommand — the CLI's own
`--help` output is the source of truth for its flags.

## Example config

`vaultkeeper config init` (no `--backend`) writes this config — the safe-by-default `file` backend,
not your OS credential store:

```json
{
  "version": 1,
  "backends": [{ "type": "file", "enabled": true }],
  "keyRotation": { "gracePeriodDays": 7 },
  "defaults": { "ttlMinutes": 60, "trustTier": 3 }
}
```

`vaultkeeper config show` prints this same shape (the file if one exists, otherwise the platform
defaults) — that's where `keyRotation.gracePeriodDays` and `defaults.trustTier` are visible
directly. `vaultkeeper exec` surfaces a related but distinct concept on every run: the caller's
trust-on-first-use (TOFU) status (see below), not these config fields.

## Key rotation and trust

`vaultkeeper rotate-key` replaces the active encryption key but keeps the previous one valid for
decryption for `keyRotation.gracePeriodDays` days, so secrets minted before a rotation don't break
immediately; once the grace period elapses, they become permanently unreadable.

`vaultkeeper exec` checks the caller executable (`--caller <path>`) against a local
trust-on-first-use (TOFU) manifest before granting access, and reports the outcome to stderr:
`Trust: verified (hash matches trust manifest)` for an already-approved caller, or a prompt/error
if the caller is unrecognized or its hash has changed since it was approved (requiring
re-approval). `vaultkeeper approve --script <path>` pre-registers a caller's hash so it's already
trusted on its first `exec` run. This TOFU trust check is separate from the `trustTier` label
(`1`, `2`, or `3`) that `defaults.trustTier` attaches to each minted token as policy metadata —
the label doesn't itself reflect the TOFU check's outcome.

## Development mode

`vaultkeeper dev-mode enable --script <path>` relaxes the TOFU check above for one executable, so
a binary you're actively rebuilding doesn't get rejected every time its hash changes. It's
persisted in the config's `developmentMode.executables` list — use `dev-mode disable --script
<path>` to remove it again. Reserve this for local development only; a production caller should
stay on TOFU verification so a tampered or swapped binary is still caught.

## Exit codes

Every command exits with one of three codes, so scripts and CI pipelines can branch on the class
of failure without parsing stderr:

| Code | Meaning       | Example                                                               |
| ---- | ------------- | --------------------------------------------------------------------- |
| `0`  | Success       | `vaultkeeper doctor` when all required dependencies are present       |
| `1`  | Runtime error | `vaultkeeper delete --name DOES_NOT_EXIST` — the secret doesn't exist |
| `2`  | Usage error   | `vaultkeeper --bogus` or `vaultkeeper some-unknown-command`           |

## Available commands

`doctor`, `config init` / `config show`, `store`, `delete`, `exec`, `approve`, `dev-mode`,
`rotate-key`, `revoke-key`. The native Rust CLI (`vaultkeeper-cli`, installable via
`cargo install vaultkeeper-cli`) shares this same command surface.

## Full documentation

The [`vaultkeeper`](https://www.npmjs.com/package/vaultkeeper) library package's README and shipped
`.d.ts` cover the TypeScript API and access patterns for embedding vaultkeeper programmatically. For
narrative coverage of development mode and the full error hierarchy, see the
[repository README](https://github.com/mike-north/vaultkeeper#readme).

## License

MIT
