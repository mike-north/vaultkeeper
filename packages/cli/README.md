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

# Run a command with the secret injected as an env var
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
defaults). `keyRotation.gracePeriodDays` and `defaults.trustTier` are the two fields `config show`
and `exec` surface directly — see below for what they mean.

## Key rotation and trust tiers

`vaultkeeper rotate-key` replaces the active encryption key but keeps the previous one valid for
decryption for `keyRotation.gracePeriodDays` days, so secrets minted before a rotation don't break
immediately; after the grace period, they become permanently unreadable.

`vaultkeeper exec` mints a token tagged with the config's `defaults.trustTier` (`1`, `2`, or `3`)
as a policy label describing how the caller executable's identity was verified: `1` = Sigstore
transparency log, `2` = registry signature, `3` = TOFU (Trust On First Use, hash stored in the
local trust manifest — the default). `vaultkeeper approve --script <path>` pre-registers a TOFU
hash so tier-3 executables aren't prompted on first use.

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
