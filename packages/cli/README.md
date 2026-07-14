# @vaultkeeper/cli

Command-line interface for [vaultkeeper](https://www.npmjs.com/package/vaultkeeper) — store,
retrieve, and inject secrets with policy-enforced access control, backed by your OS credential
store.

## Installation

```sh
pnpm add -g @vaultkeeper/cli
# or
npm install -g @vaultkeeper/cli
```

**Requirements:** Node >= 20

## Quick start

```sh
# Run preflight checks
vaultkeeper doctor

# Initialize configuration
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

## Available commands

`doctor`, `config init` / `config show`, `store`, `delete`, `exec`, `approve`, `dev-mode`,
`rotate-key`, `revoke-key`. The native Rust CLI (`vaultkeeper-cli`, installable via
`cargo install vaultkeeper-cli`) shares this same command surface.

## Full documentation

See the [repository README](https://github.com/mike-north/vaultkeeper#readme) for the TypeScript
library API, access patterns, key rotation, trust tiers, and configuration reference.

## License

MIT
