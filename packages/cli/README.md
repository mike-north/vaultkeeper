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

<!-- readme-example: skip - overview of the command surface; `approve`/`exec`/`dev-mode` reference placeholder tool paths, not runnable verbatim -->

```sh
# Run preflight checks
vaultkeeper doctor

# Initialize configuration. With no --backend this writes the safe, portable
# `file` backend — never your real OS keychain. Opt into the native store
# explicitly with --backend, e.g. `vaultkeeper config init --backend keychain`.
vaultkeeper config init

# Store a secret (reads from stdin)
echo "my-secret-value" | vaultkeeper store --name MY_API_KEY

# Pre-approve an executable (TOFU) so it's trusted on its first `exec`.
# In non-interactive/CI use this is a REQUIRED first step for a new caller: with
# no TTY to show an approval prompt, the first `exec` of an unrecognized caller
# fails unless it was pre-approved here (or you pass --yes / VAULTKEEPER_YES to
# approve it inline). Interactively it just avoids the one-time prompt.
vaultkeeper approve --script /usr/local/bin/my-tool

# Run a command with the secret injected as an env var. By default the secret
# value is redacted from the command's stdout/stderr as `[REDACTED]` — pass
# --no-redact if you need to see the real output while debugging.
vaultkeeper exec --secret MY_API_KEY --env MY_API_KEY --caller /usr/local/bin/my-tool -- my-tool --flag

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
persisted in the config's `developmentMode.executables` list — use
`vaultkeeper dev-mode disable --script <path>` to remove it again. Reserve this for local
development only; a production caller should stay on TOFU verification so a tampered or swapped
binary is still caught.

## Doctor / preflight checks

`vaultkeeper doctor` lists a dependency check per backend tool and marks each present or missing.
Two things are easy to misread:

- **A checkmark means the binary was found on `PATH`, not that a backend is active.** A green `op`
  means the 1Password CLI is installed — not that a 1Password backend is enabled. Secrets only
  route through a backend that is enabled in your config (`vaultkeeper config show`).
- **Plugin-backend checks (`op`, `ykman`) are informational only while their backend isn't
  enabled.** They're always listed — even with just the default `file` backend — and a missing one
  is a **warning** that doesn't make `doctor` fail. But enabling the corresponding backend
  (`1password` → `op`, `yubikey` → `ykman`) **promotes that check to required**, so a missing tool
  then makes `doctor` report "not ready" and exit non-zero. The same promotion applies to the
  native credential tool (`security`/`powershell`/`secret-tool`): required when its backend is the
  enabled one, informational otherwise. `openssl` is always required.

The native Rust CLI's `doctor` and the WASM SDK's `doctor()` apply the same required-vs-informational
rules.

## Exit codes

Every command exits with one of the codes below, so scripts and CI pipelines can branch on the
class of failure without parsing stderr:

| Code | Meaning                                 | Example                                                                          |
| ---- | --------------------------------------- | -------------------------------------------------------------------------------- |
| `0`  | Success                                 | `vaultkeeper doctor` when all required dependencies are present                  |
| `1`  | Runtime error                           | `vaultkeeper delete --name DOES_NOT_EXIST` — the secret doesn't exist            |
| `2`  | Usage error                             | `vaultkeeper --bogus`, `vaultkeeper some-unknown-command`, empty stdin to `sign` |
| `3`  | `verify` only: signature did not verify | `vaultkeeper verify` on a tampered payload, the wrong key, or a malformed JWS    |

Exit `3` is a deliberate, documented exception to the `0/1/2` taxonomy, scoped to `verify` alone
(precedent: `gpg --verify`, `ssh-keygen -Y verify`). It lets a script tell "the signature is bad"
from "the tool broke" without parsing stderr — `verify` reserves `1` for operational faults (an
unreadable file, a structurally unparseable public key), never for a bad signature.

## Signing keys, sign, and verify

Signing keys are a distinct resource from secrets — private key material never leaves the backend
and is never readable as a secret. Enroll a key, export its public half, sign an arbitrary payload
from stdin (the detached signature is the only thing on stdout, so it is pipeline-safe), and verify
fully offline:

```sh
CHALLENGE="hello-challenge"
vaultkeeper key create --name approval-signing-key --type ed25519   # an unknown --type value exits 2
vaultkeeper key export --name approval-signing-key > approval.pub   # SPKI PEM public key
printf '%s' "$CHALLENGE" | vaultkeeper sign --name approval-signing-key > sig
printf '%s' "$CHALLENGE" | vaultkeeper verify --public-key approval.pub --signature sig   # exit 0 = valid
```

Feed `sign` and `verify` the payload the **same way** — here, `printf '%s'` piped into
both — so each reads byte-identical stdin. A detached signature covers the exact bytes it was
given, so a construct that changes them breaks verification: a here-string (`<<<"$CHALLENGE"`)
appends a trailing newline in bash and zsh, and `echo` does too, so mixing either with
`printf '%s'` makes `verify` see one more byte than `sign` signed and fail with exit `3`.

The signature is a detached-payload Compact JWS (algorithm `EdDSA` / Ed25519; base64url without
padding, [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515); detached payload via
[RFC 7797](https://www.rfc-editor.org/rfc/rfc7797) `b64:false`, `crit:["b64"]`), so any standard
JOSE library can verify it independently. `verify` needs no config, backend, or key store — only
the public key, the payload on stdin, and the signature.

## Presence-per-use (require a fresh human action)

Discover which backends can force a **fresh, per-use human action** (a distinct touch/biometric that
no cached or session unlock can satisfy), then require it for an operation:

<!-- readme-example: skip - fragment; reuses the approval-signing-key and $CHALLENGE created in the sign/verify fence above -->

```sh
# List each registered backend and whether it forces a fresh per-use action.
vaultkeeper backend capabilities          # human-readable
vaultkeeper backend capabilities --json   # [{ "type", "displayName", "presencePerUse" }, ...]

# Require it for a backend-touching op. On a non-qualifying backend this fails
# with NotCapableError (exit 1) before any credential is touched.
printf '%s' "$CHALLENGE" | vaultkeeper sign --name approval-signing-key --require-presence-per-use
```

`--require-presence-per-use` is accepted on `store`, `delete`, `sign`, and `exec` (never a global
flag, and never on `verify`, which touches no backend). With `exec`, a cached token is never reused
under this flag — a fresh action is forced for the invocation. A YubiKey slot with a touch policy or
1Password in `per-access` mode qualifies; `file`/`keychain`/`dpapi`/`secret-tool` do not. See the
library README's [Presence-per-use](https://www.npmjs.com/package/vaultkeeper) section for the
per-backend truth basis and the cached-OS-unlock caveat.

## Available commands

`doctor`, `config init` / `config show`, `store`, `delete`, `backend capabilities`, `key create` /
`key export`, `sign`, `verify`, `run`, `exec`, `approve`, `dev-mode`, `rotate-key`, `revoke-key`. The native
Rust CLI (`vaultkeeper-cli`, installable via `cargo install vaultkeeper-cli`) shares the secret-management
command surface; signing (`key`/`sign`/`verify`) currently ships in the Node CLI, with Rust parity
tracked separately.

`run --token <jwe> [--as VAR]` redeems an already-minted JWE and launches a command with it injected as
an env var (default `VAULTKEEPER_SECRET`), with full stdio and signal transparency — `run` is now the
single launcher verb (surface-governance ruling B9, `docs/specs/001-surface-governance.md`). `exec`'s
own `--secret`/`--env`/`--caller` flow (mint a token from scratch, enforcing the TOFU trust gate) is
unaffected and still the way to go from a bare secret name to a running command in one step.

## Full documentation

The [`vaultkeeper`](https://www.npmjs.com/package/vaultkeeper) library package's README and shipped
`.d.ts` cover the TypeScript API and access patterns for embedding vaultkeeper programmatically —
including the complete error hierarchy and full `VaultConfig` reference, shipped inline in that
package's README. The [repository README](https://github.com/mike-north/vaultkeeper#readme) covers
related narrative online, but for the complete reference see the `vaultkeeper` package's own
README linked above.

## License

MIT
