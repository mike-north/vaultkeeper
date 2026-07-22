# vaultkeeper PRFAQ

> Internal working document. The press release is aspirational-at-launch framing; the FAQ is
> honest about what exists today versus what is in flight. Kept current by the maintainers.

---

## Press Release

### vaultkeeper brings policy-enforced secret custody to every developer — using the credential store you already own

**Developers can now get the secret-handling posture that previously required a business-tier
subscription — scoped tokens, expiring grants, per-use approval — locally, offline, and free,
on top of macOS Keychain, 1Password, a YubiKey, or an encrypted file.**

Today, the standard way to give a tool a secret is still an environment variable holding a
plaintext credential, sourced from a dotfile or pasted into a config. Every MCP server config
with a `GITHUB_TOKEN` in it, every `.env` in a backup, every API key in shell history is the
same story: a long-lived, unscoped credential at rest in plaintext, readable by anything and
revocable only by rotating it everywhere at once. The tools that fix this properly — scoped
service tokens, dedicated vaults, per-use biometric approval — largely gate those capabilities
behind paid business tiers or cloud subscriptions.

vaultkeeper unbundles **storage** from **policy**. Your secrets live in whatever backend you
already trust — macOS Keychain, 1Password, a YubiKey, Windows DPAPI, libsecret, or an encrypted
file store — and vaultkeeper supplies the governance layer those stores lack: capability tokens
scoped by expiry, usage count, and executable identity; per-use human-presence requirements
(a Touch ID tap or YubiKey touch *for this operation, right now*); delegated access patterns
where the raw secret never enters the calling process at all; and full local revocation.

Adoption is a gradient, not a rewrite. `vaultkeeper run --profile github-mcp -- npx
@github/mcp-server` wraps any unmodified tool: the plaintext token leaves the config file and is
materialized only into the child process, under policy, with nothing at rest. Tools that
integrate further can hold a **VaultKeeper lease** instead of the secret itself — an encrypted,
expiring, revocable capability that is worthless off the machine and worthless after its window
closes. Signing keys go further still: the private key never leaves the backend at all;
consumers request signatures, never key material.

The same identity primitives serve human and automation signers alike. An agent fleet can hold
signing identities whose keys are born inside vaultkeeper and cannot be extracted by the
processes they govern — with human presence proven once at session establishment rather than
demanded per signature.

vaultkeeper is a single Rust core reachable from a native CLI and from TypeScript via
WebAssembly, with a data-driven conformance suite holding every implementation to the same
behavior. It is open source, local-first, and has no cloud component: nothing about your
secrets ever leaves your machine.

---

## FAQ

### What problem does vaultkeeper actually solve?

Plaintext credentials at rest, and the absence of policy between a secret and the processes that
use it. The realistic adversaries it defeats are **exfiltration-at-rest** (dotfiles, backups,
synced folders, committed configs, shell history) and **accidental disclosure** (logs, bug
reports, telemetry, copy-paste). It also bounds the blast radius of what a process holds: an
expiring, usage-limited, revocable lease instead of a forever-credential.

### What does it *not* defend against?

An attacker with arbitrary code execution as your own user, on your unlocked machine. A
same-UID process can read a child's environment on some platforms, attach a debugger, or drive
vaultkeeper's own APIs. Presence-gated backends (YubiKey touch, Touch ID) are the exception —
they force a fresh physical action per operation that no same-UID software can fake. We state
this plainly because a secrets tool that overclaims is worse than none: vaultkeeper raises the
floor dramatically without pretending to be a sandbox.

### How is this different from dotenvx / `op run` / SOPS?

Those tools solve *encrypted at rest, injected at runtime* — and solve it well. vaultkeeper's
differences are: (1) **policy at resolution** — trust tiers on the calling executable, TTLs,
usage limits, per-use presence — not just decryption; (2) **storage-agnostic** — the same policy
over Keychain, 1Password, YubiKey, DPAPI, libsecret, or a file, rather than one blessed store;
(3) **the lease rung** — consumers can hold a capability instead of the secret, which nothing
env-injection-shaped offers; (4) **no subscription** — the scoped-token/dedicated-vault posture
that 1Password gates behind Business tiers, locally and free. What those tools have that
vaultkeeper deliberately does not: team sync and cloud distribution (see non-goals).

### What is a VaultKeeper lease?

An encrypted, serializable capability token that occupies the env-var slot *instead of* a
secret. It carries expiry, a usage limit, and revocation state; redeeming it requires the local
vault key, so a lease captured into a log aggregator or bug report is dead on arrival anywhere
else. Signing leases authorize signature operations for a bounded session — minted with human
presence at launch, usable non-interactively until expiry, revocable individually or per-key.

### What is the adoption gradient?

Three rungs, chosen **per secret**, permanently mixable in one profile:

1. **Plaintext on disk** — the status quo being replaced.
2. **Resolved environment** — the real secret, never at rest, materialized under policy into
   one process. Works with any unmodified tool. This is the on-ramp, and the MCP-server wrapper
   is its headline: point `mcp.json` at `vaultkeeper run` and the PAT leaves the file.
3. **Lease** — the env var carries a capability, not the secret. Requires the consumer to speak
   vaultkeeper; today that means first-party tooling, by choice (a language-agnostic local
   redemption endpoint is a named future epic, gated on an installed base worth integrating
   against).

### Does this work for AI-agent fleets?

It is one of the primary design cases. Agents need credentials but must not *hold* them in any
durable way; some agents (e.g. an adjudicator that signs policy-change proposals) need signing
identities that the agents they govern cannot extract or invoke. vaultkeeper's answer: keys born
inside a backend and never exported; signatures produced backend-side; session-scoped signing
leases minted at harness launch with presence proven once; and honest documentation that
*non-invocability* additionally requires OS-level isolation between the privileged harness and
the processes it governs — custody cannot substitute for process isolation, and we say so.

### Can a signature prove a human was present?

Not yet, and not claimed. Presence is enforced at signing time by capable backends and is
visible to the local caller, but a verifier of the resulting signature cannot currently
distinguish a presence-backed signature from an automation one. Making assurance
verifier-visible is a known, deliberately-deferred design question shared with downstream
attestation tooling.

### How do humans and automation coexist as signers?

Identically. An identity is an Ed25519 keypair; nothing about being a human or an agent pins an
identity to a role. What differs is **custody** — an attribute of the identity that can
strengthen over time (file-backed today, presence-gated hardware tomorrow) without the identity
becoming a different actor. Role semantics (who may author, who may approve) belong to the
verifying system's policy, not to vaultkeeper.

### What about testing? Secrets tooling is notoriously untestable.

vaultkeeper ships its own test doubles as products: an in-memory backend with real Ed25519
signing and scriptable fault injection (throwing the same typed errors production throws), a
presence simulator that is structurally unreachable from production code, and — in flight —
backend-flavored doubles carrying real data shapes and choreography, held to the *same
conformance corpus* as the real adapters. Manual testing reduces to a minutes-scale,
tool-upgrade-triggered audit: "does the real adapter still match its double?"

### What are the non-goals?

Team sync, cloud storage, and cross-device distribution — that is where subscription products
genuinely earn their fee, and competing there would require becoming the cloud service
vaultkeeper exists to not be. Locked-down corporate environments behind MCP proxies with
cert-based auth are also out of scope: users there cannot add servers or edit configs, and do
not have the secret-handling problem vaultkeeper solves. Single machine, single developer,
policy-enforced: that is the product.

### What exists today, and what is in flight?

Shipped: the Rust core (backends, JWE capability tokens, key management and rotation, trust
tiers/TOFU, presence model, detached-JWS signing with backend-held keys, the opaque handle
table), the TypeScript SDK and CLI, the WASM bridge, encrypted key-state persistence, the
environment-profile primitive, and the conformance suite. In flight: the `run` wrapper verb,
session signing leases with tamper-evident revocation, native-CLI backend parity (keychain,
secret-tool, DPAPI, YubiKey ports to the shared core), and the paired-double test strategy.
Future: the local redemption endpoint, external key import with custody provenance, and
verifier-visible assurance.

### What does it cost?

Nothing. Open source, no tiers, no cloud account. The premise is that this security posture
should not be a subscription feature.
