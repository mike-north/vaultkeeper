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
already trust — today: macOS Keychain, 1Password, a YubiKey, Windows DPAPI, the Linux Secret
Service (`secret-tool`), or an encrypted file store, with further stores (Dashlane and others)
on the table wherever demand appears, since a backend is a small adapter over a stable
interface — and vaultkeeper supplies the governance layer those stores lack: capability tokens
scoped by expiry, usage count, and executable identity; per-use human-presence requirements
(a Touch ID tap or YubiKey touch *for this operation, right now*); delegated access patterns
where the raw secret never enters the calling process at all; and full local revocation.

Adoption is a gradient, not a rewrite, and the wrapper works on anything that reads
environment variables. Wrap an MCP server so the PAT leaves the config file
(`vaultkeeper run --profile github-mcp -- npx @github/mcp-server`); wrap an ordinary CLI for
one policy-resolved invocation (`vaultkeeper run --profile deploy -- terraform apply`); or
wrap the command that launches an agentic coding session, so the agent's whole environment —
real secrets and vaultkeeper leases alike — is resolved under policy at launch and nothing
lives in a dotfile. In every case the tool is unmodified: secrets are materialized only into
the child process, under policy, with nothing at rest. Tools that integrate further can hold a
**VaultKeeper lease** instead of the secret itself — an encrypted, expiring, revocable
capability that is worthless off the machine and worthless after its window closes. Signing
keys go further still: the private key never leaves the backend at all; consumers request
signatures, never key material.

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

Those tools solve *encrypted at rest, injected at runtime* — and solve it well. But they are
not context-aware: they decrypt for whoever invokes them, so in practice you choose between
security and friction (lock things down and pay for it on every invocation, or loosen them
and hope). Because vaultkeeper's resolution step evaluates *policy* — who is asking, with
what trust, for how long — it can offer both at once: strong defaults with low-friction
day-to-day use. The concrete differences:

1. **Policy at resolution** — trust tiers on the calling executable, TTLs, usage limits,
   per-use presence — not just decryption.
2. **Storage-agnostic** — the same policy over Keychain, 1Password, YubiKey, DPAPI, the
   Linux Secret Service, or a file, rather than one blessed store.
3. **The lease rung** — consumers can hold a capability instead of the secret, which nothing
   env-injection-shaped offers.
4. **No subscription** — the scoped-token/dedicated-vault posture that 1Password gates behind
   Business tiers, locally and free.

What those tools have that vaultkeeper deliberately does not: team sync and cloud
distribution (see non-goals).

### What is a VaultKeeper lease?

An encrypted, serializable capability token that occupies the env-var slot *instead of* a
secret. It carries expiry, a usage limit, and revocation state; redeeming it requires the
local vault key (the encryption key vaultkeeper generates at setup and keeps in your
configured backend — only the vaultkeeper process on this machine can use it, enforced by the
backend's own access control plus owner-only file permissions on the encrypted key state), so
a lease captured into a log aggregator or bug report is dead on arrival anywhere else. Signing
leases are the same idea for signing keys: holding one lets a process *ask vaultkeeper to
produce signatures* with a key it never sees — minted with human presence at launch, usable
non-interactively until expiry, revocable individually or per-key.

### How do I adopt this without rewriting my tools?

You don't adopt vaultkeeper wholesale — you upgrade **one secret at a time**, and each secret
sits at whichever of three levels fits it. Nothing forces a migration: a single profile can
hold secrets at different levels side by side, indefinitely, so there is no cliff where
everything must convert at once and no penalty for upgrading one credential while its
neighbors stay put.

1. **Environment variables holding plaintext secrets in your terminal or tool config** (an
   `export GITHUB_TOKEN=ghp_…` in `.bashrc`, a token pasted into `mcp.json` or a `.env`) —
   the status quo being replaced. The secret sits on disk in plaintext, readable by anything,
   forever.
2. **Resolved at launch, never on disk.** You run the same tool through
   `vaultkeeper run`, and the secret is fetched from your backend and handed *only to that
   one process, for that one run*. If you have ever thought "I just need to pass this key to
   this one command without leaving it lying around in a file" — this is that, made routine.
   The tool is unmodified; the difference from level 1 is that the secret is no longer
   floating around on disk for every other process, backup, and sync client to see.
3. **The process gets a lease, not the secret.** At level 2 the chosen process still holds
   the real GitHub key. At level 3 it holds a vaultkeeper lease instead: a token that — under
   the right conditions — lets operations be performed *with* a key the process never has any
   direct access to. Those "right conditions" are yours to define: a time window, a usage
   count, and — because vaultkeeper sits in the middle of every call — policy **more granular
   than the target system itself can express**. GitHub's permission model cannot say "may
   update issues, but only ones carrying this label"; a delegated fetch through vaultkeeper
   can, because each invocation is evaluated against your policy before the key is ever used.
   This level requires the consuming tool to speak vaultkeeper; today that means first-party
   tooling, by choice (a language-agnostic local redemption endpoint is a named future epic,
   gated on an installed base worth integrating against).

### Does this work for AI-agent fleets?

It is one of the primary design cases. Agents need credentials but must not *hold* them in any
durable way; some agents (e.g. an adjudicator that signs policy-change proposals) need signing
identities that the agents they govern cannot extract or invoke. vaultkeeper's answer: keys born
inside a backend and never exported; signatures produced backend-side; session-scoped signing
leases minted at harness launch with presence proven once; and honest documentation that
*non-invocability* additionally requires OS-level isolation between the privileged harness and
the processes it governs — custody cannot substitute for process isolation, and we say so.

### Can a signature prove a human was present?

Not in what ships today, but the path exists and is on the roadmap. Presence is enforced at
signing time by capable backends and is visible to the local caller; the resulting signature,
however, does not yet carry that fact to a verifier. Two mechanisms can close the gap. The
strongest is **presence-bound keys**: when a key lives in hardware whose signing policy
requires a physical touch (a YubiKey with touch-required, a Secure-Enclave key gated on
biometrics) and that policy is attested at enrollment, then *every* valid signature from that
key is proof of presence by construction — nothing extra to encode, nothing to forge. The
complementary mechanism is a **vaultkeeper-signed assurance assertion** bound into the signed
payload, covering backends where the property is enforced by vaultkeeper rather than by the
hardware itself (with the honest caveat that its trust root is the vault, not the physical
token). Sequencing verifier-visible assurance is a design question shared with downstream
attestation tooling, which currently treats the distinction as consumer-side convention.

### How do humans and automation coexist as signers?

Identically. An identity is an Ed25519 keypair; nothing about being a human or an agent pins an
identity to a role. What differs is **custody** — an attribute of the identity that can
strengthen over time (file-backed today, presence-gated hardware tomorrow) without the identity
becoming a different actor. Role semantics (who may author, who may approve) belong to the
verifying system's policy, not to vaultkeeper.

### What about testing? Secrets tooling is notoriously untestable.

vaultkeeper treats its test doubles as products. Shipped today: an in-memory backend and a
test-vault harness for hermetic consumer tests. In review as of this writing: that backend
gaining real Ed25519 signing and scriptable fault injection (throwing the same typed errors
production throws), plus a presence simulator built to be structurally unreachable from
production code. Planned behind those: backend-flavored doubles carrying real data shapes and
choreography, held to the *same conformance corpus* as the real adapters — at which point
manual testing reduces to a minutes-scale, tool-upgrade-triggered audit: "does the real
adapter still match its double?"

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
