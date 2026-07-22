# vaultkeeper 1.0 PRFAQ

> This is the PRFAQ for **vaultkeeper 1.0 — a release that has not shipped yet.** It is
> written from 1.0's launch perspective, deliberately without hedging: everything described
> here is in scope for 1.0 whether or not it has landed today. This document is the working
> definition of what 1.0 means, and the artifact against which product feedback is given.
> Current implementation status lives where it stays current — the repository's releases,
> epics, and issue tracker — never here.

---

## Press Release

### vaultkeeper brings policy-enforced secret custody to every developer — using the credential store you already own

**Developers can now get — and go beyond — the secret-handling posture that previously
required a business-tier subscription: scoped tokens, expiring grants, per-use approval, and
per-invocation policy that no subscription tier offers at any price. Locally, offline, and
free, on top of macOS Keychain, 1Password, a YubiKey, or an encrypted file.**

Today, the standard way to give a tool a secret is still an environment variable holding a
plaintext credential, sourced from a dotfile or pasted into a config. Every MCP server config
with a `GITHUB_TOKEN` in it, every `.env` in a backup, every API key in shell history is the
same story: a long-lived, unscoped credential at rest in plaintext, readable by anything and
revocable only by rotating it everywhere at once. The tools that fix this properly — scoped
service tokens, dedicated vaults, per-use biometric approval — largely gate those capabilities
behind paid business tiers or cloud subscriptions. And even the paid tiers only offer stronger
*mechanisms* for who may access which secrets; none of them let you define policy over the
conditions of each individual use.

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

vaultkeeper is open source and fully auditable, local-first, with no cloud component: nothing
about your secrets ever leaves your machine. It runs wherever your environment already permits
— as a library inside Node.js where Node is the approved runtime (compatible with binary
authorization tooling such as Santa), or as a single native binary where you can run one — and
a data-driven conformance suite holds every implementation to the same behavior.

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

1. **Policy at resolution, per invocation** — trust tiers on the calling executable, time
   windows, use counts, per-use presence — evaluated for each use, not just each grant, with
   custom rule expressions as the roadmap direction (policy as expressive as your rules, not
   as coarse as a permission checkbox).
2. **Works with the store you already use, with no lock-in** — the same policy over Keychain,
   1Password, YubiKey, DPAPI, the Linux Secret Service, or a file. Script against vaultkeeper
   once and mix stores freely — Keychain for some secrets, 1Password for others, a YubiKey at
   work — one unified facade, and changing stores never changes your tooling.
3. **The lease rung** — consumers can hold a capability (a token that permits specific
   operations to be performed on the holder's behalf — not the secret itself) instead of the
   secret, which nothing env-injection-shaped offers.
4. **No subscription** — the scoped-token/dedicated-vault posture that 1Password gates behind
   Business tiers, locally and free.

What those tools have that vaultkeeper deliberately does not: team sync and cloud
distribution (see non-goals).

### What is a VaultKeeper lease?

It starts at setup: when vaultkeeper is set up on a machine, it creates an encryption key that
only it can use — the **minting key** — held in your configured backend behind that backend's
own access control, with the encrypted key state further protected by owner-only file
permissions. Every lease begins and ends with this key.

A lease is an encrypted token, **minted** with the minting key, that occupies the env-var slot
*instead of* a secret. It carries expiry, a usage limit, and revocation state, and it can only
be **redeemed** — decrypted and honored — by the vaultkeeper that holds the minting key, *and
only when presented by the process it was issued to*. That is why you should care: a lease
captured into a log aggregator, a telemetry payload, or a bug report is dead on arrival —
no other machine's vaultkeeper can decrypt it, and even another process on the same machine
is refused at redemption. The leak classes that actually happen simply stop mattering.

Signing leases are the same idea for signing keys: holding one lets a process *ask vaultkeeper
to produce signatures* with a key it never sees — minted with human presence at launch, usable
non-interactively until expiry, revocable individually or per-key.

### How do I adopt this without rewriting my tools?

You don't have to adopt vaultkeeper wholesale — you may upgrade **one secret at a time**, and
each secret sits at whichever of three levels fits it. Nothing forces a migration: a single profile can
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
   The tool is unmodified; the difference from using `.env` files with secrets in plaintext is
   that the secret is no longer floating around on disk for every other process, backup, and
   sync client to see.
3. **The process gets a lease, not the secret.** When raw secrets (e.g. API keys) are made
   available to a process at launch, the chosen process still holds the real key. With a lease it holds a vaultkeeper token instead: one that — under
   the right conditions — lets operations be performed *with* a key the process never has any
   direct access to. Those "right conditions" are yours to define: a time window, a usage
   count, and — because vaultkeeper sits in the middle of every call — policy **more granular
   than the target system itself can express**. GitHub's permission model cannot say "may
   update issues, but only ones carrying this label"; a delegated fetch through vaultkeeper
   can, because each invocation is evaluated against your policy before the key is ever used.
   This level requires the consuming tool to speak vaultkeeper — natively, through its SDKs,
   or through the local redemption endpoint that lets any tool in any language trade a lease
   for what it needs in one call.

### What is a profile?

A profile is a named, per-project file that describes the environment a command should
receive: which env vars exist, which secret in your backend each one draws from, whether each
materializes as the real value or as a lease, and the policy for that entry (expiry, trust
requirement, presence). Profiles contain names and policy — never secret values — so they are
safe to commit next to your code, which turns any weakening of policy into a reviewable diff.
`vaultkeeper run --profile <name> -- <command>` resolves the profile and launches the command
with that environment.

### I build tools or libraries — why would I integrate vaultkeeper directly?

Because it makes someone else's secret store your feature instead of your problem. Integrate
against vaultkeeper once and your tool supports whatever secret-keeping backend each user
already has — Keychain, 1Password, a YubiKey, an encrypted file — without you writing a line
of keychain code, handling a biometric flow, or maintaining the notoriously annoying manual
test rigs those integrations demand. vaultkeeper carries those tests (and ships test doubles
so *your* integration tests run hermetically in CI, no hardware, no accounts). Your users
choose how their secrets are protected; your tool doesn't have to know or care — it can even
use vaultkeeper entirely under the hood, unbeknownst to the user.

### Does this work for AI-agent fleets?

It is one of the primary design cases. Agents need credentials but must not *hold* them in any
durable way; some agents (e.g. an adjudicator that signs policy-change proposals) need signing
identities that the agents they govern cannot extract or invoke. vaultkeeper's answer: keys born
inside a backend and never exported; signatures produced backend-side; session-scoped signing
leases minted at harness launch with presence proven once; and honest documentation that
*non-invocability* additionally requires OS-level isolation between the privileged harness and
the processes it governs — custody cannot substitute for process isolation, and we say so.

There is a companion need in agent-heavy development: some acts must remain *deterministically
human* — provably performed by a person, not by an agent that discovered a workaround.
vaultkeeper powers a solution there too, through its sibling project
[`attest-it`](https://github.com/mike-north/attest-it): cryptographic proof that a designated
identity performed a gated act, with vaultkeeper holding the signing keys.

### Can a signature prove a human was present?

Yes — at two strengths. The strongest is **presence-bound keys**: when a key lives in hardware
whose signing policy demands a human action at the moment of signing (a YubiKey with
touch-required, a Secure-Enclave key gated on biometrics) and that policy is attested at
enrollment, then *every* valid signature from that key is proof of presence by construction —
nothing extra to encode, nothing to forge. The complementary mechanism is a
**vaultkeeper-signed assurance assertion** bound into the signed payload, covering backends
where the property is enforced by vaultkeeper rather than by the hardware (with the honest
caveat that its trust root is the vault, not the physical token).

"Presence" here is deliberately broader than a fingerprint or a touch: the aim is integration
with the full range of human-in-the-loop approval mechanisms — a passkey ceremony, an
authenticated web approval behind a CAPTCHA, anything that yields a trustworthy indication of
a human's involvement at the moment of approval. This is a solved pattern in the e-signature
world; vaultkeeper's job is to bind it to key use.

### How do humans and automation coexist as signers?

Identically. An identity is an Ed25519 keypair; nothing about being a human or an agent pins an
identity to a role. What differs is **custody** — an attribute of the identity that can
strengthen over time (file-backed today, presence-gated hardware tomorrow) without the identity
becoming a different actor. Role semantics (who may author, who may approve) belong to the
verifying system's policy, not to vaultkeeper.

### What about testing?

Secret-store integrations aren't untestable — they're *annoying and difficult* to test:
hardware to touch, sessions to authenticate, prompts that hang CI. The idea is that
vaultkeeper owns those annoying tests so you don't have to write them.

vaultkeeper treats its test doubles as products: an in-memory backend with real Ed25519
signing and scriptable fault injection (throwing the same typed errors production throws), a
presence simulator that is structurally unreachable from production code, and backend-flavored
doubles carrying real data shapes and choreography — every double held to the *same
conformance corpus* as the real adapter it stands in for. Test artifacts are self-announcing
(a test-minted lease is unmistakably marked, and production refuses marked artifacts), so test
data can never pass as real. Manual testing reduces to a minutes-scale, tool-upgrade-triggered
audit: "does the real adapter still match its double?"

### What are the non-goals?

Team sync, cloud storage, and cross-device distribution — that is where subscription products
genuinely earn their fee, and competing there would require becoming the cloud service
vaultkeeper exists to not be. Locked-down corporate environments behind MCP proxies with
cert-based auth are also out of scope: users there cannot add servers or edit configs, and do
not have the secret-handling problem vaultkeeper solves. Single machine, single developer,
policy-enforced: that is the product.

### Is everything here real today?

No — and that is the point of this document. This PRFAQ describes **vaultkeeper 1.0** and is
written from its launch perspective: it is the target the project builds toward, and the
artifact its owner gives product feedback against. Some of what it describes has shipped;
some is in flight; some is not yet started. The one place to learn which is which is the
repository itself — releases, epics, and the issue tracker — which stays current the way a
durable document cannot.

### What does it cost?

Nothing. Open source, no tiers, no cloud account. The premise is that this security posture
should not be a subscription feature.
