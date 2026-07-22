# vaultkeeper Product Brief

> The durable statement of what vaultkeeper is, who it serves, what it will not do, and how we
> reason about its security claims. Companion to [PRFAQ.md](./PRFAQ.md); where the PRFAQ
> persuades, this document decides. Kept current by the maintainers.

## 1. The single value proposition

**A massive step up in security and control over secrets, relative to plaintext keys sitting in
a shell environment or on disk.**

Everything vaultkeeper builds serves that sentence. The environment variable is the universal
interface every tool already reads; vaultkeeper progressively upgrades *what occupies that
slot* — from a plaintext credential, to a policy-resolved value that never rests on disk, to a
capability lease that is not the secret at all.

## 2. Positioning: unbundle storage from policy

The products that offer scoped service tokens, dedicated vaults, and per-use approval bundle
those capabilities with their storage — and price the bundle as a business subscription.
Meanwhile the storage most developers already own (macOS Keychain, a YubiKey, DPAPI, libsecret,
a 1Password personal account) is good, hardware-backed, and free — but ships with no governance
layer: no scoped tokens, no expiry, no usage limits, no policy on who may resolve what.

vaultkeeper is that governance layer, over the backend you already have. **Upgrade your storage
independently of your policy**: Keychain today, hardware tomorrow, 1Password if you later want
it — the policy vocabulary never changes. Local, offline, no cloud component, no subscription.

The honest comparison boundary: versus plaintext-in-config (the actual status quo for most
developers, including most MCP-server configs), rung 2 alone is a large, obvious win. Versus a
user already on `op run` with a business account, the delta is policy, audit, expiry, and
backend independence — real, but different. Both claims are true; we do not swap their
audiences.

## 3. The adoption gradient (three rungs, per secret)

| Rung | Env var contains | Works with | What it buys |
|---|---|---|---|
| 1 | The plaintext secret, from a file | Everything | Nothing. The status quo being replaced. |
| 2 | The real secret, resolved at launch | **Any unmodified tool** | No plaintext at rest; exposure bounded to a process lifetime; a policy decision (trust tier, TTL, presence) at every resolution; centralized rotation; kills the copy-paste-into-files habit. |
| 3 | A **VaultKeeper lease** — an encrypted, expiring, revocable capability | vaultkeeper-aware consumers | The secret never enters the consumer's process; the lease is worthless off-box and after expiry; usage-limited; revocable per-lease and per-key. |

The rung is chosen **per entry** in a profile, and mixing is the permanent steady state, not a
migration phase. Rung 2's delivery mechanism is the `vaultkeeper run` wrapper — most visibly as
the `command` in an MCP server config. (`run` is in flight; today's shipped mechanism is the
single-secret `vaultkeeper exec`, which `run` generalizes to profile-driven, multi-secret
resolution.) Rung 3 is first-party-only today *by choice*; the
language-agnostic local redemption endpoint that would open it to any consumer in any language
is a named future epic, triggered by an installed base worth integrating against.

## 4. Who it serves

- **The individual developer with credential-bearing configs** — MCP servers, CLIs, local
  services. Wants the PAT out of `mcp.json` with zero changes to the tools. Rung 2.
- **The agent-fleet operator** — runs autonomous coding agents that need credentials but must
  not durably hold them, and privileged automation identities (reviewers, adjudicators) whose
  signing keys must be neither extractable nor invocable by the agents they govern. Rungs 2+3,
  signing leases, presence-at-session-establishment.
- **The consuming toolmaker** — builds software (e.g. attestation tooling) on vaultkeeper
  custody and needs to test its integration without hardware or accounts. Served by the shipped
  test doubles and the paired-double conformance strategy.

## 5. Core concepts

- **Backend** — where secrets live. Pluggable: file (encrypted), macOS Keychain, 1Password,
  YubiKey, DPAPI, `secret-tool` (Linux Secret Service via libsecret); additional stores are
  small adapters over the same interface, added where demand appears. Backends self-report
  **capabilities**; policy fails closed when a capability is absent rather than silently
  downgrading.
- **Capability token / lease** — an encrypted JWE granting scoped access: expiry, usage limit,
  executable-identity binding at mint, revocation. The serialized, cross-process form is the
  **lease**; "lease" is the house term for any serialized, expiring, revocable capability.
- **Trust tier** — classification of the calling executable: `sigstore` (cryptographic
  provenance) > `registry` (approved-hash manifest, TOFU) > `unverified`. Policy expresses a
  minimum (`minTrust`), or-stronger.
- **Presence** — a backend's ability to force a *fresh physical human action* for a specific
  operation, right now (YubiKey touch, Touch ID, per-use biometric approval). Enforced
  fail-closed; and any test aid capable of simulating presence is required to be structurally
  unreachable from production code paths.
- **Profile** — a named, committable, per-project set of env-var bindings, each entry carrying
  its secret source, its rung (`materialize: "secret" | "lease"`), and its policy. Profiles
  contain names and policy, never secrets; committing one makes policy loosening a reviewable
  event.
- **Delegated access** — `fetch`/`exec`/`sign` patterns where vaultkeeper performs the
  operation and the raw secret never appears in the caller's memory; signing keys never leave
  their backend at all.

## 6. Architecture in one paragraph

One semantic core in Rust (`vaultkeeper-core`), reached two ways: a native CLI, and TypeScript
via a WASM bridge — with the TypeScript library's parallel logic being progressively retired as
the core reaches parity (single-core consolidation). Backends are subprocess orchestration over
a host-platform abstraction wherever the underlying store has a CLI (keychain, secret-tool,
DPAPI, YubiKey); 1Password remains host-provided because its per-process desktop-app grant is
reachable only through a mechanism the WASM sandbox cannot load. A data-driven conformance
corpus runs against every implementation — and, by design, against every test double — so
"the Rust and TypeScript flavors of the same experience" is enforced mechanically, not by
promise.

## 7. How we make security claims

The rule: **a claim appears in docs only if the code enforces it; a mechanism that only
appears to deliver a property is treated as a defect.** Standing consequences:

- Per-rung threat honesty. Rung 2 provides essentially zero confidentiality against same-UID
  code execution; its real adversaries are exfiltration-at-rest and accidental disclosure. We
  say this everywhere the value proposition is stated.
- A lease's decisive property is off-box worthlessness — the leak class that actually happens
  (log aggregators, telemetry, bug reports).
- Non-invocability of a privileged identity requires OS-level isolation; custody cannot
  substitute for it, and every custody recommendation states the precondition.
- Fail-closed is the default posture: unknown backends report no capabilities; corrupt or
  missing revocation state refuses lease validation; config naming an unavailable backend is an
  error, never a silent fallback.
- Test aids that could forge a security signal (e.g. a presence simulator) must be
  structurally unreachable from production: separate dev-only package, no registry entry,
  opt-in-only construction, loud refusal under production environments. This is a standing
  requirement on any such aid, enforced by negative tests wherever one exists.

## 8. Non-goals

- **Team sync, cloud storage, cross-device distribution.** Subscription products earn their fee
  there; competing would require becoming a cloud service and forfeiting "nothing leaves your
  machine." Single-machine, single-developer parity is the scope.
- **Locked-down corporate MCP environments** (proxy, cert auth, curated servers) — users there
  cannot edit configs and do not have this problem.
- **Matching 1Password's UX breadth.** Biometric ergonomics, browser integration, and sharing
  are not the competition; custody policy is.
- **Modeling signature *semantics*** (authorship vs approval). What a signature means belongs to
  the verifying system's per-gate policy; vaultkeeper makes identities distinguishable and
  their keys non-transferable, and stops there.

## 9. State of the world

**Shipped** (through `vaultkeeper@0.7.x`): the Rust core — backends (file, in-memory,
secret-tool), JWE capability tokens, key management and rotation, trust tiers/TOFU, the
presence model, detached-JWS signing with backend-held Ed25519 keys, the opaque handle table
with bearer-safe redaction, encrypted key-state persistence, the environment-profile
primitive, the lease-aware claims validator; the TypeScript SDK/CLI with the full backend
suite; the WASM bridge with host-callback contracts; OIDC trusted publishing; conformance and
packaging test suites.

**In flight**: the `run` wrapper verb (stdio/signal-transparent); session signing leases with
tamper-evident two-axis revocation; native backend parity (keychain via `security -i`, DPAPI,
YubiKey ports); consumer test doubles (signing and fault-injection capabilities being added to
the existing in-memory backend, plus a new presence simulator); the paired-double test
strategy (stub framework, golden transcripts, flavored doubles, the manual-residue register).

**Committed roadmap**: verifier-visible assurance — a signature provably presence-backed, via
presence-bound hardware keys (signing policy attested at enrollment) and a vault-signed
assurance assertion for software-enforced backends. Owner-decided 2026-07; presence here spans
human-in-the-loop approval broadly (hardware touch, biometrics, passkey ceremonies,
authenticated web approval), not only physical tokens.

**Deliberately future**: the local redemption endpoint (opens rung 3 to any language);
external key import with custody provenance modeled; issuance-side principal checks binding
capabilities to the invoking context.

## 10. How we measure success

- A new user gets a secret out of plaintext and behind policy in under five minutes, without
  modifying the consuming tool.
- The manual-testing residue stays a minutes-scale, tool-upgrade-triggered checklist — never a
  suite that can rot unrun.
- Consumers (starting with attestation tooling) cover their vaultkeeper integration on every
  PR using shipped doubles, with zero hardware.
- Every security property claimed in this document has a test that fails when the property
  regresses.
