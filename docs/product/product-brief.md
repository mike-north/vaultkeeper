# vaultkeeper 1.0 Product Brief

> The durable statement of what **vaultkeeper 1.0** is, who it serves, what it will not do,
> and how we reason about its security claims. Like its companion [PRFAQ.md](./PRFAQ.md),
> this describes the 1.0 target — not the current state of the code — without distinguishing
> landed from planned; the repository's releases, epics, and tracker own current status.
> Where the PRFAQ persuades, this document decides.

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
the `command` in an MCP server config. Rung 3 is first-party-only today *by choice*; the
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
via a WASM bridge. The TypeScript library's parallel logic **will be retired** as the core
reaches parity — single-core consolidation is the settled direction, not an open question.
Backends are small adapters over a host-platform abstraction. A data-driven conformance corpus
runs against every implementation — and, by design, against every test double — so "the Rust
and TypeScript flavors of the same experience" is enforced mechanically, not by promise.

## 7. How we make security claims

The rule: **a claim appears in docs only if the code enforces it; a mechanism that only
appears to deliver a property is treated as a defect.** Standing consequences:

- Per-rung threat honesty. Rung 2 provides essentially zero confidentiality against same-UID
  code execution; its real adversaries are exfiltration-at-rest and accidental disclosure. We
  say this everywhere the value proposition is stated.
- A lease's decisive property is **worthlessness outside its intended holder**: off-box it
  cannot even be decrypted, and on the same machine redemption verifies *who* presents it —
  a lease lifted by a different process is refused. The leak classes that actually happen
  (log aggregators, telemetry, bug reports) and the lateral-theft case are both covered.
- Holding the only copy of a key does not help if any process on the machine can simply ask
  vaultkeeper to use it. So when a privileged identity (like an adjudicating agent's signing
  key) must be unusable by the processes it governs, those processes have to run under a
  different OS user — vaultkeeper's custody cannot substitute for that separation, and every
  custody recommendation says so up front.
- Fail-closed is the default posture: unknown backends report no capabilities; corrupt or
  missing revocation state refuses lease validation; config naming an unavailable backend is an
  error, never a silent fallback.
- Test aids that could forge a security signal (e.g. a presence simulator) must be
  structurally unreachable from production: separate dev-only package, no registry entry,
  opt-in-only construction, loud refusal under production environments. This is a standing
  requirement on any such aid, enforced by negative tests wherever one exists.
- Test artifacts must be **self-announcing, and production must refuse them**: anything a test
  aid emits that resembles a real security artifact (a lease, a token, an assertion) carries
  an unmistakable test marking, and non-test code paths explicitly reject marked artifacts
  rather than honoring them. Unreachability guards protect against test *code* leaking into
  production; this guards against test *data* doing the same.

## 8. Non-goals

- **Team sync, cloud storage, cross-device distribution.** Subscription products earn their fee
  there; competing would require becoming a cloud service and forfeiting "nothing leaves your
  machine." Single-machine, single-developer parity is the scope.
- **Governing auth that isn't secret-material.** Where access rests on client certificates,
  platform-attested identity, or other non-secret mechanisms, there is no key for vaultkeeper
  to custody and no policy for it to enforce. Wherever an API-key-shaped secret exists —
  including in otherwise locked-down corporate environments — vaultkeeper aims to be usable.
- **Competing with 1Password — vaultkeeper is complementary to it.** 1Password is one of
  vaultkeeper's best backends, and vaultkeeper is a power tool *for* 1Password users: policy,
  leases, and delegated use layered over the vault they already trust. (The same goes for
  every store vaultkeeper fronts.)
- **Modeling signature *semantics*** (authorship vs approval). Such things can absolutely be
  built *on top of* vaultkeeper — and are: that layer of meaning belongs, Unix-style, to tools
  that leverage it (attest-it being the first). vaultkeeper aims to be excellent at its own
  job — making identities distinguishable and their keys non-transferable — and stops there.

## 9. What 1.0 means

1.0's scope is defined by this document and the PRFAQ, not by a feature checklist — but these
pillars are its load-bearing walls. Each is a commitment a reader may hold us to:

- **Single-core consolidation** — one Rust semantic core behind every surface; the parallel
  TypeScript logic will be retired.
- **The profile-driven `run` wrapper** — the universal on-ramp for unmodified tools, MCP
  servers first among them.
- **Session signing leases** — presence-anchored at mint, non-interactive for the session,
  with tamper-evident two-axis revocation.
- **Per-process lease boundaries** — redemption verifies the presenter; a lease is worthless
  outside its intended holder, not merely off-box.
- **Backend parity in the native CLI** for every store the library fronts.
- **The paired-double test strategy** — every production adapter has a double held to the
  same conformance corpus; manual testing is a minutes-scale fidelity audit; test artifacts
  are self-announcing and refused by production.
- **Verifier-visible assurance** — signatures provably presence-backed, via presence-bound
  hardware keys (signing policy attested at enrollment) and vault-signed assurance
  assertions, with "presence" spanning human-in-the-loop approval broadly (hardware touch,
  biometrics, passkey ceremonies, authenticated web approval).
- **The local redemption endpoint** — leases redeemable by any tool in any language in one
  call, opening the lease rung beyond first-party tooling.

## 10. How we measure success

- Dramatically more secure secrets handling is brought to bear across an extremely wide range
  of CLI and MCP tools — breadth of tools running under vaultkeeper is the headline measure.
- A new user gets a secret out of plaintext and behind policy in under five minutes, without
  modifying the consuming tool.
- Library and tool builders who need a secrets-backend integration achieve a high degree of
  release confidence without building or maintaining their own manual test suites (for
  1Password integration and the like) — they test against vaultkeeper's doubles instead.
- The manual-testing residue stays a minutes-scale, tool-upgrade-triggered checklist — never a
  suite that can rot unrun.
- Every security property claimed in this document has a test that fails when the property
  regresses.
