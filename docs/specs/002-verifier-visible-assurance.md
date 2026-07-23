# Architecture Spec — Verifier-Visible Assurance (issue #320)

Contract read in full: **#320** (OPEN, its five ACs are this spec's charter), product-brief §7
(claims-only-if-enforced; test artifacts self-announcing, production refuses them) and §9 (assurance is a
committed 1.0 pillar), the PRFAQ "Can a signature prove a human was present?" answer, the frozen env-epic §5
`pres`-claim (assertion seed), and **attest-it#150** (consumer side; leans convention, notes a vaultkeeper
custody attribute "would age better"). Enrollment-attestation capabilities verified against real systems
(sources at end), not assumed. **Rev 2** reframes the model onto two orthogonal dimensions (owner direction);
the facts, forgery analysis, and reality-check all carry forward.

## §0 The model: two orthogonal dimensions, no strength hierarchy

Assurance is **not** a single strength axis. An earlier draft ranked "hardware-attested" above
"vault-asserted" — that quietly treats *trusting vaultkeeper* as a liability, which is wrong: **vaultkeeper is
the product's trust anchor.** A user who won't trust it shouldn't let it govern their secrets at all. YubiKey
attestation does not *remove* trust; it *relocates* it to Yubico. Every basis is "trust some named party." So
the model has two independent dimensions, and the verifier composes their own policy over both — we disclose
facts, we don't rank for them.

**Dimension 1 — `perApprovalAction` (boolean, the policy-bearing axis).** From vaultkeeper's perspective: did
a fresh, human-originated approval action **have to occur, scoped to this individual approval request, applied
at the moment of approval, with no possibility that an already-unlocked / already-authorized state satisfied
it?** The final clause is the definitional test. This is `presencePerUse` evaluated at signing time.

- `true`: Touch ID in a fresh context, YubiKey touch-**always**, 1Password `per-access` fresh-process grant.
- `false`: an open/unlocked vault, session-mode caching, YubiKey touch-**cached** (15s window), a reused
  `LAContext`.

Every freshness finding from the earlier specs (the op-CLI session cache, the SE fresh-context requirement,
the touch-cached window) is now an *instance of this one rule*, not a per-mechanism caveat.

**Dimension 2 — `attestedBy` (a named party, the disclosure axis).** The party vouching for the claim:
`yubico`, `vaultkeeper`, `1password`, `apple` (future). **Not a rank — a name the verifier chooses to trust
or not.** The closed-enum discipline lives *here*: the **party list is the small closed set** verifiers must
be exhaustive over (an unrecognized party fails closed); the **mechanism vocabulary stays open/append-only**
(§3). Each party has, in the registry, a documented **evidence format** and one documented property:

> **`independentlyCheckable`** — can a verifier confirm this party's attestation *without trusting
> vaultkeeper*? `yubico`: **yes** (verify the Yubico attestation cert chain). `vaultkeeper`: **no** (the
> evidence *is* the vault signature — trusting it is trusting the anchor). `1password`/`apple`: per the
> party's evidence format if/when available.

This per-party `independentlyCheckable` property is where the old "proven vs recorded-and-trusted" honesty
now lives — as a **factual property of the attesting party, stated once in the registry**, never as a class
that demotes a mechanism.

**The two dimensions interact cleanly:** `attestedBy` determines *who vouches for `perApprovalAction`*. When
`attestedBy = yubico`, the attestation cert independently establishes touch-always, so `perApprovalAction=true`
is itself independently checkable. When `attestedBy = vaultkeeper`, `perApprovalAction=true` is vaultkeeper's
own assertion — fully usable, anchored in the party the user already trusts.

## §1 The claim, its two carriers, and the per-party forgery disclosure (AC 1)

There is **one** artifact — an `AssuranceClaim` — with **two carriers**, an encoding choice, *not* a strength
class:

- **Key-custody carrier:** the claim is a property of the enrolled public key (e.g. a YubiKey whose touch
  policy Yubico attests, or an SE key whose policy vaultkeeper records). Verifier resolves signer → key →
  claim. Nothing per-signature.
- **Payload-bound carrier:** the claim is bound into the signed payload (the env-epic §5 `pres` seed), for
  presence that is a per-event fact vaultkeeper witnessed (web approval). Covered by the vault signature.

Both yield the same `{ perApprovalAction, mechanism, attestedBy, evidence?, enrollmentVerification? }`.

**Forgery disclosure — factual, per attesting party, not ranked.** Can an attacker forge a claim bearing this
party's attestation? (✗ = cannot; ✓ = can.)

| Attacker / compromise | `attestedBy: yubico` | `attestedBy: vaultkeeper` |
|---|---|---|
| Same-UID code execution | ✗ — hardware refuses to sign without a live touch | `perApprovalAction=true` was proven **at mint**, but a same-UID attacker rides the non-interactive redemption inside the lease window (env-epic §6) |
| Stolen laptop (token/biometric absent) | ✗ — no physical token | ✓ if the vault key is readable on the stolen disk |
| **Compromised vault key** | ✗ — the vault key cannot produce the hardware signature (the key never entered the vault) | ✓ — can mint a claim for presence that never occurred |

The verifier reads this as disclosure and draws their own line: *a party whose signatures survive a
compromised vault key* (yubico) *is what I require for high-stakes gates; for everyday approvals the anchor I
already trust* (vaultkeeper) *is sufficient.* We state the facts; we do not tell them one is "the strong
mechanism." Two honesty points hold regardless of party:

1. **Presence proves a human was in the loop, never *which* human.** A thief who steals laptop *and* YubiKey
   and touches it produces a valid `perApprovalAction=true` signature. Assurance is not authentication of a
   specific person — said wherever the claim appears (§7 discipline).
2. **`perApprovalAction=false` is a first-class, self-documenting value.** An automation signer is exactly
   `perApprovalAction=false` — no special "automation" class needed (re-answers the earlier open Q).

## §2 Enrollment: deriving `perApprovalAction` and the available attesting party (AC 2)

Enrollment does two things — establish `perApprovalAction` and determine which party can attest it — and what
is *possible* differs by system, grounded in real capability:

- **YubiKey PIV — Yubico can attest.** `ykman piv keys attest <slot>` emits an attestation cert signed by a
  Yubico intermediate chaining to a Yubico root; touch/PIN policy is in extension **OID
  `1.3.6.1.4.1.41482.3.8`** (touch `02` = always). Enrollment verifies the chain to the pinned Yubico root and
  asserts touch `== 02` → `perApprovalAction=true`, `attestedBy=yubico`, `independentlyCheckable`. Records the
  cert as `evidence`.
- **WebAuthn / passkey — the authenticator attests per assertion.** The **User Verification (UV)** bit in
  `authenticatorData` proves a biometric/PIN ceremony for *that* assertion → `perApprovalAction=true`,
  `attestedBy` = the authenticator/party per its AAGUID attestation, independently checkable per signature.
- **Secure Enclave biometric — vaultkeeper attests; `apple` is not (yet) an available party.** Verified
  limitation: **there is no macOS API for an app to obtain an Apple-signed attestation of a Secure-Enclave
  key's access-control policy** (App Attest attests app+device, not a `SecKey`'s biometric gating). So the key
  is created with `.biometryCurrentSet` (fresh-context biometric → `perApprovalAction=true`) and enrolled as
  `attestedBy=vaultkeeper`. **This is not a downgrade — it is fully usable**, anchored in the party the user
  trusts. The "no Apple attestation" fact is recorded in `enrollmentVerification` as *why `apple` is not an
  available attesting party for this key*; if Apple ever ships such an API, the same key **promotes
  automatically** to `attestedBy=apple, independentlyCheckable` with no re-enrollment of the human.
- **Authenticated web approval / IdP — vaultkeeper attests a witnessed event.** No key policy to attest;
  `perApprovalAction=true`, `attestedBy=vaultkeeper`, payload-bound carrier, optional IdP `evidence`.

**`enrollmentVerification` — how vaultkeeper knows `perApprovalAction`, recorded honestly.** This is where
the enrollment-attested-vs-TOFU distinction survives — *within Dimension 1's derivation*, as an evidence note,
**not** as a class that demotes the claim. `{ method: "hardware-attestation" | "tofu-recorded", verifiedAt,
notes }`: YubiKey is `hardware-attestation`; SE is `tofu-recorded` ("policy recorded, not independently
verified; apple attestation unavailable"). record-with-honest-downgrade stays: the flag **informs** the
`vaultkeeper`-attested claim's evidence, it does not move it to a lower tier.

**Refusal is reserved for contradiction, not for the unverifiable.** SE-biometric is recorded, not refused —
refusing it would push users to weaker setups. Enrollment **fails closed only when a claim of an
independently-checkable party is contradicted**: an enrollment asserting `attestedBy=yubico` whose chain fails,
whose root isn't Yubico, or whose touch ≠ `02`. A false checkable claim is worse than an honest
vaultkeeper-anchored one.

## §3 Extensible vocabulary (AC 3)

Three fields, three openness policies:

- **`mechanism` — open, append-only registry (descriptive):** `hardware-touch`, `biometric`, `passkey-uv`,
  `web-approval`, extended without a schema or verifier-code change — the e-signature breadth #320 wants.
- **`attestedBy` — closed party set (decision-bearing):** verifiers are exhaustive over it; an unknown party
  fails closed. New parties are added deliberately, each with its evidence format and `independentlyCheckable`
  property.
- **`perApprovalAction` — boolean:** the one policy-bearing value; a new mechanism maps to `true`/`false` by
  the §0 definitional test, never a new tier.

## §4 Verifier vocabulary

A verifier resolves a signature (via key-custody attribute or bound assertion) to
`AssuranceClaim { perApprovalAction, mechanism, attestedBy, evidence?, enrollmentVerification? }`, then
evaluates a policy that **composes over both dimensions** — e.g. `perApprovalAction == true AND attestedBy ∈
{yubico, vaultkeeper}`, or a stricter `attestedBy.independentlyCheckable == true` for a high-stakes gate. This
is generic and consumer-independent — exactly the misconfiguration-proof predicate attest-it#150 weighs. The
verifier draws the strength conclusion; the spec supplies the two orthogonal facts.

## §5 Wire-format proposal — proposed, not frozen (AC 4)

**Cross-repo consultation recorded: attest-it#150.** It leans consumer-side convention but states a
vaultkeeper custody attribute "would age better." **I concur and recommend vaultkeeper originate it**, because
`perApprovalAction` and `attestedBy` are stable properties of *key custody* attest-it already tracks per
identity — encode once at the identity layer, not re-derived per consumer. A seal cannot carry assurance today
(neither policy nor seal schema has the field), so the schema change is **attest-it's call**; this spec
proposes shapes and freezes nothing.

```jsonc
// Key-custody carrier (attest-it identity layer) — e.g. a YubiKey identity
"assurance": {
  "perApprovalAction": true,
  "mechanism": "hardware-touch",
  "attestedBy": "yubico",
  "evidence": { "type": "yubico-piv-attestation", "certChain": ["<base64…>"], "touchPolicy": "always" },
  "enrollmentVerification": { "method": "hardware-attestation", "verifiedAt": 1770000000 }
}

// Payload-bound carrier (seeded by env-epic §5 `pres`) — e.g. a Secure-Enclave or web-approval signer
"assurance": {
  "perApprovalAction": true,
  "mechanism": "biometric",
  "attestedBy": "vaultkeeper",
  "enrollmentVerification": { "method": "tofu-recorded", "notes": "policy recorded; apple attestation unavailable" }
}
```

`attestedBy` (+ its registry `independentlyCheckable`) and `perApprovalAction` are the two fields a verifier's
policy may key on; `mechanism` is descriptive; `evidence` lets a verifier re-derive an independently-checkable
party's claim. **Open question for #150:** does a "requires presence" gate predicate live in attest-it's
policy schema (generic, misconfig-proof — my lean) or stay consumer convention?

## §6 Migration for existing enrolled keys

Keys enrolled before assurance carry **no `assurance` claim → `perApprovalAction` unknown → they satisfy no
`perApprovalAction==true` gate** (absence is never presence — fail closed, §7). Upgrade is **explicit
re-enrollment**, never silent: YubiKey keys run the attestation check (`attestedBy=yubico`); SE keys are
re-recorded (`attestedBy=vaultkeeper`, `tofu-recorded`); others stay unbacked. No existing signature's meaning
changes retroactively.

## §7 Test-artifact discipline (from product-brief §7)

A presence simulator or any test aid must be **structurally unable to emit a production-honored assurance
claim**: test-emitted claims carry an unmistakable marker and the verifier **refuses marked assurance in
production** — the same self-announcing / production-refuses rule the brief mandates for leases and tokens,
applied to this artifact class. Negative tests assert a marked claim is rejected.

## §8 Decomposition (AC 5)

Substrate: the lease/presence lane (**#298–#300**, env-epic §5) and the handle table (**#268**). `[S]`/`[M]`.

1. **`AssuranceClaim` model — `perApprovalAction` boolean + closed `attestedBy` party registry (each with
   evidence format + `independentlyCheckable`) + open `mechanism` registry** — core types, serde; encode the
   §0 rule that `perApprovalAction` derives from the definitional test and an unknown party fails closed.
   **[S]** (the two-dimension schema is the contract). *Deps:* env-epic §5 `pres` seed.
2. **YubiKey enrollment → `attestedBy=yubico`** — verify `ykman piv keys attest` chain to a pinned Yubico
   root, assert touch `== 02` → `perApprovalAction=true`; fail closed on a contradicted checkable claim.
   **[S]**. *Deps:* 1; #288 yubikey port.
3. **Secure-Enclave enrollment → `attestedBy=vaultkeeper`, `perApprovalAction=true`, `tofu-recorded`** —
   `.biometryCurrentSet`; record the apple-unavailable note; **auto-promote hook** if an Apple attestation API
   ever appears. **[M]**. *Deps:* 1.
4. **`perApprovalAction` derivation at signing time + payload-bound carrier** — evaluate the §0 definitional
   test against the active backend/session (touch-always vs cached, fresh vs reused context), and bind the
   `assurance` object into the payload under the vault key for `attestedBy=vaultkeeper` mechanisms
   (`biometric`, `web-approval`). **[S]** (touches the sign path + §5 claim). *Deps:* 1; #299/#300; #268.
5. **Verifier vocabulary + two-dimension policy predicate** — resolve a signature to an `AssuranceClaim`
   (either carrier); evaluate a predicate over `perApprovalAction` × `attestedBy` (incl.
   `independentlyCheckable`); re-verify checkable-party evidence. **[M]**. *Deps:* 1, 2, 4.
6. **Migration + fail-closed defaults + test-artifact refusal** — unenrolled keys assert nothing;
   re-enrollment explicit; marked test assurance refused in production (§6, §7). **[M]**. *Deps:* 1, 5.
7. **Wire-format finalization with attest-it (#150)** — **BLOCKED on attest-it's response**; do not freeze the
   seal/policy schema unilaterally. Land 1–6 against the *proposed* shape behind an internal boundary so
   attest-it's decision changes one adapter, not the core. **[S]**. *Deps:* 1–6; attest-it#150.

**Sequencing:** 1 gates all; 2/3/4 parallelize after 1; 5 after 2+4. **Item 7 is the only cross-repo freeze
and must not front-run #150** — everything else ships against the proposed shape so the eventual schema is a
thin adapter.

## §9 Open questions for the owner / attest-it

1. **Gate predicate placement (#150):** in attest-it's policy model (generic, misconfig-proof — my lean) vs.
   consumer convention?
2. **Is `attestedBy` a single party or a set per key?** A key could carry both a Yubico attestation *and* a
   vaultkeeper record; modeling `attestedBy` as a set lets a verifier pick the strongest party *they* trust.
   Slightly more schema; more future-proof. I lean single-party value on a set-capable shape for v1.
3. **SE re-enrollment on biometric reset:** `.biometryCurrentSet` invalidates the key when Face/Touch ID is
   re-enrolled — a natural revocation signal but an availability footgun. Treat invalidation as automatic
   assurance-revocation (fail closed)? Confirm.
4. **`independentlyCheckable` for `1password`:** the DesktopAuth dylib grant is per-process (consolidation
   epic §2) but yields no verifier-checkable evidence — so `attestedBy=1password` would be
   `independentlyCheckable: false` (vaultkeeper-equivalent trust). Confirm 1Password earns a distinct party
   name vs folding under `vaultkeeper` until it can produce checkable evidence.

---

**Sources (enrollment-attestation reality check):**
- [Yubico — Verifying the PIN/Touch policy of the PIV slots](https://support.yubico.com/hc/en-us/articles/4711638123932-Verifying-the-PIN-Touch-policy-of-the-PIV-slots) and [yk-attest-verify](https://github.com/joemiller/yk-attest-verify) — touch policy in ext OID `1.3.6.1.4.1.41482.3.8`, verifiable via the Yubico attestation cert chain.
- [Private Key Attestation on macOS (SecureW2)](https://www.securew2.com/blog/key-attestation-macos) and [blink SE-SSH discussion](https://github.com/blinksh/blink/discussions/1892) — no macOS API for Apple-signed attestation of a Secure-Enclave key's access-control policy; `.biometryCurrentSet` gating and its reset-invalidation behavior.
