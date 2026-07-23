# Specification: CLI & Library Surface Governance

Status: draft for review · Applies to: `vaultkeeper-cli`, `@vaultkeeper/cli`, `vaultkeeper` (TS lib),
`@vaultkeeper/wasm`, `vaultkeeper-core` · Authority: this document is the **design gate** for the programmatic
integration surfaces. Feature work conforms to it; a surface change that is not also a diff to this spec is a
review failure (§1.4, §2.5).

Grounded in code read from `origin/main` @ `87c615f`: `crates/vaultkeeper-cli/src/main.rs` (clap definitions,
authoritative for the CLI), `packages/vaultkeeper/api-report/vaultkeeper.api.md` and `src/index.ts` (library).
Three registers are kept distinct throughout: **IS** (current inventory), **SHOULD BE** (normative rule),
**BROKEN** (a divergence, §1.3).

---

## Part 1 — CLI Surface

### 1.1 Command tree (normative inventory)

Landed on `origin/main`. `stdin`/`stdout`/`stderr` columns state the contract; `exit` is the success/typed
range. "Secrets" = does a secret value transit this command, and by what channel.

| Command | Positional | Flags | stdin | stdout | Secrets | exit |
|---|---|---|---|---|---|---|
| `exec` | `COMMAND…` (trailing) | `--token <jwe>` | inherited by child | child's | value → child env (`VAULTKEEPER_SECRET`) | child's code |
| `store` | — | `--name <n>`, `--require-presence-per-use` | **secret value** | status line | value ← stdin | 0 / 1 |
| `delete` | — | `--name <n>`, `--require-presence-per-use` | — | status line | — | 0 / 1 |
| `doctor` | — | — | — | check report | — | 0 ready / 1 not |
| `approve` | — | `--path <p>` | — | confirmation | — | 0 / 1 |
| `dev-mode` | — | `--path <p>`, `--enable` | — | confirmation | — | 0 / 1 |
| `rotate-key` | — | — | — | confirmation | — | 0 / 1 |
| `revoke-key` | — | — | — | confirmation | — | 0 / 1 |
| `config init` | — | — | — | confirmation | — | 0 / 1 |
| `config show` | — | — | — | config text | — | 0 / 1 |
| `backend capabilities` | — | `--json` | — | text \| JSON array | — | 0 / 1 |
| `profile init` | `NAME` | `--profile-file <p>` | — | confirmation | — | 0 / 1 |
| `profile show` | `NAME?` | `--profile-file <p>` | — | shape+policy text | never prints values | 0 / 1 |
| `profile list` | — | — | — | name list | — | 0 / 1 |
| `profile lint` | `NAME?` | `--profile-file <p>` | — | warnings | never prints values | **always 0** (advisory) |
| `session mint` | `PROFILE` | `--entry <e>` | — | **JWE lease → stdout** | lease (capability, not secret) | 0 / 1 |
| `session revoke` | — | `--jti <j>` \| `--key <k>` (xor) | — | confirmation | — | 0 / 1 |

**In review / designed, not landed** (env-epic-spec.md §4, lease lane #298–#300) — rows tracked here so the
grammar review covers them before they land:

| Command | Positional | Flags | Notes |
|---|---|---|---|
| `run` | `COMMAND…` (trailing) | `--profile <n>`, `--profile-file <p>`, `--set <VAR=SECRET>`, `--dry-run`, `--require-presence` | stdio/signal transparent; stdout is the child's alone; **in review** |
| `session redeem` (shape TBD) | — | lease presenter | lease redemption over the #268 handle table; **designed, unscheduled** |

### 1.2 Design grammar (SHOULD BE)

**G1 — Noun-verb for resource families; bare verb for whole-vault process actions.** A command earns a
**noun namespace** (`<noun> <verb>`) when it manages a *category of addressable resources* with more than one
operation: `config`, `backend`, `profile`, `session`. A command is a **bare top-level verb** when it is a
single process action against the vault as a whole with no sibling operations on a shared resource: `exec`,
`run`, `doctor`, `approve`, `dev-mode`.

**G2 — The primary subject is positional; modifiers are flags.** A command's required primary subject — the
resource it acts on — is a **positional argument**. Options, policy toggles, and alternate sources are
**flags**. `profile show NAME`, `session mint PROFILE`, `approve --path` (see BROKEN-4). A secret value is
**never** a positional or a flag value (G6).

**G3 — Flag naming is a stable vocabulary.** A concept has exactly one flag spelling across the whole surface.
`--profile-file` for the explicit-path override, `--json` for machine output, `--profile`/`--entry` for
profile addressing. The presence family is **one** name (see BROKEN-5).

**G4 — stdout is data; stderr is diagnostics.** stdout carries *only* the command's payload — a JWE
(`session mint`), a JSON value (`--json`), a name list, or the child's own stream (`exec`/`run`). Every
human-facing message — progress, warnings, the file-only degradation notice, errors — goes to **stderr**.
This is the #279 rule generalized to the whole surface, and it is what makes every data-producing command
pipeable. `--dry-run` and human-report commands print their report to stdout (there is no child to protect),
but a command that emits a machine artifact must never interleave diagnostics into it.

**G5 — `--json` is opt-in and total.** Absent, output is human text. Present, stdout is a **single JSON
value** and nothing else. `--json` is the only machine-output switch; no command invents a second one.

**G6 — Secrets never appear in argv.** A CLI-surface invariant, not a per-command choice. A secret value
enters only via **stdin** (`store`) and leaves only via **stdout** (`session mint` prints a lease, `exec`
injects into a child's environment). No command accepts a secret as a positional or flag value; `--set
VAR=SECRET` on `run` is the one deliberate exception and is documented as such, marked UNREVIEWED in
`--dry-run`. (Backend implementations honor the same rule downstream, e.g. keychain `store` via `security
-i` stdin.)

**G7 — Exit-code taxonomy.** `0` success; `1` a typed operational failure (the `VaultError` surface, §2.1);
`2` reserved for clap usage errors; `exec`/`run` **propagate the child's exit code**, and a signal-terminated
child yields `128+N`. Advisory commands that cannot "fail" (`profile lint`) exit `0` on any successfully
loaded input and signal concerns only through stderr warnings — this is deliberate and normative, not a bug.

### 1.3 Inconsistencies (BROKEN) — the review surface

Each row is a concrete divergence from §1.2 with a recommended disposition. **fix-now** = correct before the
1.0 surface freeze; **legacy** = keep, document, and gate behind the deprecation path; **leave** = conforms
on reflection, recorded to close the question.

| # | Location | Violates | Divergence | Disposition |
|---|---|---|---|---|
| B1 | `store --name`, `delete --name` | G2 | The primary subject (the secret name) is a **flag**, while `profile`/`session` make the subject positional. | **fix-now**: `store NAME` / `delete NAME` positional; keep `--name` as a hidden deprecated alias for one minor. |
| B2 | `store`, `delete`, `rotate-key`, `revoke-key` as bare verbs | G1 | These act on addressable resource categories (secrets; keys) but are top-level verbs. `store`/`delete`/(future `list`) are the CRUD of a `secret` noun; `rotate-key`/`revoke-key` are `key rotate`/`key revoke`. | **decide**: either promote to `secret <verb>` / `key <verb>` (grammar-pure, my lean) or record a documented exception for the highest-frequency verbs. Owner call — this is the single biggest grammar question. |
| B3 | `dev-mode --enable` (a boolean subject-mode) | G2 | An enable/disable *mode* is a bare boolean flag; the natural shape is `dev-mode enable PATH` / `dev-mode disable PATH` or `dev-mode set --path --on/--off`. | **fix-now** or **legacy**: low traffic; align to `key`/`secret` decision in B2. |
| B4 | `approve --path`, `dev-mode --path` | G2 | The path *is* the primary subject and should be positional (`approve PATH`), matching `profile show NAME`. | **fix-now**: positional `PATH`; `--path` deprecated alias. |
| B5 | `store`/`delete` `--require-presence-per-use` vs `run` `--require-presence` | G3 | Two spellings for the presence family. | **fix-now**: pick one before `run` lands. Recommend `--require-presence-per-use` (precise; "presence" alone is ambiguous about scope) across all commands, or a shared `--require-presence[=per-use]`. Resolve **before** #279 merges so `run` ships correct. |
| B6 | `session mint PROFILE --entry E` vs `profile show NAME` | G2 | Reviewed in #328: `mint` takes the profile positionally (consistent) but the *entry* — arguably a co-primary subject — is a flag. | **leave** (documented): the profile is the addressed resource; the entry is a selector within it, legitimately a flag. Recorded so the #328 question is closed, not reopened. |
| B7 | `backend capabilities` is the only `backend` verb | G1 | A noun namespace with a single verb is defensible only if more verbs are foreseen. | **leave**: `backend list`/`backend test` are natural future siblings; the namespace is intentional headroom, not premature. |
| B8 | `config`/`backend`/`profile` support `--json` unevenly | G5 | `backend capabilities` has `--json`; `config show`, `profile show/list` do not. | **fix-now (additive)**: any command whose output a script would consume gets `--json`. Audit `config show`, `profile show`, `profile list`, `doctor`. |

### 1.4 Evolution policy (SHOULD BE)

- **E1 — Spec-diff-in-PR.** A PR that adds, removes, or changes a command/subcommand/flag/exit-code **must**
  edit §1.1 and, if it bends a rule, §1.3 in the same PR. A surface change without a spec diff is an
  automatic review block. This is what makes drift visible as a reviewable diff rather than an archaeological
  finding.
- **E2 — Deprecation path.** A removed or renamed flag/command survives one minor release as a hidden alias
  emitting a stderr deprecation notice (never on stdout — G4), then is removed at the next minor. Renames land
  the new spelling and the alias together.
- **E3 — Cross-implementation enforcement.** The native and TS CLIs are one surface; `crates/vaultkeeper-
  conformance` is the mechanical proof of it. Every new command lands with conformance cases so the two CLIs
  cannot diverge — the surface is enforced by test, not by discipline.

---

## Part 2 — Library Surface

### 2.1 Organizing principles (SHOULD BE, normative)

- **L1 — Everything through `index.ts`.** The public API is exactly the re-exports of `src/index.ts`; a
  symbol not re-exported is not public regardless of file visibility. API Extractor's report is the mechanical
  witness (§2.5).
- **L2 — Capability-token opacity.** A `CapabilityToken` exposes no readable secret: the secret is reachable
  only through a one-time `SecretAccessor.read()`, a signing key never egresses (sign happens backend-side),
  and passing the wrong token kind to `getSecret`/`sign` is a typed refusal. This opacity is a load-bearing
  security property, not an ergonomic detail — no future API may add a token accessor that returns claims.
- **L3 — Typed failures only.** Every thrown error is a subclass of `VaultError`. Plain `Error` is never
  thrown across the public boundary; new failure modes add a `VaultError` subclass, exported from `index.ts`.
- **L4 — Minimal runtime dependency.** The `vaultkeeper` TS library's only runtime dependency is `jose`;
  `@vaultkeeper/wasm` has none. New runtime deps require explicit owner approval (recorded in CLAUDE.md).
- **L5 — Wire and type discipline.** Config/claim JSON is camelCase; public option shapes are
  `exactOptionalPropertyTypes`-safe (no `undefined`-assignable optionals); no `as` casts in the surface.

### 2.2 The surface by concept (IS)

The 88 `@public` symbols group into coherent concepts. The owner reviews whether each grouping is complete and
whether membership is intentional.

- **Entry & lifecycle:** `VaultKeeper` (the façade class), `VaultKeeper.init`, `VaultKeeperOptions`,
  `VaultResponse`.
- **Setup / identity / trust:** `setup`, `SetupOptions` (a discriminated union enforcing exactly one of
  `executablePath`/`skipTrust` — a craft high point, keep as the pattern), `SetupOptionsBase`,
  `approveExecutable`, `checkExecutableTrust`, `setDevelopmentMode`, `ExecutableTrustStatus`,
  `ExecutableTrustRequiredError`, `IdentityMismatchError`.
- **Secrets & access tokens:** `store`, `delete`, `secretExists`, `authorize`, `getSecret`, `CapabilityToken`,
  `SecretAccessor`, `SecretTokenMap`, `AccessorConsumedError`, `SecretNotFoundError`.
- **Delegated access patterns:** `fetch`, `exec`, `FetchRequest`, `ExecRequest`, `ExecResult`,
  `redactSecrets`, `REDACTED`, `FetchError`, `ExecError`.
- **Signing & leases:** `createSigningKey`, `authorizeSigningKey`, `sign`, `exportPublicKey`,
  `VaultKeeper.verify`, `SigningAlgorithm`, `SigningPublicKey`, `SignRequest`, `SignResult`, `VerifyRequest`,
  `SigningBackend`, `isSigningBackend`, and the signing error family.
- **Backends & registry:** `SecretBackend`, `ListableBackend`, `PresenceCapableBackend`, `BackendRegistry`,
  `BackendConfig`, `BackendFactory`, `BackendSetupFactory`, `BackendCapabilities`, `getBackendCapabilities`,
  `isListableBackend`, `isPresenceCapableBackend`, `defaultBackendType`, `platformNativeBackendType`,
  `PresenceOperation`, `PresenceRequirementOptions`, the `Setup*` interactive types (`SetupQuestion`,
  `SetupChoice`, `SetupResult`).
- **Config & platform:** `VaultConfig`, `loadConfig`, `getDefaultConfigDir`, `getPlatformDefaultConfigDir`,
  `TrustTier`, `KeyStatus`, `Platform`.
- **Doctor:** `runDoctor` / `VaultKeeper.doctor`, `RunDoctorOptions`, `PreflightResult`, `PreflightCheck`,
  `ScopedPreflightCheck`, `PreflightCheckError`, `PreflightCheckErrorKind`, `PreflightCheckStatus`.
- **Error hierarchy:** `VaultError` plus ~30 subclasses — the sole failure surface (L3).

**Completeness gap (BROKEN-L1):** there is **no profile / resolution surface in the TS library** — profile
schema and `resolve_profile` live in `vaultkeeper-core` (and are reaching the CLI), but the embedding library
persona (§2.4) has no typed entry point to load a profile or materialize a resolved environment. Under
single-core consolidation (#234) this should surface as a host-layer API over the core. **Flag: design it,
don't let it arrive by accretion when a consumer files for it.**

### 2.3 Stability tiers (BROKEN — the accretion finding)

**IS: 88 `@public`, 0 `@beta`, 0 `@alpha`.** The entire surface is committed-stable by default. That is
accretion, not craft: a symbol is `@public` because it was exported, not because it was chosen for a 1.0
compatibility promise. **SHOULD BE:**

- `@public` — a 1.0 compatibility commitment; breaking it is a major-version event.
- `@beta` — intended-public, shape may still change before promotion; opt-in acknowledged.
- `@alpha` / `@internal` — not for external use; may change or vanish any release.
- **Promotion policy:** `@alpha → @beta → @public` only by an explicit PR that names the symbol and updates
  this spec; nothing reaches `@public` by default.

**Named craft-vs-accretion judgment calls (owner adjudicates):**

| Symbol(s) | Question | Recommendation |
|---|---|---|
| `BackendRegistry` (`@internal` methods visible in the class) | The class is `@public` but carries `@internal` members — a leaky boundary. | Split the public construction/registration API from internal dispatch; keep only the former `@public`. |
| `Setup*` interactive types (`SetupQuestion`/`Choice`/`Result`, `BackendSetupFactory`) | Public because interactive backend setup needed them — a real but *unstable* extension surface. | `@beta` until the plugin-backend setup flow is 1.0-frozen. |
| `is*Backend` type guards | Public convenience or committed contract? | `@public` — they are the sanctioned way to narrow a `SecretBackend`; keep, document. |
| `TestDoubleMisuseError` | A test-shaped error in the main library surface. | Verify it is thrown by production paths; if only by test doubles, move to `@vaultkeeper/test-helpers`. |
| `redactSecrets` / `REDACTED` | Internal helper or public utility? | `@public` — useful to embedders scrubbing their own logs; keep. |

The tiering pass is a **pre-1.0 gate**: freezing 88 symbols as `@public` without this review commits us to
compatibility on surface we never deliberately chose.

### 2.4 Integration personas (SHOULD BE)

| Persona (product brief) | Primary surface | Status |
|---|---|---|
| **Tool user** (unmodified tool via CLI) | Part 1 — `run`/`exec`/`store`/`profile` | served (pending `run`) |
| **Library / tool author** (embeds vaultkeeper) | `VaultKeeper` façade + access patterns + `SecretBackend` for a custom store | served for secrets/signing; **gap: profile resolution (§2.2 BROKEN-L1)** |
| **Backend author** (new OS/store) | `SecretBackend` + `BackendRegistry` + `Setup*` + capability/signing extension interfaces | served; stabilize `Setup*` (§2.3) |
| **Redemption-endpoint consumer** (future, any language) | — | **no designed entry point.** The local redemption socket (env-epic §7) is the intended home; until it is specced, this persona has no surface. **Flag, do not improvise.** |

### 2.5 Governance loop (SHOULD BE)

Two gates, one rule.

- **Mechanical gate (exists):** the per-package `api-report/*.api.md` is regenerated and diff-checked in CI; a
  surface change that does not update the committed report fails the build. This catches *that* the surface
  changed.
- **Design gate (this spec):** §2.1–§2.4 (and Part 1 for the CLI) say *whether the change is well-formed*.
- **The connecting rule (G-L):** a surface-changing PR updates **both** the api-report **and** this spec — the
  mechanical diff proves the change happened; the spec diff proves it was designed. A PR that moves one
  without the other fails review. This is the same E1 discipline as the CLI, applied to the library, and it is
  what turns "the surface evolved organically" into "every surface change is a reviewed design decision."

Part 3 completes the committed-artifact set this rule operates on (the Rust API listing and the help
snapshots), adds the vocabulary dimension, and states the single overarching gate (§3.5) that generalizes this
loop across every surface artifact.

---

## Part 3 — Enforcement artifacts & vocabulary governance

The gates in §1.4/§2.5 rest on **committed surface artifacts** whose diffs make change visible. Part 3
completes that artifact set (Rust API, help text), adds the product **glossary** the owner authors, and states
the overarching rule that binds them.

### 3.1 Rust public-API snapshot (SHOULD BE)

The `api-report/*.api.md` gate covers only the TypeScript packages. The Rust core has no equivalent, so
`vaultkeeper-core`'s public surface can drift silently — unacceptable under single-core consolidation (#234),
where the core *is* the surface every host re-exposes.

- **Tool: `cargo public-api`.** Evaluated against `cargo-semver-checks`: the latter is a *breaking-change
  lint* (it explains why a change is semver-major) but does **not** emit a committed, reviewable listing;
  `cargo public-api` produces exactly the "list the public API to a text file, diff it in CI, update via an
  env var" workflow that mirrors `check:api-report`. **Pick `cargo public-api`** as the snapshot gate;
  `cargo-semver-checks` is an optional *later* addition as a semver guard, not a substitute.
- **Scope:** `vaultkeeper-core` (mandatory — the consolidation surface). `vaultkeeper-cli` has no library
  surface to snapshot (it is a binary; its surface is the CLI, Part 1). The **wasm crate's exported bindings**
  are already partly covered by the existing wasm-export-fingerprint script (env-epic/consolidation context) —
  **integrate, do not duplicate**: the fingerprint script asserts the *set* of wasm exports; the
  `@vaultkeeper/wasm` `api-report` covers the *TS* shape; `cargo public-api` need only cover the native Rust
  crate. State this three-way split in the spec so no one adds a redundant fourth check.
- **Artifact + script:** a committed `crates/vaultkeeper-core/public-api.txt`; `pnpm check:rust-api`
  regenerates into a temp file and diffs (CI-enforced, exactly like `check:api-report`); `pnpm
  generate:rust-api` updates the committed file.
- **Operational cost, stated honestly:** `cargo public-api` builds rustdoc JSON, which requires a **pinned
  nightly toolchain**. Pin it in a toolchain file (the repo already pins the wasm toolchain — same pattern,
  precedent exists), so the snapshot is deterministic and a nightly bump is a deliberate, reviewed event.

### 3.2 CLI help-text snapshots (SHOULD BE)

`--help` output is the CLI's *rendered* surface — the wording a user reads. A flag rename, a description
edit, or a reordered subcommand is invisible to the api-report gates but is a real surface change. Golden
help snapshots make every such change a reviewable diff that fails CI until deliberately regenerated.

- **Coverage:** `--help` for the top-level command and **every** subcommand, for both CLIs while the TS one
  lives (its retirement removes its snapshots, itself a reviewable diff).
- **Host: dedicated golden files, not the conformance corpus.** The conformance corpus is behavior cases
  (argv/stdin → stdout/exit); help text is large multi-line rendered output better held as one golden file
  per command, mirroring the `docs/api/` generate-and-diff pattern. Layout:
  `crates/vaultkeeper-cli/tests/help/<command-path>.txt` (e.g. `session-mint.txt`).
- **Determinism (the real engineering point):** clap renders width-dependently and embeds the crate version.
  The regen and check **must** pin rendering: set a fixed terminal width (`COLUMNS`/clap `.term_width(80)`)
  and **normalize the version token** to a placeholder (`<VERSION>`) before writing/diffing, so a version bump
  or a CI terminal-width difference does not spuriously fail the gate. Without this the snapshots flap and get
  disabled — specify it or the gate rots.
- **Script:** `pnpm generate:cli-help` writes the goldens; `pnpm check:cli-help` regenerates to temp and
  diffs. CI-enforced.

### 3.3 Product glossary (NORMATIVE — owner-authored)

The canonical vocabulary. Each term has a one-line definition and its **sanctioned surface names** (CLI nouns,
API type names, claim fields). Drafted here from the de-facto usage in code and the frozen specs; **the owner
edits and ratifies each line.** Tensions are flagged **⚠ OWNER-DECIDES**, not resolved silently.

| Term | Definition | Sanctioned surface names | Notes / tension |
|---|---|---|---|
| **vaultkeeper** | The product and the semantic core. | product name; `VaultKeeper` (the orchestrator class) | ⚠ OWNER-DECIDES: is bare **"vault"** a sanctioned noun for the product, or only in compounds (`vault key`)? And is **"keeper"** ever standalone? *Rec:* product = "vaultkeeper"; `VaultKeeper` = the type; "vault" only adjectivally. |
| **secret** | The protected value at rest/in a backend. | `secret` (CLI noun, see B2); `materialize: "secret"`; `SecretBackend`, `SecretNotFoundError` | ⚠ OWNER-DECIDES: **secret vs value.** `store(name, value)` uses "value" for the raw string. *Rec:* "secret" is the domain noun; "value" only as the raw-string parameter. |
| **lease** | A serialized, expiring, revocable capability presented back to the issuer to redeem. | `session` (CLI); `materialize: "lease"`; "session signing lease" | House term (env-epic rev 5). See mint/redeem/revoke. |
| **token** | A wire-form credential (compact JWE) or the opaque in-process handle to authorized claims. | `--token` (CLI `exec`); `CapabilityToken` (the handle); "JWE token" | ⚠ OWNER-DECIDES: **token vs lease vs capability.** *Rec:* "token" = the JWE wire form + the opaque `CapabilityToken` handle; "lease" = the expiring/revocable capability as an issued artifact. A redeemed lease is *held as* a `CapabilityToken`. Consider whether `CapabilityToken` should read `LeaseHandle`. |
| **capability** | The abstract authority a token/lease confers; separately, a backend's advertised security feature. | `CapabilityToken`; `BackendCapabilities`, `backend capabilities` (CLI) | ⚠ OWNER-DECIDES: two senses (conferred authority vs backend feature-set) share the word. *Rec:* keep both, documented; they never co-occur ambiguously. |
| **grant** | — | **BANNED as a vaultkeeper term** (retired for "lease", env-epic rev 5). | ⚠ OWNER-DECIDES the exception: "grant" is 1Password's own term for its Mach-port authorization (consolidation §2). *Rec:* allowed **only** when describing 1Password's external mechanism; never for a vaultkeeper artifact. Banned-terms lint (§3.4) encodes this scope. |
| **mint / redeem / revoke** | The lease lifecycle verbs: create, present-to-use, kill. | `session mint`, `session redeem` (designed), `session revoke` | ⚠ OWNER-DECIDES: **mint vs issue vs create.** *Rec:* "mint" canonical (matches the minting-key term below). |
| **minting key** | The key that signs (mints) leases. | (no surface name yet) | ⚠ OWNER-DECIDES — **most ambiguous term.** Is the minting key the **vault key** (the AES/KeyManager key that seals leases) or a distinct signing key? *Rec:* define precisely before it reaches any surface; today the vault key both encrypts state and mints leases — if that stays, "minting key" = "vault key" and one term should win. |
| **vault key** | The `KeyManager` key sealing key-state and lease JWEs. | internal; `rotate-key`, `revoke-key` (CLI) | See minting key. |
| **signing key** | The Ed25519 key a signing lease authorizes use of (private half never leaves the backend). | `createSigningKey`, `authorizeSigningKey`, `SigningBackend`; `signingKey` (profile entry) | Distinct from vault key; keep separate. |
| **presence** | A human-in-the-loop approval at the moment of an operation. | `--require-presence-per-use` (CLI, see B5); `PresenceOperation`, `PresenceCapableBackend`; `pres` claim | ⚠ OWNER-DECIDES: **presence vs `perApprovalAction`** (the assurance-claim field). *Rec:* "presence" is the user/product term; `perApprovalAction` is the assurance wire field — document them as the same concept at two layers. |
| **backend** | A storage adapter for a specific OS/store. | `backend` (CLI noun); `SecretBackend`, `BackendRegistry` | Stable. |
| **profile** | A named env-var binding set (var → source → materialization → policy). | `profile` (CLI noun); profile JSON | Stable. |
| **entry** | One binding within a profile. | `--entry` (CLI); profile `entries` map | Stable. |
| **materialize / materialization mode** | How an entry resolves: to a secret value or to a lease. | `materialize: "secret" \| "lease"` | Stable (env-epic rev 5). |
| **rung** | A level of the adoption gradient (plaintext → resolved env → lease). | docs/product only | Internal framing term; ⚠ OWNER-DECIDES whether it appears in any user surface or stays product-doc-only. |

### 3.4 Vocabulary as lintable surface (SHOULD BE)

A `check:vocabulary` scan makes vocabulary drift fail CI the way surface drift does.

- **Scope: the committed surface artifacts only** — `api-report/*.api.md`, the §3.1 Rust API listing, and the
  §3.2 help snapshots. **Not** arbitrary source or comments (too noisy; the goal is *surface* vocabulary, and
  the surface artifacts are exactly the reviewed, canonical text). This keeps the check precise and its
  failures meaningful.
- **Banned-terms list — lives beside the glossary** (`docs/specs/vocabulary.banned.toml`), one row per rule:
  `{ term, canonical, scope: "all" | <artifact-glob>, exception?: <regex/context> }`. Example: `{ term =
  "grant", canonical = "lease", scope = "all", exception = "1[Pp]assword" }` encodes the §3.3 grant ruling.
- **Failure = a named diff:** the check prints the artifact, line, banned term, and canonical replacement —
  the same reviewable-diff experience as the surface gates. New banned terms are added by the owner as
  vocabulary decisions land (e.g. if `CapabilityToken` → `LeaseHandle` is ratified, `CapabilityToken` becomes
  a deprecated term with a migration window).

### 3.5 The overarching surface-artifact gate (NORMATIVE)

**Any PR whose diff touches a committed surface artifact — `api-report/*.api.md`, the Rust public-API listing,
or a help snapshot — is *by definition* a surface change.** It therefore:

1. **requires the corresponding spec section and/or glossary updated in the same PR** (Part 1 for a CLI
   change, Part 2 for a library change, §3.3 for a vocabulary change), and
2. **carries explicit owner-level review scrutiny** — a surface change is a design decision, reviewed as one.

The snapshots make a surface change **impossible to do invisibly**; this rule makes it **impossible to do
accidentally**. Together they are the whole governance intent: the surface evolves only by deliberate,
reviewed, spec-tracked decisions.

### 3.6 Decomposition (enforcement + glossary)

Mechanical enforcement items (mid-tier) are separated from owner-in-the-loop glossary authoring, per the
different kind of work each is.

| # | Item | Kind | Flag |
|---|---|---|---|
| S1 | `cargo public-api` snapshot for `vaultkeeper-core` + `check:rust-api`/`generate:rust-api` + pinned nightly toolchain file; wire into CI beside `check:api-report` | mechanical | [M] |
| S2 | CLI `--help` golden snapshots (both CLIs) + `check:cli-help`/`generate:cli-help` with pinned width + version normalization | mechanical | [M] |
| S3 | `check:vocabulary` lint + `vocabulary.banned.toml` format, scoped to the surface artifacts (S1/S2 outputs + api-reports) | mechanical | [M] |
| S4 | **Glossary authoring & ratification (§3.3)** — owner resolves each ⚠ OWNER-DECIDES tension; seeds the banned-terms list from the rulings | owner-in-the-loop | [S] |
| S5 | Wire the §3.5 gate into the PR-review checklist / CODEOWNERS so a surface-artifact diff routes to owner review | mechanical | [M] |

**Sequencing:** S1/S2 are independent and can land first (they only add gates, break nothing). S3 depends on
S1/S2 existing (it scans their outputs) and on **S4** for its initial banned list — so S3 lands its
*mechanism* early but its *rules* follow the owner's glossary rulings. S4 gates the vocabulary decisions the
whole of §3.3/§3.4 encodes and is the item the owner most wants to own.

---

## Appendix — register key

**IS** rows/tables are inventory from `origin/main` @ `87c615f`. **SHOULD BE** items (`G*`, `L*`, `E*`, and
Part 3's rules) are normative rules feature work must satisfy. **BROKEN** rows (`B*`, `BROKEN-L*`) are current
divergences with a disposition the owner approves, defers, or vetoes line by line. **⚠ OWNER-DECIDES** rows in
the glossary (§3.3) are vocabulary tensions surfaced for the owner to rule on, each with a recommendation he
may accept or overturn — this is the artifact the amendment most wants him to author. **S\*** items (§3.6) are
enforcement/glossary work, mechanical gates separated from owner-in-the-loop ratification. In-review CLI rows
(`run`, `session redeem`) are proposals; they must satisfy the grammar *before* landing, which is the point of
reviewing them here rather than after.
