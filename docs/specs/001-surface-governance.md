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

### 1.0 Command purposes (normative one-liners)

Each command's purpose, stated as the canonical one-liner — these are also the first line of
each command's `--help` and are pinned by the help snapshots (§3.2). A purpose change is a
surface change.

| Command | Purpose |
|---|---|
| `exec` *(deprecated → `run --token`; hidden from `--help`, still works until 1.0)* | Legacy alias for single-token launching; folds into `run` and retires at 1.0 (B9). Landed: emits a stderr-only deprecation notice, delegates entirely to `run --token`'s launch path. |
| `secret store` | Save a secret into the active backend (value read from stdin — never from arguments). *(was `store`, deprecated alias until 1.0)* |
| `secret delete` | Remove a secret from the active backend. *(was `delete`)* |
| `doctor` | Run preflight checks and report whether vaultkeeper is ready to use on this machine. |
| `trust approve` | Trust an executable: record its hash in the trust manifest. *(was `approve`; PATH positional)* |
| `trust dev-mode` | Enable or disable relaxed identity verification for a script during development. *(was `dev-mode`)* |
| `trust status` *(designed)* | Report the current trust state of an executable — recomputed hash vs manifest, tier, dev-mode status; scriptable exit code (0 intact / 2 mismatch-or-conflict). |
| `key rotate` | Rotate the vault encryption key, re-sealing stored state under the new key. *(was `rotate-key`)* |
| `key revoke` | Emergency-revoke the vault encryption key, invalidating all outstanding tokens. *(was `revoke-key`)* |
| `config init` | Create a new configuration file with defaults. |
| `config show` | Print the current effective configuration. |
| `backend capabilities` | Report the active backend's security capabilities (e.g. per-use presence enforcement). |
| `profile init` | Scaffold a new named environment profile. |
| `profile show` | Display a profile's entries and their policy — never secret values. |
| `profile list` | List the available profiles. |
| `profile lint` | Validate a profile and warn where its policy is looser than this machine's defaults (advisory). |
| `lease issue` | Issue a signing lease for a profile entry, proving human presence at issuance. *(was `session mint`, deprecated alias until 1.0)* |
| `lease revoke` | Revoke an outstanding lease by id, or every outstanding lease for a signing key. *(was `session revoke`)* |
| `run` *(landed — native Rust CLI; `--token` source landed on the TS CLI too, `--profile`/`--profile-file` native-CLI-only for now)* | Launch a command with one or more secrets available in its subshell — stdio- and signal-transparent. The source options (`--profile`, `--token`, `--set`) describe only *how many secrets and by what means they are populated*; the operation is one. (Owner-adjudicated: `run` is the single launcher verb.) |
| `lease redeem` *(designed; library/core operation — CLI shape deliberately TBD)* | Redeem a signing lease into an in-process signing handle for non-interactive signing. *(né `session redeem`)* |

### 1.1 Command tree (normative inventory)

Landed on `origin/main`. `stdin`/`stdout`/`stderr` columns state the contract; `exit` is the success/typed
range. "Secrets" = does a secret value transit this command, and by what channel.

| Command | Positional | Flags | stdin | stdout | Secrets | exit |
|---|---|---|---|---|---|---|
| `exec` *(deprecated — hidden alias for `run --token`)* | `COMMAND…` (trailing) | `--token <jwe>` | inherited by child | child's | value → child env (`VAULTKEEPER_SECRET`) | child's code |
| `run` | `COMMAND…` (trailing) | `--profile <n>` \| `--profile-file <p>` \| `--token <jwe>` (exactly one, native CLI; TS CLI: `--token` only), `--as <VAR>` (`--token` only, default `VAULTKEEPER_SECRET`), `--set <VAR=SECRET>`, `--dry-run`, `--require-presence-at-issuance` (per §3.3.1 r.5; `--profile` source only) | inherited by child (never read by `run` itself) | child's (`--dry-run` prints the plan to stdout instead of launching) | value → child env; `--token` redeems an already-minted JWE, `--profile`/`--set` mint/resolve | child's code (128+N on signal-kill) |
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
| `lease redeem` (shape TBD) | — | lease presenter | lease redemption over the #268 handle table; **designed — library/core first, CLI surface TBD** |

### 1.2 Design grammar (SHOULD BE)

**G1 — Noun-verb for resource families; bare verb for whole-vault process actions.** A command earns a
**noun namespace** (`<noun> <verb>`) when it manages a *category of addressable resources* with more than one
operation: `config`, `backend`, `profile`, `lease` (né `session`, ruling §3.3.1), and (post-B2/B3/B4 adjudication)
`secret`, `key`, `trust`. A command is a **bare top-level verb** only when it is a single process action against the vault as
a whole with no sibling operations on a shared resource — after adjudication, exactly two qualify: `run`
(the launcher) and `doctor` (the whole-machine check).

**G2 — The primary subject is positional; modifiers are flags.** A command's required primary subject — the
resource it acts on — is a **positional argument**. Options, policy toggles, and alternate sources are
**flags**. `profile show NAME`, `lease issue PROFILE`, `trust approve PATH` (see B4). A secret value is
**never** a positional or a flag value (G6).

**G3 — Flags are a surface-wide vocabulary with defined levels.** A concept has exactly one flag spelling
across the whole surface **and** a defined applicability *level*, and the two are inseparable — a flag's name
carries a promise about where it applies. Three levels:

- **Near-universal flags** — apply to nearly every command and mean the same thing everywhere: `--format`
  (and its `--json` alias) for output-format selection (§G5).
- **Family flags** — apply across a related group of commands with one fixed spelling: `--profile` is **the**
  single way any command references a profile; `--profile-file` is the explicit-path override; the
  `--require-presence-*` family (see B5) carries presence policy wherever presence applies.
- **Command-local flags** — meaningful to a single command (e.g. `--entry` selecting within a profile).

A new flag **must** state its level. Promoting a command-local flag to a family or near-universal level (or
the reverse) is a **surface change** and therefore a spec change (§1.4), never an ad-hoc addition.

**G4 — stdout is data; stderr is diagnostics.** stdout carries *only* the command's payload — a JWE
(`lease issue`), a structured value (`--format json`), a name list, or the child's own stream (`run`). Every
human-facing message — progress, warnings, the file-only degradation notice, errors — goes to **stderr**.
This is the #279 rule generalized to the whole surface, and it is what makes every data-producing command
pipeable. `--dry-run` and human-report commands print their report to stdout (there is no child to protect),
but a command that emits a machine artifact must never interleave diagnostics into it.

**G5 — Output has an output-formatter architecture: generation is separated from formatting.** A command
*generates* a value; a separate *formatter* renders it. This separation is the rule — no command hand-rolls
its own serialization. Format selection is layered:

- **Explicit `--format <human|toon|json>`** wins whenever present. `--json` is a defined alias for
  `--format json`; no command invents a second machine-output switch.
- **Absent an explicit choice**, the CLI detects agentic invocation — the environment variables catalogued by
  [is-agentic-tui](https://github.com/mike-north/is-agentic-tui#supported-tools) — and defaults to
  [toon](https://toonformat.dev/) for token efficiency; otherwise it renders human-readable text.

When a structured format (`toon` or `json`) is selected, stdout is a **single well-formed document** and
nothing else — the totality rule of §G4 stands: diagnostics never interleave into it. This is a shared
output-formatter across the surface; its implementation lands as its own work item.

**G6 — Secrets never appear in argv.** A CLI-surface invariant, not a per-command choice. A secret value
enters only via **stdin** (`secret store`) and leaves only via **stdout** (`lease issue` prints a lease, `run`
injects into a child's environment). No command accepts a **raw secret** as a positional or flag value; `--set
VAR=SECRET` on `run` is the one deliberate exception and is documented as such, marked UNREVIEWED in
`--dry-run`. (Backend implementations honor the same rule downstream, e.g. keychain `secret store` via
`security -i` stdin.) Lease tokens are a distinct case: they *do* travel as values — a `--token <JWE>` flag,
a printed lease on stdout. This is unavoidable and permitted, because a lease is a scoped, expiring
**capability**, not a raw secret; but it still warrants care — a lease authorizes use, so it must be handled
deliberately and never logged casually.

**G7 — Exit-code taxonomy.** `0` success; `1` a typed operational failure (the `VaultError` surface, §2.1);
`2` reserved for clap usage errors; `run` **propagates the child's exit code**, and a signal-terminated
child yields `128+N`. Advisory commands that cannot "fail" (`profile lint`) exit `0` on any successfully
loaded input and signal concerns only through stderr warnings — this is deliberate and normative, not a bug.

**G8 — `lint` judges what you wrote; `status` reports what is** *(owner-adjudicated)*.
`lint` is **advisory static analysis of an authored artifact** (a profile file): opinions about a document,
never a verdict — and it always exits `0`, because its baseline (this machine's config defaults) is
machine-relative, so gating on it would crown one machine's defaults as project authority. `status` is a
**factual state report against an objective baseline** (a recomputed hash vs the committed manifest): it does
not opine, it reports what is — with **meaningful, gate-safe exit codes** (`0` intact, non-zero for a
mismatch or conflict), safe for scripts and CI to gate on. The prior art is `git status` and `systemctl
status`: a state report, not an advisory. The exit-code semantics *derive from the subject* — machine-relative
baselines cannot gate; objective baselines must. `doctor` is the bundled whole-machine `status`. New commands
must pick the verb that matches their subject; the near-synonyms `check`, `validate`, `verify`, and `audit`
are **reserved pending a spec proposal** — propose them through this spec, not ad hoc.

**G9 — YAML-first for structured configuration artifacts** *(owner-adjudicated)*. The committable structured
artifacts — profiles and the config file — are **canonically YAML**: it carries comments (the policy intent a
profile encodes deserves inline explanation) and is more token-efficient for the agentic readers that consume
it. JSON is **accepted for compatibility** during the migration window, so an existing `.json` artifact keeps
working, but new artifacts and all examples are YAML. Profile storage is therefore `profiles/<name>.yaml`
canonical (`.json` still accepted); `config init` writes YAML. The JSON→YAML migration is a tracked work
item. (This governs the on-disk *artifact* format; the *wire* encoding of config/claim JSON remains camelCase,
§L5.)

### 1.3 Inconsistencies (BROKEN) — the review surface

Each row is a concrete divergence from §1.2 with a recommended disposition. **fix-now** = correct before the
1.0 surface freeze; **legacy** = keep, document, and gate behind the deprecation path; **leave** = conforms
on reflection, recorded to close the question.

| # | Location | Violates | Divergence | Disposition |
|---|---|---|---|---|
| B1 | `store --name`, `delete --name` | G2 | The primary subject (the secret name) is a **flag**, while `profile`/`session` make the subject positional. | **fix-now**: `store NAME` / `delete NAME` positional; keep `--name` as a hidden deprecated alias for one minor. |
| B2 | `store`, `delete`, `rotate-key`, `revoke-key` as bare verbs | G1 | These act on addressable resource categories (secrets; keys) but are top-level verbs. | **ADJUDICATED (owner)**: promote — `secret store NAME`, `secret delete NAME` (future `secret list`); `key rotate`, `key revoke` (future `key show`, `key generations`). Hyphenated/bare forms become deprecated aliases, removed at 1.0. |
| B3 | `dev-mode` as a bare top-level verb with `--enable` | G1/G2 | Trust-manifest operation stranded outside any namespace. | **ADJUDICATED (owner)**: joins the `trust` namespace — `trust dev-mode PATH …` (exact enable/disable shape settled at implementation under G2/G3). Deprecated alias until 1.0. |
| B4 | `approve --path` (and `dev-mode --path`) | G1/G2 | The subject is a flag, and the verb names the act without its noun: approving is a *trust* decision. `command`/`bin` rejected as the noun — "command" is already load-bearing (`run … -- COMMAND`) and "bin" misdescribes interpreted scripts. | **ADJUDICATED (owner)**: `trust approve PATH` (positional). The `trust` namespace matches the domain's own vocabulary (trust manifest, trust tiers) and gains designed future members: `trust status PATH` (recompute + compare now; `--json`; exit 0 intact / non-zero mismatch — a scriptable gate primitive and the first-class surface for TOFU-conflict reporting), `trust list`, `trust revoke PATH`. Deprecated aliases until 1.0. |
| B5 | `store`/`delete` `--require-presence-per-use` vs `run` `--require-presence` | G3 | Two spellings for the presence family. | **fix-now**: pick one before `run` lands. Recommend `--require-presence-per-use` (precise; "presence" alone is ambiguous about scope) across all commands, or a shared `--require-presence[=per-use]`. Resolve **before** #279 merges so `run` ships correct. |
| B6 | `session mint PROFILE --entry E` vs `profile show NAME` | G2 | Reviewed in #328: `mint` takes the profile positionally (consistent) but the *entry* — arguably a co-primary subject — is a flag. | **leave** (documented): the profile is the addressed resource; the entry is a selector within it, legitimately a flag. Recorded so the #328 question is closed, not reopened. |
| B7 | `backend capabilities` is the only `backend` verb | G1 | A noun namespace with a single verb is defensible only if more verbs are foreseen. | **leave**: `backend list`/`backend test` are natural future siblings; the namespace is intentional headroom, not premature. |
| B8 | `config`/`backend`/`profile` support `--json` unevenly | G5 | `backend capabilities` has `--json`; `config show`, `profile show/list` do not. | **fix-now (additive)**: any command whose output a script would consume gets `--json`. Audit `config show`, `profile show`, `profile list`, `doctor`. |
| B9 | `exec` vs `run` as separate launchers | G1 | Both launch a delegated command with secret(s) in its subshell; token-vs-profile is the *source*, not a different action — two verbs for one operation. | **LANDED (issue #333, owner-adjudicated)**: `run` is the single launcher. `run --token <JWE> [--as VAR]` absorbs `exec` (`--as` defaults to `VAULTKEEPER_SECRET`); `exec` is a hidden, deprecated alias (stderr-only notice, removed at 1.0) on the native Rust CLI. TS CLI: `run --token`/`--as` landed as new functionality with the same stdio/signal-transparency contract; the TS `exec --secret/--env/--caller` command (a distinct, TOFU-trust-gated mint-from-scratch flow that has no `--token` mode to alias from) is unchanged — see the issue #333 PR description for why that pre-existing divergence isn't folded here. One stdio-transparency contract lives in one command (`run`). |

### 1.4 Evolution policy (SHOULD BE)

- **E1 — Spec-diff-in-PR.** A PR that adds, removes, or changes a command/subcommand/flag/exit-code **must**
  edit §1.1 and, if it bends a rule, §1.3 in the same PR. A surface change without a spec diff is an
  automatic review block. This is what makes drift visible as a reviewable diff rather than an archaeological
  finding.
- **E2 — Deprecation path.** A removed or renamed flag/command survives one minor release as a hidden alias
  emitting a stderr deprecation notice (never on stdout — G4), then is removed at the next minor. Renames land
  the new spelling and the alias together.
- **E3 — Cross-implementation enforcement.** The native and TS CLIs are one surface;
  `crates/vaultkeeper-conformance` is the mechanical proof of it. Every new command lands with conformance cases so the two CLIs
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
- **L6 — No subpath exports.** Each TS package has exactly one public entry point — the package root. There
  are no deep-import subpaths (`vaultkeeper/foo`); the conditional `exports` map exposes only the root, and
  everything public flows through `index.ts`. A consumer never reaches into a package's internal file layout,
  so that layout stays free to change without breaking anyone. This is L1 enforced at the package boundary:
  `index.ts` is the surface, and it is the *only* door.
- **L7 — TypeScript compiler support policy.** The library commits to compiling under the **latest minor of
  each supported TS major** — currently the latest minors of TS 5.x, 6.x, and 7.x — plus `typescript@latest`.
  A CI **test matrix** covers exactly these entries, and a **non-blocking** CI lane tracks the TS **nightly**
  build as an early-warning signal (its failure never gates a PR). The consumer-facing guarantee: the public
  types compile cleanly under every matrix entry. Adding or dropping a supported major is a spec change.

### 2.2 The surface by concept (IS)

The 88 `@public` symbols group into coherent concepts. The owner reviews whether each grouping is complete and
whether membership is intentional.

- **Entry & lifecycle:** `VaultKeeper` (the façade class), `VaultKeeper.init`, `VaultKeeperOptions`,
  `VaultResponse` **⚠ name under workshop** — this operation-metadata wrapper's name collides with the
  adjacent tools' "vault" noun and predates the glossary; the rename is adjudicated at the tiering pass (§2.3)
  (candidate shapes: per-operation result/receipt types). Do not invent the final name here.
- **Setup / identity / trust:** `setup` (**normative clarification:** `setup()` is **per-process
  initialization by the embedding application** — load config, verify caller identity, wire the backend — run
  each time a host process starts; it is **not** one-time user onboarding, which is the CLI's `config init`.
  The *name* is under workshop for that ambiguity, see below), `SetupOptions` (a discriminated union enforcing
  exactly one of `executablePath`/`skipTrust` — a craft high point, keep as the pattern), `SetupOptionsBase`,
  `approveExecutable`, `checkExecutableTrust`, `setDevelopmentMode`, `ExecutableTrustStatus`,
  `ExecutableTrustRequiredError`, `IdentityMismatchError`.
- **Secrets & access tokens:** `store`, `delete`, `secretExists`, `authorize`, `getSecret`, `CapabilityToken`,
  `SecretAccessor`, `SecretTokenMap`, `AccessorConsumedError`, `SecretNotFoundError`.
- **Delegated access patterns:** `fetch`; the delegated-launch verb **aligns to `run`** (CLI ubiquitous
  language — the library method today named `exec` and its `Exec*` request/result/error types rename to the
  `run` family at the tiering pass, §2.3, so the launcher is spelled `run` in both surfaces), `FetchRequest`,
  `ExecRequest`, `ExecResult`, `redactSecrets`, `REDACTED`, `FetchError`, `ExecError`.
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
- **Error hierarchy:** `VaultError` plus ~30 subclasses — the sole failure surface (L3). **Designed
  addition:** `UnreachableError` — its constructor accepts a `never`, so a missed `enum`/union arm becomes a
  **compile error at the switch site** (the value that should be `never` still has a type, and passing it
  fails to typecheck) rather than a silent fall-through at runtime.

**Names under workshop (⚠ owner-flagged, decision deferred — no surface change yet):**

- `VaultResponse` — the "vault"-noun collision above; rename resolved at the tiering pass (§2.3).
- `setup` (the name) — reads like one-time onboarding but denotes per-process initialization (see the
  clarification above); the name is under review even though the semantics are settled.
- **development mode** (`setDevelopmentMode`, CLI `trust dev-mode`) — the owner is not settled on the naming
  ("I'm not sure I love it"); flagged for a later naming decision. No rename lands here.

**Completeness gap (BROKEN-L1):** there is **no profile / resolution surface in the TS library** — profile
schema and `resolve_profile` live in `vaultkeeper-core` (and are reaching the CLI), but the embedding library
persona (§2.4) has no typed entry point to load a profile or materialize a resolved environment. Under
single-core consolidation (#234) this should surface as a host-layer API over the core. **Flag: design it,
don't let it arrive by accretion when a consumer files for it.**

### 2.3 Stability tiers (BROKEN — the accretion finding)

**IS: 88 `@public`, 0 `@beta`, 0 `@alpha`.** The entire surface is committed-stable by default. That is
accretion, not craft: a symbol is `@public` because it was exported, not because it was chosen for a 1.0
compatibility promise. **SHOULD BE:**

- `@public` — conventional SemVer stability commitment; breaking it is a major-version event.
- `@beta` — intended-public, shape may still change before promotion; opt-in acknowledged.
- `@alpha` / `@internal` — not for external use; may change or vanish any release.
- **Promotion policy:** `@alpha → @beta → @public` only by an explicit PR that names the symbol and updates
  this spec; nothing reaches `@public` by default.
- **Breaking-change policy (tested in CI).** The tiers are only meaningful if the compatibility promise each
  makes is *enforced*, so the project adopts a **defined breaking-change policy** gated in CI via
  [@api-extractor-tools/change-detector](https://github.com/mike-north/api-extractor-tools/tree/main/tools/change-detector).
  Enforcement grows to an **API report per maturity stage** — `internal`, `alpha`, `beta`, `public` — and the
  change-detector applies each stage's rules to its report: a breaking change to a `@public` symbol fails CI
  unless the PR is a deliberate major-version event, while lower stages permit the churn their contract allows.
  This turns "don't break `@public`" from a review-time judgment into a mechanical gate.

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
| **Tool user** (unmodified tool via CLI) | Part 1 — `run`/`secret store`/`profile` | served (`run` landed) |
| **Library / tool author** (embeds vaultkeeper) | `VaultKeeper` façade + access patterns + `SecretBackend` for a custom store | served for secrets/signing; **gap: profile resolution (§2.2 BROKEN-L1)** |
| **Backend author** (new OS/store) | `SecretBackend` + `BackendRegistry` + `Setup*` + capability/signing extension interfaces | served; stabilize `Setup*` (§2.3) |
| **Redemption-endpoint consumer** (future, any language) | — | **no designed entry point.** The local redemption socket (env-epic §7) is the intended home; until it is specced, this persona has no surface. **Flag, do not improvise.** |

### 2.5 Governance loop (SHOULD BE)

Two gates, one rule.

- **Mechanical gate (exists, growing):** the per-package `api-report/*.api.md` is regenerated and diff-checked
  in CI; a surface change that does not update the committed report fails the build. This catches *that* the
  surface changed. It grows to a **per-maturity-stage report** (`internal`/`alpha`/`beta`/`public`, §2.3) with
  [@api-extractor-tools/change-detector](https://github.com/mike-north/api-extractor-tools/tree/main/tools/change-detector)
  gating each stage's breaking-change rules — so the gate catches not just *that* the surface changed but
  whether the change is *allowed* at that symbol's committed stability.
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
- **Typed surface, not just names (owner requirement).** The `--help` output — and therefore the snapshot —
  **must render the value type / placeholder of every positional and flag** (e.g. `--ttl <SECONDS>`,
  `PATH`, `--set <VAR=SECRET>`), not the bare flag name. The snapshot then pins the *typed* surface: a change
  to an argument's expected type or placeholder is a surface change and shows up as a reviewable diff, exactly
  like a rename.
- **Host: dedicated golden files, not the conformance corpus.** The conformance corpus is behavior cases
  (argv/stdin → stdout/exit); help text is large multi-line rendered output better held as one golden file
  per command, mirroring the `docs/api/` generate-and-diff pattern. Layout:
  `crates/vaultkeeper-cli/tests/help/<command-path>.txt` (e.g. `lease-issue.txt`).
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
| **lease** | A serialized, expiring, revocable capability presented back to the issuer to redeem. | `lease` (CLI namespace); `materialize: "lease"`; "signing lease"; `LeaseToken` (wire-form type, §3.3.1 r.7) | House term (env-epic rev 5), ratified §3.3.1 r.1. `session` retired (r.2). See issue/redeem/revoke. |
| **token** | A wire-form credential (compact JWE) or the opaque in-process handle to authorized claims. | `--token` (CLI `run`); `LeaseToken` (né `CapabilityToken`, §3.3.1 r.7); "JWE token" | Resolved (§3.3.1 r.7): "token" = the JWE wire form; the lease's wire-form and in-process handle types are both `LeaseToken` (`CapabilityToken` renamed in the tiering batch). "lease" = the expiring/revocable capability as an issued artifact; a redeemed lease is *held as* a `LeaseToken`. |
| **capability** | The abstract authority a token/lease confers; separately, a backend's advertised security feature. | `CapabilityToken`; `BackendCapabilities`, `backend capabilities` (CLI) | ⚠ OWNER-DECIDES: two senses (conferred authority vs backend feature-set) share the word. *Rec:* keep both, documented; they never co-occur ambiguously. |
| **grant** | — | **BANNED as a vaultkeeper term** (retired for "lease", env-epic rev 5). | ⚠ OWNER-DECIDES the exception: "grant" is 1Password's own term for its Mach-port authorization (consolidation §2). *Rec:* allowed **only** when describing 1Password's external mechanism; never for a vaultkeeper artifact. Banned-terms lint (§3.4) encodes this scope. |
| **issue / redeem / revoke** | The lease lifecycle verbs: issue (create), redeem (present back to the issuer for its accounted, at-most-once effect), revoke (kill). | `lease issue`, `lease redeem` (designed), `lease revoke` | Ratified §3.3.1 r.3 — `mint` replaced by `issue`; `redeem` names the effect at the issuer, not the gesture. |
| **minting key** | The key that signs (mints) leases. | (no surface name yet) | ⚠ OWNER-DECIDES — **most ambiguous term.** Is the minting key the **vault key** (the AES/KeyManager key that seals leases) or a distinct signing key? *Rec:* define precisely before it reaches any surface; today the vault key both encrypts state and mints leases — if that stays, "minting key" = "vault key" and one term should win. |
| **vault key** | The `KeyManager` key sealing key-state and lease JWEs. | internal; `rotate-key`, `revoke-key` (CLI) | See minting key. |
| **signing key** | The Ed25519 key a signing lease authorizes use of (private half never leaves the backend). | `createSigningKey`, `authorizeSigningKey`, `SigningBackend`; `signingKey` (profile entry) | Distinct from vault key; keep separate. |
| **presence** | A human-in-the-loop approval at the moment of an operation. | `--require-presence-per-use` (CLI, see B5); `PresenceOperation`, `PresenceCapableBackend`; `pres` claim | ⚠ OWNER-DECIDES: **presence vs `perApprovalAction`** (the assurance-claim field). *Rec:* "presence" is the user/product term; `perApprovalAction` is the assurance wire field — document them as the same concept at two layers. |
| **backend** | A storage adapter for a specific OS/store. | `backend` (CLI noun); `SecretBackend`, `BackendRegistry` | Stable. |
| **profile** | The named, committable **policy contract** for a launched context (var → source → materialization → policy). | `profile` (CLI noun); profile YAML (`.json` accepted, §G9) | Ratified §3.3.1 r.8. Defines an environment; never the reverse. |
| **environment** | The **resolved output** a profile produces at launch — the materialized var set. **Not** an artifact name. | (none — banned as an artifact name, §3.3.1 r.8) | "A profile defines an environment," one-directional. |
| **entry** | One binding within a profile. | `--entry` (CLI); profile `entries` map | Stable. |
| **materialize / materialization mode** | How an entry resolves: to a secret value or to a lease. | `materialize: "secret" \| "lease"` | Stable (env-epic rev 5). |
| **rung** | A level of the adoption gradient (plaintext → resolved env → lease). | docs/product only | Internal framing term; ⚠ OWNER-DECIDES whether it appears in any user surface or stays product-doc-only. |

#### 3.3.1 Adjudicated rulings (owner, 2026-07-23) — supersede the ⚠ markers above where they overlap

1. **`lease` — RATIFIED** as the artifact's name. Definition: *an encrypted, self-expiring,
   issuer-revocable authorization that confers scoped use without possession, and has effect
   only when redeemed back to the vault that issued it.* Rationale of record: self-expiry as
   the inherent, default-safe property (CS lease prior art — DHCP, distributed-systems
   leases), which no alternative (token/grant/ticket/pass/permit) carries intrinsically.
   `capability` remains the *concept* one layer up; `lease` is the artifact.
2. **`session` — RETIRED as a noun.** It named nothing in the system (no session object, id,
   or state); every property it gestured at lives on the lease (`exp`, `pres`,
   injected-at-launch). Docs may describe the launch-wrapper *pattern* in prose; no surface
   name uses it. CLI namespace `session` → **`lease`**, deprecated aliases until 1.0.
3. **Lease verb set — `issue` / `redeem` / `revoke`.** `mint` replaced by `issue`
   (CLI: `lease issue`); `redeem` kept over "present" because it names the *effect at the
   issuer* (accounted, at-most-once semantics), not the gesture; `revoke` unchanged
   (`--jti` scalpel / `--key` guillotine).
4. **`vault key` — RATIFIED as the single name** for the credential that seals stored state
   and issues leases; **"minting key" retired** (it existed only to rhyme with the retired
   verb, and was the glossary's flagged top ambiguity). "Issuing key" is likewise rejected —
   one key, one name, and its role is self-explanatory in a project called vaultkeeper.
5. **Presence-flag ripple (G3):** the scope-suffix family follows the verb change —
   `--require-presence-at-issuance` (not `-at-mint`; "at-issue" rejected for the English
   idiom collision). `--require-presence-per-use` unchanged.
6. **Banned-terms additions** (§3.4 list): `mint`/`minting` and `session` banned from
   surface artifacts where lease vocabulary applies; `grant` ban stands.
7. **`LeaseToken` — RATIFIED** as the name of the lease's **serialized wire-form** type
   (consistent with the prior ruling that *token = the wire form*). The in-process handle
   `CapabilityToken` **renames to `LeaseToken`** in the tiering batch (§2.3), so one name
   spans the artifact's wire and handle forms and the retired "capability"-prefixed name goes
   away. Until that batch lands, `CapabilityToken` is the deprecated spelling.
8. **`profile` / `environment` — RATIFIED as a directional pair.** A **profile** is the named,
   committable **policy contract** for a launched context (which secrets it draws, at what
   trust, for how long). An **environment** is reserved for the **resolved output only** — the
   materialized var set a profile produces at launch. The relation is one-directional: *a
   profile defines an environment*, **never** the reverse. "environment" is therefore **banned
   as an artifact name** (no `environment` file, type, or CLI noun); it names only the resolved
   result. Added to the §3.4 banned-terms list.

#### 3.3.2 Vocabulary in use

The ratified vocabulary, shown in ordinary sentences — the register docs and help text should match:

> Store your GitHub token as a secret once; from then on, run gives each tool a lease instead of the key.

> A profile defines the environment a command launches with — which secrets it draws, at what trust, for how long.

> At launch, vaultkeeper issued a signing lease under the vault key; the agent redeems it for each signature until it expires.

> The lease had expired, so redemption was refused — launch again with presence to issue a new one.

> lease revoke --key release-signer kills every outstanding lease under that key, instantly.

> trust status ./deploy.sh reports whether trust is intact — the script still hashes to what you approved.

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
  vocabulary decisions land: the ratified `CapabilityToken` → `LeaseToken` rename (§3.3.1 r.7) makes
  `CapabilityToken` a deprecated term with a migration window, and `environment` is banned as an *artifact*
  name (§3.3.1 r.8) — flagged wherever it appears as a file/type/CLI-noun rather than the resolved output.

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
(`lease redeem`) are proposals; they must satisfy the grammar *before* landing, which is the point of
reviewing them here rather than after. (`run` was one such row and has since landed — §1.0/§1.1.)
