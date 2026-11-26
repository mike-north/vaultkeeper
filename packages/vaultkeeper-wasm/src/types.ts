/**
 * Options for {@link WasmHostPlatform.exec} (issue #239). Every field is
 * optional; omitting all of them reproduces the pre-#239 2-argument
 * `exec(cmd, args)` behavior exactly: no stdin, the child inherits the host
 * process's environment unchanged, and the child inherits the host
 * process's current working directory unchanged.
 */
export interface ExecOptions {
  /** Bytes piped to the child process's stdin. Omit to pipe nothing in. */
  stdin?: Uint8Array
  /**
   * Extra/overriding environment variables layered onto the host process's
   * inherited environment — existing variables not named here are
   * preserved. The Node bridge ({@link createNodeHost}) implements this as
   * `{ ...process.env, ...env }`. Omit to leave the environment untouched.
   */
  env?: Record<string, string>
  /**
   * Working directory for the child process. Omit to inherit the host
   * process's current working directory.
   */
  cwd?: string
}

/** A minimal HTTP request description for {@link WasmHostPlatform.httpFetch}. */
export interface HttpFetchRequest {
  method: string
  url: string
  headers: Record<string, string>
  body?: Uint8Array
}

/** The response produced by {@link WasmHostPlatform.httpFetch}. */
export interface HttpFetchResponse {
  status: number
  headers: Record<string, string>
  body: Uint8Array
}

/** Context for a {@link WasmHostPlatform.promptApproval} request. */
export interface ApprovalContext {
  /** Short machine-readable identifier for the action being approved (e.g. `'delegated-fetch'`). */
  action: string
  /** Human-readable detail shown to the approver (e.g. the resolved URL). */
  detail: string
}

/**
 * Host platform interface that bridges Node.js OS calls to the WASM module.
 *
 * Implementations of this interface are passed to the WASM VaultKeeper
 * constructor to provide file I/O, subprocess execution, and networking.
 *
 * @remarks
 * **No-reentrancy contract**: none of these methods may call back into the
 * vault (no `VaultKeeper` method calls, no `createVaultKeeper()`) during
 * their own execution. The Rust core does not guard against reentrant
 * calls; violating this can deadlock or corrupt in-flight state.
 */
export interface WasmHostPlatform {
  /**
   * @param options - Optional stdin/env/cwd (issue #239). Omitting `options`
   *   (or all of its fields) preserves the exact pre-#239 exec behavior.
   */
  exec(
    cmd: string,
    args: string[],
    options?: ExecOptions,
  ): Promise<{ stdout: Uint8Array; stderr: Uint8Array; exitCode: number }>
  readFile(path: string): Promise<Uint8Array>
  writeFile(path: string, content: Uint8Array, mode: number): Promise<void>
  fileExists(path: string): Promise<boolean>
  deleteFile(path: string): Promise<void>
  renameFile(from: string, to: string): Promise<void>
  listDir(path: string): Promise<string[]>
  platform(): string
  configDir(): string
  /**
   * Perform an HTTP request through the host's networking stack (issue
   * #239). {@link createNodeHost} implements this over the global `fetch`.
   *
   * @remarks
   * No core consumer calls this yet — the delegated-access port (a later
   * issue) is the first real caller. A host that cannot supply real
   * networking may still implement this and reject every call; the WASM
   * core surfaces that as a `FetchError`.
   */
  httpFetch(request: HttpFetchRequest): Promise<HttpFetchResponse>
  /**
   * Optional interactive human-approval capability (issue #239). Absent
   * means "no interactive approval available" — the Rust core treats that
   * as an automatic refusal (fail closed), never an automatic allow. No
   * consumer wires this up yet.
   */
  promptApproval?(context: ApprovalContext): Promise<boolean>
}

/**
 * Capabilities a host-implemented {@link HostSecretBackend} may advertise.
 *
 * @remarks
 * Kept as a loose passthrough on purpose: the authoritative Rust-side
 * capability shape (`BackendCapabilities`) is owned by issue #242, which had
 * not landed when this contract was published. This type is the seam that
 * lets a host probe/report capabilities today without inventing a parallel
 * convention; expect its shape to narrow once #242 lands.
 */
export type HostBackendCapabilities = Record<string, unknown>

/**
 * Contract a JS/TS-implemented secret backend must satisfy to be driven by
 * the Rust core via `JsSecretBackend` (`crates/vaultkeeper-wasm`).
 *
 * Mirrors the core `SecretBackend` trait
 * (`crates/vaultkeeper-core/src/backend/types.rs`): `type`/`displayName` are
 * synchronous identity, everything else is async. Every byte payload at this
 * boundary is a `Uint8Array` — never a Node `Buffer` — so the contract is
 * identical whether the backend runs under Node or another JS host.
 *
 * @remarks
 * **No-reentrancy contract**: none of these methods may call back into the
 * vault (no `VaultKeeper` method calls, no `authorize()`/`setup()`) during
 * their own execution. The Rust core does not guard against reentrant calls;
 * violating this can deadlock or corrupt in-flight state.
 *
 * **Phase 0 scope**: the current `JsSecretBackend` scaffold
 * (`crates/vaultkeeper-wasm/src/wasm_impl.rs`) only dispatches
 * `type`/`displayName`/`isAvailable`/`store`/`retrieve`/`delete`/`exists`/`list`.
 * `getCapabilities`, `generateSigningKey`, `getPublicKey`, and `signWithKey`
 * are published here as the forward-looking contract shape, but are not yet
 * called from Rust — the capability trait (issue #242) and signing trait
 * (issue #237) they depend on had not landed when this contract was
 * published. Registry dispatch (making a `JsSecretBackend` reachable via
 * `BackendRegistry`) is also a later phase.
 */
export interface HostSecretBackend {
  readonly type: string
  readonly displayName: string
  isAvailable(): Promise<boolean>
  /**
   * Store `secret`, a **UTF-8 encoded** byte payload — the Rust core's
   * `SecretBackend` trait this contract mirrors is `&str`/`String`-based, so
   * `JsSecretBackend` (`crates/vaultkeeper-wasm/src/wasm_impl.rs`) decodes
   * these bytes as UTF-8 on the way in. `Uint8Array` is used here (rather
   * than a JS `string`) only to keep the boundary encoding-agnostic and
   * `Buffer`-free; it is not a license to store arbitrary binary data.
   * Non-UTF-8 bytes are rejected at the boundary, not silently mangled.
   */
  store(id: string, secret: Uint8Array): Promise<void>
  /**
   * Retrieve the secret stored under `id`, encoded the same way `store` was
   * called — UTF-8 bytes, not arbitrary binary. A non-UTF-8 result surfaces
   * as an error rather than producing corrupted text.
   */
  retrieve(id: string): Promise<Uint8Array>
  delete(id: string): Promise<void>
  exists(id: string): Promise<boolean>
  list?(): Promise<string[]>
  getCapabilities?(): Promise<HostBackendCapabilities>
  generateSigningKey?(name: string, algorithm: string): Promise<void>
  getPublicKey?(name: string): Promise<Uint8Array>
  signWithKey?(name: string, data: Uint8Array): Promise<Uint8Array>
}

/** Options for creating a WasmVaultKeeper instance. */
export interface VaultKeeperOptions {
  skipDoctor?: boolean
}

/**
 * Options for {@link VaultKeeper.setup} that are independent of the mandatory
 * executable-trust choice. Intersected with that choice to form
 * {@link SetupOptions}.
 */
export interface SetupOptionsBase {
  ttlMinutes?: number
  useLimit?: number
  /**
   * Backend identifier recorded as a claim label in the minted token's `bkd`
   * claim. This is a label only: it does not select, connect to, or route
   * through a functional backend. Setting `'keychain'`, for example, records the
   * string `'keychain'` in the token without performing any keychain access. This
   * WASM SDK's `setup()` mints the token directly from the supplied secret value
   * and never reads from a backend.
   */
  backendType?: string
}

/**
 * Options for the setup (token creation) operation.
 *
 * @remarks
 * The executable-trust choice is **mandatory and mutually exclusive**, and the
 * type system enforces it: `SetupOptions` is {@link SetupOptionsBase}
 * intersected with a choice of **exactly one** of `executablePath` (run
 * trust-on-first-use verification — the production choice) or `skipTrust: true`
 * (deliberately skip verification — development only). An options object with
 * **neither** field, or with **both**, fails to typecheck; and because
 * {@link VaultKeeper.setup}'s options argument is required, a 2-argument
 * `vault.setup(name, value)` call and a `vault.setup(name, value, {})` call are
 * compile-time type errors rather than runtime-only failures.
 * `ExecutableTrustRequiredError` remains a
 * runtime backstop for callers without static typing (e.g. plain JavaScript),
 * and is still thrown if `executablePath` is the retired legacy `'dev'`
 * sentinel. This mirrors the TypeScript `vaultkeeper` library's `SetupOptions`.
 */
export type SetupOptions = SetupOptionsBase &
  (
    | {
        /**
         * The calling executable's real path. When supplied, `setup()` hashes
         * the executable and runs trust-on-first-use verification (Sigstore →
         * trust-manifest match → TOFU first-encounter), binding the verified
         * hash into the minted token's `exe` claim; a hash conflicting with a
         * previously approved value throws `IdentityMismatchError`. Mutually
         * exclusive with `skipTrust`. The retired `'dev'` sentinel is rejected —
         * use `skipTrust: true` to skip verification instead.
         */
        executablePath: string
        skipTrust?: never
      }
    | {
        /**
         * Development-only opt-out that deliberately skips binding a real
         * executable identity, producing a `'dev'`-bound token (no executable
         * identity bound). Mutually exclusive with `executablePath`.
         */
        skipTrust: true
        executablePath?: never
      }
  )

/** Trust tier classification. */
export type TrustTier = '1' | '2' | '3'

/** Key status in the vault response. */
export type KeyStatus = 'current' | 'previous' | 'deprecated'

/**
 * Claims embedded in a JWE token, as returned by {@link AuthorizeResult}.
 *
 * The raw secret value (`val`) is deliberately **absent** — it is never part
 * of `authorize()`'s return shape. Read the secret through
 * {@link SecretAccessor} instead.
 */
export interface VaultClaims {
  jti: string
  exp: number
  iat: number
  sub: string
  exe: string
  use?: number | null
  tid: TrustTier
  bkd: string
  ref: string
}

/** Response from token authorization. */
export interface VaultResponse {
  keyStatus: KeyStatus
  rotatedJwt?: string | null
}

/**
 * A one-time accessor for the raw secret produced by `authorize()`.
 *
 * Mirrors the `getSecret()` pattern in the TypeScript library: the
 * plaintext secret is exposed only through a single `read()` callback and
 * cannot be read a second time. This keeps the secret out of the default
 * return shape and confines its lifetime to the callback.
 */
export interface SecretAccessor {
  /**
   * Invoke `fn` with the raw secret exactly once and return its result. The
   * secret must not be retained beyond `fn`'s execution.
   *
   * @throws AccessorConsumedError if called after the secret has been read.
   */
  read<T>(fn: (secret: string) => T): T

  /** Whether the secret is still available (i.e. `read()` has not run). */
  readonly available: boolean
}

/**
 * Authorization result. Combines the validated claims (secret redacted), the
 * response metadata, and a one-time {@link SecretAccessor} for the plaintext
 * secret.
 */
export interface AuthorizeResult {
  claims: VaultClaims
  response: VaultResponse
  secret: SecretAccessor
}

/** Preflight check status (Rust kebab-case serialization). */
export type PreflightCheckStatus = 'ok' | 'missing' | 'version-unsupported'

/**
 * Individual preflight check result. The Rust struct serializes with
 * `#[serde(rename_all = "camelCase")]`, so the wire/JSON field names here
 * are camelCase (matching this interface), not the Rust source's
 * snake_case.
 *
 * `required` reflects whether this dependency is required for the
 * active/configured backend(s); plugin-backend checks (`op`, `ykman`) are
 * `required: false` when their backend isn't enabled (issue #116).
 */
export interface PreflightCheck {
  name: string
  status: PreflightCheckStatus
  version?: string | null
  reason?: string | null
  required: boolean
}

/** Overall preflight result. */
export interface PreflightResult {
  ready: boolean
  checks: PreflightCheck[]
  warnings: string[]
  nextSteps: string[]
}

/** Vault configuration. */
export interface VaultConfig {
  version: number
  backends: {
    type: string
    enabled: boolean
    plugin?: boolean
  }[]
  keyRotation: {
    gracePeriodDays: number
  }
  defaults: {
    ttlMinutes: number
    trustTier: TrustTier
  }
  developmentMode?: {
    executables: string[]
  } | null
}
