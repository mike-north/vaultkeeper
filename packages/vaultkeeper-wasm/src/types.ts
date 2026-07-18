/**
 * Host platform interface that bridges Node.js OS calls to the WASM module.
 *
 * Implementations of this interface are passed to the WASM VaultKeeper
 * constructor to provide file I/O and subprocess execution.
 */
export interface WasmHostPlatform {
  exec(
    cmd: string,
    args: string[],
    stdin?: Uint8Array,
  ): Promise<{ stdout: Uint8Array; stderr: Uint8Array; exitCode: number }>
  readFile(path: string): Promise<Uint8Array>
  writeFile(path: string, content: Uint8Array, mode: number): Promise<void>
  fileExists(path: string): Promise<boolean>
  deleteFile(path: string): Promise<void>
  renameFile(from: string, to: string): Promise<void>
  listDir(path: string): Promise<string[]>
  platform(): string
  configDir(): string
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
