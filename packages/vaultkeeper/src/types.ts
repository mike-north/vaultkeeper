/**
 * Shared types and interfaces for vaultkeeper.
 */

/** Trust tier for executable identity verification. */
export type TrustTier = 1 | 2 | 3

/** Key status in the rotation lifecycle. */
export type KeyStatus = 'current' | 'previous' | 'deprecated'

/** Status of a preflight check. */
export type PreflightCheckStatus = 'ok' | 'missing' | 'version-unsupported'

/** Result of a preflight check for a single dependency. */
export interface PreflightCheck {
  /** Human-readable name of the dependency being checked. */
  name: string
  /** Whether the dependency was found and is a supported version. */
  status: PreflightCheckStatus
  /** The detected version string, if the dependency was found. */
  version?: string | undefined
  /** Human-readable explanation of why the status is not `'ok'`. */
  reason?: string | undefined
}

/** Aggregated result from all preflight checks. */
export interface PreflightResult {
  /** Individual check results, one per dependency inspected. */
  checks: PreflightCheck[]
  /** `true` if all required checks passed and the system is ready. */
  ready: boolean
  /** Non-fatal advisory messages about optional missing dependencies. */
  warnings: string[]
  /** Action items the user should complete before vaultkeeper will work. */
  nextSteps: string[]
}

/** JWE claim payload. @internal */
export interface VaultClaims {
  /** Unique token ID */
  jti: string
  /** Expiration (Unix timestamp) */
  exp: number
  /** Issued-at (Unix timestamp) */
  iat: number
  /** Secret reference path */
  sub: string
  /** Executable identity hash or "dev" */
  exe: string
  /** Usage limit (null for unlimited) */
  use: number | null
  /** Trust tier */
  tid: TrustTier
  /** Backend identifier hint */
  bkd: string
  /** Encrypted secret value */
  val: string
  /** Backend-specific reference path */
  ref: string
}

/** Response from a vault access operation. */
export interface VaultResponse {
  /** Replacement JWE if key was rotated */
  rotatedJwt?: string | undefined
  /** Current key status */
  keyStatus: KeyStatus
}

/**
 * Request for delegated HTTP fetch.
 *
 * String values in `url`, `headers`, and `body` may include the placeholder
 * `{{secret}}`, which is replaced with the actual secret value immediately
 * before the request is sent.
 */
export interface FetchRequest {
  /**
   * The target URL. May contain `{{secret}}` which is replaced with the secret
   * value before the fetch is executed (e.g. for API-key-in-URL patterns).
   */
  url: string
  /** HTTP method (defaults to `'GET'` when omitted). */
  method?: string | undefined
  /**
   * Request headers. Any header value may contain `{{secret}}`, which is
   * replaced with the secret value before the request is sent.
   */
  headers?: Record<string, string> | undefined
  /**
   * Request body. May contain `{{secret}}`, which is replaced with the secret
   * value before the request is sent.
   */
  body?: string | undefined
}

/**
 * Request for delegated command execution.
 *
 * String values in `args` and `env` may include the placeholder `{{secret}}`,
 * which is replaced with the actual secret value immediately before the command
 * is spawned.
 */
export interface ExecRequest {
  /** The command (binary) to execute. */
  command: string
  /**
   * Command-line arguments. Any argument may contain `{{secret}}`, which is
   * replaced with the secret value before the command is spawned.
   */
  args?: string[] | undefined
  /**
   * Additional environment variables to merge into the child process
   * environment. Any value may contain `{{secret}}`, which is replaced with
   * the secret value before the command is spawned.
   */
  env?: Record<string, string> | undefined
  /** Working directory for the spawned process. */
  cwd?: string | undefined
}

/** Result from delegated command execution. */
export interface ExecResult {
  /** Captured standard output from the process. */
  stdout: string
  /** Captured standard error from the process. */
  stderr: string
  /** Process exit code. */
  exitCode: number
}

/**
 * Callback-based secret accessor with auto-zeroing.
 *
 * The accessor is backed by a revocable Proxy. Calling `read()` passes a
 * `Buffer` containing the secret to the callback, then zeroes the buffer after
 * the callback returns. The accessor can only be read once; a second call
 * throws.
 */
export interface SecretAccessor {
  /**
   * Read the secret value via a callback.
   *
   * The `buf` argument is a temporary `Buffer` containing the secret encoded
   * as UTF-8. The buffer is zeroed immediately after the callback returns, so
   * callers must not store a reference to it beyond the callback scope.
   *
   * @param callback - Function that receives the secret buffer.
   * @throws {Error} If the accessor has already been consumed.
   */
  read(callback: (buf: Buffer) => void): void
}

/** Vaultkeeper configuration file structure. */
export interface VaultConfig {
  /** Config schema version. Currently must be `1`. */
  version: number
  /** Ordered list of backend configurations. The first enabled backend is used. */
  backends: BackendConfig[]
  /** Key rotation policy. */
  keyRotation: {
    /**
     * Number of days the previous key remains valid for decryption after a
     * rotation event.
     */
    gracePeriodDays: number
  }
  /** Default values applied to `setup()` when options are not explicitly provided. */
  defaults: {
    /** Default JWE time-to-live in minutes. */
    ttlMinutes: number
    /** Default trust tier for executable identity verification. */
    trustTier: TrustTier
  }
  /** Development mode configuration. When present, identity checks are relaxed for listed executables. */
  developmentMode?: {
    /** Paths of executables that bypass identity verification in development mode. */
    executables: string[]
  } | undefined
}

/** Configuration for a single backend. */
export interface BackendConfig {
  /** Backend type identifier (e.g. `'keychain'`, `'file'`, `'1password'`). */
  type: string
  /** Whether this backend is active. Only enabled backends are considered during initialization. */
  enabled: boolean
  /** Whether this backend is provided by an external plugin rather than built in. */
  plugin?: boolean | undefined
  /** Filesystem path used by file-based backends. */
  path?: string | undefined
}
