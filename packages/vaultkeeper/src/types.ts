/**
 * Shared types and interfaces for vaultkeeper.
 */

import type { Buffer } from 'node:buffer'

/** Trust tier for executable identity verification. */
export type TrustTier = 1 | 2 | 3

/** Key status in the rotation lifecycle. */
export type KeyStatus = 'current' | 'previous' | 'deprecated'

/**
 * Status of a preflight check.
 *
 * `'invalid'` applies specifically to the `config` check: the config file
 * exists but fails to parse or fails schema validation (see issue #68).
 */
export type PreflightCheckStatus = 'ok' | 'missing' | 'version-unsupported' | 'invalid'

/**
 * The kind of error that made a preflight check fail, as a stable
 * machine-readable discriminant. `'config-parse'` means the config file
 * could not be parsed as JSON; `'config-validation'` means it parsed but
 * failed schema validation; `'config-unknown-backend'` is a specific
 * validation failure where `backends[].type` names a backend that is not
 * registered, carrying the offending type and the valid options;
 * `'config-read'` means the config file could not be read at all (for example
 * a permission failure on the file or its parent directory) — a different
 * remediation from parse/validation, since overwriting the file with
 * `config init --force` cannot fix a read-permission problem.
 */
export type PreflightCheckErrorKind =
  | 'config-parse'
  | 'config-validation'
  | 'config-unknown-backend'
  | 'config-read'

/**
 * Structured, remediation-free error context for a failed preflight check.
 *
 * This carries the machine-readable facts a caller needs to build its own
 * audience-appropriate remediation message, so a consumer never has to parse
 * the human-readable `reason` prose. It is currently populated only for the
 * `config` check when the config file is present but invalid.
 *
 * The `reason` field intentionally keeps the library's own remediation text
 * (which points a library consumer at installing the CLI); a consumer that
 * ships its own CLI should read this structured field instead and phrase the
 * remediation itself.
 */
export interface PreflightCheckError {
  /** The kind of failure, as a stable machine-readable discriminant. */
  kind: PreflightCheckErrorKind
  /**
   * Path to the config file that failed to parse or validate, as derived from
   * the doctor call's `configDir`. Not guaranteed to be absolute — it is
   * `configDir` joined with `config.json` exactly as given, so it is relative
   * when `configDir` is relative.
   */
  configPath: string
  /**
   * Human-readable parse location within the config file (for example
   * `line 3, column 12`), present only for a `'config-parse'` failure.
   */
  location?: string | undefined
  /**
   * The dotted/bracketed path to the offending config field (for example
   * `backends` or `backends[0].path`), present for a `'config-validation'` or
   * `'config-unknown-backend'` failure. This is the validation analogue of
   * `location`: it lets a consumer point the user at exactly which field
   * failed schema validation, the way `location` points at a parse position,
   * without reusing the human-readable `reason` prose (which carries the
   * library's own "install @vaultkeeper/cli" remediation).
   */
  field?: string | undefined
  /**
   * The unregistered backend type named in `backends[].type`, present only for
   * a `'config-unknown-backend'` failure. Lets a consumer echo the offending
   * type in its remediation without parsing the `reason` prose.
   */
  backendType?: string | undefined
  /**
   * The backend type identifiers that were registered when validation ran —
   * the valid options — present only for a `'config-unknown-backend'` failure.
   * Lets a consumer offer the same "Available types: …" guidance the runtime
   * `BackendUnavailableError` gives.
   */
  knownBackendTypes?: readonly string[] | undefined
  /**
   * The Node.js errno code (for example `EACCES`, `EPERM`, `EISDIR`) from the
   * underlying filesystem failure, present only for a `'config-read'` failure
   * and only when the cause exposed a string errno code. Lets a consumer
   * distinguish a permission problem from another read failure when phrasing
   * the remediation.
   */
  code?: string | undefined
}

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
  /**
   * Structured, remediation-free error context when this check failed with a
   * recognized error, so a caller can build its own remediation message
   * instead of parsing the `reason` prose. Populated only for the `config`
   * check when the config file is present but invalid.
   */
  error?: PreflightCheckError | undefined
}

/**
 * A {@link PreflightCheck} scoped by whether its dependency is required for
 * the active/configured backend(s). Plugin-backend checks (`op`, `ykman`)
 * are `required: false` when their backend isn't enabled — a non-`'ok'`
 * status there is informational, not a system-readiness blocker (issue
 * #116). They are promoted to `required: true` when their backend is
 * explicitly enabled (e.g. `--backend yubikey` requires `ykman`).
 */
export interface ScopedPreflightCheck extends PreflightCheck {
  /** Whether this dependency is required by the active/configured backend(s). */
  required: boolean
}

/** Aggregated result from all preflight checks. */
export interface PreflightResult {
  /** Individual check results, one per dependency inspected. */
  checks: ScopedPreflightCheck[]
  /** `true` if all required checks passed and the system is ready. */
  ready: boolean
  /** Non-fatal advisory messages about optional missing dependencies. */
  warnings: string[]
  /** Action items the user should complete before vaultkeeper will work. */
  nextSteps: string[]
}

/**
 * Discriminates a {@link VaultClaims} payload's kind: an ordinary secret claim
 * (the default, used when `kty` is omitted — for backward compatibility with
 * tokens minted before this discriminator existed) or a session signing-key
 * lease, which carries no secret value.
 * @internal
 */
export type ClaimsKind = 'secret' | 'signing-key'

/**
 * A signing lease's most recent presence-per-use action, if the backend
 * enforces one. Informational only — not validated by `validateClaims`.
 * @internal
 */
export interface LeasePresence {
  /** The operation the presence action covered (e.g. `'sign'`). */
  op: string
  /** Unix timestamp (seconds) the presence action was recorded. */
  at: number
  /** The presence mechanism used (e.g. `'touch'`). */
  method: string
  /** The backend type that enforced the presence action. */
  backend: string
}

/**
 * JWE claim payload.
 *
 * A claim payload is one of two kinds, discriminated by {@link VaultClaims.kty}:
 * an ordinary **secret** claim (`kty` omitted or `'secret'`), which requires a
 * non-empty {@link VaultClaims.bkd} and {@link VaultClaims.val}; or a session
 * **signing-key lease** (`kty: 'signing-key'`), which carries no secret value
 * at all and instead requires {@link VaultClaims.kid} and
 * {@link VaultClaims.kgen}. See `validateClaims` for the exact rules.
 * @internal
 */
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
  /**
   * Backend identifier hint. Required (non-empty) for a secret claim; absent
   * for a signing-key lease.
   */
  bkd?: string | undefined
  /**
   * Encrypted secret value. Required (non-empty) for a secret claim; MUST be
   * absent (or empty) for a signing-key lease — a lease carrying a `val` is
   * rejected outright.
   */
  val?: string | undefined
  /** Backend-specific reference path */
  ref: string
  /**
   * Discriminates a secret claim (default, when omitted) from a session
   * signing-key lease.
   */
  kty?: ClaimsKind | undefined
  /**
   * The leased signing key's stable identifier (see
   * {@link SigningPublicKey.kid}). Required (non-empty) for a signing-key
   * lease.
   */
  kid?: string | undefined
  /**
   * The signing key's generation at lease-mint time. Required for a
   * signing-key lease — a lease missing `kgen` is rejected rather than
   * defaulted to generation 0, since the revocation design depends on this
   * being an explicit, honest claim.
   */
  kgen?: number | undefined
  /** The lease's most recent presence-per-use action, if any. */
  pres?: LeasePresence | undefined
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
 * `{{secret}}` (single-token mode) or `{{secret:name}}` (multi-token mode),
 * which are replaced with actual secret values immediately before the request
 * is sent.
 */
export interface FetchRequest {
  /**
   * The target URL. May contain `{{secret}}` or `{{secret:name}}` which is
   * replaced with the secret value before the fetch is executed.
   */
  url: string
  /** HTTP method (defaults to `'GET'` when omitted). */
  method?: string | undefined
  /**
   * Request headers. Any header value may contain `{{secret}}` or
   * `{{secret:name}}`, which is replaced with the secret value before
   * the request is sent.
   */
  headers?: Record<string, string> | undefined
  /**
   * Request body. May contain `{{secret}}` or `{{secret:name}}`, which is
   * replaced with the secret value before the request is sent.
   */
  body?: string | undefined
}

/**
 * Request for delegated command execution.
 *
 * String values in `env` may include the placeholder `{{secret}}`
 * (single-token mode) or `{{secret:name}}` (multi-token mode), which are
 * replaced with actual secret values immediately before the command is
 * spawned. Placeholders are **not** supported in `command` or `args` —
 * `VaultKeeper.exec()` throws `ExecError` if one appears there.
 */
export interface ExecRequest {
  /** The command (binary) to execute. */
  command: string
  /**
   * Command-line arguments. Secret placeholders (`{{secret}}` or
   * `{{secret:name}}`) are **not** supported here — process arguments are
   * visible to other processes via `ps` and often collected in logs and
   * telemetry. `VaultKeeper.exec()` throws `ExecError` if a placeholder
   * appears in any argument. Use `env` to inject secrets instead.
   */
  args?: string[] | undefined
  /**
   * Additional environment variables to merge into the child process
   * environment. Any value may contain `{{secret}}` or `{{secret:name}}`,
   * which is replaced with the secret value before the command is spawned.
   */
  env?: Record<string, string> | undefined
  /** Working directory for the spawned process. */
  cwd?: string | undefined
  /**
   * Whether to redact injected secret values from the captured `stdout` and
   * `stderr` before they are returned. Defaults to `true`: every occurrence of
   * an injected secret value in the captured output is replaced with
   * `[REDACTED]`, so the raw secret never appears in {@link ExecResult} even
   * when the spawned command echoes it. Set to `false` to receive the raw,
   * unredacted output — only for callers that genuinely need it (for example
   * output that legitimately contains the secret and must be preserved), since
   * doing so forfeits the redaction guarantee.
   */
  redact?: boolean | undefined
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
 * The accessor is backed by a Proxy and is single-use via an internal
 * consumed flag. Calling `read()` passes a `Buffer` containing the secret to
 * the callback, then zeroes the buffer after the callback returns and passes
 * the callback's return value through. The accessor can only be read once; a
 * second call throws.
 */
export interface SecretAccessor {
  /**
   * Read the secret value via a callback.
   *
   * The `buf` argument is a temporary `Buffer` containing the secret encoded
   * as UTF-8. The buffer is zeroed immediately after the callback returns, so
   * callers must not store a reference to it beyond the callback scope.
   *
   * The callback's return value is passed through, so a caller-derived result
   * (for example `buf.toString()` or a hash) flows out of `read()`:
   * `const digest = accessor.read((buf) => sha256(buf))`. To preserve the
   * zero-copy, auto-zeroing contract, derive a new value inside the callback —
   * never return the raw `buf` itself, which is zeroed before `read()` returns.
   *
   * @param callback - Function that receives the secret buffer and returns a
   *   caller-derived value.
   * @returns Whatever the callback returns.
   * @throws {Error} If the accessor has already been consumed.
   */
  read<T>(callback: (buf: Buffer) => T): T
}

/**
 * A signing algorithm identifier from the strict JOSE registry (RFC 7518).
 *
 * Only `'EdDSA'` (Ed25519) is supported today; the identifier is intentionally
 * a strict JOSE `alg` value so future algorithms (`'ES256'`, `'RS256'`, …) each
 * bind to their proper curve/key type rather than an ambiguous label.
 */
export type SigningAlgorithm = 'EdDSA'

/**
 * The public half of an enrolled signing key.
 *
 * Returned by `key create` / `key export` and used to verify detached
 * signatures independently of vaultkeeper.
 */
export interface SigningPublicKey {
  /** SPKI (SubjectPublicKeyInfo) PEM encoding of the public key. */
  publicKeyPem: string
  /** The JOSE algorithm this key signs with. */
  algorithm: SigningAlgorithm
  /**
   * Stable key identifier: the base64url-encoded SHA-256 of the SPKI DER. Used
   * as the JWS `kid` protected-header value so a verifier can select the key.
   */
  kid: string
}

/**
 * Request to sign a caller-supplied payload with a named signing key.
 *
 * The `payload` is arbitrary bytes to be signed with detachment (RFC 7797) —
 * it is never stored and never treated as a secret. Strings are UTF-8-encoded
 * before signing.
 */
export interface SignRequest {
  /** The payload bytes to sign. Strings are treated as UTF-8. */
  payload: string | Buffer
}

/**
 * Result of a signing operation.
 *
 * The signature is a detached-payload Compact JWS (RFC 7515 §7.2.2 + RFC 7797
 * `b64:false`, `crit:["b64"]`): `<protected>..<signature>`, with the payload
 * omitted. Any standards-compliant JOSE library can verify it given the
 * detached payload and the public key.
 */
export interface SignResult {
  /** The detached-payload compact JWS (`<protected>..<signature>`). */
  jws: string
}

/**
 * Request for detached-signature verification.
 *
 * This is a fully offline operation that only requires public key material —
 * no VaultKeeper instance, backend, config, or capability token is needed.
 */
export interface VerifyRequest {
  /** The detached payload bytes that were signed. Strings are treated as UTF-8. */
  payload: string | Buffer
  /**
   * The detached-payload compact JWS produced by {@link SignResult.jws}
   * (`<protected>..<signature>`).
   */
  jws: string
  /**
   * PEM-encoded public key (SPKI format) as a string.
   *
   * Other `KeyLike` formats supported by `crypto.createPublicKey()` are not
   * accepted by this interface.
   */
  publicKey: string
}

/**
 * Claims backing a signing-key capability token.
 *
 * @remarks
 * A signing-key token carries only the references needed to ask the backend to
 * sign — never any private key material. The `keyType` discriminator lets
 * secret-access paths (`getSecret`/`fetch`/`exec`) reject a signing-key token
 * outright, and lets `sign` reject an ordinary secret token.
 *
 * @internal
 */
export interface SigningClaims {
  /** Discriminator marking this as a signing-key capability, not a secret. */
  keyType: 'signing-key'
  /** The signing key's stable identifier (see {@link SigningPublicKey.kid}). */
  kid: string
  /** The backend key identifier used to invoke `signWithKey` (never the key). */
  backendRef: string
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
  developmentMode?:
    | {
        /** Paths of executables that bypass identity verification in development mode. */
        executables: string[]
      }
    | undefined
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
  /** Backend-specific options collected during interactive setup. */
  options?: Record<string, string> | undefined
}
