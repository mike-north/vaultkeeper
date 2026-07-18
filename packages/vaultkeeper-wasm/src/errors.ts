/**
 * Error hierarchy for the WASM SDK.
 *
 * Mirrors the `VaultError` hierarchy of the pure-TypeScript `vaultkeeper`
 * library so that consumers of `@vaultkeeper/wasm` can rely on the same
 * ecosystem-wide contract: every *operational* error thrown by the SDK is an
 * instance of {@link VaultError}.
 *
 * One deliberate exception: passing a wrongly-typed argument (e.g. a
 * non-string secret name) throws a built-in `TypeError` — Node's own
 * convention for programmer errors — rather than a `VaultError` subclass.
 * `authorize()` is the special case that throws `InvalidTokenError` for a
 * non-string token, since a malformed token is an operational condition its
 * callers already handle. A `catch (e) { if (e instanceof VaultError) ... }`
 * handler therefore covers every runtime failure, but not caller-side type
 * mistakes, which indicate a bug to fix rather than a condition to handle.
 *
 * The Rust/WASM core throws values tagged with a stable `vaultErrorCode`;
 * {@link mapWasmError} reconstructs the matching typed instance at the bridge
 * boundary.
 */

/** Base error for all `@vaultkeeper/wasm` errors. */
export class VaultError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'VaultError'
  }
}

/** Thrown when a requested secret does not exist in the backend store. */
export class SecretNotFoundError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'SecretNotFoundError'
  }
}

/**
 * Thrown when a stored secret entry cannot be decrypted — the ciphertext is
 * corrupted/truncated or the AES-GCM authentication tag failed to verify.
 * Mirrors the pure-TypeScript `vaultkeeper` library's `DecryptionError`.
 */
export class DecryptionError extends VaultError {
  /**
   * The path of the encrypted entry that failed to decrypt. `undefined` only
   * if the WASM boundary did not supply one — this is never fabricated as an
   * empty string, so its absence is distinguishable from a genuine path.
   */
  readonly path?: string

  constructor(message: string, path?: string) {
    super(message)
    this.name = 'DecryptionError'
    if (path !== undefined) {
      this.path = path
    }
  }
}

/**
 * Thrown when a filesystem operation fails while reading, writing, or
 * deleting a stored secret entry. Common causes include a permission or
 * access problem, but the underlying failure may be any OS errno condition —
 * inspect {@link FilesystemError.code} for the specific errno when one is
 * available. Mirrors the pure-TypeScript `vaultkeeper` library's
 * `FilesystemError` field names (`path`, `permission`, `code`).
 */
export class FilesystemError extends VaultError {
  /**
   * The path that caused the error. In practice the Rust core always
   * supplies this for `VaultError::Filesystem`, so `undefined` only occurs
   * if a malformed boundary shape omitted it — never fabricated as an empty
   * string, so its absence is distinguishable from a genuine path.
   */
  readonly path?: string

  /**
   * The file operation that was being attempted, e.g. `'read'` or `'write'`
   * — the WASM host bridge reports a delete as `'write'`, mirroring the
   * native CLI host's classification (crates/vaultkeeper-cli/src/host.rs).
   * Despite the field name, this does not imply the failure was itself a
   * permission problem: it names the attempted operation regardless of the
   * underlying errno, which may be a non-permission code. As with `path`,
   * this is always populated by the real core; `undefined` only guards a
   * malformed boundary shape.
   */
  readonly permission?: string

  /**
   * The underlying OS errno code (e.g. `'ENOENT'`, `'EACCES'`), when the
   * Node host bridge was able to supply one. `undefined` when no code was
   * available — never fabricated.
   */
  readonly code: string | undefined

  constructor(
    message: string,
    path: string | undefined,
    permission: string | undefined,
    code: string | undefined,
  ) {
    super(message)
    this.name = 'FilesystemError'
    if (path !== undefined) {
      this.path = path
    }
    if (permission !== undefined) {
      this.permission = permission
    }
    this.code = code
  }
}

/**
 * Thrown when a JWE string is invalid or cannot be processed — structurally
 * malformed, decryption failure (wrong key, tampered ciphertext), or a
 * decrypted payload that does not match the expected claims schema.
 */
export class InvalidTokenError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'InvalidTokenError'
  }
}

/** Thrown when a JWE token has passed its expiration time (`exp` claim). */
export class TokenExpiredError extends VaultError {
  /**
   * Whether the token can be refreshed by calling `setup()` again. When
   * `true`, the secret still exists in the backend and a new token can be
   * issued.
   */
  readonly canRefresh: boolean

  constructor(message: string, canRefresh: boolean) {
    super(message)
    this.name = 'TokenExpiredError'
    this.canRefresh = canRefresh
  }
}

/**
 * Thrown when the encryption key used to create a JWE has been rotated out of
 * the grace period and can no longer be used for decryption.
 */
export class KeyRotatedError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'KeyRotatedError'
  }
}

/**
 * Thrown when the backend keychain or credential store is locked and requires
 * user interaction (e.g. biometric prompt or password entry) before access can
 * be granted. Mirrors the pure-TypeScript `vaultkeeper` library's
 * `BackendLockedError`.
 */
export class BackendLockedError extends VaultError {
  /**
   * Whether the lock can be resolved through an interactive user prompt.
   * `false` only if the WASM boundary did not supply a value — never
   * fabricated as `true`.
   */
  readonly interactive: boolean

  constructor(message: string, interactive: boolean) {
    super(message)
    this.name = 'BackendLockedError'
    this.interactive = interactive
  }
}

/**
 * Thrown when a hardware device (e.g. YubiKey or smart card) required for
 * authentication is not currently connected. Mirrors the pure-TypeScript
 * `vaultkeeper` library's `DeviceNotPresentError`.
 */
export class DeviceNotPresentError extends VaultError {
  /**
   * How long (in milliseconds) the operation waited for the device before
   * giving up. `0` only if the WASM boundary did not supply a value — never
   * fabricated.
   */
  readonly timeoutMs: number

  constructor(message: string, timeoutMs: number) {
    super(message)
    this.name = 'DeviceNotPresentError'
    this.timeoutMs = timeoutMs
  }
}

/**
 * Thrown when the user explicitly denies an authorization request for a
 * secret access operation. Mirrors the pure-TypeScript `vaultkeeper`
 * library's `AuthorizationDeniedError`.
 */
export class AuthorizationDeniedError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'AuthorizationDeniedError'
  }
}

/**
 * Thrown when an operation requires a backend capability (e.g.
 * presence-per-use) that the active backend cannot provide. Mirrors the
 * pure-TypeScript `vaultkeeper` library's `NotCapableError`.
 */
export class NotCapableError extends VaultError {
  /**
   * The `type` identifier of the active backend that lacked the capability.
   * `undefined` only if the WASM boundary did not supply one — never
   * fabricated.
   */
  readonly backendType?: string

  /**
   * The machine-readable capability key that was required but not
   * advertised. `undefined` only if the WASM boundary did not supply one —
   * never fabricated.
   */
  readonly capability?: string

  constructor(message: string, backendType?: string, capability?: string) {
    super(message)
    this.name = 'NotCapableError'
    if (backendType !== undefined) {
      this.backendType = backendType
    }
    if (capability !== undefined) {
      this.capability = capability
    }
  }
}

/**
 * Thrown when a required fresh, per-use human presence action was explicitly
 * declined by the human. Mirrors the pure-TypeScript `vaultkeeper` library's
 * `PresenceDeclinedError`.
 */
export class PresenceDeclinedError extends VaultError {
  /**
   * The `type` identifier of the backend that requested the presence action.
   * `undefined` only if the WASM boundary did not supply one — never
   * fabricated.
   */
  readonly backendType?: string

  constructor(message: string, backendType?: string) {
    super(message)
    this.name = 'PresenceDeclinedError'
    if (backendType !== undefined) {
      this.backendType = backendType
    }
  }
}

/**
 * Thrown when a required fresh, per-use human presence action did not happen
 * within the allotted time. Mirrors the pure-TypeScript `vaultkeeper`
 * library's `PresenceTimeoutError`.
 */
export class PresenceTimeoutError extends VaultError {
  /**
   * The `type` identifier of the backend that requested the presence action.
   * `undefined` only if the WASM boundary did not supply one — never
   * fabricated.
   */
  readonly backendType?: string

  /**
   * How long (in milliseconds) the operation waited for the presence action.
   * `0` only if the WASM boundary did not supply a value — never fabricated.
   */
  readonly timeoutMs: number

  constructor(message: string, backendType: string | undefined, timeoutMs: number) {
    super(message)
    this.name = 'PresenceTimeoutError'
    if (backendType !== undefined) {
      this.backendType = backendType
    }
    this.timeoutMs = timeoutMs
  }
}

/**
 * Thrown when no configured backend is available or reachable. Mirrors the
 * pure-TypeScript `vaultkeeper` library's `BackendUnavailableError`.
 */
export class BackendUnavailableError extends VaultError {
  /**
   * Machine-readable reason code describing why the backend is unavailable
   * (e.g. `'none-enabled'`, `'all-failed'`). `undefined` only if the WASM
   * boundary did not supply one — never fabricated.
   */
  readonly reason?: string

  /**
   * The backend type identifiers that were attempted before this error was
   * thrown. `[]` only if the WASM boundary did not supply a value — never
   * fabricated as a false claim that a specific backend was attempted.
   */
  readonly attempted: string[]

  constructor(message: string, reason: string | undefined, attempted: string[]) {
    super(message)
    this.name = 'BackendUnavailableError'
    if (reason !== undefined) {
      this.reason = reason
    }
    this.attempted = attempted
  }
}

/**
 * Thrown when a required backend plugin is not installed on the current
 * system. Mirrors the pure-TypeScript `vaultkeeper` library's
 * `PluginNotFoundError`.
 */
export class PluginNotFoundError extends VaultError {
  /**
   * The plugin package or binary name that was not found. `undefined` only
   * if the WASM boundary did not supply one — never fabricated.
   */
  readonly plugin?: string

  /**
   * A URL pointing to installation instructions for the missing plugin.
   * `undefined` only if the WASM boundary did not supply one — never
   * fabricated.
   */
  readonly installUrl?: string

  constructor(message: string, plugin?: string, installUrl?: string) {
    super(message)
    this.name = 'PluginNotFoundError'
    if (plugin !== undefined) {
      this.plugin = plugin
    }
    if (installUrl !== undefined) {
      this.installUrl = installUrl
    }
  }
}

/**
 * Thrown when the encryption key referenced by a JWE's `kid` header has been
 * explicitly revoked and is no longer available for decryption.
 */
export class KeyRevokedError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'KeyRevokedError'
  }
}

/**
 * Thrown when a JWE token has been explicitly blocked (e.g. after a single-use
 * token has already been consumed).
 */
export class TokenRevokedError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'TokenRevokedError'
  }
}

/**
 * Thrown when a token with a finite `use` limit has been presented more times
 * than the limit allows.
 */
export class UsageLimitExceededError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'UsageLimitExceededError'
  }
}

/**
 * Thrown when a key rotation is requested while a previous rotation is still
 * within its grace period (i.e. the previous key has not yet been retired).
 */
export class RotationInProgressError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'RotationInProgressError'
  }
}

/**
 * Thrown when a one-time secret accessor's `read()` is called after the
 * secret has already been consumed.
 */
export class AccessorConsumedError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'AccessorConsumedError'
  }
}

/**
 * Machine-readable discriminator for why an executable-trust choice was
 * rejected by `setup()`. `'missing-choice'` means neither `executablePath` nor
 * `skipTrust: true` was provided (an empty/whitespace `executablePath` counts
 * as missing). `'conflicting-choice'` means both were provided, which are
 * mutually exclusive intents. `'legacy-dev-sentinel'` means `executablePath`
 * was the retired literal `'dev'` opt-out sentinel, which is no longer
 * supported and must be replaced with `skipTrust: true`.
 */
export type ExecutableTrustRequiredReason =
  | 'missing-choice'
  | 'conflicting-choice'
  | 'legacy-dev-sentinel'

/**
 * Thrown by `setup()` when the caller does not make an unambiguous
 * executable-trust decision.
 *
 * Mirrors the pure-TypeScript `vaultkeeper` library's
 * `ExecutableTrustRequiredError`: `setup()` deliberately has no default trust
 * behaviour, so the caller must pass either a real `executablePath` or
 * explicitly opt out with `skipTrust: true`. Supplying neither — or both — or
 * the retired `'dev'` sentinel as `executablePath` throws this error rather
 * than silently minting an unbound token. Inspect
 * {@link ExecutableTrustRequiredError.reason} to distinguish the cases.
 */
export class ExecutableTrustRequiredError extends VaultError {
  /** Machine-readable discriminator; see {@link ExecutableTrustRequiredReason}. */
  readonly reason: ExecutableTrustRequiredReason

  constructor(message: string, reason: ExecutableTrustRequiredReason) {
    super(message)
    this.name = 'ExecutableTrustRequiredError'
    this.reason = reason
  }
}

/**
 * Thrown by `setup()` when the executable at `executablePath` has a hash that
 * conflicts with a value previously approved for it under trust-on-first-use.
 *
 * Mirrors the pure-TypeScript `vaultkeeper` library's `IdentityMismatchError`:
 * the first encounter with an executable records its hash, and a later hash
 * change (a rebuilt or substituted binary) surfaces here rather than silently
 * re-approving. Re-approval is required before the executable can be bound
 * again. Inspect {@link IdentityMismatchError.previousHash} and
 * {@link IdentityMismatchError.currentHash} to see what changed.
 */
export class IdentityMismatchError extends VaultError {
  /**
   * The hash recorded at approval time (most-recently approved value).
   * `undefined` only if the WASM boundary did not supply one — never
   * fabricated, so its absence is distinguishable from a genuine hash.
   */
  readonly previousHash?: string

  /**
   * The hash computed from the current executable. `undefined` only if the
   * WASM boundary did not supply one — never fabricated.
   */
  readonly currentHash?: string

  constructor(message: string, previousHash?: string, currentHash?: string) {
    super(message)
    this.name = 'IdentityMismatchError'
    if (previousHash !== undefined) {
      this.previousHash = previousHash
    }
    if (currentHash !== undefined) {
      this.currentHash = currentHash
    }
  }
}

/**
 * Thrown when spawning or running a subprocess fails. Mirrors the
 * pure-TypeScript `vaultkeeper` library's `ExecError`.
 */
export class ExecError extends VaultError {
  /**
   * The command that failed to execute. `undefined` only if the WASM
   * boundary did not supply one — never fabricated.
   */
  readonly command?: string

  constructor(message: string, command?: string) {
    super(message)
    this.name = 'ExecError'
    if (command !== undefined) {
      this.command = command
    }
  }
}

/**
 * Thrown when a caller requests a signing key algorithm that is not a
 * supported JOSE algorithm identifier. Mirrors the pure-TypeScript
 * `vaultkeeper` library's `InvalidAlgorithmError`.
 */
export class InvalidAlgorithmError extends VaultError {
  /**
   * The algorithm that was requested. `undefined` only if the WASM boundary
   * did not supply one — never fabricated.
   */
  readonly algorithm?: string

  /**
   * The set of algorithms that are allowed. `[]` only if the WASM boundary
   * did not supply a value — never fabricated.
   */
  readonly allowed: string[]

  constructor(message: string, algorithm: string | undefined, allowed: string[]) {
    super(message)
    this.name = 'InvalidAlgorithmError'
    if (algorithm !== undefined) {
      this.algorithm = algorithm
    }
    this.allowed = allowed
  }
}

/**
 * Thrown when signing-key material cannot be parsed — corrupt or tampered key
 * material, or a structurally invalid public key supplied for verification.
 * Mirrors the pure-TypeScript `vaultkeeper` library's `InvalidKeyMaterialError`.
 */
export class InvalidKeyMaterialError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'InvalidKeyMaterialError'
  }
}

/**
 * Thrown when a named signing key does not exist in the active backend.
 * Mirrors the pure-TypeScript `vaultkeeper` library's `SigningKeyNotFoundError`.
 */
export class SigningKeyNotFoundError extends VaultError {
  /**
   * The signing-key name that was requested. `undefined` only if the WASM
   * boundary did not supply one — never fabricated.
   */
  readonly keyName?: string

  constructor(message: string, keyName?: string) {
    super(message)
    this.name = 'SigningKeyNotFoundError'
    if (keyName !== undefined) {
      this.keyName = keyName
    }
  }
}

/**
 * Thrown when a signing key enrollment is attempted under a name that already
 * exists. Mirrors the pure-TypeScript `vaultkeeper` library's
 * `SigningKeyAlreadyExistsError`.
 */
export class SigningKeyAlreadyExistsError extends VaultError {
  /**
   * The signing-key name that already exists. `undefined` only if the WASM
   * boundary did not supply one — never fabricated.
   */
  readonly keyName?: string

  constructor(message: string, keyName?: string) {
    super(message)
    this.name = 'SigningKeyAlreadyExistsError'
    if (keyName !== undefined) {
      this.keyName = keyName
    }
  }
}

/**
 * Thrown when a signing operation is requested against a backend that does
 * not implement the signing contract. Mirrors the pure-TypeScript
 * `vaultkeeper` library's `SigningNotSupportedError`.
 */
export class SigningNotSupportedError extends VaultError {
  /**
   * The type identifier of the active backend that cannot sign. `undefined`
   * only if the WASM boundary did not supply one — never fabricated.
   */
  readonly backendType?: string

  /**
   * The built-in backend type identifiers known to implement the signing
   * contract. `[]` only if the WASM boundary did not supply a value — never
   * fabricated.
   */
  readonly builtInSigningBackends: string[]

  constructor(message: string, backendType: string | undefined, builtInSigningBackends: string[]) {
    super(message)
    this.name = 'SigningNotSupportedError'
    if (backendType !== undefined) {
      this.backendType = backendType
    }
    this.builtInSigningBackends = builtInSigningBackends
  }
}

/**
 * Thrown when a delegated `fetch()` call fails before a `Response` can be
 * produced. Mirrors the pure-TypeScript `vaultkeeper` library's `FetchError`.
 */
export class FetchError extends VaultError {
  /**
   * The unresolved URL template that fetch failed to request, with
   * `{{secret}}`/`{{secret:name}}` placeholders left intact. `undefined`
   * only if the WASM boundary did not supply one — never fabricated.
   */
  readonly url?: string

  constructor(message: string, url?: string) {
    super(message)
    this.name = 'FetchError'
    if (url !== undefined) {
      this.url = url
    }
  }
}

/**
 * Thrown when a config value fails structural or semantic validation.
 * Mirrors the pure-TypeScript `vaultkeeper` library's `ConfigValidationError`.
 */
export class ConfigValidationError extends VaultError {
  /**
   * The dotted/bracketed path to the offending config field. `undefined`
   * only if the WASM boundary did not supply one — never fabricated.
   */
  readonly field?: string

  /**
   * The path of the config file that failed validation, when the error
   * originated from loading a file on disk rather than validating an
   * in-memory value directly.
   */
  readonly configFilePath?: string

  constructor(message: string, field?: string, configFilePath?: string) {
    super(message)
    this.name = 'ConfigValidationError'
    if (field !== undefined) {
      this.field = field
    }
    if (configFilePath !== undefined) {
      this.configFilePath = configFilePath
    }
  }
}

/**
 * Thrown when a config's `backends[].type` names a backend that is not
 * registered. A specialization of {@link ConfigValidationError}. Mirrors the
 * pure-TypeScript `vaultkeeper` library's `UnknownBackendTypeError`.
 */
export class UnknownBackendTypeError extends ConfigValidationError {
  /**
   * The unregistered backend type named in the config. `undefined` only if
   * the WASM boundary did not supply one — never fabricated.
   */
  readonly backendType?: string

  /**
   * The backend type identifiers that were registered when validation ran.
   * `[]` only if the WASM boundary did not supply a value — never fabricated.
   */
  readonly knownTypes: string[]

  constructor(
    message: string,
    field: string | undefined,
    backendType: string | undefined,
    knownTypes: string[],
    configFilePath?: string,
  ) {
    super(message, field, configFilePath)
    this.name = 'UnknownBackendTypeError'
    if (backendType !== undefined) {
      this.backendType = backendType
    }
    this.knownTypes = knownTypes
  }
}

/**
 * Thrown when a config file's contents cannot be parsed as JSON. Mirrors the
 * pure-TypeScript `vaultkeeper` library's `ConfigParseError`.
 */
export class ConfigParseError extends VaultError {
  /**
   * The path of the config file that failed to parse. `undefined` only if
   * the WASM boundary did not supply one — never fabricated.
   */
  readonly path?: string

  /**
   * A human-readable parse location (e.g. `'line 3, column 12'`), derived
   * from the boundary's raw `line`/`column` numbers when both are present.
   */
  readonly location?: string

  constructor(message: string, path?: string, location?: string) {
    super(message)
    this.name = 'ConfigParseError'
    if (path !== undefined) {
      this.path = path
    }
    if (location !== undefined) {
      this.location = location
    }
  }
}

/**
 * Thrown during initialization when a required system dependency is missing
 * or incompatible. Mirrors the pure-TypeScript `vaultkeeper` library's
 * `SetupError`.
 */
export class SetupError extends VaultError {
  /**
   * The name of the dependency that caused the setup failure. `undefined`
   * only if the WASM boundary did not supply one — never fabricated.
   */
  readonly dependency?: string

  constructor(message: string, dependency?: string) {
    super(message)
    this.name = 'SetupError'
    if (dependency !== undefined) {
      this.dependency = dependency
    }
  }
}

/**
 * Canonical list of every machine-readable `vaultErrorCode` the TypeScript
 * reconstruction map ({@link mapWasmError}) knows how to turn into a
 * dedicated typed subclass, plus the generic `'vault-error'` fallback that
 * deliberately stays the base {@link VaultError} class.
 *
 * This is the TypeScript half of the error-taxonomy single source of truth
 * (issue #236): `packages/vaultkeeper-wasm/src/test/error-parity.test.ts`
 * fetches the Rust-side `ALL_ERROR_CODES` from the compiled WASM binary (via
 * the exported `allVaultErrorCodes()`) and asserts it equals this list
 * exactly, sorted — catching drift between the two languages in either
 * direction.
 */
export const ALL_VAULT_ERROR_CODES = [
  'secret-not-found',
  'decryption',
  'token-expired',
  'key-rotated',
  'key-revoked',
  'token-revoked',
  'usage-limit-exceeded',
  'rotation-in-progress',
  'backend-locked',
  'device-not-present',
  'authorization-denied',
  'backend-unavailable',
  'plugin-not-found',
  'identity-mismatch',
  'executable-trust-required',
  'invalid-algorithm',
  'setup',
  'filesystem',
  'not-capable',
  'presence-declined',
  'presence-timeout',
  'invalid-key-material',
  'signing-key-not-found',
  'signing-key-already-exists',
  'signing-not-supported',
  'exec',
  'fetch',
  'invalid-token',
  'accessor-consumed',
  'config-validation',
  'unknown-backend-type',
  'config-parse',
  'vault-error',
] as const

/** Shape of the tagged error value thrown across the WASM boundary. */
interface WasmErrorShape {
  vaultErrorCode: string
  message: string
  // Only `vaultErrorCode` and `message` are validated by isWasmErrorShape;
  // the rest are typed `unknown` so consumers are forced to narrow through
  // optionalString/optionalBoolean/optionalNumber/optionalStringArray instead
  // of trusting a malformed boundary value to honor the field types.
  canRefresh?: unknown
  path?: unknown
  reason?: unknown
  permission?: unknown
  code?: unknown
  previousHash?: unknown
  currentHash?: unknown
  interactive?: unknown
  timeoutMs?: unknown
  backendType?: unknown
  capability?: unknown
  attempted?: unknown
  plugin?: unknown
  installUrl?: unknown
  command?: unknown
  algorithm?: unknown
  allowed?: unknown
  keyName?: unknown
  builtInSigningBackends?: unknown
  url?: unknown
  field?: unknown
  configFilePath?: unknown
  knownTypes?: unknown
  line?: unknown
  column?: unknown
  dependency?: unknown
}

/**
 * Narrow an unvalidated boundary field to `string | undefined` — non-string
 * values (including `null`) become `undefined`, never a fabricated string,
 * so the typed errors' documented `string | undefined` contracts hold even
 * for malformed boundary shapes.
 */
function optionalString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined
}

/** Boolean analogue of {@link optionalString}: non-booleans become `undefined`. */
function optionalBoolean(value: unknown): boolean | undefined {
  return typeof value === 'boolean' ? value : undefined
}

/** Numeric analogue of {@link optionalString}: non-numbers become `undefined`. */
/**
 * Numeric analogue of {@link optionalString}. Rejects `NaN`, `Infinity`,
 * `-Infinity`, and non-integer values (via `Number.isSafeInteger`) in
 * addition to non-numbers — every current use (`timeoutMs`, `line`,
 * `column`) is inherently an integer count, so a non-finite or fractional
 * value is exactly as untrustworthy as a non-number and must fall back to
 * `undefined` the same way, rather than leaking `NaN`/`Infinity` into a typed
 * field or into a formatted string like {@link toConfigParseLocation}'s
 * output (e.g. `'line NaN, column 12'`).
 */
function optionalNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isSafeInteger(value) ? value : undefined
}

/**
 * Array analogue of {@link optionalString} for `string[]` context fields
 * (e.g. `attempted`, `allowed`, `knownTypes`): anything that isn't an array of
 * strings becomes `undefined` — never a fabricated array, and never an array
 * containing non-string elements that would violate the field's `string[]`
 * contract.
 *
 * Iterates with `for...of` rather than `Array#every`: `every` skips sparse
 * holes (e.g. `new Array(2)` has no assigned indices), so it would vacuously
 * accept a hole-filled array as `string[]` even though reading a hole later
 * yields `undefined`, not a string. `for...of` visits holes as `undefined`,
 * so they are correctly rejected here.
 */
function optionalStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined
  const result: string[] = []
  for (const item of value) {
    if (typeof item !== 'string') return undefined
    result.push(item)
  }
  return result
}

/**
 * Build a human-readable parse location from the WASM boundary's raw `line`
 * and `column` numbers, mirroring the pure-TypeScript `vaultkeeper` library's
 * `ConfigParseError.location` format. `undefined` unless both are present —
 * a partial location is not fabricated into a misleading string.
 */
function toConfigParseLocation(line: unknown, column: unknown): string | undefined {
  const l = optionalNumber(line)
  const c = optionalNumber(column)
  return l !== undefined && c !== undefined ? `line ${String(l)}, column ${String(c)}` : undefined
}

function isWasmErrorShape(value: unknown): value is WasmErrorShape {
  if (typeof value !== 'object' || value === null) return false
  const record: Record<string, unknown> = { ...value }
  return typeof record.vaultErrorCode === 'string' && typeof record.message === 'string'
}

/**
 * Narrow the raw `reason` string from the WASM boundary to the known union.
 * Falls back to `'missing-choice'` for any unrecognized value so the typed
 * error is always constructible.
 */
function toTrustRequiredReason(reason: unknown): ExecutableTrustRequiredReason {
  switch (reason) {
    case 'conflicting-choice':
    case 'legacy-dev-sentinel':
      return reason
    default:
      return 'missing-choice'
  }
}

/**
 * Reconstruct a typed {@link VaultError} instance from a value thrown by the
 * WASM core. Unrecognized shapes are wrapped in a base {@link VaultError} so
 * that callers can always rely on `instanceof VaultError`.
 */
export function mapWasmError(thrown: unknown): VaultError {
  if (thrown instanceof VaultError) return thrown

  if (isWasmErrorShape(thrown)) {
    const { vaultErrorCode, message } = thrown
    switch (vaultErrorCode) {
      case 'secret-not-found':
        return new SecretNotFoundError(message)
      case 'decryption':
        return new DecryptionError(message, optionalString(thrown.path))
      case 'filesystem':
        // A `filesystem`-coded thrown value is still more informative as a
        // `FilesystemError` with undefined `path`/`permission` than a
        // downgrade to the generic `VaultError` base class, which would
        // hide `code` and the fact that this was a filesystem failure at
        // all. Pass `path`/`permission` through as-is — never fabricate a
        // fallback value — mirroring how `decryption`'s `path` is handled
        // above.
        return new FilesystemError(
          message,
          optionalString(thrown.path),
          optionalString(thrown.permission),
          optionalString(thrown.code),
        )
      case 'invalid-token':
        return new InvalidTokenError(message)
      case 'token-expired':
        return new TokenExpiredError(message, optionalBoolean(thrown.canRefresh) ?? false)
      case 'key-rotated':
        return new KeyRotatedError(message)
      case 'key-revoked':
        return new KeyRevokedError(message)
      case 'token-revoked':
        return new TokenRevokedError(message)
      case 'usage-limit-exceeded':
        return new UsageLimitExceededError(message)
      case 'rotation-in-progress':
        return new RotationInProgressError(message)
      case 'accessor-consumed':
        return new AccessorConsumedError(message)
      case 'executable-trust-required':
        return new ExecutableTrustRequiredError(message, toTrustRequiredReason(thrown.reason))
      case 'identity-mismatch':
        // Sanitize the hashes: a malformed boundary value (e.g. `null`) must not
        // land as a non-string field and violate IdentityMismatchError's
        // documented `string | undefined` contract — leave it honestly
        // undefined, exactly as every other pass-through field above.
        return new IdentityMismatchError(
          message,
          optionalString(thrown.previousHash),
          optionalString(thrown.currentHash),
        )
      case 'backend-locked':
        return new BackendLockedError(message, optionalBoolean(thrown.interactive) ?? false)
      case 'device-not-present':
        return new DeviceNotPresentError(message, optionalNumber(thrown.timeoutMs) ?? 0)
      case 'authorization-denied':
        return new AuthorizationDeniedError(message)
      case 'not-capable':
        return new NotCapableError(
          message,
          optionalString(thrown.backendType),
          optionalString(thrown.capability),
        )
      case 'presence-declined':
        return new PresenceDeclinedError(message, optionalString(thrown.backendType))
      case 'presence-timeout':
        return new PresenceTimeoutError(
          message,
          optionalString(thrown.backendType),
          optionalNumber(thrown.timeoutMs) ?? 0,
        )
      case 'backend-unavailable':
        return new BackendUnavailableError(
          message,
          optionalString(thrown.reason),
          optionalStringArray(thrown.attempted) ?? [],
        )
      case 'plugin-not-found':
        return new PluginNotFoundError(
          message,
          optionalString(thrown.plugin),
          optionalString(thrown.installUrl),
        )
      case 'invalid-algorithm':
        return new InvalidAlgorithmError(
          message,
          optionalString(thrown.algorithm),
          optionalStringArray(thrown.allowed) ?? [],
        )
      case 'setup':
        return new SetupError(message, optionalString(thrown.dependency))
      case 'invalid-key-material':
        return new InvalidKeyMaterialError(message)
      case 'signing-key-not-found':
        return new SigningKeyNotFoundError(message, optionalString(thrown.keyName))
      case 'signing-key-already-exists':
        return new SigningKeyAlreadyExistsError(message, optionalString(thrown.keyName))
      case 'signing-not-supported':
        return new SigningNotSupportedError(
          message,
          optionalString(thrown.backendType),
          optionalStringArray(thrown.builtInSigningBackends) ?? [],
        )
      case 'exec':
        return new ExecError(message, optionalString(thrown.command))
      case 'fetch':
        return new FetchError(message, optionalString(thrown.url))
      case 'config-validation':
        return new ConfigValidationError(
          message,
          optionalString(thrown.field),
          optionalString(thrown.configFilePath),
        )
      case 'unknown-backend-type':
        return new UnknownBackendTypeError(
          message,
          optionalString(thrown.field),
          optionalString(thrown.backendType),
          optionalStringArray(thrown.knownTypes) ?? [],
          optionalString(thrown.configFilePath),
        )
      case 'config-parse':
        return new ConfigParseError(
          message,
          optionalString(thrown.path),
          toConfigParseLocation(thrown.line, thrown.column),
        )
      case 'vault-error':
        // The generic fallback code deliberately stays the base VaultError —
        // it represents a malformed/validation failure the core hasn't given
        // a dedicated variant yet, so there is no more specific subclass to
        // construct.
        return new VaultError(message)
      default:
        return new VaultError(message)
    }
  }

  if (thrown instanceof Error) return new VaultError(thrown.message)
  return new VaultError(String(thrown))
}
