/**
 * Error hierarchy for vaultkeeper.
 */

/** Base error for all vaultkeeper errors. */
export class VaultError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'VaultError'
  }
}

// --- Backend Access Failures ---

/**
 * Thrown when the backend keychain or credential store is locked and requires
 * user interaction (e.g. biometric prompt or password entry) before access can
 * be granted.
 */
export class BackendLockedError extends VaultError {
  /**
   * Whether the lock can be resolved through an interactive user prompt.
   * When `true`, callers may retry after prompting the user.
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
 * authentication is not currently connected.
 */
export class DeviceNotPresentError extends VaultError {
  /**
   * How long (in milliseconds) the operation waited for the device before
   * giving up.
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
 * secret access operation (e.g. cancels an OS permission dialog).
 */
export class AuthorizationDeniedError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'AuthorizationDeniedError'
  }
}

/**
 * Thrown when no configured backend is available or reachable.
 * Inspect `reason` for a machine-readable cause and `attempted` for the list
 * of backend types that were tried.
 */
export class BackendUnavailableError extends VaultError {
  /**
   * Machine-readable reason code describing why the backend is unavailable
   * (e.g. `'none-enabled'`, `'all-failed'`).
   */
  readonly reason: string

  /**
   * The backend type identifiers that were attempted before this error was
   * thrown.
   */
  readonly attempted: string[]

  constructor(message: string, reason: string, attempted: string[]) {
    super(message)
    this.name = 'BackendUnavailableError'
    this.reason = reason
    this.attempted = attempted
  }
}

/**
 * Thrown when a required backend plugin (e.g. a third-party credential
 * manager) is not installed on the current system.
 */
export class PluginNotFoundError extends VaultError {
  /**
   * The plugin package or binary name that was not found.
   */
  readonly plugin: string

  /**
   * A URL pointing to installation instructions for the missing plugin.
   */
  readonly installUrl: string

  constructor(message: string, plugin: string, installUrl: string) {
    super(message)
    this.name = 'PluginNotFoundError'
    this.plugin = plugin
    this.installUrl = installUrl
  }
}

/**
 * Thrown when a requested secret does not exist in the backend store.
 */
export class SecretNotFoundError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'SecretNotFoundError'
  }
}

// --- JWE Lifecycle Failures ---

/**
 * Thrown when a JWE token has passed its expiration time (`exp` claim).
 */
export class TokenExpiredError extends VaultError {
  /**
   * Whether the token can be refreshed by calling `setup()` again.
   * When `true`, the secret still exists in the backend and a new token can be
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
 * Thrown when the encryption key that was used to create a JWE has since been
 * rotated out of the grace period and can no longer be used for decryption.
 */
export class KeyRotatedError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'KeyRotatedError'
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

// --- Identity and Trust Failures ---

/**
 * Thrown when the hash of an executable no longer matches the previously
 * approved hash stored in the trust manifest (TOFU conflict).
 *
 * Callers must re-approve the executable before a new token can be issued for
 * it.
 */
export class IdentityMismatchError extends VaultError {
  /**
   * The hash that was recorded in the trust manifest at approval time.
   */
  readonly previousHash: string

  /**
   * The hash computed from the executable at the current moment.
   */
  readonly currentHash: string

  constructor(message: string, previousHash: string, currentHash: string) {
    super(message)
    this.name = 'IdentityMismatchError'
    this.previousHash = previousHash
    this.currentHash = currentHash
  }
}

/**
 * Thrown by {@link VaultKeeper.setup} when the caller does not make an
 * unambiguous executable-trust decision.
 *
 * `setup()` deliberately has no default trust behaviour: the caller must either
 * pass a real `executablePath` (which runs trust-on-first-use verification) or
 * explicitly opt out with `skipTrust: true` (a development-only escape hatch).
 * Supplying neither — or both at once — throws this error rather than silently
 * skipping verification. Passing the retired `'dev'` sentinel as `executablePath`
 * also throws this error. Inspect {@link ExecutableTrustRequiredError.reason} to
 * distinguish the cases.
 *
 * @public
 */
export class ExecutableTrustRequiredError extends VaultError {
  /**
   * Machine-readable discriminator for why the trust choice was rejected.
   * `'missing-choice'` means neither `executablePath` nor `skipTrust: true`
   * was provided, so no trust decision was expressed. `'conflicting-choice'`
   * means both `executablePath` and `skipTrust: true` were provided, which
   * are mutually exclusive intents. `'legacy-dev-sentinel'` means
   * `executablePath` was the retired literal `'dev'` opt-out sentinel, which is
   * no longer supported and must be replaced with `skipTrust: true`.
   */
  readonly reason: 'missing-choice' | 'conflicting-choice' | 'legacy-dev-sentinel'

  constructor(
    message: string,
    reason: 'missing-choice' | 'conflicting-choice' | 'legacy-dev-sentinel',
  ) {
    super(message)
    this.name = 'ExecutableTrustRequiredError'
    this.reason = reason
  }
}

// --- Access Pattern Failures ---

/**
 * Thrown when a delegated `exec()` call fails due to an invalid request
 * (e.g. a `{{secret}}` placeholder in the `command` field) or a
 * process-level error (e.g. the command binary is not found or cannot
 * be spawned).
 *
 * @public
 */
export class ExecError extends VaultError {
  /**
   * The command that failed to execute.
   */
  readonly command: string

  constructor(message: string, command: string) {
    super(message)
    this.name = 'ExecError'
    this.command = command
  }
}

/**
 * Thrown when a JWE string is invalid or cannot be processed — for example,
 * it is structurally malformed (wrong number of segments, invalid
 * Base64URL), decryption fails (wrong key, tampered ciphertext), or the
 * decrypted payload does not match the expected claims schema.
 *
 * @public
 */
export class InvalidTokenError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'InvalidTokenError'
  }
}

/**
 * Thrown when `SecretAccessor.read()` is called after the accessor has
 * already been consumed.
 *
 * @public
 */
export class AccessorConsumedError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'AccessorConsumedError'
  }
}

// --- Infrastructure Failures ---

/**
 * Thrown when a caller requests a signing/verification algorithm that is not
 * in the allowed set (e.g. `'md5'`).
 *
 * @public
 */
export class InvalidAlgorithmError extends VaultError {
  /**
   * The algorithm that was requested.
   */
  readonly algorithm: string

  /**
   * The set of algorithms that are allowed.
   */
  readonly allowed: string[]

  constructor(message: string, algorithm: string, allowed: string[]) {
    super(message)
    this.name = 'InvalidAlgorithmError'
    this.algorithm = algorithm
    this.allowed = allowed
  }
}

/**
 * Thrown when a stored secret is used as signing key material but is not
 * valid PEM or DER private key data (e.g. `crypto.createPrivateKey()`
 * rejects it). Signing raises this error; verification instead returns
 * `false` for invalid key material. The message never echoes any part of
 * the secret.
 *
 * @public
 */
export class InvalidKeyMaterialError extends VaultError {
  constructor(message: string) {
    super(message)
    this.name = 'InvalidKeyMaterialError'
  }
}

/**
 * Thrown when a delegated `fetch()` call fails before a `Response` can be
 * produced — for example the URL is malformed or the underlying network
 * request fails (DNS failure, connection refused, TLS error).
 *
 * @public
 */
export class FetchError extends VaultError {
  /**
   * The unresolved URL template that fetch failed to request, with
   * `{{secret}}`/`{{secret:name}}` placeholders left intact. The
   * placeholder-resolved URL is deliberately never stored here, so an
   * injected secret is never exposed.
   */
  readonly url: string

  constructor(message: string, url: string) {
    super(message)
    this.name = 'FetchError'
    this.url = url
  }
}

/**
 * Thrown when a config value fails structural or semantic validation (e.g. a
 * whitespace-only `BackendConfig.path`).
 */
export class ConfigValidationError extends VaultError {
  /**
   * The dotted/bracketed path to the offending config field (e.g.
   * `'backends[0].path'`).
   */
  readonly field: string

  /**
   * The path of the config file that failed validation, when the error
   * originated from loading a file on disk (via `loadConfig`) rather than
   * from validating an in-memory value directly. This is `configDir` joined
   * with `config.json` exactly as provided to `loadConfig` — it is not
   * guaranteed to be absolute (`loadConfig` does not resolve a relative
   * `configDir`).
   */
  readonly configFilePath: string | undefined

  constructor(message: string, field: string, configFilePath?: string) {
    super(message)
    this.name = 'ConfigValidationError'
    this.field = field
    this.configFilePath = configFilePath
  }
}

/**
 * Thrown when a config file's contents cannot be parsed as JSON.
 *
 * The `message` already embeds the file path, the parse location (when the
 * underlying `SyntaxError` exposes one), and a remediation hint that either
 * points at `vaultkeeper config init` (via the separate `@vaultkeeper/cli`
 * package — this library ships no CLI of its own) or at repairing/replacing
 * the config directly through this library's JS API — see issues #68, #100.
 * `path` and `location` are also exposed individually for callers (e.g.
 * `doctor`) that want to report them as structured fields rather than
 * re-parsing the message.
 */
export class ConfigParseError extends VaultError {
  /**
   * The path of the config file that failed to parse. This is `configDir`
   * joined with `config.json` exactly as provided to `loadConfig` — it is
   * not guaranteed to be absolute (`loadConfig` does not resolve a relative
   * `configDir`).
   */
  readonly path: string

  /**
   * A human-readable parse location (e.g. `'line 3, column 12'`), when one
   * could be derived from the underlying `SyntaxError`.
   */
  readonly location: string | undefined

  constructor(message: string, path: string, location: string | undefined) {
    super(message)
    this.name = 'ConfigParseError'
    this.path = path
    this.location = location
  }
}

/**
 * Thrown during initialization when a required system dependency (e.g. OpenSSL
 * or a native credential helper) is missing or incompatible.
 */
export class SetupError extends VaultError {
  /**
   * The name of the dependency that caused the setup failure.
   */
  readonly dependency: string

  constructor(message: string, dependency: string) {
    super(message)
    this.name = 'SetupError'
    this.dependency = dependency
  }
}

/**
 * Thrown when a filesystem operation fails due to a permission or access
 * problem (e.g. the config directory is not writable).
 */
export class FilesystemError extends VaultError {
  /**
   * The path of the file or directory that caused the error, as provided by
   * the caller. Not guaranteed to be absolute — e.g. `loadConfig` throws this
   * with `configDir` joined with `config.json` exactly as given, without
   * resolving a relative `configDir`.
   */
  readonly path: string

  /**
   * The permission level that was required but not available
   * (e.g. `'read'`, `'write'`, `'execute'`).
   */
  readonly permission: string

  constructor(message: string, filePath: string, permission: string) {
    super(message)
    this.name = 'FilesystemError'
    this.path = filePath
    this.permission = permission
  }
}

/**
 * Thrown when a key rotation is requested while a previous rotation is still
 * within its grace period (i.e. the previous key has not yet been retired).
 */
export class RotationInProgressError extends VaultError {
  constructor(message: string) {
    const trimmed = message.trim()
    const nextSteps =
      'Either wait for the current grace period to elapse before rotating again, ' +
      "or run 'vaultkeeper revoke-key' (or call revokeKey()) to invalidate the previous key " +
      'immediately and clear the grace period.'
    const prefix = trimmed.length === 0 ? '' : `${trimmed}${/[.!?]$/.test(trimmed) ? '' : '.'} `
    super(`${prefix}${nextSteps}`)
    this.name = 'RotationInProgressError'
  }
}
