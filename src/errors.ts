/**
 * Error hierarchy for vaultkeeper.
 *
 * @packageDocumentation
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

// --- Infrastructure Failures ---

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
   * The absolute path of the file or directory that caused the error.
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
    super(message)
    this.name = 'RotationInProgressError'
  }
}
