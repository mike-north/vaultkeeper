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

/** Shape of the tagged error value thrown across the WASM boundary. */
interface WasmErrorShape {
  vaultErrorCode: string
  message: string
  // Only `vaultErrorCode` and `message` are validated by isWasmErrorShape;
  // the rest are typed `unknown` so consumers are forced to narrow through
  // optionalString/optionalBoolean instead of trusting a malformed boundary
  // value to honor the field types.
  canRefresh?: unknown
  path?: unknown
  reason?: unknown
  permission?: unknown
  code?: unknown
  previousHash?: unknown
  currentHash?: unknown
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
      default:
        return new VaultError(message)
    }
  }

  if (thrown instanceof Error) return new VaultError(thrown.message)
  return new VaultError(String(thrown))
}
