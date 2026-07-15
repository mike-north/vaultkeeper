/**
 * Error hierarchy for the WASM SDK.
 *
 * Mirrors the `VaultError` hierarchy of the pure-TypeScript `vaultkeeper`
 * library so that consumers of `@vaultkeeper/wasm` can rely on the same
 * ecosystem-wide contract: every error thrown by the SDK is an instance of
 * {@link VaultError}.
 *
 * The Rust/WASM core throws values tagged with a stable `vaultErrorCode`;
 * {@link mapWasmError} reconstructs the matching typed instance at the bridge
 * boundary.
 */

/** Base error for all `@vaultkeeper/wasm` errors. */
export class VaultError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VaultError';
  }
}

/** Thrown when a requested secret does not exist in the backend store. */
export class SecretNotFoundError extends VaultError {
  constructor(message: string) {
    super(message);
    this.name = 'SecretNotFoundError';
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
  readonly path?: string;

  constructor(message: string, path?: string) {
    super(message);
    this.name = 'DecryptionError';
    if (path !== undefined) {
      this.path = path;
    }
  }
}

/**
 * Thrown when a JWE string is invalid or cannot be processed — structurally
 * malformed, decryption failure (wrong key, tampered ciphertext), or a
 * decrypted payload that does not match the expected claims schema.
 */
export class InvalidTokenError extends VaultError {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidTokenError';
  }
}

/** Thrown when a JWE token has passed its expiration time (`exp` claim). */
export class TokenExpiredError extends VaultError {
  /**
   * Whether the token can be refreshed by calling `setup()` again. When
   * `true`, the secret still exists in the backend and a new token can be
   * issued.
   */
  readonly canRefresh: boolean;

  constructor(message: string, canRefresh: boolean) {
    super(message);
    this.name = 'TokenExpiredError';
    this.canRefresh = canRefresh;
  }
}

/**
 * Thrown when the encryption key used to create a JWE has been rotated out of
 * the grace period and can no longer be used for decryption.
 */
export class KeyRotatedError extends VaultError {
  constructor(message: string) {
    super(message);
    this.name = 'KeyRotatedError';
  }
}

/**
 * Thrown when the encryption key referenced by a JWE's `kid` header has been
 * explicitly revoked and is no longer available for decryption.
 */
export class KeyRevokedError extends VaultError {
  constructor(message: string) {
    super(message);
    this.name = 'KeyRevokedError';
  }
}

/**
 * Thrown when a JWE token has been explicitly blocked (e.g. after a single-use
 * token has already been consumed).
 */
export class TokenRevokedError extends VaultError {
  constructor(message: string) {
    super(message);
    this.name = 'TokenRevokedError';
  }
}

/**
 * Thrown when a token with a finite `use` limit has been presented more times
 * than the limit allows.
 */
export class UsageLimitExceededError extends VaultError {
  constructor(message: string) {
    super(message);
    this.name = 'UsageLimitExceededError';
  }
}

/**
 * Thrown when a key rotation is requested while a previous rotation is still
 * within its grace period (i.e. the previous key has not yet been retired).
 */
export class RotationInProgressError extends VaultError {
  constructor(message: string) {
    super(message);
    this.name = 'RotationInProgressError';
  }
}

/**
 * Thrown when a one-time secret accessor's `read()` is called after the
 * secret has already been consumed.
 */
export class AccessorConsumedError extends VaultError {
  constructor(message: string) {
    super(message);
    this.name = 'AccessorConsumedError';
  }
}

/** Shape of the tagged error value thrown across the WASM boundary. */
interface WasmErrorShape {
  vaultErrorCode: string;
  message: string;
  canRefresh?: boolean;
  path?: string;
}

function isWasmErrorShape(value: unknown): value is WasmErrorShape {
  if (typeof value !== 'object' || value === null) return false;
  const record: Record<string, unknown> = { ...value };
  return typeof record.vaultErrorCode === 'string' && typeof record.message === 'string';
}

/**
 * Reconstruct a typed {@link VaultError} instance from a value thrown by the
 * WASM core. Unrecognized shapes are wrapped in a base {@link VaultError} so
 * that callers can always rely on `instanceof VaultError`.
 */
export function mapWasmError(thrown: unknown): VaultError {
  if (thrown instanceof VaultError) return thrown;

  if (isWasmErrorShape(thrown)) {
    const { vaultErrorCode, message } = thrown;
    switch (vaultErrorCode) {
      case 'secret-not-found':
        return new SecretNotFoundError(message);
      case 'decryption':
        return new DecryptionError(message, thrown.path);
      case 'invalid-token':
        return new InvalidTokenError(message);
      case 'token-expired':
        return new TokenExpiredError(message, thrown.canRefresh ?? false);
      case 'key-rotated':
        return new KeyRotatedError(message);
      case 'key-revoked':
        return new KeyRevokedError(message);
      case 'token-revoked':
        return new TokenRevokedError(message);
      case 'usage-limit-exceeded':
        return new UsageLimitExceededError(message);
      case 'rotation-in-progress':
        return new RotationInProgressError(message);
      case 'accessor-consumed':
        return new AccessorConsumedError(message);
      default:
        return new VaultError(message);
    }
  }

  if (thrown instanceof Error) return new VaultError(thrown.message);
  return new VaultError(String(thrown));
}
