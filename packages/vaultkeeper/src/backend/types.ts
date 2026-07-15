/**
 * Backend abstraction layer types for vaultkeeper.
 */

/**
 * Factory function for creating a SecretBackend instance.
 *
 * @remarks
 * Factories may optionally accept a {@link BackendConfig} to configure the
 * backend from the user's vaultkeeper config file, and the resolved config
 * directory (the same directory config and key material are read from) so
 * file-based backends can default their storage under it. Factories that do
 * not need either can ignore the parameters.
 *
 * @public
 */
// Inline import() avoids a circular dependency: ../types.js imports from this barrel.
export type BackendFactory = (
  config?: import('../types.js').BackendConfig,
  configDir?: string,
) => SecretBackend

/**
 * Abstraction interface for all secret storage backends.
 *
 * @remarks
 * Each backend implementation must handle its own availability check and
 * secret lifecycle (store, retrieve, delete, exists).
 *
 * @public
 */
export interface SecretBackend {
  /** Unique type identifier for this backend. */
  readonly type: string

  /** Human-readable display name for this backend. */
  readonly displayName: string

  /**
   * Check whether this backend is available on the current system.
   * @returns true if the backend can be used, false otherwise
   */
  isAvailable(): Promise<boolean>

  /**
   * Store a secret under the given id.
   * @param id - Unique identifier for the secret
   * @param secret - The secret value to store
   */
  store(id: string, secret: string): Promise<void>

  /**
   * Retrieve a secret by id.
   * @param id - Unique identifier for the secret
   * @returns The stored secret value
   * @throws SecretNotFoundError if the secret does not exist
   */
  retrieve(id: string): Promise<string>

  /**
   * Delete a secret by id.
   * @param id - Unique identifier for the secret
   * @throws SecretNotFoundError if the secret does not exist
   */
  delete(id: string): Promise<void>

  /**
   * Check whether a secret exists for the given id.
   * @param id - Unique identifier for the secret
   * @returns true if the secret exists, false otherwise
   */
  exists(id: string): Promise<boolean>
}

/**
 * Backend that can enumerate stored secret IDs.
 * @public
 */
export interface ListableBackend extends SecretBackend {
  /**
   * List IDs of all secrets managed by this backend.
   * @returns Array of secret identifiers
   */
  list(): Promise<string[]>
}

/**
 * Type guard for backends that support listing.
 * @public
 */
export function isListableBackend(backend: SecretBackend): backend is ListableBackend {
  return 'list' in backend && typeof backend.list === 'function'
}

/**
 * Backend that can enroll and use signing keys entirely on its own side.
 *
 * @remarks
 * Signing keys are a distinct resource from secrets: a private key must never
 * flow through {@link SecretBackend.store}/{@link SecretBackend.retrieve} or a
 * capability token's claims. A signing backend generates the keypair, exposes
 * only the public half, and performs the signature itself — the private key
 * never leaves the backend. This is what keeps a key out of any JWE claims
 * token and lets a presence-per-use backend enforce its guarantee for signing.
 *
 * Implementations must keep signing keys in a namespace that cannot collide
 * with or be read as ordinary secrets.
 *
 * @public
 */
export interface SigningBackend extends SecretBackend {
  /**
   * Enroll a new signing keypair under `id`.
   * @param id - Namespaced signing-key identifier.
   * @param algorithm - The JOSE algorithm to generate a key for.
   * @throws If a signing key already exists under `id`, or `algorithm` is not
   *   supported by this backend.
   */
  generateSigningKey(id: string, algorithm: import('../types.js').SigningAlgorithm): Promise<void>

  /**
   * Return the public half of the signing key stored under `id`.
   * @param id - Namespaced signing-key identifier.
   * @throws A `SigningKeyNotFoundError` if no signing key exists under `id`.
   */
  getPublicKey(id: string): Promise<import('../types.js').SigningPublicKey>

  /**
   * Sign `data` with the private key stored under `id`, returning the raw
   * signature bytes. The private key never leaves the backend.
   * @param id - Namespaced signing-key identifier.
   * @param data - The exact bytes to sign (e.g. a JWS signing input).
   * @throws A `SigningKeyNotFoundError` if no signing key exists under `id`.
   */
  signWithKey(id: string, data: Buffer): Promise<Buffer>
}

/**
 * Type guard for backends that implement the signing contract.
 * @public
 */
export function isSigningBackend(backend: SecretBackend): backend is SigningBackend {
  return (
    'generateSigningKey' in backend &&
    typeof backend.generateSigningKey === 'function' &&
    'getPublicKey' in backend &&
    typeof backend.getPublicKey === 'function' &&
    'signWithKey' in backend &&
    typeof backend.signWithKey === 'function'
  )
}
