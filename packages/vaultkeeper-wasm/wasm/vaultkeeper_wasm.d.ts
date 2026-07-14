/* tslint:disable */
/* eslint-disable */

/**
 * Result of a successful [`WasmVaultKeeper::authorize`] call.
 *
 * Holds the validated claims (with the raw secret redacted) and the raw
 * secret behind a one-time read. The secret is deliberately not part of the
 * `claims` shape — callers must opt in explicitly via [`Self::read_secret`],
 * which yields the value exactly once.
 */
export class WasmAuthorization {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Read the raw secret value exactly once. Subsequent calls throw an
     * `accessor-consumed` error. This is the explicit, deliberately-named
     * escape hatch for flows that must touch the plaintext secret.
     */
    readSecret(): string;
    /**
     * The validated token claims, with the raw secret (`val`) redacted.
     */
    readonly claims: any;
    /**
     * The authorization response (key status, optional rotated token).
     */
    readonly response: any;
    /**
     * Whether the secret is still available to read (i.e. `read_secret` has
     * not yet been called).
     */
    readonly secretAvailable: boolean;
}

/**
 * WASM-exposed VaultKeeper wrapper.
 */
export class WasmVaultKeeper {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Decrypt a JWE token, validate its claims, and return a
     * [`WasmAuthorization`].
     *
     * The returned object's `claims` **never** contains the raw secret value
     * (`val` is redacted). The secret is held internally and can be read
     * exactly once via [`WasmAuthorization::read_secret`], mirroring the TS
     * library's one-time accessor pattern.
     */
    authorize(jwe: string): WasmAuthorization;
    /**
     * Get the current configuration as JSON.
     */
    config(): any;
    /**
     * Delete a secret via the file backend.
     */
    delete(id: string): Promise<void>;
    /**
     * Run doctor checks and return a PreflightResult as JSON.
     */
    doctor(): Promise<any>;
    /**
     * Retrieve a secret via the file backend.
     */
    retrieve(id: string): Promise<string>;
    /**
     * Emergency key revocation — removes previous key and generates a new current key.
     */
    revokeKey(): void;
    /**
     * Rotate the encryption key.
     */
    rotateKey(): void;
    /**
     * Create a JWE token encapsulating a secret.
     */
    setup(secret_name: string, secret_value: string, options: any): string;
    /**
     * Store a secret via the file backend.
     *
     * FileBackend is stateless (holds only a host reference), so creating it
     * per-call avoids lifetime complexity without performance cost.
     */
    store(id: string, secret: string): Promise<void>;
}

/**
 * Factory function to create a WasmVaultKeeper.
 */
export function createVaultKeeper(host: any, options: any): Promise<WasmVaultKeeper>;

/**
 * Initialize the WASM module. Called once on load.
 */
export function init(): void;
