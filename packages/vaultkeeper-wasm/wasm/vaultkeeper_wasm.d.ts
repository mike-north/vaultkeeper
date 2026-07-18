/* tslint:disable */
/* eslint-disable */

/**
 * Result of a successful [`WasmVaultKeeper::authorize`] call.
 *
 * Holds the validated claims (with the raw secret redacted) and the raw
 * secret behind a one-time read. The secret is deliberately not part of the
 * `claims` shape — callers must opt in explicitly via the exported
 * `readSecret()` method, which yields the value exactly once.
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
     * Whether the secret is still available to read (i.e. `readSecret()` has
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
     * exactly once via the exported `readSecret()` method, mirroring the TS
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
    revokeKey(): Promise<void>;
    /**
     * Rotate the encryption key.
     */
    rotateKey(): Promise<void>;
    /**
     * Create a JWE token encapsulating a secret.
     *
     * When `options.executablePath` is supplied, the executable is hashed and
     * run through trust verification (Sigstore → trust-manifest match → TOFU
     * first-encounter) via the host bridge; a first-encounter TOFU record is
     * persisted only after the token has been minted (issue #148).
     */
    setup(secret_name: string, secret_value: string, options: any): Promise<string>;
    /**
     * Store a secret via the file backend.
     *
     * FileBackend is stateless (holds only a host reference), so creating it
     * per-call avoids lifetime complexity without performance cost.
     */
    store(id: string, secret: string): Promise<void>;
}

/**
 * Diagnostic-only export: constructs one instance of every `VaultError`
 * variant with fixed dummy field values and converts each through the real
 * `vault_error_to_js` bridge, exactly as a genuine thrown error would be.
 *
 * This exists solely so `error-parity.test.ts` can round-trip real
 * bridge-produced values through the TypeScript reconstruction map, instead
 * of guessing at the JSON shape `vault_error_to_js` produces. It is not part
 * of the SDK's public TypeScript API (`packages/vaultkeeper-wasm/src/index.ts`
 * does not re-export it) and is never called from a real code path — see
 * `all_variants_for_parity_test` in `crates/vaultkeeper-core/src/errors.rs`
 * for the fixture values.
 */
export function __testAllVaultErrors(): Array<any>;

/**
 * The canonical list of every machine-readable `vaultErrorCode` this WASM
 * binary can throw — the single source of truth for the error taxonomy (see
 * `ALL_ERROR_CODES` in `crates/vaultkeeper-core/src/errors.rs`).
 *
 * `packages/vaultkeeper-wasm/src/test/error-parity.test.ts` fetches this
 * exact list at test time and asserts it equals the TypeScript
 * reconstruction map's known codes exactly, catching drift between the two
 * languages in either direction.
 */
export function allVaultErrorCodes(): string[];

/**
 * Factory function to create a WasmVaultKeeper.
 */
export function createVaultKeeper(host: any, options: any): Promise<WasmVaultKeeper>;

/**
 * Initialize the WASM module. Called once on load.
 */
export function init(): void;
