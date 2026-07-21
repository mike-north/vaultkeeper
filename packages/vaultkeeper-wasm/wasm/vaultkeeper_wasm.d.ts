/* tslint:disable */
/* eslint-disable */

/**
 * Result of a successful [`WasmVaultKeeper::authorize`] call.
 *
 * Holds the validated claims (with the raw secret redacted) and the raw
 * secret behind a one-time read. The secret is deliberately not part of the
 * `claims` shape — callers must opt in explicitly via the exported
 * `readSecret()` method, which yields the value exactly once.
 *
 * Also carries the underlying core capability handle id (`handleId`, issue
 * #241 AC6) so a caller can additionally use `WasmVaultKeeper`'s
 * handle-based entry points (`resolveSecretClaims`/`releaseHandle`)
 * directly — the primitives a future engine swap builds on instead of this
 * eager wrapper.
 */
export class WasmAuthorization {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Read the raw secret value exactly once. Subsequent calls throw an
     * `accessor-consumed` error. This is the explicit, deliberately-named
     * escape hatch for flows that must touch the plaintext secret.
     *
     * The Rust side never clones the secret to produce this value: the
     * plaintext is moved out of the `Zeroizing<String>` wrapper (leaving it
     * holding an empty string, which is a no-op to scrub on drop) rather
     * than copied out. The one residual, unprotected copy this cannot close
     * is on the far side of the `wasm-bindgen`-generated FFI glue itself —
     * returning an owned `String` from a `#[wasm_bindgen]` method has that
     * glue copy the bytes into a fresh JS string and then free this Rust
     * `String` via ordinary (non-zeroizing) `Drop`. That hand-off is
     * generated code we do not control, and JS strings are immutable and
     * cannot be scrubbed by this crate regardless — the same trust boundary
     * already noted for a dishonest/misbehaving JS host elsewhere in this
     * file (see `JsHostPlatform`'s "No-reentrancy contract").
     */
    readSecret(): string;
    /**
     * The validated token claims, with the raw secret (`val`) redacted.
     */
    readonly claims: any;
    /**
     * The underlying core capability handle id (issue #241 AC6). Usable
     * with `WasmVaultKeeper.resolveSecretClaims`/`releaseHandle`.
     */
    readonly handleId: string;
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
     * (`val` is redacted) — `vaultkeeper_core::VaultKeeper::authorize` (issue
     * #241) never returns it either; it stays behind a core-side capability
     * handle. This call performs the one-time `read_secret` against that
     * handle immediately, internally, and caches the result on the returned
     * `WasmAuthorization` exactly as this method always has, so the
     * `@vaultkeeper/wasm` public shape (`claims`, `response`,
     * `secretAvailable`, `readSecret()`) is unchanged. The handle itself is
     * also retained (exposed as `WasmAuthorization.handleId`) so a caller
     * can additionally use the handle-based entry points below
     * (`resolveSecretClaims`/`releaseHandle`) — the primitives a future
     * engine swap would build directly on instead of this eager wrapper.
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
     * Explicitly release a capability handle (issue #241 AC6). Returns
     * `true` if a handle was actually present and removed, `false` if it
     * was already gone (released, expired, or evicted). A caller that is
     * done with a handle should call this rather than waiting on its
     * expiry. Throws an `authorization-denied` error for a `handleId` that
     * is not even shaped like a real handle (see
     * `validate_handle_id_shape`), rather than allocating/looking it up.
     */
    releaseHandle(handle_id: string): boolean;
    /**
     * Resolve the non-secret claims behind a capability handle id (issue
     * #241 AC6 — a new, handle-based entry point for the future engine
     * swap, alongside the eager `authorize()`/`WasmAuthorization` wrapper
     * above). Returns the claims as JSON, with `val` always absent. Refuses
     * a signing-key handle.
     */
    resolveSecretClaims(handle_id: string): any;
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
 * Diagnostic-only export exercising `HostPlatform::exec` directly through
 * the real `JsHostPlatform` bridge (issue #239 AC1, and the malformed-result
 * hardening below it). Lets tests drive a mock host whose `exec()` returns a
 * malformed `stdout`/`stderr`/`exitCode` without needing a core consumer
 * that calls `exec` with such a host. Not part of the SDK's public
 * TypeScript API (`packages/vaultkeeper-wasm/src/index.ts` does not
 * re-export it).
 *
 * `host` must satisfy the full `JsHostPlatform::new` contract (`platform()`,
 * `configDir()`) in addition to `exec()`, since it's constructed the same
 * way a real `WasmVaultKeeper` host is.
 */
export function __testExec(host: any, cmd: string, args: string[]): Promise<any>;

/**
 * Diagnostic-only export exercising `HostPlatform::http_fetch` directly
 * through the real `JsHostPlatform` bridge (issue #239 AC2 — "land the
 * primitive with direct tests"). No core consumer calls `http_fetch` yet
 * (see the trait default in `crates/vaultkeeper-core/src/backend/types.rs`),
 * so this is the only way to exercise the bridge end-to-end today. Not part
 * of the SDK's public TypeScript API (`packages/vaultkeeper-wasm/src/index.ts`
 * does not re-export it).
 *
 * `host` must satisfy the full `JsHostPlatform::new` contract (`platform()`,
 * `configDir()`) in addition to `httpFetch()`, since it's constructed the
 * same way a real `WasmVaultKeeper` host is.
 */
export function __testHttpFetch(host: any, request: any): Promise<any>;

/**
 * Diagnostic-only export exercising `JsSecretBackend::delete`.
 */
export function __testJsSecretBackendDelete(host: any, id: string): Promise<void>;

/**
 * Diagnostic-only export exercising `JsSecretBackend::exists`.
 */
export function __testJsSecretBackendExists(host: any, id: string): Promise<boolean>;

/**
 * Diagnostic-only export exercising `JsSecretBackend::is_available`.
 */
export function __testJsSecretBackendIsAvailable(host: any): Promise<boolean>;

/**
 * Diagnostic-only export exercising `JsSecretBackend::list`
 * (`ListableBackend`), including the `NotCapable` path when the JS mock
 * doesn't provide `list()`.
 */
export function __testJsSecretBackendList(host: any): Promise<string[]>;

/**
 * Diagnostic-only export: constructs a `JsSecretBackend` from `host` and
 * returns its `{ type, displayName }` identity — issue #239 AC5 "unit
 * coverage with a mock JS backend". Not part of the SDK's public TypeScript
 * API.
 */
export function __testJsSecretBackendMeta(host: any): any;

/**
 * Diagnostic-only export exercising `JsSecretBackend::retrieve`.
 */
export function __testJsSecretBackendRetrieve(host: any, id: string): Promise<string>;

/**
 * Diagnostic-only export exercising `JsSecretBackend::store`. `secret` is a
 * UTF-8 string on this side of the boundary — the core `SecretBackend`
 * trait's `store`/`retrieve` are `&str`/`String`-based — but crosses to the
 * JS mock as a `Uint8Array`, exactly as a real `JsSecretBackend::store` call
 * would.
 */
export function __testJsSecretBackendStore(host: any, id: string, secret: string): Promise<void>;

/**
 * Diagnostic-only export exercising `HostPlatform::prompt_approval`
 * directly through the real `JsHostPlatform` bridge (issue #239 AC3). Not
 * part of the SDK's public TypeScript API.
 */
export function __testPromptApproval(host: any, action: string, detail: string): Promise<boolean>;

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
