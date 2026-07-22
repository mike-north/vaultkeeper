/* @ts-self-types="./vaultkeeper_wasm.d.ts" */

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
class WasmAuthorization {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmAuthorization.prototype);
        obj.__wbg_ptr = ptr;
        WasmAuthorizationFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmAuthorizationFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmauthorization_free(ptr, 0);
    }
    /**
     * The validated token claims, with the raw secret (`val`) redacted.
     * @returns {any}
     */
    get claims() {
        const ret = wasm.wasmauthorization_claims(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * The underlying core capability handle id (issue #241 AC6). Usable
     * with `WasmVaultKeeper.resolveSecretClaims`/`releaseHandle`.
     * @returns {string}
     */
    get handleId() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.wasmauthorization_handleId(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
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
     * @returns {string}
     */
    readSecret() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.wasmauthorization_readSecret(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * The authorization response (key status, optional rotated token).
     * @returns {any}
     */
    get response() {
        const ret = wasm.wasmauthorization_response(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * Whether the secret is still available to read (i.e. `readSecret()` has
     * not yet been called).
     * @returns {boolean}
     */
    get secretAvailable() {
        const ret = wasm.wasmauthorization_secretAvailable(this.__wbg_ptr);
        return ret !== 0;
    }
}
if (Symbol.dispose) WasmAuthorization.prototype[Symbol.dispose] = WasmAuthorization.prototype.free;
exports.WasmAuthorization = WasmAuthorization;

/**
 * WASM-exposed VaultKeeper wrapper.
 */
class WasmVaultKeeper {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmVaultKeeper.prototype);
        obj.__wbg_ptr = ptr;
        WasmVaultKeeperFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmVaultKeeperFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmvaultkeeper_free(ptr, 0);
    }
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
     * @param {string} jwe
     * @returns {WasmAuthorization}
     */
    authorize(jwe) {
        const ptr0 = passStringToWasm0(jwe, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmvaultkeeper_authorize(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return WasmAuthorization.__wrap(ret[0]);
    }
    /**
     * Get the current configuration as JSON.
     * @returns {any}
     */
    config() {
        const ret = wasm.wasmvaultkeeper_config(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * Delete a secret via the file backend.
     * @param {string} id
     * @returns {Promise<void>}
     */
    delete(id) {
        const ptr0 = passStringToWasm0(id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmvaultkeeper_delete(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Run doctor checks and return a PreflightResult as JSON.
     * @returns {Promise<any>}
     */
    doctor() {
        const ret = wasm.wasmvaultkeeper_doctor(this.__wbg_ptr);
        return ret;
    }
    /**
     * Explicitly release a capability handle (issue #241 AC6). Returns
     * `true` if a handle was actually present and removed, `false` if it
     * was already gone (released, expired, or evicted). A caller that is
     * done with a handle should call this rather than waiting on its
     * expiry. Throws an `authorization-denied` error for a `handleId` that
     * is not even shaped like a real handle (see
     * `validate_handle_id_shape`), rather than allocating/looking it up.
     * @param {string} handle_id
     * @returns {boolean}
     */
    releaseHandle(handle_id) {
        const ptr0 = passStringToWasm0(handle_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmvaultkeeper_releaseHandle(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * Resolve the non-secret claims behind a capability handle id (issue
     * #241 AC6 — a new, handle-based entry point for the future engine
     * swap, alongside the eager `authorize()`/`WasmAuthorization` wrapper
     * above). Returns the claims as JSON, with `val` always absent. Refuses
     * a signing-key handle.
     * @param {string} handle_id
     * @returns {any}
     */
    resolveSecretClaims(handle_id) {
        const ptr0 = passStringToWasm0(handle_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmvaultkeeper_resolveSecretClaims(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * Retrieve a secret via the file backend.
     * @param {string} id
     * @returns {Promise<string>}
     */
    retrieve(id) {
        const ptr0 = passStringToWasm0(id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmvaultkeeper_retrieve(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Emergency key revocation — removes previous key and generates a new current key.
     * @returns {Promise<void>}
     */
    revokeKey() {
        const ret = wasm.wasmvaultkeeper_revokeKey(this.__wbg_ptr);
        return ret;
    }
    /**
     * Rotate the encryption key.
     * @returns {Promise<void>}
     */
    rotateKey() {
        const ret = wasm.wasmvaultkeeper_rotateKey(this.__wbg_ptr);
        return ret;
    }
    /**
     * Create a JWE token encapsulating a secret.
     *
     * When `options.executablePath` is supplied, the executable is hashed and
     * run through trust verification (Sigstore → trust-manifest match → TOFU
     * first-encounter) via the host bridge; a first-encounter TOFU record is
     * persisted only after the token has been minted (issue #148).
     * @param {string} secret_name
     * @param {string} secret_value
     * @param {any} options
     * @returns {Promise<string>}
     */
    setup(secret_name, secret_value, options) {
        const ptr0 = passStringToWasm0(secret_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(secret_value, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmvaultkeeper_setup(this.__wbg_ptr, ptr0, len0, ptr1, len1, options);
        return ret;
    }
    /**
     * Store a secret via the file backend.
     *
     * FileBackend is stateless (holds only a host reference), so creating it
     * per-call avoids lifetime complexity without performance cost.
     * @param {string} id
     * @param {string} secret
     * @returns {Promise<void>}
     */
    store(id, secret) {
        const ptr0 = passStringToWasm0(id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmvaultkeeper_store(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret;
    }
}
if (Symbol.dispose) WasmVaultKeeper.prototype[Symbol.dispose] = WasmVaultKeeper.prototype.free;
exports.WasmVaultKeeper = WasmVaultKeeper;

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
 * @returns {Array<any>}
 */
function __testAllVaultErrors() {
    const ret = wasm.__testAllVaultErrors();
    return ret;
}
exports.__testAllVaultErrors = __testAllVaultErrors;

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
 * @param {any} host
 * @param {string} cmd
 * @param {string[]} args
 * @returns {Promise<any>}
 */
function __testExec(host, cmd, args) {
    const ptr0 = passStringToWasm0(cmd, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArrayJsValueToWasm0(args, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.__testExec(host, ptr0, len0, ptr1, len1);
    return ret;
}
exports.__testExec = __testExec;

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
 * @param {any} host
 * @param {any} request
 * @returns {Promise<any>}
 */
function __testHttpFetch(host, request) {
    const ret = wasm.__testHttpFetch(host, request);
    return ret;
}
exports.__testHttpFetch = __testHttpFetch;

/**
 * Diagnostic-only export exercising `JsSecretBackend::delete`.
 * @param {any} host
 * @param {string} id
 * @returns {Promise<void>}
 */
function __testJsSecretBackendDelete(host, id) {
    const ptr0 = passStringToWasm0(id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.__testJsSecretBackendDelete(host, ptr0, len0);
    return ret;
}
exports.__testJsSecretBackendDelete = __testJsSecretBackendDelete;

/**
 * Diagnostic-only export exercising `JsSecretBackend::exists`.
 * @param {any} host
 * @param {string} id
 * @returns {Promise<boolean>}
 */
function __testJsSecretBackendExists(host, id) {
    const ptr0 = passStringToWasm0(id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.__testJsSecretBackendExists(host, ptr0, len0);
    return ret;
}
exports.__testJsSecretBackendExists = __testJsSecretBackendExists;

/**
 * Diagnostic-only export exercising `JsSecretBackend::is_available`.
 * @param {any} host
 * @returns {Promise<boolean>}
 */
function __testJsSecretBackendIsAvailable(host) {
    const ret = wasm.__testJsSecretBackendIsAvailable(host);
    return ret;
}
exports.__testJsSecretBackendIsAvailable = __testJsSecretBackendIsAvailable;

/**
 * Diagnostic-only export exercising `JsSecretBackend::list`
 * (`ListableBackend`), including the `NotCapable` path when the JS mock
 * doesn't provide `list()`.
 * @param {any} host
 * @returns {Promise<string[]>}
 */
function __testJsSecretBackendList(host) {
    const ret = wasm.__testJsSecretBackendList(host);
    return ret;
}
exports.__testJsSecretBackendList = __testJsSecretBackendList;

/**
 * Diagnostic-only export: constructs a `JsSecretBackend` from `host` and
 * returns its `{ type, displayName }` identity — issue #239 AC5 "unit
 * coverage with a mock JS backend". Not part of the SDK's public TypeScript
 * API.
 * @param {any} host
 * @returns {any}
 */
function __testJsSecretBackendMeta(host) {
    const ret = wasm.__testJsSecretBackendMeta(host);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}
exports.__testJsSecretBackendMeta = __testJsSecretBackendMeta;

/**
 * Diagnostic-only export exercising `JsSecretBackend::retrieve`.
 * @param {any} host
 * @param {string} id
 * @returns {Promise<string>}
 */
function __testJsSecretBackendRetrieve(host, id) {
    const ptr0 = passStringToWasm0(id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.__testJsSecretBackendRetrieve(host, ptr0, len0);
    return ret;
}
exports.__testJsSecretBackendRetrieve = __testJsSecretBackendRetrieve;

/**
 * Diagnostic-only export exercising `JsSecretBackend::store`. `secret` is a
 * UTF-8 string on this side of the boundary — the core `SecretBackend`
 * trait's `store`/`retrieve` are `&str`/`String`-based — but crosses to the
 * JS mock as a `Uint8Array`, exactly as a real `JsSecretBackend::store` call
 * would.
 * @param {any} host
 * @param {string} id
 * @param {string} secret
 * @returns {Promise<void>}
 */
function __testJsSecretBackendStore(host, id, secret) {
    const ptr0 = passStringToWasm0(id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(secret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.__testJsSecretBackendStore(host, ptr0, len0, ptr1, len1);
    return ret;
}
exports.__testJsSecretBackendStore = __testJsSecretBackendStore;

/**
 * Diagnostic-only export proving the core-resident environment-profile
 * loader (issue #277) is reachable from the TS path through the real WASM
 * binary (AC7's wasm-bridge half; the Rust half is
 * `crates/vaultkeeper-core/tests/profile_loader_integration.rs`). Not part
 * of the SDK's public TypeScript API — `packages/vaultkeeper-wasm/src/index.ts`
 * does not re-export it.
 *
 * `config_defaults` is `{ ttlMinutes: number, trustTier: 1 | 2 | 3 }`,
 * mirroring `config.json`'s `defaults` shape; this function performs the
 * same `ttlMinutes` → seconds conversion
 * `vaultkeeper_core::profile::ProfileDefaults::from_vault_defaults` does.
 * @param {string} json
 * @param {any} config_defaults
 * @returns {any}
 */
function __testLoadProfile(json, config_defaults) {
    const ptr0 = passStringToWasm0(json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.__testLoadProfile(ptr0, len0, config_defaults);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}
exports.__testLoadProfile = __testLoadProfile;

/**
 * Diagnostic-only export exercising `HostPlatform::prompt_approval`
 * directly through the real `JsHostPlatform` bridge (issue #239 AC3). Not
 * part of the SDK's public TypeScript API.
 * @param {any} host
 * @param {string} action
 * @param {string} detail
 * @returns {Promise<boolean>}
 */
function __testPromptApproval(host, action, detail) {
    const ptr0 = passStringToWasm0(action, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(detail, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.__testPromptApproval(host, ptr0, len0, ptr1, len1);
    return ret;
}
exports.__testPromptApproval = __testPromptApproval;

/**
 * Diagnostic-only export: runs the Rust core's `validate_claims` — the
 * single validation chokepoint every token passes through — directly against
 * a caller-supplied claims payload, without needing a real JWE, key, or
 * `VaultKeeper` instance.
 *
 * `claims_json` must deserialize as `VaultClaims`. Returns `Ok(())` when
 * validation passes, or a `JsValue` produced by the real `vault_error_to_js`
 * bridge (matching every other error surfaced from this binary) when it
 * fails.
 *
 * This exists so `packages/cli-tests/test/conformance/claims-validation-parity.test.ts`
 * can assert the Rust core and the TypeScript library's `validateClaims`
 * (`packages/vaultkeeper/src/jwe/claims.ts`) produce byte-identical error
 * messages for the same malformed claims payload (issue #280) — it is not
 * part of the SDK's public TypeScript API (`../index.ts` does not re-export
 * it) and is never called from a real code path.
 *
 * # Errors
 * Returns the bridged `VaultError` when `claims_json` fails to parse as
 * `VaultClaims`, or when `validate_claims` rejects the parsed claims.
 * @param {string} claims_json
 * @param {bigint} used_count
 */
function __testValidateClaims(claims_json, used_count) {
    const ptr0 = passStringToWasm0(claims_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.__testValidateClaims(ptr0, len0, used_count);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}
exports.__testValidateClaims = __testValidateClaims;

/**
 * The canonical list of every machine-readable `vaultErrorCode` this WASM
 * binary can throw — the single source of truth for the error taxonomy (see
 * `ALL_ERROR_CODES` in `crates/vaultkeeper-core/src/errors.rs`).
 *
 * `packages/vaultkeeper-wasm/src/test/error-parity.test.ts` fetches this
 * exact list at test time and asserts it equals the TypeScript
 * reconstruction map's known codes exactly, catching drift between the two
 * languages in either direction.
 * @returns {string[]}
 */
function allVaultErrorCodes() {
    const ret = wasm.allVaultErrorCodes();
    var v1 = getArrayJsValueFromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
    return v1;
}
exports.allVaultErrorCodes = allVaultErrorCodes;

/**
 * Factory function to create a WasmVaultKeeper.
 * @param {any} host
 * @param {any} options
 * @returns {Promise<WasmVaultKeeper>}
 */
function createVaultKeeper(host, options) {
    const ret = wasm.createVaultKeeper(host, options);
    return ret;
}
exports.createVaultKeeper = createVaultKeeper;

/**
 * Initialize the WASM module. Called once on load.
 */
function init() {
    wasm.init();
}
exports.init = init;

function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_83742b46f01ce22d: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg___wbindgen_boolean_get_c0f3f60bac5a78d1: function(arg0) {
            const v = arg0;
            const ret = typeof(v) === 'boolean' ? v : undefined;
            return isLikeNone(ret) ? 0xFFFFFF : ret ? 1 : 0;
        },
        __wbg___wbindgen_debug_string_5398f5bb970e0daa: function(arg0, arg1) {
            const ret = debugString(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_is_function_3c846841762788c1: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_null_0b605fc6b167c56f: function(arg0) {
            const ret = arg0 === null;
            return ret;
        },
        __wbg___wbindgen_is_object_781bc9f159099513: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_undefined_52709e72fb9f179c: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_number_get_34bb9d9dcfa21373: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'number' ? obj : undefined;
            getDataViewMemory0().setFloat64(arg0 + 8 * 1, isLikeNone(ret) ? 0 : ret, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
        },
        __wbg___wbindgen_string_get_395e606bd0ee4427: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_6ddd609b62940d55: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg__wbg_cb_unref_6b5b6b8576d35cb1: function(arg0) {
            arg0._wbg_cb_unref();
        },
        __wbg_call_2d781c1f4d5c0ef8: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_call_dcc2662fa17a72cf: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg0.call(arg1, arg2, arg3);
            return ret;
        }, arguments); },
        __wbg_call_e133b57c9155d22c: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.call(arg1);
            return ret;
        }, arguments); },
        __wbg_call_f858478a02f9600f: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            const ret = arg0.call(arg1, arg2, arg3, arg4);
            return ret;
        }, arguments); },
        __wbg_error_a6fa202b58aa1cd3: function(arg0, arg1) {
            let deferred0_0;
            let deferred0_1;
            try {
                deferred0_0 = arg0;
                deferred0_1 = arg1;
                console.error(getStringFromWasm0(arg0, arg1));
            } finally {
                wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
            }
        },
        __wbg_from_4bdf88943703fd48: function(arg0) {
            const ret = Array.from(arg0);
            return ret;
        },
        __wbg_getRandomValues_3f44b700395062e5: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_getRandomValues_a1cf2e70b003a59d: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_get_3ef1eba1850ade27: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.get(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_get_a8ee5c45dabc1b3b: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_instanceof_Uint8Array_740438561a5b956d: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Uint8Array;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_isArray_33b91feb269ff46e: function(arg0) {
            const ret = Array.isArray(arg0);
            return ret;
        },
        __wbg_keys_ab0d051a1c55236d: function(arg0) {
            const ret = Object.keys(arg0);
            return ret;
        },
        __wbg_length_b3416cf66a5452c8: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_length_ea16607d7b61445b: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_new_227d7c05414eb861: function() {
            const ret = new Error();
            return ret;
        },
        __wbg_new_5f486cdf45a04d78: function(arg0) {
            const ret = new Uint8Array(arg0);
            return ret;
        },
        __wbg_new_a70fbab9066b301f: function() {
            const ret = new Array();
            return ret;
        },
        __wbg_new_ab79df5bd7c26067: function() {
            const ret = new Object();
            return ret;
        },
        __wbg_new_typed_aaaeaf29cf802876: function(arg0, arg1) {
            try {
                var state0 = {a: arg0, b: arg1};
                var cb0 = (arg0, arg1) => {
                    const a = state0.a;
                    state0.a = 0;
                    try {
                        return wasm_bindgen__convert__closures_____invoke__h1d09f6aac4bd3d03(a, state0.b, arg0, arg1);
                    } finally {
                        state0.a = a;
                    }
                };
                const ret = new Promise(cb0);
                return ret;
            } finally {
                state0.a = state0.b = 0;
            }
        },
        __wbg_new_with_length_825018a1616e9e55: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        },
        __wbg_now_16f0c993d5dd6c27: function() {
            const ret = Date.now();
            return ret;
        },
        __wbg_parse_e9eddd2a82c706eb: function() { return handleError(function (arg0, arg1) {
            const ret = JSON.parse(getStringFromWasm0(arg0, arg1));
            return ret;
        }, arguments); },
        __wbg_prototypesetcall_d62e5099504357e6: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_push_e87b0e732085a946: function(arg0, arg1) {
            const ret = arg0.push(arg1);
            return ret;
        },
        __wbg_queueMicrotask_0c399741342fb10f: function(arg0) {
            const ret = arg0.queueMicrotask;
            return ret;
        },
        __wbg_queueMicrotask_a082d78ce798393e: function(arg0) {
            queueMicrotask(arg0);
        },
        __wbg_resolve_ae8d83246e5bcc12: function(arg0) {
            const ret = Promise.resolve(arg0);
            return ret;
        },
        __wbg_set_7eaa4f96924fd6b3: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = Reflect.set(arg0, arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_set_8c0b3ffcf05d61c2: function(arg0, arg1, arg2) {
            arg0.set(getArrayU8FromWasm0(arg1, arg2));
        },
        __wbg_stack_3b0d974bbf31e44f: function(arg0, arg1) {
            const ret = arg1.stack;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_static_accessor_GLOBAL_8adb955bd33fac2f: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_THIS_ad356e0db91c7913: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_f207c857566db248: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_bb9f1ba69d61b386: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_then_098abe61755d12f6: function(arg0, arg1) {
            const ret = arg0.then(arg1);
            return ret;
        },
        __wbg_then_9e335f6dd892bc11: function(arg0, arg1, arg2) {
            const ret = arg0.then(arg1, arg2);
            return ret;
        },
        __wbg_wasmvaultkeeper_new: function(arg0) {
            const ret = WasmVaultKeeper.__wrap(arg0);
            return ret;
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { dtor_idx: 234, function: Function { arguments: [Externref], shim_idx: 235, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm.wasm_bindgen__closure__destroy__h1722208547e491cb, wasm_bindgen__convert__closures_____invoke__h8760ba3086f56474);
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000003: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000004: function(arg0, arg1) {
            var v0 = getArrayJsValueFromWasm0(arg0, arg1).slice();
            wasm.__wbindgen_free(arg0, arg1 * 4, 4);
            // Cast intrinsic for `Vector(NamedExternref("string")) -> Externref`.
            const ret = v0;
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./vaultkeeper_wasm_bg.js": import0,
    };
}

function wasm_bindgen__convert__closures_____invoke__h8760ba3086f56474(arg0, arg1, arg2) {
    const ret = wasm.wasm_bindgen__convert__closures_____invoke__h8760ba3086f56474(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen__convert__closures_____invoke__h1d09f6aac4bd3d03(arg0, arg1, arg2, arg3) {
    wasm.wasm_bindgen__convert__closures_____invoke__h1d09f6aac4bd3d03(arg0, arg1, arg2, arg3);
}

const WasmAuthorizationFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmauthorization_free(ptr >>> 0, 1));
const WasmVaultKeeperFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmvaultkeeper_free(ptr >>> 0, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

const CLOSURE_DTORS = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(state => state.dtor(state.a, state.b));

function debugString(val) {
    // primitive types
    const type = typeof val;
    if (type == 'number' || type == 'boolean' || val == null) {
        return  `${val}`;
    }
    if (type == 'string') {
        return `"${val}"`;
    }
    if (type == 'symbol') {
        const description = val.description;
        if (description == null) {
            return 'Symbol';
        } else {
            return `Symbol(${description})`;
        }
    }
    if (type == 'function') {
        const name = val.name;
        if (typeof name == 'string' && name.length > 0) {
            return `Function(${name})`;
        } else {
            return 'Function';
        }
    }
    // objects
    if (Array.isArray(val)) {
        const length = val.length;
        let debug = '[';
        if (length > 0) {
            debug += debugString(val[0]);
        }
        for(let i = 1; i < length; i++) {
            debug += ', ' + debugString(val[i]);
        }
        debug += ']';
        return debug;
    }
    // Test for built-in
    const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
    let className;
    if (builtInMatches && builtInMatches.length > 1) {
        className = builtInMatches[1];
    } else {
        // Failed to match the standard '[object ClassName]'
        return toString.call(val);
    }
    if (className == 'Object') {
        // we're a user defined class or Object
        // JSON.stringify avoids problems with cycles, and is generally much
        // easier than looping through ownProperties of `val`.
        try {
            return 'Object(' + JSON.stringify(val) + ')';
        } catch (_) {
            return 'Object';
        }
    }
    // errors
    if (val instanceof Error) {
        return `${val.name}: ${val.message}\n${val.stack}`;
    }
    // TODO we could test for more things here, like `Set`s and `Map`s.
    return className;
}

function getArrayJsValueFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    const mem = getDataViewMemory0();
    const result = [];
    for (let i = ptr; i < ptr + 4 * len; i += 4) {
        result.push(wasm.__wbindgen_externrefs.get(mem.getUint32(i, true)));
    }
    wasm.__externref_drop_slice(ptr, len);
    return result;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function makeMutClosure(arg0, arg1, dtor, f) {
    const state = { a: arg0, b: arg1, cnt: 1, dtor };
    const real = (...args) => {

        // First up with a closure we increment the internal reference
        // count. This ensures that the Rust closure environment won't
        // be deallocated while we're invoking it.
        state.cnt++;
        const a = state.a;
        state.a = 0;
        try {
            return f(a, state.b, ...args);
        } finally {
            state.a = a;
            real._wbg_cb_unref();
        }
    };
    real._wbg_cb_unref = () => {
        if (--state.cnt === 0) {
            state.dtor(state.a, state.b);
            state.a = 0;
            CLOSURE_DTORS.unregister(state);
        }
    };
    CLOSURE_DTORS.register(real, state, state);
    return real;
}

function passArrayJsValueToWasm0(array, malloc) {
    const ptr = malloc(array.length * 4, 4) >>> 0;
    for (let i = 0; i < array.length; i++) {
        const add = addToExternrefTable0(array[i]);
        getDataViewMemory0().setUint32(ptr + 4 * i, add, true);
    }
    WASM_VECTOR_LEN = array.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
function decodeText(ptr, len) {
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

const wasmPath = `${__dirname}/vaultkeeper_wasm_bg.wasm`;
const wasmBytes = require('fs').readFileSync(wasmPath);
const wasmModule = new WebAssembly.Module(wasmBytes);
let wasm = new WebAssembly.Instance(wasmModule, __wbg_get_imports()).exports;
wasm.__wbindgen_start();
