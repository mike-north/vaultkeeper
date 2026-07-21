//! WASM bindings implementation — only compiled on wasm32.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use js_sys::{Function, Promise, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use zeroize::Zeroizing;

use vaultkeeper_core::backend::{
    ApprovalContext, ExecOptions, ExecOutput, FileBackend, HostPlatform, HttpRequest, HttpResponse,
    ListableBackend, Platform, SecretBackend,
};
use vaultkeeper_core::errors::{
    ALL_ERROR_CODES, all_variants_for_parity_test, vault_error_code, vault_error_fields,
};
use vaultkeeper_core::vault::{SetupOptions, VaultKeeperOptions};
use vaultkeeper_core::{ExecutableTrustRequiredReason, VaultError};

// ─── JsHostPlatform ──────────────────────────────────────────────

/// A `HostPlatform` implementation backed by JavaScript callbacks.
///
/// The JS object must implement:
/// - `exec(cmd, args, options?)` → `Promise<{stdout, stderr, exitCode}>`, where
///   `options` is `{ stdin?, env?, cwd? }` (issue #239)
/// - `readFile(path)` → `Promise<Uint8Array>`
/// - `writeFile(path, content, mode)` → `Promise<void>`
/// - `fileExists(path)` → `Promise<boolean>`
/// - `deleteFile(path)` → `Promise<void>`
/// - `renameFile(from, to)` → `Promise<void>`
/// - `listDir(path)` → `Promise<string[]>`
/// - `platform()` → `string` ("darwin"|"linux"|"win32")
/// - `configDir()` → `string`
/// - `httpFetch(request)` → `Promise<{status, headers, body}>` (issue #239)
/// - `promptApproval?(context)` → `Promise<boolean>` (issue #239, optional —
///   absent means fail closed, never an automatic allow)
///
/// # No-reentrancy contract
///
/// None of these JS callbacks may call back into the vault (no
/// `VaultKeeper`/`createVaultKeeper` method calls) while running. Core does
/// not guard against reentrant calls; violating this can deadlock or corrupt
/// in-flight state.
struct JsHostPlatform {
    host: JsValue,
    config_dir: PathBuf,
    platform: Platform,
}

// SAFETY: In single-threaded WASM, JsValue is never accessed from multiple threads.
unsafe impl Send for JsHostPlatform {}
unsafe impl Sync for JsHostPlatform {}

impl JsHostPlatform {
    fn new(host: JsValue) -> Result<Self, JsError> {
        let platform_fn = get_method(&host, "platform")?;
        let platform_str = platform_fn
            .call0(&host)
            .map_err(|e| JsError::new(&format!("platform() failed: {e:?}")))?;
        let platform_str = platform_str
            .as_string()
            .ok_or_else(|| JsError::new("platform() must return a string"))?;
        let platform = match platform_str.as_str() {
            "darwin" => Platform::Darwin,
            "linux" => Platform::Linux,
            "win32" => Platform::Windows,
            other => return Err(JsError::new(&format!("Unknown platform: {other}"))),
        };

        let config_dir_fn = get_method(&host, "configDir")?;
        let config_dir_val = config_dir_fn
            .call0(&host)
            .map_err(|e| JsError::new(&format!("configDir() failed: {e:?}")))?;
        let config_dir_str = config_dir_val
            .as_string()
            .ok_or_else(|| JsError::new("configDir() must return a string"))?;

        Ok(Self {
            host,
            config_dir: PathBuf::from(config_dir_str),
            platform,
        })
    }
}

fn get_method(obj: &JsValue, name: &str) -> Result<Function, JsError> {
    let val = Reflect::get(obj, &JsValue::from_str(name))
        .map_err(|_| JsError::new(&format!("Missing method: {name}")))?;
    val.dyn_into::<Function>()
        .map_err(|_| JsError::new(&format!("{name} is not a function")))
}

fn js_err(msg: &str) -> VaultError {
    VaultError::Other(msg.to_string())
}

/// Read the `code`/`message`/`path` properties off a value rejected by a
/// `readFile`/`writeFile`/`deleteFile`/`fileExists` promise. The Node host
/// bridge (packages/vaultkeeper-wasm/src/node-host.ts, `toHostFilesystemError`)
/// guarantees `code`/`message` are present on the rejection; `code` mirrors
/// Node's `NodeJS.ErrnoException.code` (e.g. `"ENOENT"`, `"EACCES"`) and is
/// `None` only if the bridge itself couldn't determine one. `path` is present
/// whenever the bridge determined one — which is not always the same string
/// this Rust call sent it: `writeFile`'s `mkdir` sub-step reports the
/// *directory* it failed to create, not the file path this call was
/// nominally about (see `fs_rejection_to_vault_error`).
fn read_fs_rejection(rejected: &JsValue) -> (Option<String>, String, Option<String>) {
    let code = Reflect::get(rejected, &JsValue::from_str("code"))
        .ok()
        .and_then(|v| v.as_string());
    let message = Reflect::get(rejected, &JsValue::from_str("message"))
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_else(|| format!("{rejected:?}"));
    let path = Reflect::get(rejected, &JsValue::from_str("path"))
        .ok()
        .and_then(|v| v.as_string());
    (code, message, path)
}

/// Convert a rejected `readFile`/`writeFile`/`deleteFile`/`fileExists`
/// promise into a typed `VaultError::Filesystem`, mirroring the native
/// host's classification (`crates/vaultkeeper-cli/src/host.rs`): every fs
/// failure is reported as `Filesystem` rather than collapsed into a generic
/// `Other`, with `code` carrying the errno when the JS host bridge supplied
/// one. This is what lets core `FileBackend`'s existing exists-probe
/// (unchanged by #138) disambiguate "missing" from "unreadable" identically
/// under both hosts.
///
/// Prefers the bridge's own `path` over the `path` argument this call was
/// made with: for `readFile`/`deleteFile`/`fileExists` the two are always
/// identical (the bridge operates on the exact string this call sent it),
/// but `writeFile`'s `mkdir` sub-step can fail on a parent directory that
/// differs from the file path passed in — the bridge's `path` is the more
/// precise one in that case. Falls back to the argument when the bridge
/// didn't supply one.
fn fs_rejection_to_vault_error(rejected: &JsValue, path: &Path, permission: &str) -> VaultError {
    let (code, message, bridge_path) = read_fs_rejection(rejected);
    let resolved_path = bridge_path.unwrap_or_else(|| path.display().to_string());
    VaultError::Filesystem {
        message: format!("Failed to {permission} {resolved_path}: {message}"),
        path: resolved_path,
        permission: permission.to_string(),
        code,
    }
}

/// Convert a [`VaultError`] into a thrown JS value carrying a stable
/// `vaultErrorCode`, its `message`, and any structured context fields. The
/// TypeScript bridge maps `vaultErrorCode` back to a `VaultError` subclass so
/// callers receive a real typed error instance.
///
/// The code and field logic themselves live in `vaultkeeper_core` (see
/// `vault_error_code`/`vault_error_fields` in
/// `crates/vaultkeeper-core/src/errors.rs`) so they're unit-testable without
/// a wasm32 target; this function is just the thin JSON-serialization
/// wrapper that gets those values across the actual WASM/JS boundary, plus
/// the one JS-facing message override below.
///
/// If serializing or parsing the full field map ever fails — not expected in
/// practice, since every field is a plain string/number/bool/array — this
/// falls back to [`coded_js_error`] rather than silently degrading to
/// `undefined`, so `vaultErrorCode`/`message` are never lost even in that
/// pathological case.
fn vault_error_to_js(e: &VaultError) -> JsValue {
    let mut fields = vault_error_fields(e);
    let code = vault_error_code(e);
    fields.insert(
        "vaultErrorCode".to_string(),
        serde_json::Value::String(code.to_string()),
    );
    let message = match e {
        VaultError::ExecutableTrustRequired { reason, .. } => {
            // The core carries a Rust-native message (SetupOptions.executable_path
            // etc.) for direct Rust callers; at this JS boundary we replace it
            // with the JS-facing wording (options.executablePath / skipTrust) so
            // WASM SDK consumers see their own API's names.
            executable_trust_required_js_message(*reason).to_string()
        }
        _ => e.to_string(),
    };
    fields.insert(
        "message".to_string(),
        serde_json::Value::String(message.clone()),
    );

    serde_json::to_string(&fields)
        .ok()
        .and_then(|json| js_sys::JSON::parse(&json).ok())
        .unwrap_or_else(|| coded_js_error(code, &message))
}

/// JS-facing message for an [`ExecutableTrustRequiredReason`], phrased in the
/// WASM SDK's own option names (`options.executablePath` / `options.skipTrust`).
fn executable_trust_required_js_message(reason: ExecutableTrustRequiredReason) -> &'static str {
    match reason {
        ExecutableTrustRequiredReason::MissingChoice => {
            "VaultKeeper.setup() requires an explicit executable-trust choice and no longer \
             defaults to skipping it. Either pass options.executablePath set to the calling \
             executable's real path (a non-empty path binds that identity into the token), or set \
             options.skipTrust: true to deliberately skip the binding (development only)."
        }
        ExecutableTrustRequiredReason::ConflictingChoice => {
            "VaultKeeper.setup() received both options.executablePath and options.skipTrust: true, \
             which are mutually exclusive. Pass options.executablePath to bind the calling \
             executable's identity, or options.skipTrust: true to skip the binding (development \
             only) — not both."
        }
        ExecutableTrustRequiredReason::LegacyDevSentinel => {
            "VaultKeeper.setup() no longer supports the legacy options.executablePath: 'dev' \
             sentinel for skipping the identity binding. Set options.skipTrust: true to \
             deliberately skip the binding (development only), or pass options.executablePath set \
             to the calling executable's real path to bind it."
        }
    }
}

/// Build a thrown JS value for an error originating at the WASM boundary
/// itself (not from a `VaultError`), e.g. a consumed one-time accessor.
fn coded_js_error(code: &str, message: &str) -> JsValue {
    let obj = js_sys::Object::new();
    let _ = Reflect::set(
        &obj,
        &JsValue::from_str("vaultErrorCode"),
        &JsValue::from_str(code),
    );
    let _ = Reflect::set(
        &obj,
        &JsValue::from_str("message"),
        &JsValue::from_str(message),
    );
    obj.into()
}

/// Shared shape guard for `handle_id` parameters at every handle-based WASM
/// entry point (`resolveSecretClaims`, `releaseHandle`) — issue #241 group B.
///
/// A real `HandleId` (`crates/vaultkeeper-core/src/identity/handles.rs`) is
/// generated as the canonical hyphenated string form of a UUID v4, but this
/// guard is a cheap bound/shape sanity check, not a canonical-form
/// authority — it accepts a bounded UUID string, and `Uuid::parse_str`'s
/// leniency (e.g. accepting other RFC 4122 UUID string forms besides the
/// canonical 36-character hyphenated one) is fine here, because a
/// shape-valid-but-non-live id simply misses the table lookup and gets the
/// same `authorization-denied` verdict either way. A JS caller (a hostile or
/// simply buggy host) can hand these entry points an arbitrary string of any
/// length, and both used to `.to_string()`-allocate it immediately and feed
/// it straight into a core lookup before anything checked its shape. This
/// rejects anything that isn't a syntactically plausible UUID *before* that
/// allocation/lookup — including before the
/// [`HandleId`](vaultkeeper_core::HandleId)-and-hash work `Display`/`Debug`'s
/// redaction does on a failed lookup — so an attacker handing in a
/// multi-megabyte string pays for none of that.
///
/// Deliberately does not distinguish "too long", "too short", or
/// "wrong shape" in the error message: any of those already means the value
/// cannot possibly be a handle this table minted, which is exactly the
/// `authorization-denied` a real (shape-valid but unrecognized) lookup would
/// eventually return anyway — this just returns the same verdict cheaper.
fn validate_handle_id_shape(handle_id: &str) -> Result<(), JsValue> {
    uuid::Uuid::parse_str(handle_id).map(|_| ()).map_err(|_| {
        coded_js_error(
            "authorization-denied",
            "Malformed capability handle id: not a recognizable handle",
        )
    })
}

#[async_trait::async_trait(?Send)]
impl HostPlatform for JsHostPlatform {
    async fn exec(
        &self,
        cmd: &str,
        args: &[&str],
        options: ExecOptions<'_>,
    ) -> Result<ExecOutput, VaultError> {
        let exec_fn = get_method(&self.host, "exec").map_err(|e| js_err(&format!("{e:?}")))?;

        let js_cmd = JsValue::from_str(cmd);
        let js_args = js_sys::Array::new();
        for arg in args {
            js_args.push(&JsValue::from_str(arg));
        }

        // Issue #239: bundle stdin/env/cwd into a single options object
        // rather than the pre-#239 positional stdin argument. Only fields
        // that are `Some` are set, so an all-`None` `ExecOptions` produces an
        // empty `{}` — the Node bridge (`node-host.ts`) treats every field of
        // that object as optional, preserving pre-#239 behavior exactly.
        let js_options = js_sys::Object::new();
        if let Some(data) = options.stdin {
            let arr = Uint8Array::new_with_length(data.len() as u32);
            arr.copy_from(data);
            let _ = Reflect::set(&js_options, &JsValue::from_str("stdin"), &arr.into());
        }
        if let Some(env) = options.env {
            let env_obj = js_sys::Object::new();
            for (key, value) in env {
                let _ = Reflect::set(&env_obj, &JsValue::from_str(key), &JsValue::from_str(value));
            }
            let _ = Reflect::set(&js_options, &JsValue::from_str("env"), &env_obj);
        }
        if let Some(cwd) = options.cwd {
            let _ = Reflect::set(
                &js_options,
                &JsValue::from_str("cwd"),
                &JsValue::from_str(&cwd.to_string_lossy()),
            );
        }

        let promise = exec_fn
            .call3(&self.host, &js_cmd, &js_args, &js_options.into())
            .map_err(|e| js_err(&format!("exec() call failed: {e:?}")))?;

        let result = JsFuture::from(Promise::from(promise))
            .await
            .map_err(|e| js_err(&format!("exec() promise rejected: {e:?}")))?;

        let stdout_val = Reflect::get(&result, &JsValue::from_str("stdout"))
            .map_err(|_| js_err("exec result missing stdout"))?;
        let stderr_val = Reflect::get(&result, &JsValue::from_str("stderr"))
            .map_err(|_| js_err("exec result missing stderr"))?;
        let exit_code_val = Reflect::get(&result, &JsValue::from_str("exitCode"))
            .map_err(|_| js_err("exec result missing exitCode"))?;

        let stdout = stdout_val
            .dyn_into::<Uint8Array>()
            .map_err(|_| js_err("stdout is not a Uint8Array"))?
            .to_vec();
        let stderr = stderr_val
            .dyn_into::<Uint8Array>()
            .map_err(|_| js_err("stderr is not a Uint8Array"))?
            .to_vec();
        let exit_code = exit_code_val
            .as_f64()
            .ok_or_else(|| js_err("exitCode is not a number"))? as i32;

        Ok(ExecOutput {
            stdout,
            stderr,
            exit_code,
        })
    }

    async fn read_file(&self, path: &Path) -> Result<Vec<u8>, VaultError> {
        let read_fn = get_method(&self.host, "readFile").map_err(|e| js_err(&format!("{e:?}")))?;

        let js_path = JsValue::from_str(&path.to_string_lossy());
        let promise = read_fn
            .call1(&self.host, &js_path)
            .map_err(|e| js_err(&format!("readFile() call failed: {e:?}")))?;

        let result = JsFuture::from(Promise::from(promise))
            .await
            .map_err(|e| fs_rejection_to_vault_error(&e, path, "read"))?;

        Ok(Uint8Array::new(&result).to_vec())
    }

    async fn write_file(&self, path: &Path, content: &[u8], mode: u32) -> Result<(), VaultError> {
        let write_fn =
            get_method(&self.host, "writeFile").map_err(|e| js_err(&format!("{e:?}")))?;

        let js_path = JsValue::from_str(&path.to_string_lossy());
        let js_content = Uint8Array::new_with_length(content.len() as u32);
        js_content.copy_from(content);
        let js_mode = JsValue::from_f64(f64::from(mode));

        let promise = write_fn
            .call3(&self.host, &js_path, &js_content.into(), &js_mode)
            .map_err(|e| js_err(&format!("writeFile() call failed: {e:?}")))?;

        JsFuture::from(Promise::from(promise))
            .await
            .map_err(|e| fs_rejection_to_vault_error(&e, path, "write"))?;

        Ok(())
    }

    async fn file_exists(&self, path: &Path) -> Result<bool, VaultError> {
        let exists_fn =
            get_method(&self.host, "fileExists").map_err(|e| js_err(&format!("{e:?}")))?;

        let js_path = JsValue::from_str(&path.to_string_lossy());
        let promise = exists_fn
            .call1(&self.host, &js_path)
            .map_err(|e| js_err(&format!("fileExists() call failed: {e:?}")))?;

        // Mirror the native host's `file_exists` (crates/vaultkeeper-cli/src/host.rs):
        // the JS bridge (`toHostFilesystemError` in node-host.ts) already
        // collapses a genuine "does not exist" to a resolved `false`, so any
        // rejection reaching here is a real failure (e.g. EACCES) that must
        // surface as `VaultError::Filesystem`, not be swallowed to `false`
        // the way a bare `Path::exists()`-style check would.
        let result = JsFuture::from(Promise::from(promise))
            .await
            .map_err(|e| fs_rejection_to_vault_error(&e, path, "read"))?;

        Ok(result.as_bool().unwrap_or(false))
    }

    async fn delete_file(&self, path: &Path) -> Result<(), VaultError> {
        let delete_fn =
            get_method(&self.host, "deleteFile").map_err(|e| js_err(&format!("{e:?}")))?;

        let js_path = JsValue::from_str(&path.to_string_lossy());
        let promise = delete_fn
            .call1(&self.host, &js_path)
            .map_err(|e| js_err(&format!("deleteFile() call failed: {e:?}")))?;

        JsFuture::from(Promise::from(promise))
            .await
            .map_err(|e| fs_rejection_to_vault_error(&e, path, "write"))?;

        Ok(())
    }

    async fn rename_file(&self, from: &Path, to: &Path) -> Result<(), VaultError> {
        let rename_fn =
            get_method(&self.host, "renameFile").map_err(|e| js_err(&format!("{e:?}")))?;

        let js_from = JsValue::from_str(&from.to_string_lossy());
        let js_to = JsValue::from_str(&to.to_string_lossy());
        let promise = rename_fn
            .call2(&self.host, &js_from, &js_to)
            .map_err(|e| js_err(&format!("renameFile() call failed: {e:?}")))?;

        JsFuture::from(Promise::from(promise))
            .await
            .map_err(|e| fs_rejection_to_vault_error(&e, to, "write"))?;

        Ok(())
    }

    async fn list_dir(&self, path: &Path) -> Result<Vec<String>, VaultError> {
        let list_fn = get_method(&self.host, "listDir").map_err(|e| js_err(&format!("{e:?}")))?;

        let js_path = JsValue::from_str(&path.to_string_lossy());
        let promise = list_fn
            .call1(&self.host, &js_path)
            .map_err(|e| js_err(&format!("listDir() call failed: {e:?}")))?;

        let result = JsFuture::from(Promise::from(promise))
            .await
            .map_err(|e| js_err(&format!("listDir() rejected: {e:?}")))?;

        let arr = js_sys::Array::from(&result);
        let mut names = Vec::new();
        for i in 0..arr.length() {
            if let Some(s) = arr.get(i).as_string() {
                names.push(s);
            }
        }
        Ok(names)
    }

    fn platform(&self) -> Platform {
        self.platform
    }

    fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    /// Bridges to the JS host's required `httpFetch(request)` method over
    /// the global `fetch` (issue #239). No core consumer calls this yet —
    /// see the trait default's doc comment
    /// (`crates/vaultkeeper-core/src/backend/types.rs`) — this override just
    /// makes the primitive real end-to-end for direct testing
    /// (`__testHttpFetch` below) ahead of a later consumer.
    async fn http_fetch(&self, request: HttpRequest) -> Result<HttpResponse, VaultError> {
        let url = request.url.clone();
        let fetch_fn = get_method(&self.host, "httpFetch").map_err(|e| VaultError::Fetch {
            message: format!("{e:?}"),
            url: url.clone(),
        })?;

        let js_request = http_request_to_js(&request);

        let promise = fetch_fn
            .call1(&self.host, &js_request)
            .map_err(|e| VaultError::Fetch {
                message: format!("httpFetch() call failed: {e:?}"),
                url: url.clone(),
            })?;

        let result =
            JsFuture::from(Promise::from(promise))
                .await
                .map_err(|e| VaultError::Fetch {
                    message: format!("httpFetch() promise rejected: {e:?}"),
                    url: url.clone(),
                })?;

        js_result_to_http_response(&result, &url)
    }

    /// Bridges to the JS host's *optional* `promptApproval(context)` method
    /// (issue #239). A JS host that omits the method — the common case, since
    /// no consumer wires this up yet — fails closed (`Ok(false)`), matching
    /// the trait default in `crates/vaultkeeper-core/src/backend/types.rs`
    /// exactly rather than surfacing a "missing method" error.
    async fn prompt_approval(&self, context: ApprovalContext<'_>) -> Result<bool, VaultError> {
        let Ok(prompt_fn) = get_method(&self.host, "promptApproval") else {
            return Ok(false);
        };

        let js_context = js_sys::Object::new();
        let _ = Reflect::set(
            &js_context,
            &JsValue::from_str("action"),
            &JsValue::from_str(context.action),
        );
        let _ = Reflect::set(
            &js_context,
            &JsValue::from_str("detail"),
            &JsValue::from_str(context.detail),
        );

        let promise = prompt_fn
            .call1(&self.host, &js_context.into())
            .map_err(|e| js_err(&format!("promptApproval() call failed: {e:?}")))?;

        let result = JsFuture::from(Promise::from(promise))
            .await
            .map_err(|e| js_err(&format!("promptApproval() promise rejected: {e:?}")))?;

        Ok(result.as_bool().unwrap_or(false))
    }
}

/// Build the `{ method, url, headers, body? }` JS object `httpFetch` expects,
/// mirroring `HttpFetchRequest` (`packages/vaultkeeper-wasm/src/types.ts`).
fn http_request_to_js(request: &HttpRequest) -> JsValue {
    let obj = js_sys::Object::new();
    let _ = Reflect::set(
        &obj,
        &JsValue::from_str("method"),
        &JsValue::from_str(&request.method),
    );
    let _ = Reflect::set(
        &obj,
        &JsValue::from_str("url"),
        &JsValue::from_str(&request.url),
    );
    let headers_obj = js_sys::Object::new();
    for (key, value) in &request.headers {
        let _ = Reflect::set(
            &headers_obj,
            &JsValue::from_str(key),
            &JsValue::from_str(value),
        );
    }
    let _ = Reflect::set(&obj, &JsValue::from_str("headers"), &headers_obj);
    if let Some(body) = &request.body {
        let arr = Uint8Array::new_with_length(body.len() as u32);
        arr.copy_from(body);
        let _ = Reflect::set(&obj, &JsValue::from_str("body"), &arr.into());
    }
    obj.into()
}

/// Parse the `{ status, headers, body }` value `httpFetch` resolved with into
/// an [`HttpResponse`], mirroring `HttpFetchResponse`
/// (`packages/vaultkeeper-wasm/src/types.ts`). `url` is only used to label a
/// malformed-shape failure with the request it came from.
fn js_result_to_http_response(result: &JsValue, url: &str) -> Result<HttpResponse, VaultError> {
    let malformed = |field: &str| VaultError::Fetch {
        message: format!("httpFetch() result missing/invalid '{field}' (requested {url})"),
        url: url.to_string(),
    };

    // Reject anything that isn't a genuine non-negative integer in u16 range
    // (negative, fractional, NaN, `Infinity`, or > 65535) rather than
    // truncating/wrapping it into a misleading in-range `u16` via `as`.
    let status_f64 = Reflect::get(result, &JsValue::from_str("status"))
        .ok()
        .and_then(|v| v.as_f64())
        .ok_or_else(|| malformed("status"))?;
    if status_f64.fract() != 0.0 || !(0.0..=f64::from(u16::MAX)).contains(&status_f64) {
        return Err(malformed("status"));
    }
    let status = status_f64 as u16;

    // A missing or non-object `headers` must fail loudly, not silently
    // degrade to an empty header list.
    let headers_val =
        Reflect::get(result, &JsValue::from_str("headers")).map_err(|_| malformed("headers"))?;
    if !headers_val.is_object() {
        return Err(malformed("headers"));
    }
    let mut headers = Vec::new();
    let keys = js_sys::Object::keys(&js_sys::Object::from(headers_val.clone()));
    for i in 0..keys.length() {
        // `Object.keys()` always yields strings, so `key` is infallible in
        // practice; `value` is the part that can genuinely be a non-string
        // (e.g. a header value set to a number), which must reject the whole
        // response rather than silently drop that one header.
        let key = keys
            .get(i)
            .as_string()
            .ok_or_else(|| malformed("headers"))?;
        let value = Reflect::get(&headers_val, &JsValue::from_str(&key))
            .map_err(|_| malformed("headers"))?;
        let value_str = value.as_string().ok_or_else(|| malformed("headers"))?;
        headers.push((key, value_str));
    }

    // `Uint8Array::new` on a non-Uint8Array value (e.g. `undefined`, a
    // string, a plain array) either coerces to a misleading result or throws
    // inside the JS constructor — check the real type first via `dyn_ref`
    // instead of constructing blind.
    let body_val =
        Reflect::get(result, &JsValue::from_str("body")).map_err(|_| malformed("body"))?;
    let body = body_val
        .dyn_ref::<Uint8Array>()
        .ok_or_else(|| malformed("body"))?
        .to_vec();

    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

/// Parse a JS `{ method, url, headers?, body? }` value (the same shape
/// `httpFetch` receives) into an [`HttpRequest`]. Used only by the
/// `__testHttpFetch` diagnostic export below, so a real caller never
/// round-trips through this — it exists purely to let a TS test construct a
/// request without hand-building the internal `HttpRequest` struct.
fn js_value_to_http_request(request: &JsValue) -> Result<HttpRequest, JsError> {
    let method = Reflect::get(request, &JsValue::from_str("method"))
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_else(|| "GET".to_string());
    let url = Reflect::get(request, &JsValue::from_str("url"))
        .ok()
        .and_then(|v| v.as_string())
        .ok_or_else(|| JsError::new("request.url must be a string"))?;

    let mut headers = Vec::new();
    if let Ok(headers_val) = Reflect::get(request, &JsValue::from_str("headers"))
        && headers_val.is_object()
    {
        let keys = js_sys::Object::keys(&js_sys::Object::from(headers_val.clone()));
        for i in 0..keys.length() {
            if let Some(key) = keys.get(i).as_string()
                && let Ok(value) = Reflect::get(&headers_val, &JsValue::from_str(&key))
                && let Some(value_str) = value.as_string()
            {
                headers.push((key, value_str));
            }
        }
    }

    // Check the real type via `dyn_ref` rather than handing a possibly
    // non-Uint8Array value blind to `Uint8Array::new`, which either coerces
    // it into misleading bytes or throws inside the JS constructor.
    let body = match Reflect::get(request, &JsValue::from_str("body")).ok() {
        Some(v) if !v.is_undefined() && !v.is_null() => {
            let arr = v
                .dyn_ref::<Uint8Array>()
                .ok_or_else(|| JsError::new("request.body must be a Uint8Array"))?;
            Some(arr.to_vec())
        }
        _ => None,
    };

    Ok(HttpRequest {
        method,
        url,
        headers,
        body,
    })
}

// ─── JsSecretBackend ─────────────────────────────────────────────────

/// A `SecretBackend` implementation backed by JavaScript callbacks (issue
/// #239 Phase 0 scaffold).
///
/// The JS object must implement (mirrors `HostSecretBackend`,
/// `packages/vaultkeeper-wasm/src/types.ts`):
/// - `type` → `string` (read once at construction)
/// - `displayName` → `string` (read once at construction)
/// - `isAvailable()` → `Promise<boolean>`
/// - `store(id, secret: Uint8Array)` → `Promise<void>`
/// - `retrieve(id)` → `Promise<Uint8Array>`
/// - `delete(id)` → `Promise<void>`
/// - `exists(id)` → `Promise<boolean>`
/// - `list?()` → `Promise<string[]>` (optional; probed once at construction —
///   `list()` rejects with `NotCapable` if the JS object didn't provide one)
///
/// This scaffold implements only the core `SecretBackend`/`ListableBackend`
/// traits. It deliberately does **not** dispatch `getCapabilities`,
/// `generateSigningKey`, `getPublicKey`, or `signWithKey` — those forward-looking
/// `HostSecretBackend` fields exist in the TS contract ahead of the Rust-side
/// capability trait (issue #242) and signing trait (issue #237), which are
/// out of scope here. Registry dispatch (making a `JsSecretBackend` reachable
/// via `BackendRegistry`) is also a later phase; this type exists to be
/// constructed directly (see the `__testJsSecretBackend*` diagnostic exports
/// below) until that wiring lands.
///
/// # No-reentrancy contract
///
/// None of these JS callbacks may call back into the vault while running —
/// same contract as `JsHostPlatform` above.
struct JsSecretBackend {
    host: JsValue,
    backend_type: String,
    display_name: String,
    has_list: bool,
}

// SAFETY: In single-threaded WASM, JsValue is never accessed from multiple threads.
unsafe impl Send for JsSecretBackend {}
unsafe impl Sync for JsSecretBackend {}

impl JsSecretBackend {
    fn new(host: JsValue) -> Result<Self, JsError> {
        let backend_type = Reflect::get(&host, &JsValue::from_str("type"))
            .ok()
            .and_then(|v| v.as_string())
            .ok_or_else(|| JsError::new("HostSecretBackend.type must be a string"))?;
        let display_name = Reflect::get(&host, &JsValue::from_str("displayName"))
            .ok()
            .and_then(|v| v.as_string())
            .ok_or_else(|| JsError::new("HostSecretBackend.displayName must be a string"))?;
        let has_list = Reflect::get(&host, &JsValue::from_str("list"))
            .map(|v| v.is_function())
            .unwrap_or(false);

        Ok(Self {
            host,
            backend_type,
            display_name,
            has_list,
        })
    }
}

// ─── Zeroization boundary ────────────────────────────────────────
//
// `store`/`retrieve` copy secret material across the wasm/JS boundary as a
// `Uint8Array`. The Rust-side intermediate buffers created for that crossing
// (the owned `Vec<u8>` copy handed to JS in `store`, and the owned `Vec<u8>`
// read back from JS in `retrieve`) are wrapped in `zeroize::Zeroizing` so
// they are scrubbed on drop — in `store` that's forced explicitly right
// after the copy is handed off (see the `drop` call below), rather than left
// to happen whenever the intermediate would otherwise go out of scope. This
// follows the same secret-hygiene goal as `keys/storage.rs`'s explicit
// `.zeroize()` calls on key material — the project-wide principle of
// scrubbing secret-bearing buffers after use (CLAUDE.md security rules),
// applied here to a Rust `Vec<u8>` rather than the Node `Buffer` those rules
// name directly.
//
// This does **not** extend past the boundary: once bytes are copied into a
// JS-owned `Uint8Array` (in `store`) or handed to us by the host (in
// `retrieve`), Rust has no reliable way to scrub that JS-side memory — it may
// already have been copied, retained, or garbage-collected on its own
// schedule. Scrubbing JS-side copies is out of scope here, consistent with
// the "dishonest host" trust limit documented on `JsHostPlatform` above: a
// malicious or buggy host can always retain what it's handed, so the
// achievable goal is limited to zeroing the Rust-side intermediates.
#[async_trait::async_trait(?Send)]
impl SecretBackend for JsSecretBackend {
    fn backend_type(&self) -> &str {
        &self.backend_type
    }

    fn display_name(&self) -> &str {
        &self.display_name
    }

    async fn is_available(&self) -> bool {
        let Ok(is_available_fn) = get_method(&self.host, "isAvailable") else {
            return false;
        };
        let Ok(promise) = is_available_fn.call0(&self.host) else {
            return false;
        };
        JsFuture::from(Promise::from(promise))
            .await
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    async fn store(&self, id: &str, secret: &str) -> Result<(), VaultError> {
        let store_fn = get_method(&self.host, "store").map_err(|e| js_err(&format!("{e:?}")))?;

        let js_id = JsValue::from_str(id);
        // Owned copy of the secret bytes, scrubbed on drop (see the
        // "Zeroization boundary" note above `impl SecretBackend`).
        let secret_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(secret.as_bytes().to_vec());
        let js_secret = Uint8Array::new_with_length(secret_bytes.len() as u32);
        js_secret.copy_from(&secret_bytes);
        // Scrub the Rust-side copy eagerly now that it's been copied into the
        // JS-owned `Uint8Array`, rather than waiting for it to go out of
        // scope at the end of the function (which would leave it live across
        // the `.await` below).
        drop(secret_bytes);

        let promise = store_fn
            .call2(&self.host, &js_id, &js_secret.into())
            .map_err(|e| js_err(&format!("store() call failed: {e:?}")))?;

        JsFuture::from(Promise::from(promise))
            .await
            .map_err(|e| js_err(&format!("store() promise rejected: {e:?}")))?;

        Ok(())
    }

    async fn retrieve(&self, id: &str) -> Result<String, VaultError> {
        let retrieve_fn =
            get_method(&self.host, "retrieve").map_err(|e| js_err(&format!("{e:?}")))?;

        let js_id = JsValue::from_str(id);
        let promise = retrieve_fn
            .call1(&self.host, &js_id)
            .map_err(|e| js_err(&format!("retrieve() call failed: {e:?}")))?;

        let result = JsFuture::from(Promise::from(promise))
            .await
            .map_err(|e| js_err(&format!("retrieve() promise rejected: {e:?}")))?;

        // Check the real type via `dyn_ref` rather than handing a possibly
        // non-Uint8Array result blind to `Uint8Array::new`, which either
        // coerces it into misleading bytes or throws inside the JS
        // constructor — a host contract violation should fail loudly with a
        // typed VaultError, not corrupt data or crash.
        //
        // The read-back copy is wrapped in `Zeroizing` (see the
        // "Zeroization boundary" note above `impl SecretBackend`) so it is
        // scrubbed once this function returns. UTF-8 validation is done via
        // `str::from_utf8` (borrowing) rather than `String::from_utf8`
        // (consuming) specifically so `bytes` stays owned by the `Zeroizing`
        // wrapper — and therefore still gets scrubbed on drop — instead of
        // being moved into the returned `String` or a `FromUtf8Error`. The
        // returned `String` itself is the vault secret, not an intermediate;
        // per CLAUDE.md it is expected to flow onward and is the caller's
        // responsibility to keep short-lived.
        let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
            result
                .dyn_ref::<Uint8Array>()
                .ok_or_else(|| js_err("retrieve() did not resolve to a Uint8Array"))?
                .to_vec(),
        );
        std::str::from_utf8(&bytes)
            .map(str::to_string)
            .map_err(|e| VaultError::Other(format!("retrieve() returned non-UTF-8 bytes: {e}")))
    }

    async fn delete(&self, id: &str) -> Result<(), VaultError> {
        let delete_fn = get_method(&self.host, "delete").map_err(|e| js_err(&format!("{e:?}")))?;

        let js_id = JsValue::from_str(id);
        let promise = delete_fn
            .call1(&self.host, &js_id)
            .map_err(|e| js_err(&format!("delete() call failed: {e:?}")))?;

        JsFuture::from(Promise::from(promise))
            .await
            .map_err(|e| js_err(&format!("delete() promise rejected: {e:?}")))?;

        Ok(())
    }

    async fn exists(&self, id: &str) -> Result<bool, VaultError> {
        let exists_fn = get_method(&self.host, "exists").map_err(|e| js_err(&format!("{e:?}")))?;

        let js_id = JsValue::from_str(id);
        let promise = exists_fn
            .call1(&self.host, &js_id)
            .map_err(|e| js_err(&format!("exists() call failed: {e:?}")))?;

        let result = JsFuture::from(Promise::from(promise))
            .await
            .map_err(|e| js_err(&format!("exists() promise rejected: {e:?}")))?;

        // A non-boolean result is a host contract violation, not a "does not
        // exist" answer — defaulting it to `false` (via `unwrap_or`) would
        // mask a broken host implementation as a normal negative result.
        result
            .as_bool()
            .ok_or_else(|| js_err("exists() did not resolve to a boolean"))
    }
}

#[async_trait::async_trait(?Send)]
impl ListableBackend for JsSecretBackend {
    async fn list(&self) -> Result<Vec<String>, VaultError> {
        if !self.has_list {
            return Err(VaultError::NotCapable {
                message: format!("{} does not implement list()", self.backend_type),
                backend_type: self.backend_type.clone(),
                capability: "list".to_string(),
            });
        }

        let list_fn = get_method(&self.host, "list").map_err(|e| js_err(&format!("{e:?}")))?;
        let promise = list_fn
            .call0(&self.host)
            .map_err(|e| js_err(&format!("list() call failed: {e:?}")))?;

        let result = JsFuture::from(Promise::from(promise))
            .await
            .map_err(|e| js_err(&format!("list() promise rejected: {e:?}")))?;

        // `js_sys::Array::from` on a non-array-like/non-iterable value (e.g.
        // `undefined`, a plain number) throws inside the JS call rather than
        // returning an empty array, and even a genuine array with non-string
        // entries would otherwise have those entries silently dropped below
        // — check `Array.isArray()` first and reject every entry's type
        // explicitly, so a host contract violation fails loudly instead of
        // crashing or producing a partial/incorrect list.
        if !js_sys::Array::is_array(&result) {
            return Err(js_err("list() did not resolve to an array"));
        }
        let arr = js_sys::Array::from(&result);
        let mut ids = Vec::with_capacity(arr.length() as usize);
        for i in 0..arr.length() {
            let s = arr
                .get(i)
                .as_string()
                .ok_or_else(|| js_err("list() array contained a non-string entry"))?;
            ids.push(s);
        }
        Ok(ids)
    }
}

/// Diagnostic-only export: constructs a `JsSecretBackend` from `host` and
/// returns its `{ type, displayName }` identity — issue #239 AC5 "unit
/// coverage with a mock JS backend". Not part of the SDK's public TypeScript
/// API.
#[wasm_bindgen(js_name = "__testJsSecretBackendMeta")]
pub fn __test_js_secret_backend_meta(host: JsValue) -> Result<JsValue, JsValue> {
    let backend = JsSecretBackend::new(host)?;
    let obj = js_sys::Object::new();
    Reflect::set(
        &obj,
        &JsValue::from_str("type"),
        &JsValue::from_str(backend.backend_type()),
    )
    .map_err(|e| JsValue::from(JsError::new(&format!("{e:?}"))))?;
    Reflect::set(
        &obj,
        &JsValue::from_str("displayName"),
        &JsValue::from_str(backend.display_name()),
    )
    .map_err(|e| JsValue::from(JsError::new(&format!("{e:?}"))))?;
    Ok(obj.into())
}

/// Diagnostic-only export exercising `JsSecretBackend::is_available`.
#[wasm_bindgen(js_name = "__testJsSecretBackendIsAvailable")]
pub async fn __test_js_secret_backend_is_available(host: JsValue) -> Result<bool, JsValue> {
    let backend = JsSecretBackend::new(host)?;
    Ok(backend.is_available().await)
}

/// Diagnostic-only export exercising `JsSecretBackend::store`. `secret` is a
/// UTF-8 string on this side of the boundary — the core `SecretBackend`
/// trait's `store`/`retrieve` are `&str`/`String`-based — but crosses to the
/// JS mock as a `Uint8Array`, exactly as a real `JsSecretBackend::store` call
/// would.
#[wasm_bindgen(js_name = "__testJsSecretBackendStore")]
pub async fn __test_js_secret_backend_store(
    host: JsValue,
    id: &str,
    secret: &str,
) -> Result<(), JsValue> {
    let backend = JsSecretBackend::new(host)?;
    backend
        .store(id, secret)
        .await
        .map_err(|e| vault_error_to_js(&e))
}

/// Diagnostic-only export exercising `JsSecretBackend::retrieve`.
#[wasm_bindgen(js_name = "__testJsSecretBackendRetrieve")]
pub async fn __test_js_secret_backend_retrieve(host: JsValue, id: &str) -> Result<String, JsValue> {
    let backend = JsSecretBackend::new(host)?;
    backend
        .retrieve(id)
        .await
        .map_err(|e| vault_error_to_js(&e))
}

/// Diagnostic-only export exercising `JsSecretBackend::delete`.
#[wasm_bindgen(js_name = "__testJsSecretBackendDelete")]
pub async fn __test_js_secret_backend_delete(host: JsValue, id: &str) -> Result<(), JsValue> {
    let backend = JsSecretBackend::new(host)?;
    backend.delete(id).await.map_err(|e| vault_error_to_js(&e))
}

/// Diagnostic-only export exercising `JsSecretBackend::exists`.
#[wasm_bindgen(js_name = "__testJsSecretBackendExists")]
pub async fn __test_js_secret_backend_exists(host: JsValue, id: &str) -> Result<bool, JsValue> {
    let backend = JsSecretBackend::new(host)?;
    backend.exists(id).await.map_err(|e| vault_error_to_js(&e))
}

/// Diagnostic-only export exercising `JsSecretBackend::list`
/// (`ListableBackend`), including the `NotCapable` path when the JS mock
/// doesn't provide `list()`.
#[wasm_bindgen(js_name = "__testJsSecretBackendList")]
pub async fn __test_js_secret_backend_list(host: JsValue) -> Result<Vec<String>, JsValue> {
    let backend = JsSecretBackend::new(host)?;
    backend.list().await.map_err(|e| vault_error_to_js(&e))
}

// ─── WASM API ──────────────────────────────────────────────────────

/// Initialize the WASM module. Called once on load.
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// The canonical list of every machine-readable `vaultErrorCode` this WASM
/// binary can throw — the single source of truth for the error taxonomy (see
/// `ALL_ERROR_CODES` in `crates/vaultkeeper-core/src/errors.rs`).
///
/// `packages/vaultkeeper-wasm/src/test/error-parity.test.ts` fetches this
/// exact list at test time and asserts it equals the TypeScript
/// reconstruction map's known codes exactly, catching drift between the two
/// languages in either direction.
#[wasm_bindgen(js_name = "allVaultErrorCodes")]
#[must_use]
pub fn all_vault_error_codes() -> Vec<String> {
    ALL_ERROR_CODES.iter().map(|s| (*s).to_string()).collect()
}

/// Diagnostic-only export: constructs one instance of every `VaultError`
/// variant with fixed dummy field values and converts each through the real
/// `vault_error_to_js` bridge, exactly as a genuine thrown error would be.
///
/// This exists solely so `error-parity.test.ts` can round-trip real
/// bridge-produced values through the TypeScript reconstruction map, instead
/// of guessing at the JSON shape `vault_error_to_js` produces. It is not part
/// of the SDK's public TypeScript API (`packages/vaultkeeper-wasm/src/index.ts`
/// does not re-export it) and is never called from a real code path — see
/// `all_variants_for_parity_test` in `crates/vaultkeeper-core/src/errors.rs`
/// for the fixture values.
#[wasm_bindgen(js_name = "__testAllVaultErrors")]
pub fn __test_all_vault_errors() -> js_sys::Array {
    let arr = js_sys::Array::new();
    for e in &all_variants_for_parity_test() {
        arr.push(&vault_error_to_js(e));
    }
    arr
}

/// Diagnostic-only export exercising `HostPlatform::http_fetch` directly
/// through the real `JsHostPlatform` bridge (issue #239 AC2 — "land the
/// primitive with direct tests"). No core consumer calls `http_fetch` yet
/// (see the trait default in `crates/vaultkeeper-core/src/backend/types.rs`),
/// so this is the only way to exercise the bridge end-to-end today. Not part
/// of the SDK's public TypeScript API (`packages/vaultkeeper-wasm/src/index.ts`
/// does not re-export it).
///
/// `host` must satisfy the full `JsHostPlatform::new` contract (`platform()`,
/// `configDir()`) in addition to `httpFetch()`, since it's constructed the
/// same way a real `WasmVaultKeeper` host is.
#[wasm_bindgen(js_name = "__testHttpFetch")]
pub async fn __test_http_fetch(host: JsValue, request: JsValue) -> Result<JsValue, JsValue> {
    let js_host = JsHostPlatform::new(host)?;
    let http_request = js_value_to_http_request(&request)?;
    let response = js_host
        .http_fetch(http_request)
        .await
        .map_err(|e| vault_error_to_js(&e))?;
    http_response_to_js(&response).map_err(JsValue::from)
}

/// Diagnostic-only export exercising `HostPlatform::prompt_approval`
/// directly through the real `JsHostPlatform` bridge (issue #239 AC3). Not
/// part of the SDK's public TypeScript API.
#[wasm_bindgen(js_name = "__testPromptApproval")]
pub async fn __test_prompt_approval(
    host: JsValue,
    action: &str,
    detail: &str,
) -> Result<bool, JsValue> {
    let js_host = JsHostPlatform::new(host)?;
    js_host
        .prompt_approval(ApprovalContext { action, detail })
        .await
        .map_err(|e| vault_error_to_js(&e))
}

/// Convert an [`HttpResponse`] to the `{ status, headers, body }` JS shape,
/// for `__testHttpFetch`'s return value.
fn http_response_to_js(response: &HttpResponse) -> Result<JsValue, JsError> {
    let obj = js_sys::Object::new();
    Reflect::set(
        &obj,
        &JsValue::from_str("status"),
        &JsValue::from_f64(f64::from(response.status)),
    )
    .map_err(|e| JsError::new(&format!("{e:?}")))?;

    let headers_obj = js_sys::Object::new();
    for (key, value) in &response.headers {
        Reflect::set(
            &headers_obj,
            &JsValue::from_str(key),
            &JsValue::from_str(value),
        )
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    }
    Reflect::set(&obj, &JsValue::from_str("headers"), &headers_obj)
        .map_err(|e| JsError::new(&format!("{e:?}")))?;

    let body_arr = Uint8Array::new_with_length(response.body.len() as u32);
    body_arr.copy_from(&response.body);
    Reflect::set(&obj, &JsValue::from_str("body"), &body_arr.into())
        .map_err(|e| JsError::new(&format!("{e:?}")))?;

    Ok(obj.into())
}

/// Diagnostic-only export exercising `HostPlatform::exec` directly through
/// the real `JsHostPlatform` bridge (issue #239 AC1, and the malformed-result
/// hardening below it). Lets tests drive a mock host whose `exec()` returns a
/// malformed `stdout`/`stderr`/`exitCode` without needing a core consumer
/// that calls `exec` with such a host. Not part of the SDK's public
/// TypeScript API (`packages/vaultkeeper-wasm/src/index.ts` does not
/// re-export it).
///
/// `host` must satisfy the full `JsHostPlatform::new` contract (`platform()`,
/// `configDir()`) in addition to `exec()`, since it's constructed the same
/// way a real `WasmVaultKeeper` host is.
#[wasm_bindgen(js_name = "__testExec")]
pub async fn __test_exec(host: JsValue, cmd: &str, args: Vec<String>) -> Result<JsValue, JsValue> {
    let js_host = JsHostPlatform::new(host)?;
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = js_host
        .exec(cmd, &args, ExecOptions::default())
        .await
        .map_err(|e| vault_error_to_js(&e))?;
    exec_output_to_js(&output).map_err(JsValue::from)
}

/// Convert an [`ExecOutput`] to the `{ stdout, stderr, exitCode }` JS shape,
/// for `__testExec`'s return value.
fn exec_output_to_js(output: &ExecOutput) -> Result<JsValue, JsError> {
    let obj = js_sys::Object::new();

    let stdout_arr = Uint8Array::new_with_length(output.stdout.len() as u32);
    stdout_arr.copy_from(&output.stdout);
    Reflect::set(&obj, &JsValue::from_str("stdout"), &stdout_arr.into())
        .map_err(|e| JsError::new(&format!("{e:?}")))?;

    let stderr_arr = Uint8Array::new_with_length(output.stderr.len() as u32);
    stderr_arr.copy_from(&output.stderr);
    Reflect::set(&obj, &JsValue::from_str("stderr"), &stderr_arr.into())
        .map_err(|e| JsError::new(&format!("{e:?}")))?;

    Reflect::set(
        &obj,
        &JsValue::from_str("exitCode"),
        &JsValue::from_f64(f64::from(output.exit_code)),
    )
    .map_err(|e| JsError::new(&format!("{e:?}")))?;

    Ok(obj.into())
}

/// WASM-exposed VaultKeeper wrapper.
#[wasm_bindgen]
pub struct WasmVaultKeeper {
    vault: vaultkeeper_core::VaultKeeper,
    host: Arc<JsHostPlatform>,
}

// SAFETY: Single-threaded WASM — no concurrent access.
unsafe impl Send for WasmVaultKeeper {}
unsafe impl Sync for WasmVaultKeeper {}

/// Factory function to create a WasmVaultKeeper.
#[wasm_bindgen(js_name = "createVaultKeeper")]
pub async fn create_vault_keeper(
    host: JsValue,
    options: JsValue,
) -> Result<WasmVaultKeeper, JsValue> {
    let js_host = JsHostPlatform::new(host)?;
    let host = Arc::new(js_host);

    let skip_doctor = if options.is_object() {
        Reflect::get(&options, &JsValue::from_str("skipDoctor"))
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    } else {
        false
    };

    let vault = vaultkeeper_core::VaultKeeper::init(
        host.as_ref(),
        Some(VaultKeeperOptions {
            skip_doctor,
            ..Default::default()
        }),
    )
    .await
    .map_err(|e| vault_error_to_js(&e))?;

    Ok(WasmVaultKeeper { vault, host })
}

#[wasm_bindgen]
impl WasmVaultKeeper {
    /// Run doctor checks and return a PreflightResult as JSON.
    pub async fn doctor(&self) -> Result<JsValue, JsError> {
        let result = vaultkeeper_core::doctor::run_doctor(self.host.as_ref(), None).await;
        to_js_value(&result)
    }

    /// Create a JWE token encapsulating a secret.
    ///
    /// When `options.executablePath` is supplied, the executable is hashed and
    /// run through trust verification (Sigstore → trust-manifest match → TOFU
    /// first-encounter) via the host bridge; a first-encounter TOFU record is
    /// persisted only after the token has been minted (issue #148).
    pub async fn setup(
        &self,
        secret_name: &str,
        secret_value: &str,
        options: JsValue,
    ) -> Result<String, JsValue> {
        let setup_opts = if options.is_object() {
            let ttl = Reflect::get(&options, &JsValue::from_str("ttlMinutes"))
                .ok()
                .and_then(|v| v.as_f64())
                .map(|v| v as u32);
            let use_limit = Reflect::get(&options, &JsValue::from_str("useLimit"))
                .ok()
                .and_then(|v| v.as_f64())
                .map(|v| v as u64);
            let executable_path = Reflect::get(&options, &JsValue::from_str("executablePath"))
                .ok()
                .and_then(|v| v.as_string());
            let skip_trust = Reflect::get(&options, &JsValue::from_str("skipTrust"))
                .ok()
                .and_then(|v| v.as_bool());
            let backend_type = Reflect::get(&options, &JsValue::from_str("backendType"))
                .ok()
                .and_then(|v| v.as_string());

            Some(SetupOptions {
                ttl_minutes: ttl,
                use_limit,
                executable_path,
                skip_trust,
                backend_type,
                trust_tier: None,
            })
        } else {
            None
        };

        self.vault
            .setup(
                self.host.as_ref(),
                secret_name,
                secret_value,
                setup_opts.as_ref(),
            )
            .await
            .map_err(|e| vault_error_to_js(&e))
    }

    /// Decrypt a JWE token, validate its claims, and return a
    /// [`WasmAuthorization`].
    ///
    /// The returned object's `claims` **never** contains the raw secret value
    /// (`val` is redacted) — `vaultkeeper_core::VaultKeeper::authorize` (issue
    /// #241) never returns it either; it stays behind a core-side capability
    /// handle. This call performs the one-time `read_secret` against that
    /// handle immediately, internally, and caches the result on the returned
    /// `WasmAuthorization` exactly as this method always has, so the
    /// `@vaultkeeper/wasm` public shape (`claims`, `response`,
    /// `secretAvailable`, `readSecret()`) is unchanged. The handle itself is
    /// also retained (exposed as `WasmAuthorization.handleId`) so a caller
    /// can additionally use the handle-based entry points below
    /// (`resolveSecretClaims`/`releaseHandle`) — the primitives a future
    /// engine swap would build directly on instead of this eager wrapper.
    pub fn authorize(&mut self, jwe: &str) -> Result<WasmAuthorization, JsValue> {
        // Any non-typed (`Other`) failure while decrypting or validating a
        // token means the token itself is invalid or unprocessable, so it maps
        // to `invalid-token`. Typed variants (expiry, revocation, usage limit,
        // unknown key) keep their own codes.
        let (handle_id, claims, response) = self.vault.authorize(jwe).map_err(|e| match &e {
            VaultError::Other(msg) => coded_js_error("invalid-token", msg),
            _ => vault_error_to_js(&e),
        })?;

        // The one-time read against the handle table — `claims.val` is
        // already empty (see `VaultKeeper::authorize`'s doc comment), so this
        // is the only place the raw secret is ever materialized on this side
        // of the WASM boundary. `read_secret` already returns a
        // `Zeroizing<String>`; move it straight into `WasmAuthorization`
        // rather than `.to_string()`-cloning it into a second, non-zeroizing
        // `String` (the same leak class fixed in `VaultKeeper::authorize` —
        // see that function's doc comment). No extra unprotected Rust-side
        // copy of the secret exists between here and `read_secret()` below.
        let secret = self
            .vault
            .read_secret(&handle_id)
            .map_err(|e| vault_error_to_js(&e))?;

        let mut claims_value =
            serde_json::to_value(&claims).map_err(|e| JsError::new(&e.to_string()))?;
        if let Some(obj) = claims_value.as_object_mut() {
            obj.remove("val");
        }

        let claims_json =
            serde_json::to_string(&claims_value).map_err(|e| JsError::new(&e.to_string()))?;
        let response_json =
            serde_json::to_string(&response).map_err(|e| JsError::new(&e.to_string()))?;

        Ok(WasmAuthorization {
            claims_json,
            response_json,
            secret: Some(secret),
            handle_id: handle_id.as_str().to_string(),
        })
    }

    /// Resolve the non-secret claims behind a capability handle id (issue
    /// #241 AC6 — a new, handle-based entry point for the future engine
    /// swap, alongside the eager `authorize()`/`WasmAuthorization` wrapper
    /// above). Returns the claims as JSON, with `val` always absent. Refuses
    /// a signing-key handle.
    #[wasm_bindgen(js_name = "resolveSecretClaims")]
    pub fn resolve_secret_claims(&mut self, handle_id: &str) -> Result<JsValue, JsValue> {
        validate_handle_id_shape(handle_id)?;
        let handle = vaultkeeper_core::HandleId::from(handle_id.to_string());
        let claims = self
            .vault
            .resolve_secret_claims(&handle)
            .map_err(|e| vault_error_to_js(&e))?;
        let mut claims_value =
            serde_json::to_value(&claims).map_err(|e| JsError::new(&e.to_string()))?;
        if let Some(obj) = claims_value.as_object_mut() {
            obj.remove("val");
        }
        to_js_value(&claims_value).map_err(JsValue::from)
    }

    /// Explicitly release a capability handle (issue #241 AC6). Returns
    /// `true` if a handle was actually present and removed, `false` if it
    /// was already gone (released, expired, or evicted). A caller that is
    /// done with a handle should call this rather than waiting on its
    /// expiry. Throws an `authorization-denied` error for a `handleId` that
    /// is not even shaped like a real handle (see
    /// `validate_handle_id_shape`), rather than allocating/looking it up.
    #[wasm_bindgen(js_name = "releaseHandle")]
    pub fn release_handle(&mut self, handle_id: &str) -> Result<bool, JsValue> {
        validate_handle_id_shape(handle_id)?;
        let handle = vaultkeeper_core::HandleId::from(handle_id.to_string());
        Ok(self.vault.release_handle(&handle))
    }

    /// Rotate the encryption key.
    #[wasm_bindgen(js_name = "rotateKey")]
    pub async fn rotate_key(&mut self) -> Result<(), JsValue> {
        self.vault
            .rotate_key(self.host.as_ref())
            .await
            .map_err(|e| vault_error_to_js(&e))
    }

    /// Emergency key revocation — removes previous key and generates a new current key.
    #[wasm_bindgen(js_name = "revokeKey")]
    pub async fn revoke_key(&mut self) -> Result<(), JsValue> {
        self.vault
            .revoke_key(self.host.as_ref())
            .await
            .map_err(|e| vault_error_to_js(&e))
    }

    /// Get the current configuration as JSON.
    pub fn config(&self) -> Result<JsValue, JsError> {
        to_js_value(self.vault.config())
    }

    /// Store a secret via the file backend.
    ///
    /// FileBackend is stateless (holds only a host reference), so creating it
    /// per-call avoids lifetime complexity without performance cost.
    pub async fn store(&self, id: &str, secret: &str) -> Result<(), JsValue> {
        let backend = FileBackend::new(self.host.clone());
        backend
            .store(id, secret)
            .await
            .map_err(|e| vault_error_to_js(&e))
    }

    /// Retrieve a secret via the file backend.
    pub async fn retrieve(&self, id: &str) -> Result<String, JsValue> {
        let backend = FileBackend::new(self.host.clone());
        backend
            .retrieve(id)
            .await
            .map_err(|e| vault_error_to_js(&e))
    }

    /// Delete a secret via the file backend.
    pub async fn delete(&self, id: &str) -> Result<(), JsValue> {
        let backend = FileBackend::new(self.host.clone());
        backend.delete(id).await.map_err(|e| vault_error_to_js(&e))
    }
}

/// Result of a successful [`WasmVaultKeeper::authorize`] call.
///
/// Holds the validated claims (with the raw secret redacted) and the raw
/// secret behind a one-time read. The secret is deliberately not part of the
/// `claims` shape — callers must opt in explicitly via the exported
/// `readSecret()` method, which yields the value exactly once.
///
/// Also carries the underlying core capability handle id (`handleId`, issue
/// #241 AC6) so a caller can additionally use `WasmVaultKeeper`'s
/// handle-based entry points (`resolveSecretClaims`/`releaseHandle`)
/// directly — the primitives a future engine swap builds on instead of this
/// eager wrapper.
#[wasm_bindgen]
pub struct WasmAuthorization {
    claims_json: String,
    response_json: String,
    /// `Zeroizing`-wrapped so an authorization whose secret is never read
    /// (`readSecret()` not called before this value is dropped) still has
    /// its buffer scrubbed, rather than sitting unzeroized until the
    /// allocator reuses it.
    secret: Option<Zeroizing<String>>,
    handle_id: String,
}

// SAFETY: Single-threaded WASM — no concurrent access.
unsafe impl Send for WasmAuthorization {}
unsafe impl Sync for WasmAuthorization {}

#[wasm_bindgen]
impl WasmAuthorization {
    /// The validated token claims, with the raw secret (`val`) redacted.
    #[wasm_bindgen(getter)]
    pub fn claims(&self) -> Result<JsValue, JsError> {
        js_sys::JSON::parse(&self.claims_json)
            .map_err(|e| JsError::new(&format!("JSON parse error: {e:?}")))
    }

    /// The authorization response (key status, optional rotated token).
    #[wasm_bindgen(getter)]
    pub fn response(&self) -> Result<JsValue, JsError> {
        js_sys::JSON::parse(&self.response_json)
            .map_err(|e| JsError::new(&format!("JSON parse error: {e:?}")))
    }

    /// Whether the secret is still available to read (i.e. `readSecret()` has
    /// not yet been called).
    #[wasm_bindgen(getter, js_name = "secretAvailable")]
    pub fn secret_available(&self) -> bool {
        self.secret.is_some()
    }

    /// The underlying core capability handle id (issue #241 AC6). Usable
    /// with `WasmVaultKeeper.resolveSecretClaims`/`releaseHandle`.
    #[wasm_bindgen(getter, js_name = "handleId")]
    pub fn handle_id(&self) -> String {
        self.handle_id.clone()
    }

    /// Read the raw secret value exactly once. Subsequent calls throw an
    /// `accessor-consumed` error. This is the explicit, deliberately-named
    /// escape hatch for flows that must touch the plaintext secret.
    ///
    /// The Rust side never clones the secret to produce this value: the
    /// plaintext is moved out of the `Zeroizing<String>` wrapper (leaving it
    /// holding an empty string, which is a no-op to scrub on drop) rather
    /// than copied out. The one residual, unprotected copy this cannot close
    /// is on the far side of the `wasm-bindgen`-generated FFI glue itself —
    /// returning an owned `String` from a `#[wasm_bindgen]` method has that
    /// glue copy the bytes into a fresh JS string and then free this Rust
    /// `String` via ordinary (non-zeroizing) `Drop`. That hand-off is
    /// generated code we do not control, and JS strings are immutable and
    /// cannot be scrubbed by this crate regardless — the same trust boundary
    /// already noted for a dishonest/misbehaving JS host elsewhere in this
    /// file (see `JsHostPlatform`'s "No-reentrancy contract").
    #[wasm_bindgen(js_name = "readSecret")]
    pub fn read_secret(&mut self) -> Result<String, JsValue> {
        let mut secret = self.secret.take().ok_or_else(|| {
            coded_js_error(
                "accessor-consumed",
                "Secret has already been read; the one-time accessor is consumed",
            )
        })?;
        Ok(std::mem::take(&mut *secret))
    }
}

/// Serialize a Rust value to a JsValue via JSON parsing in JS.
fn to_js_value<T: serde::Serialize>(value: &T) -> Result<JsValue, JsError> {
    let json = serde_json::to_string(value).map_err(|e| JsError::new(&e.to_string()))?;
    js_sys::JSON::parse(&json).map_err(|e| JsError::new(&format!("JSON parse error: {e:?}")))
}

/// Diagnostic-only export proving the core-resident environment-profile
/// loader (issue #277) is reachable from the TS path through the real WASM
/// binary (AC7's wasm-bridge half; the Rust half is
/// `crates/vaultkeeper-core/tests/profile_loader_integration.rs`). Not part
/// of the SDK's public TypeScript API — `packages/vaultkeeper-wasm/src/index.ts`
/// does not re-export it.
///
/// `config_defaults` is `{ ttlMinutes: number, trustTier: 1 | 2 | 3 }`,
/// mirroring `config.json`'s `defaults` shape; this function performs the
/// same `ttlMinutes` → seconds conversion
/// `vaultkeeper_core::profile::ProfileDefaults::from_vault_defaults` does.
#[wasm_bindgen(js_name = "__testLoadProfile")]
pub fn __test_load_profile(json: &str, config_defaults: JsValue) -> Result<JsValue, JsValue> {
    let ttl_minutes = Reflect::get(&config_defaults, &JsValue::from_str("ttlMinutes"))
        .ok()
        .and_then(|v| v.as_f64())
        .unwrap_or(60.0) as u32;
    let trust_tier_num = Reflect::get(&config_defaults, &JsValue::from_str("trustTier"))
        .ok()
        .and_then(|v| v.as_f64())
        .unwrap_or(3.0) as u8;
    let trust_tier = match trust_tier_num {
        1 => vaultkeeper_core::TrustTier::Sigstore,
        2 => vaultkeeper_core::TrustTier::Tofu,
        _ => vaultkeeper_core::TrustTier::Dev,
    };
    let defaults = vaultkeeper_core::profile::ProfileDefaults {
        ttl_seconds: u64::from(ttl_minutes) * 60,
        trust_tier,
    };

    let loaded = vaultkeeper_core::profile::load_profile_from_str(json, &defaults)
        .map_err(|e| vault_error_to_js(&e))?;
    to_js_value(&loaded).map_err(JsValue::from)
}
