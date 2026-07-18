//! WASM bindings implementation — only compiled on wasm32.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use js_sys::{Function, Promise, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use vaultkeeper_core::backend::{ExecOutput, FileBackend, HostPlatform, Platform, SecretBackend};
use vaultkeeper_core::errors::{
    ALL_ERROR_CODES, all_variants_for_parity_test, vault_error_code, vault_error_fields,
};
use vaultkeeper_core::vault::{SetupOptions, VaultKeeperOptions};
use vaultkeeper_core::{ExecutableTrustRequiredReason, VaultError};

// ─── JsHostPlatform ──────────────────────────────────────────────

/// A `HostPlatform` implementation backed by JavaScript callbacks.
///
/// The JS object must implement:
/// - `exec(cmd, args, stdin?)` → `Promise<{stdout, stderr, exitCode}>`
/// - `readFile(path)` → `Promise<Uint8Array>`
/// - `writeFile(path, content, mode)` → `Promise<void>`
/// - `fileExists(path)` → `Promise<boolean>`
/// - `deleteFile(path)` → `Promise<void>`
/// - `renameFile(from, to)` → `Promise<void>`
/// - `listDir(path)` → `Promise<string[]>`
/// - `platform()` → `string` ("darwin"|"linux"|"win32")
/// - `configDir()` → `string`
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

#[async_trait::async_trait(?Send)]
impl HostPlatform for JsHostPlatform {
    async fn exec(
        &self,
        cmd: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<ExecOutput, VaultError> {
        let exec_fn = get_method(&self.host, "exec").map_err(|e| js_err(&format!("{e:?}")))?;

        let js_cmd = JsValue::from_str(cmd);
        let js_args = js_sys::Array::new();
        for arg in args {
            js_args.push(&JsValue::from_str(arg));
        }

        let js_stdin = match stdin {
            Some(data) => {
                let arr = Uint8Array::new_with_length(data.len() as u32);
                arr.copy_from(data);
                arr.into()
            }
            None => JsValue::UNDEFINED,
        };

        let promise = exec_fn
            .call3(&self.host, &js_cmd, &js_args, &js_stdin)
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

        let stdout = Uint8Array::new(&stdout_val).to_vec();
        let stderr = Uint8Array::new(&stderr_val).to_vec();
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
    /// (`val` is redacted). The secret is held internally and can be read
    /// exactly once via the exported `readSecret()` method, mirroring the TS
    /// library's one-time accessor pattern.
    pub fn authorize(&mut self, jwe: &str) -> Result<WasmAuthorization, JsValue> {
        // Any non-typed (`Other`) failure while decrypting or validating a
        // token means the token itself is invalid or unprocessable, so it maps
        // to `invalid-token`. Typed variants (expiry, revocation, usage limit,
        // unknown key) keep their own codes.
        let (mut claims, response) = self.vault.authorize(jwe).map_err(|e| match &e {
            VaultError::Other(msg) => coded_js_error("invalid-token", msg),
            _ => vault_error_to_js(&e),
        })?;

        // Move the raw secret out of the claims before anything is serialized,
        // so it can never appear in the returned `claims` object.
        let secret = std::mem::take(&mut claims.val);

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
        })
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
#[wasm_bindgen]
pub struct WasmAuthorization {
    claims_json: String,
    response_json: String,
    secret: Option<String>,
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

    /// Read the raw secret value exactly once. Subsequent calls throw an
    /// `accessor-consumed` error. This is the explicit, deliberately-named
    /// escape hatch for flows that must touch the plaintext secret.
    #[wasm_bindgen(js_name = "readSecret")]
    pub fn read_secret(&mut self) -> Result<String, JsValue> {
        self.secret.take().ok_or_else(|| {
            coded_js_error(
                "accessor-consumed",
                "Secret has already been read; the one-time accessor is consumed",
            )
        })
    }
}

/// Serialize a Rust value to a JsValue via JSON parsing in JS.
fn to_js_value<T: serde::Serialize>(value: &T) -> Result<JsValue, JsError> {
    let json = serde_json::to_string(value).map_err(|e| JsError::new(&e.to_string()))?;
    js_sys::JSON::parse(&json).map_err(|e| JsError::new(&format!("JSON parse error: {e:?}")))
}
