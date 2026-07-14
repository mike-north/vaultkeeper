//! WASM bindings implementation — only compiled on wasm32.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use js_sys::{Function, Promise, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use vaultkeeper_core::VaultError;
use vaultkeeper_core::backend::{ExecOutput, FileBackend, HostPlatform, Platform, SecretBackend};
use vaultkeeper_core::vault::{SetupOptions, VaultKeeperOptions};

// ─── JsHostPlatform ──────────────────────────────────────────────

/// A `HostPlatform` implementation backed by JavaScript callbacks.
///
/// The JS object must implement:
/// - `exec(cmd, args, stdin?)` → `Promise<{stdout, stderr, exitCode}>`
/// - `readFile(path)` → `Promise<Uint8Array>`
/// - `writeFile(path, content, mode)` → `Promise<void>`
/// - `fileExists(path)` → `Promise<boolean>`
/// - `deleteFile(path)` → `Promise<void>`
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

/// Stable machine-readable code for a [`VaultError`], used by the TypeScript
/// bridge to reconstruct a typed error instance from the thrown value.
///
/// Typed variants map one-to-one to a code. `VaultError::Other(..)` — which the
/// core uses for malformed/decryption/validation failures — maps to the generic
/// `vault-error`; `authorize()` reclassifies its own `Other` errors to
/// `invalid-token`, since any non-typed failure there means the token is
/// unprocessable. This mapping is deliberately confined to the WASM boundary.
fn vault_error_code(e: &VaultError) -> &'static str {
    match e {
        VaultError::SecretNotFound { .. } => "secret-not-found",
        VaultError::TokenExpired { .. } => "token-expired",
        VaultError::KeyRotated { .. } => "key-rotated",
        VaultError::KeyRevoked { .. } => "key-revoked",
        VaultError::TokenRevoked { .. } => "token-revoked",
        VaultError::UsageLimitExceeded { .. } => "usage-limit-exceeded",
        VaultError::RotationInProgress { .. } => "rotation-in-progress",
        VaultError::BackendLocked { .. } => "backend-locked",
        VaultError::DeviceNotPresent { .. } => "device-not-present",
        VaultError::AuthorizationDenied { .. } => "authorization-denied",
        VaultError::BackendUnavailable { .. } => "backend-unavailable",
        VaultError::PluginNotFound { .. } => "plugin-not-found",
        VaultError::IdentityMismatch { .. } => "identity-mismatch",
        VaultError::InvalidAlgorithm { .. } => "invalid-algorithm",
        VaultError::Setup { .. } => "setup",
        VaultError::Filesystem { .. } => "filesystem",
        VaultError::Other(_) => "vault-error",
    }
}

/// Convert a [`VaultError`] into a thrown JS value carrying a stable
/// `vaultErrorCode`, its `message`, and any structured context fields. The
/// TypeScript bridge maps `vaultErrorCode` back to a `VaultError` subclass so
/// callers receive a real typed error instance.
fn vault_error_to_js(e: &VaultError) -> JsValue {
    let obj = js_sys::Object::new();
    let set = |k: &str, v: &JsValue| {
        // Reflect::set on a fresh Object cannot fail; ignore the Result.
        let _ = Reflect::set(&obj, &JsValue::from_str(k), v);
    };
    set("vaultErrorCode", &JsValue::from_str(vault_error_code(e)));
    set("message", &JsValue::from_str(&e.to_string()));
    match e {
        VaultError::TokenExpired { can_refresh, .. } => {
            set("canRefresh", &JsValue::from_bool(*can_refresh));
        }
        VaultError::BackendUnavailable {
            reason, attempted, ..
        } => {
            set("reason", &JsValue::from_str(reason));
            let arr = js_sys::Array::new();
            for a in attempted {
                arr.push(&JsValue::from_str(a));
            }
            set("attempted", &arr);
        }
        _ => {}
    }
    obj.into()
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
            .map_err(|e| js_err(&format!("readFile() rejected: {e:?}")))?;

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
            .map_err(|e| js_err(&format!("writeFile() rejected: {e:?}")))?;

        Ok(())
    }

    async fn file_exists(&self, path: &Path) -> Result<bool, VaultError> {
        let exists_fn =
            get_method(&self.host, "fileExists").map_err(|e| js_err(&format!("{e:?}")))?;

        let js_path = JsValue::from_str(&path.to_string_lossy());
        let promise = exists_fn
            .call1(&self.host, &js_path)
            .map_err(|e| js_err(&format!("fileExists() call failed: {e:?}")))?;

        let result = JsFuture::from(Promise::from(promise))
            .await
            .map_err(|e| js_err(&format!("fileExists() rejected: {e:?}")))?;

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
            .map_err(|e| js_err(&format!("deleteFile() rejected: {e:?}")))?;

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
    pub fn setup(
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
            let backend_type = Reflect::get(&options, &JsValue::from_str("backendType"))
                .ok()
                .and_then(|v| v.as_string());

            Some(SetupOptions {
                ttl_minutes: ttl,
                use_limit,
                executable_path,
                backend_type,
                trust_tier: None,
            })
        } else {
            None
        };

        self.vault
            .setup(secret_name, secret_value, setup_opts.as_ref())
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
    pub fn rotate_key(&mut self) -> Result<(), JsValue> {
        self.vault.rotate_key().map_err(|e| vault_error_to_js(&e))
    }

    /// Emergency key revocation — removes previous key and generates a new current key.
    #[wasm_bindgen(js_name = "revokeKey")]
    pub fn revoke_key(&mut self) -> Result<(), JsValue> {
        self.vault.revoke_key().map_err(|e| vault_error_to_js(&e))
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
