//! WASM bindings for vaultkeeper.
//!
//! This crate exposes vaultkeeper-core functionality to JavaScript via wasm-bindgen.
//! The JavaScript side provides a `WasmHostPlatform` implementation that bridges
//! OS calls back to Node.js.

use wasm_bindgen::prelude::*;

/// Initialize the WASM module. Called once on load.
#[wasm_bindgen(start)]
pub fn init() {
    // Future: set up panic hook for better error messages in JS
}

/// WASM-exposed VaultKeeper wrapper.
#[wasm_bindgen]
pub struct WasmVaultKeeper {
    // TODO: Phase 5 — wrap vaultkeeper_core::VaultKeeper
}

#[wasm_bindgen]
impl WasmVaultKeeper {
    /// Create a new WasmVaultKeeper instance.
    ///
    /// The `host` parameter must be a JavaScript object implementing the
    /// `WasmHostPlatform` interface (exec, readFile, writeFile, etc.).
    #[wasm_bindgen(constructor)]
    pub fn new(_host: JsValue) -> Result<WasmVaultKeeper, JsError> {
        // TODO: Phase 5 — initialize from JS host platform callbacks
        Err(JsError::new("WasmVaultKeeper not yet implemented"))
    }

    /// Run doctor checks.
    pub async fn doctor() -> Result<JsValue, JsError> {
        let result = vaultkeeper_core::doctor::run_doctor().await;
        serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
    }
}

/// Re-export for use in JS interop.
mod serde_wasm_bindgen {
    use serde::Serialize;
    use wasm_bindgen::JsValue;

    /// Serialize a Rust value to a JsValue via JSON round-trip.
    pub fn to_value<T: Serialize>(value: &T) -> Result<JsValue, String> {
        let json = serde_json::to_string(value).map_err(|e| e.to_string())?;
        Ok(JsValue::from_str(&json))
    }
}
