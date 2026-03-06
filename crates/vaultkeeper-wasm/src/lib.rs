//! WASM bindings for vaultkeeper.
//!
//! This crate exposes vaultkeeper-core functionality to JavaScript via wasm-bindgen.
//! The JavaScript side provides a `WasmHostPlatform` implementation that bridges
//! OS calls back to Node.js.
//!
//! All WASM-specific code is gated behind `cfg(target_arch = "wasm32")` because
//! wasm-bindgen types (JsFuture, etc.) are not Send, which conflicts with the
//! HostPlatform trait on native targets.

// On native targets, the crate is an empty lib — only meaningful when compiled to wasm32.
#[cfg(target_arch = "wasm32")]
mod wasm_impl;
