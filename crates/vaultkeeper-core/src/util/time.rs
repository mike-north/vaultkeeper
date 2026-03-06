//! Cross-platform time utilities.
//!
//! On native targets, uses `std::time::SystemTime`.
//! On wasm32, uses `js_sys::Date::now()`.

/// Returns the current time as seconds since the Unix epoch.
pub fn now_secs() -> u64 {
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() / 1000.0) as u64
    }
}

/// Returns the current time as milliseconds since the Unix epoch.
pub fn now_millis() -> u128 {
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    }

    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now() as u128
    }
}
