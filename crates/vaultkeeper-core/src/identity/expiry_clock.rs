//! A vault-local JWE clock for issuance, redemption, and handle expiry.

use std::sync::Mutex;

use crate::util::time::now_millis;

/// Matching wall-clock and monotonic samples, both in milliseconds.
struct ClockAnchor {
    wall_ms: u128,
    steady_ms: u128,
}

/// Preserves observed expiry across a wall-clock rollback while letting new tokens age.
#[derive(Default)]
pub(super) struct ExpiryClock {
    /// Shared with issuance through `VaultKeeper::setup(&self)`.
    anchor: Mutex<Option<ClockAnchor>>,
}

impl ExpiryClock {
    /// Observe the effective expiry time as Unix seconds, matching the JWE claim format.
    pub(super) fn read(&self) -> u64 {
        self.read_with(|| (now_millis(), steady_millis()))
    }

    /// Serialize clock observations so concurrent minting cannot reorder the anchor samples.
    pub(super) fn read_with(&self, sample: impl FnOnce() -> (u128, u128)) -> u64 {
        let mut anchor = self
            .anchor
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let (wall_ms, steady_ms) = sample();
        let projected_ms = anchor.as_ref().map_or(wall_ms, |previous| {
            previous
                .wall_ms
                .saturating_add(steady_ms.saturating_sub(previous.steady_ms))
        });
        if wall_ms >= projected_ms {
            *anchor = Some(ClockAnchor { wall_ms, steady_ms });
        }
        u64::try_from(wall_ms.max(projected_ms) / 1_000).unwrap_or(u64::MAX)
    }
}

/// Native monotonic time uses an arbitrary process-local origin.
#[cfg(not(target_arch = "wasm32"))]
fn steady_millis() -> u128 {
    use std::sync::OnceLock;
    use std::time::Instant;

    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis()
}

/// Node's performance clock provides elapsed time for the wasm32 SDK.
#[cfg(target_arch = "wasm32")]
fn steady_millis() -> u128 {
    use js_sys::wasm_bindgen::{JsCast, JsValue};
    use js_sys::{Function, Reflect};
    use std::time::Duration;

    let millis = (|| {
        let performance =
            Reflect::get(&js_sys::global(), &JsValue::from_str("performance")).ok()?;
        let now: Function = Reflect::get(&performance, &JsValue::from_str("now"))
            .ok()?
            .dyn_into()
            .ok()?;
        now.call0(&performance).ok()?.as_f64()
    })();
    // A host without a performance clock still retains the last observed wall time.
    millis
        .and_then(|millis| Duration::try_from_secs_f64(millis / 1_000.0).ok())
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::ExpiryClock;

    #[test]
    fn deadlines_advance_at_elapsed_speed_while_wall_time_is_behind() {
        let clock = ExpiryClock::default();
        assert_eq!(clock.read_with(|| (120_000, 0)), 120);
        let expires_at = clock.read_with(|| (0, 0)) + 60;
        assert_eq!(clock.read_with(|| (59_999, 59_999)), expires_at - 1);
        assert_eq!(clock.read_with(|| (60_000, 60_000)), expires_at);
        assert_eq!(clock.read_with(|| (181_000, 60_001)), expires_at + 1);
    }
}
