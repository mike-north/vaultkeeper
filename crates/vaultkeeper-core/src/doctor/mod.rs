//! Preflight checks for system dependencies.

mod types;

pub use types::DoctorCheckFn;

use crate::types::PreflightResult;

/// Run all preflight checks and return the aggregated result.
///
/// # Errors
/// Individual checks may fail; the result aggregates all outcomes.
pub async fn run_doctor() -> PreflightResult {
    // TODO: Phase 3 — implement actual dependency checks
    PreflightResult {
        checks: vec![],
        ready: true,
        warnings: vec![],
        next_steps: vec![],
    }
}
