//! Preflight checks for system dependencies.

mod checks;
mod types;

pub use types::DoctorCheckFn;

use crate::backend::{HostPlatform, Platform};
use crate::types::{PreflightCheck, PreflightCheckStatus, PreflightResult};
use checks::{
    check_bash, check_op, check_openssl, check_powershell, check_secret_tool, check_security,
    check_ykman,
};

/// A check entry pairing the check function result with whether it is required.
struct CheckEntry {
    result: PreflightCheck,
    required: bool,
}

/// Run all platform-appropriate preflight checks and return the aggregated result.
pub async fn run_doctor(host: &dyn HostPlatform) -> PreflightResult {
    let platform = host.platform();
    let entries = run_platform_checks(host, platform).await;

    let ready = entries.iter().all(|e| {
        if !e.required {
            return true;
        }
        e.result.status == PreflightCheckStatus::Ok
    });

    let mut warnings = Vec::new();
    let mut next_steps = Vec::new();

    for entry in &entries {
        match entry.result.status {
            PreflightCheckStatus::Missing => {
                if entry.required {
                    next_steps.push(format!(
                        "Install missing required dependency: {}",
                        entry.result.name
                    ));
                } else {
                    let suffix = entry
                        .result
                        .reason
                        .as_ref()
                        .map(|r| format!(" — {r}"))
                        .unwrap_or_default();
                    warnings.push(format!(
                        "Optional dependency not found: {}{}",
                        entry.result.name, suffix
                    ));
                }
            }
            PreflightCheckStatus::VersionUnsupported => {
                let suffix = entry
                    .result
                    .reason
                    .as_ref()
                    .map(|r| format!(": {r}"))
                    .unwrap_or_default();
                let msg = format!("{} version is unsupported{}", entry.result.name, suffix);
                if entry.required {
                    next_steps.push(format!("Upgrade required dependency: {msg}"));
                } else {
                    warnings.push(format!("Optional dependency version unsupported: {msg}"));
                }
            }
            PreflightCheckStatus::Ok => {}
        }
    }

    let checks = entries.into_iter().map(|e| e.result).collect();
    PreflightResult {
        checks,
        ready,
        warnings,
        next_steps,
    }
}

async fn run_platform_checks(host: &dyn HostPlatform, platform: Platform) -> Vec<CheckEntry> {
    let mut entries = vec![CheckEntry {
        result: check_openssl(host).await,
        required: true,
    }];

    match platform {
        Platform::Darwin => {
            entries.push(CheckEntry {
                result: check_security(host).await,
                required: true,
            });
            entries.push(CheckEntry {
                result: check_bash(host).await,
                required: false,
            });
        }
        Platform::Windows => {
            entries.push(CheckEntry {
                result: check_powershell(host).await,
                required: true,
            });
        }
        Platform::Linux => {
            entries.push(CheckEntry {
                result: check_bash(host).await,
                required: true,
            });
            entries.push(CheckEntry {
                result: check_secret_tool(host).await,
                required: true,
            });
        }
    }

    // Optional tools on all platforms
    entries.push(CheckEntry {
        result: check_op(host).await,
        required: false,
    });
    entries.push(CheckEntry {
        result: check_ykman(host).await,
        required: false,
    });

    entries
}
