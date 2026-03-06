//! Individual preflight check functions for each system dependency.

use crate::backend::HostPlatform;
use crate::types::{PreflightCheck, PreflightCheckStatus};

/// Parse a semver-like version string and return (major, minor, patch).
fn parse_version(raw: &str) -> Option<(u32, u32, u32)> {
    let re_like = raw
        .split(|c: char| !c.is_ascii_digit() && c != '.')
        .find(|seg| seg.contains('.'))?;

    let parts: Vec<&str> = re_like.splitn(4, '.').collect();
    if parts.len() < 3 {
        return None;
    }
    let major = parts[0].parse().ok()?;
    let minor = parts[1].parse().ok()?;
    let patch = parts[2].parse().ok()?;
    Some((major, minor, patch))
}

/// Returns true if `a >= b` by semver precedence.
fn version_gte(a: (u32, u32, u32), b: (u32, u32, u32)) -> bool {
    if a.0 != b.0 {
        return a.0 > b.0;
    }
    if a.1 != b.1 {
        return a.1 > b.1;
    }
    a.2 >= b.2
}

/// Check that openssl is present and >= 1.1.1.
pub async fn check_openssl(host: &dyn HostPlatform) -> PreflightCheck {
    let name = "openssl".to_string();
    match host.exec("openssl", &["version"], None).await {
        Ok(output) if output.exit_code == 0 => {
            let version_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            match parse_version(&version_str) {
                Some(v) if version_gte(v, (1, 1, 1)) => PreflightCheck {
                    name,
                    status: PreflightCheckStatus::Ok,
                    version: Some(version_str),
                    reason: None,
                },
                Some(_) => PreflightCheck {
                    name,
                    status: PreflightCheckStatus::VersionUnsupported,
                    version: Some(version_str),
                    reason: Some("openssl >= 1.1.1 is required".to_string()),
                },
                None => PreflightCheck {
                    name,
                    status: PreflightCheckStatus::VersionUnsupported,
                    version: Some(version_str),
                    reason: Some("Could not parse openssl version".to_string()),
                },
            }
        }
        _ => PreflightCheck {
            name,
            status: PreflightCheckStatus::Missing,
            version: None,
            reason: Some("openssl not found in PATH".to_string()),
        },
    }
}

/// Check that bash is present.
pub async fn check_bash(host: &dyn HostPlatform) -> PreflightCheck {
    let name = "bash".to_string();
    match host.exec("bash", &["--version"], None).await {
        Ok(output) if output.exit_code == 0 => {
            let full = String::from_utf8_lossy(&output.stdout);
            let first_line = full.lines().next().unwrap_or("").trim().to_string();
            PreflightCheck {
                name,
                status: PreflightCheckStatus::Ok,
                version: Some(first_line),
                reason: None,
            }
        }
        _ => PreflightCheck {
            name,
            status: PreflightCheckStatus::Missing,
            version: None,
            reason: Some("bash not found in PATH".to_string()),
        },
    }
}

/// Check that PowerShell is present (Windows only).
pub async fn check_powershell(host: &dyn HostPlatform) -> PreflightCheck {
    let name = "powershell".to_string();
    match host
        .exec(
            "powershell",
            &["-Command", "$PSVersionTable.PSVersion"],
            None,
        )
        .await
    {
        Ok(output) if output.exit_code == 0 => {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            PreflightCheck {
                name,
                status: PreflightCheckStatus::Ok,
                version: Some(version),
                reason: None,
            }
        }
        _ => PreflightCheck {
            name,
            status: PreflightCheckStatus::Missing,
            version: None,
            reason: Some("powershell not found in PATH".to_string()),
        },
    }
}

/// Check that macOS security CLI is present (macOS only, for Keychain access).
pub async fn check_security(host: &dyn HostPlatform) -> PreflightCheck {
    let name = "security".to_string();
    // `security help` exits non-zero intentionally — if we get any output, it's present.
    match host.exec("security", &["help"], None).await {
        Ok(_) => PreflightCheck {
            name,
            status: PreflightCheckStatus::Ok,
            version: None,
            reason: None,
        },
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("security") {
                PreflightCheck {
                    name,
                    status: PreflightCheckStatus::Ok,
                    version: None,
                    reason: None,
                }
            } else {
                PreflightCheck {
                    name,
                    status: PreflightCheckStatus::Missing,
                    version: None,
                    reason: Some("security command not found in PATH".to_string()),
                }
            }
        }
    }
}

/// Check that secret-tool is present (Linux only).
pub async fn check_secret_tool(host: &dyn HostPlatform) -> PreflightCheck {
    let name = "secret-tool".to_string();
    match host.exec("secret-tool", &["--version"], None).await {
        Ok(output) if output.exit_code == 0 => {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            PreflightCheck {
                name,
                status: PreflightCheckStatus::Ok,
                version: Some(version),
                reason: None,
            }
        }
        _ => PreflightCheck {
            name,
            status: PreflightCheckStatus::Missing,
            version: None,
            reason: Some("secret-tool not found in PATH (install libsecret-tools)".to_string()),
        },
    }
}

/// Check that 1Password CLI (op) is present (optional).
pub async fn check_op(host: &dyn HostPlatform) -> PreflightCheck {
    let name = "op".to_string();
    match host.exec("op", &["--version"], None).await {
        Ok(output) if output.exit_code == 0 => {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            PreflightCheck {
                name,
                status: PreflightCheckStatus::Ok,
                version: Some(version),
                reason: None,
            }
        }
        _ => PreflightCheck {
            name,
            status: PreflightCheckStatus::Missing,
            version: None,
            reason: Some("op (1Password CLI) not found in PATH".to_string()),
        },
    }
}

/// Check that ykman (YubiKey Manager CLI) is present (optional).
pub async fn check_ykman(host: &dyn HostPlatform) -> PreflightCheck {
    let name = "ykman".to_string();
    match host.exec("ykman", &["--version"], None).await {
        Ok(output) if output.exit_code == 0 => {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            PreflightCheck {
                name,
                status: PreflightCheckStatus::Ok,
                version: Some(version),
                reason: None,
            }
        }
        _ => PreflightCheck {
            name,
            status: PreflightCheckStatus::Missing,
            version: None,
            reason: Some("ykman (YubiKey Manager) not found in PATH".to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_extracts_semver() {
        assert_eq!(parse_version("OpenSSL 3.2.1 21 Nov 2023"), Some((3, 2, 1)));
        assert_eq!(parse_version("1.1.1w"), Some((1, 1, 1)));
        assert_eq!(parse_version("3.0.0"), Some((3, 0, 0)));
    }

    #[test]
    fn parse_version_returns_none_for_garbage() {
        assert_eq!(parse_version("no version here"), None);
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn version_gte_comparisons() {
        assert!(version_gte((3, 0, 0), (1, 1, 1)));
        assert!(version_gte((1, 1, 1), (1, 1, 1)));
        assert!(!version_gte((1, 1, 0), (1, 1, 1)));
        assert!(version_gte((1, 2, 0), (1, 1, 9)));
        assert!(!version_gte((0, 9, 9), (1, 0, 0)));
    }
}
