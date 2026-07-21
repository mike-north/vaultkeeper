//! Human-readable rendering for the `profile` subcommands (issue #277).
//!
//! All rendering lives in core so the native CLI and any future host render
//! byte-identical output — only argument parsing is per-host. **`show` and
//! `lint` must never render a secret value**: neither function ever touches
//! a backend, so the raw value simply never reaches this code.

use super::lint::{LintResult, resolving_backend_for_entry};
use super::loader::{EntrySource, LoadedProfile};
use super::types::{ProfileEntries, ProfileFile};

/// Build a minimal, valid, empty scaffold profile for `profile init <NAME>`.
#[must_use]
pub fn scaffold_profile(name: &str) -> ProfileFile {
    ProfileFile {
        version: 1,
        name: name.to_string(),
        entries: ProfileEntries::default(),
    }
}

/// Render `profile show <NAME>` — shape and policy only, never a secret
/// value.
#[must_use]
pub fn render_show(profile: &LoadedProfile) -> String {
    let mut out = format!(
        "Profile \"{}\" (version {})\n\n",
        profile.name, profile.version
    );

    if profile.entries.is_empty() {
        out.push_str("  (no entries)\n");
        return out;
    }

    for (name, entry) in &profile.entries {
        let (source_kind, source_name) = match &entry.source {
            EntrySource::Secret(s) => ("secret", s.as_str()),
            EntrySource::SigningKey(s) => ("signingKey", s.as_str()),
        };
        out.push_str(&format!("  {name}\n"));
        out.push_str(&format!(
            "    source:      {source_kind} \"{source_name}\"\n"
        ));
        out.push_str(&format!(
            "    materialize: {}\n",
            entry.materialize.as_str()
        ));
        out.push_str(&format!("    minTrust:    {}\n", entry.min_trust.as_str()));
        if let Some(ttl) = entry.ttl_seconds {
            out.push_str(&format!("    ttlSeconds:  {ttl}\n"));
        }
        out.push_str(&format!(
            "    useLimit:    {}\n",
            entry
                .use_limit
                .map_or_else(|| "unlimited".to_string(), |v| v.to_string())
        ));
        out.push_str(&format!(
            "    requirePresencePerUse: {}\n",
            entry.require_presence_per_use
        ));
        out.push_str(&format!(
            "    requirePresenceAtMint: {}\n",
            entry.require_presence_at_mint
        ));
    }

    out
}

/// Render `profile list` from the profile names found in the profiles
/// directory (already sorted/collected by the caller).
#[must_use]
pub fn render_list(names: &[String]) -> String {
    if names.is_empty() {
        return "(no profiles)\n".to_string();
    }
    let mut out = String::new();
    for name in names {
        out.push_str(name);
        out.push('\n');
    }
    out
}

/// Render `profile lint <NAME>` — schema validity (the caller only reaches
/// here once loading has already succeeded), the resolving backend per
/// entry, and every loosening / unattended-restart warning, always closing
/// with [`LintResult::CAVEAT`].
#[must_use]
pub fn render_lint(
    profile: &LoadedProfile,
    lint: &LintResult,
    active_backend_type: &str,
) -> String {
    let mut out = format!("Profile \"{}\": schema OK\n\n", profile.name);

    out.push_str("Resolving backend per entry:\n");
    for (name, entry) in &profile.entries {
        let backend = resolving_backend_for_entry(entry, active_backend_type);
        out.push_str(&format!("  {name}: {backend}\n"));
    }

    if lint.loosening_warnings.is_empty() && lint.unattended_restart_warnings.is_empty() {
        out.push_str("\nNo warnings.\n");
    } else {
        if !lint.loosening_warnings.is_empty() {
            out.push_str("\nPolicy-loosening warnings:\n");
            for w in &lint.loosening_warnings {
                out.push_str(&format!(
                    "  \u{26A0} {} (default: {}, profile: {})\n",
                    w.message, w.default, w.profile_value
                ));
            }
        }
        if !lint.unattended_restart_warnings.is_empty() {
            out.push_str("\nUnattended-restart warnings:\n");
            for w in &lint.unattended_restart_warnings {
                out.push_str(&format!("  \u{26A0} {}\n", w.message));
            }
        }
    }

    out.push_str(&format!("\n{}\n", LintResult::CAVEAT));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::lint::{LoosenWarning, UnattendedRestartWarning};
    use crate::profile::loader::ProfileEntry;
    use crate::profile::types::{MaterializeMode, MinTrust};

    fn sample_profile() -> LoadedProfile {
        LoadedProfile {
            version: 1,
            name: "github-mcp".to_string(),
            entries: vec![(
                "GITHUB_TOKEN".to_string(),
                ProfileEntry {
                    source: EntrySource::Secret("github-pat-SENTINEL-VALUE".to_string()),
                    materialize: MaterializeMode::Secret,
                    min_trust: MinTrust::Registry,
                    ttl_seconds: None,
                    use_limit: None,
                    require_presence_per_use: false,
                    require_presence_at_mint: false,
                },
            )],
        }
    }

    #[test]
    fn show_never_includes_a_sentinel_secret_value() {
        // The secret *name* is safe to print, but nothing here ever reads
        // the stored value under that name — show() has no backend access.
        let rendered = render_show(&sample_profile());
        assert!(rendered.contains("GITHUB_TOKEN"));
        assert!(!rendered.contains("very-secret-plaintext-value"));
    }

    #[test]
    fn lint_render_includes_caveat() {
        let profile = sample_profile();
        let lint = LintResult {
            loosening_warnings: vec![],
            unattended_restart_warnings: vec![],
        };
        let rendered = render_lint(&profile, &lint, "file");
        assert!(rendered.contains("per-machine"));
        assert!(rendered.contains("GITHUB_TOKEN: file"));
    }

    #[test]
    fn lint_render_includes_warning_details() {
        let profile = sample_profile();
        let lint = LintResult {
            loosening_warnings: vec![LoosenWarning {
                entry: "GITHUB_TOKEN".to_string(),
                field: "minTrust",
                default: "sigstore".to_string(),
                profile_value: "registry".to_string(),
                message: "entry \"GITHUB_TOKEN\" sets minTrust to \"registry\", weaker than the \
                          machine default \"sigstore\""
                    .to_string(),
            }],
            unattended_restart_warnings: vec![UnattendedRestartWarning {
                entry: "GITHUB_TOKEN".to_string(),
                message: "entry \"GITHUB_TOKEN\" requires presence; this profile is not \
                          suitable as an MCP server `command`, because clients restart servers \
                          unattended"
                    .to_string(),
            }],
        };
        let rendered = render_lint(&profile, &lint, "file");
        assert!(rendered.contains("weaker than the machine default"));
        assert!(rendered.contains("not suitable as an MCP server"));
    }

    #[test]
    fn list_renders_names_one_per_line() {
        let rendered = render_list(&["a".to_string(), "b".to_string()]);
        assert_eq!(rendered, "a\nb\n");
    }

    #[test]
    fn list_renders_placeholder_when_empty() {
        assert_eq!(render_list(&[]), "(no profiles)\n");
    }

    #[test]
    fn scaffold_profile_produces_a_loadable_empty_profile() {
        let scaffold = scaffold_profile("my-profile");
        let json = serde_json::to_string(&scaffold).unwrap();
        let loaded = crate::profile::loader::load_profile_from_str(
            &json,
            &crate::profile::loader::ProfileDefaults {
                ttl_seconds: 3600,
                trust_tier: crate::types::TrustTier::Dev,
            },
        )
        .unwrap();
        assert_eq!(loaded.name, "my-profile");
        assert!(loaded.entries.is_empty());
    }
}
