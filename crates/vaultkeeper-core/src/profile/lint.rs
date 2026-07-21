//! `profile lint` — policy-loosening and unattended-restart warnings
//! (issue #277).
//!
//! Everything here is advisory: `profile lint` validates schema (via
//! `crate::profile::loader`) and then reports warnings, but a warning is
//! never a hard gate or CI failure — see [`LintResult::CAVEAT`].

use super::loader::{LoadedProfile, ProfileEntry};
use super::types::MinTrust;

/// The conservative baseline `profile lint` compares `useLimit` and
/// `requirePresencePerUse` against when deciding whether an entry "loosens"
/// policy.
///
/// Unlike `minTrust`/`ttlSeconds`, `config.json`'s `defaults` block does not
/// carry per-field defaults for these two policy knobs — `useLimit` and
/// `requirePresencePerUse` are plain `SetupOptions` fields with no
/// configured baseline (`None`/`false`, i.e. already the loosest possible
/// values). A baseline of "unlimited"/"presence not required" could never be
/// loosened further, which would make two of the four documented loosening
/// checks unreachable. `LintBaseline` is therefore *not* sourced from
/// `config.json`; it is a fixed, documented, conservative reference point —
/// single-use and human-presence-required — chosen so the checks have
/// something meaningful to compare against, in the same direction the other
/// two checks (`minTrust`, `ttlSeconds`, which *are* config-sourced) already
/// lean.
#[derive(Debug, Clone, Copy)]
pub struct LintBaseline {
    pub use_limit: u64,
    pub require_presence_per_use: bool,
}

impl Default for LintBaseline {
    fn default() -> Self {
        Self {
            use_limit: 1,
            require_presence_per_use: true,
        }
    }
}

/// One policy-loosening warning for a single entry/field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoosenWarning {
    pub entry: String,
    pub field: &'static str,
    pub default: String,
    pub profile_value: String,
    pub message: String,
}

/// One unattended-MCP-restart-unsuitability warning for a single entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnattendedRestartWarning {
    pub entry: String,
    pub message: String,
}

/// Full `profile lint` result for a validated profile.
#[derive(Debug, Clone)]
pub struct LintResult {
    pub loosening_warnings: Vec<LoosenWarning>,
    pub unattended_restart_warnings: Vec<UnattendedRestartWarning>,
}

impl LintResult {
    /// The caveat every `lint` rendering must carry: `config.json` is
    /// per-machine while the profile is per-repository, so "loosening" is
    /// evaluated only against the linting machine's defaults, and is always
    /// advisory — never a hard gate. Also spells out which of the two
    /// baselines each policy field is compared against (see
    /// [`loosening_warnings_for_entry`]'s per-warning `message`, which
    /// already says "machine default" vs. "lint baseline" for the field it
    /// concerns), so a warning's provenance is clear without re-deriving it.
    pub const CAVEAT: &'static str = "Note: config.json is per-machine while the profile is \
        per-repository, so this loosening check is evaluated against the linting machine's \
        current defaults. minTrust and ttlSeconds warnings compare against this machine's \
        config.json defaults; useLimit and requirePresencePerUse warnings compare against a \
        fixed, conservative baseline (config.json carries no per-field default for either) — \
        each warning's message says which. This whole check is advisory only, never a hard gate \
        or CI failure; `profile lint` always exits 0 on a successfully-loaded profile regardless \
        of warnings.";
}

/// Compare `entry` against `defaults`/`baseline` and collect any loosening
/// warnings, defined precisely (issue #277) as any of:
/// - a weaker `minTrust` (further toward `unverified`)
/// - a longer `ttlSeconds`
/// - a higher or absent `useLimit`
/// - `requirePresencePerUse: false` where the default is `true`
fn loosening_warnings_for_entry(
    name: &str,
    entry: &ProfileEntry,
    config_min_trust: MinTrust,
    config_ttl_seconds: u64,
    baseline: LintBaseline,
) -> Vec<LoosenWarning> {
    let mut warnings = Vec::new();

    if entry.min_trust < config_min_trust {
        warnings.push(LoosenWarning {
            entry: name.to_string(),
            field: "minTrust",
            default: config_min_trust.as_str().to_string(),
            profile_value: entry.min_trust.as_str().to_string(),
            message: format!(
                "entry \"{name}\" sets minTrust to \"{}\", weaker than the machine default \
                 \"{}\"",
                entry.min_trust.as_str(),
                config_min_trust.as_str()
            ),
        });
    }

    if let Some(ttl) = entry.ttl_seconds
        && ttl > config_ttl_seconds
    {
        warnings.push(LoosenWarning {
            entry: name.to_string(),
            field: "ttlSeconds",
            default: config_ttl_seconds.to_string(),
            profile_value: ttl.to_string(),
            message: format!(
                "entry \"{name}\" sets ttlSeconds to {ttl}, longer than the machine \
                 default {config_ttl_seconds}"
            ),
        });
    }

    let use_limit_loosens = match entry.use_limit {
        None => true,
        Some(limit) => limit > baseline.use_limit,
    };
    if use_limit_loosens {
        warnings.push(LoosenWarning {
            entry: name.to_string(),
            field: "useLimit",
            default: baseline.use_limit.to_string(),
            profile_value: entry
                .use_limit
                .map_or_else(|| "absent (unlimited)".to_string(), |v| v.to_string()),
            message: format!(
                "entry \"{name}\" sets useLimit to {}, higher than (or absent versus) the \
                 lint baseline {}",
                entry
                    .use_limit
                    .map_or_else(|| "absent".to_string(), |v| v.to_string()),
                baseline.use_limit
            ),
        });
    }

    if baseline.require_presence_per_use && !entry.require_presence_per_use {
        warnings.push(LoosenWarning {
            entry: name.to_string(),
            field: "requirePresencePerUse",
            default: "true".to_string(),
            profile_value: "false".to_string(),
            message: format!(
                "entry \"{name}\" sets requirePresencePerUse to false, but the lint baseline \
                 default is true"
            ),
        });
    }

    warnings
}

/// Warn when an entry requires presence — unsuitable for an MCP server
/// `command`, since clients restart servers unattended.
fn unattended_restart_warning_for_entry(
    name: &str,
    entry: &ProfileEntry,
) -> Option<UnattendedRestartWarning> {
    let requires_presence = entry.require_presence_per_use || entry.require_presence_at_mint;
    if !requires_presence {
        return None;
    }
    Some(UnattendedRestartWarning {
        entry: name.to_string(),
        message: format!(
            "entry \"{name}\" requires presence; this profile is not suitable as an MCP \
             server `command`, because clients restart servers unattended"
        ),
    })
}

/// Lint every entry in `profile` against the linting machine's `config.json`
/// defaults (`config_trust_tier`/`config_ttl_seconds`), using `baseline` for
/// the two policy fields `config.json` does not carry defaults for. See
/// [`LintBaseline`] and [`LintResult::CAVEAT`].
#[must_use]
pub fn lint_profile(
    profile: &LoadedProfile,
    config_trust_tier: crate::types::TrustTier,
    config_ttl_seconds: u64,
    baseline: LintBaseline,
) -> LintResult {
    let config_min_trust = MinTrust::from_trust_tier(config_trust_tier);
    let mut loosening_warnings = Vec::new();
    let mut unattended_restart_warnings = Vec::new();

    for (name, entry) in &profile.entries {
        loosening_warnings.extend(loosening_warnings_for_entry(
            name,
            entry,
            config_min_trust,
            config_ttl_seconds,
            baseline,
        ));
        if let Some(w) = unattended_restart_warning_for_entry(name, entry) {
            unattended_restart_warnings.push(w);
        }
    }

    LintResult {
        loosening_warnings,
        unattended_restart_warnings,
    }
}

/// The resolving backend for `entry`, per issue #277's "report the resolving
/// backend per entry". Profiles do not select a backend themselves — every
/// entry resolves through the single active/configured backend (the same one
/// `store`/`delete`/`exec` use), regardless of `materialize` mode.
#[must_use]
pub fn resolving_backend_for_entry(_entry: &ProfileEntry, active_backend_type: &str) -> String {
    active_backend_type.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::loader::{EntrySource, ProfileEntry};
    use crate::profile::types::MaterializeMode;

    fn base_entry() -> ProfileEntry {
        ProfileEntry {
            source: EntrySource::Secret("s".to_string()),
            materialize: MaterializeMode::Secret,
            min_trust: MinTrust::Registry,
            ttl_seconds: None,
            use_limit: Some(1),
            require_presence_per_use: true,
            require_presence_at_mint: false,
        }
    }

    #[test]
    fn warns_on_weaker_min_trust() {
        let entry = ProfileEntry {
            min_trust: MinTrust::Unverified,
            ..base_entry()
        };
        let warnings = loosening_warnings_for_entry(
            "K",
            &entry,
            MinTrust::Registry,
            3600,
            LintBaseline::default(),
        );
        assert!(warnings.iter().any(|w| w.field == "minTrust"));
    }

    #[test]
    fn does_not_warn_on_equal_or_stronger_min_trust() {
        let entry = ProfileEntry {
            min_trust: MinTrust::Sigstore,
            ..base_entry()
        };
        let warnings = loosening_warnings_for_entry(
            "K",
            &entry,
            MinTrust::Registry,
            3600,
            LintBaseline::default(),
        );
        assert!(!warnings.iter().any(|w| w.field == "minTrust"));
    }

    #[test]
    fn warns_on_longer_ttl_seconds() {
        let entry = ProfileEntry {
            materialize: MaterializeMode::Lease,
            ttl_seconds: Some(7200),
            ..base_entry()
        };
        let warnings = loosening_warnings_for_entry(
            "K",
            &entry,
            MinTrust::Registry,
            3600,
            LintBaseline::default(),
        );
        assert!(warnings.iter().any(|w| w.field == "ttlSeconds"));
    }

    #[test]
    fn warns_on_higher_use_limit() {
        let entry = ProfileEntry {
            use_limit: Some(50),
            ..base_entry()
        };
        let warnings = loosening_warnings_for_entry(
            "K",
            &entry,
            MinTrust::Registry,
            3600,
            LintBaseline::default(),
        );
        assert!(warnings.iter().any(|w| w.field == "useLimit"));
    }

    #[test]
    fn warns_on_absent_use_limit() {
        let entry = ProfileEntry {
            use_limit: None,
            ..base_entry()
        };
        let warnings = loosening_warnings_for_entry(
            "K",
            &entry,
            MinTrust::Registry,
            3600,
            LintBaseline::default(),
        );
        assert!(warnings.iter().any(|w| w.field == "useLimit"));
    }

    #[test]
    fn warns_on_require_presence_per_use_false_vs_true_default() {
        let entry = ProfileEntry {
            require_presence_per_use: false,
            ..base_entry()
        };
        let warnings = loosening_warnings_for_entry(
            "K",
            &entry,
            MinTrust::Registry,
            3600,
            LintBaseline::default(),
        );
        assert!(warnings.iter().any(|w| w.field == "requirePresencePerUse"));
    }

    #[test]
    fn no_warnings_for_a_strict_entry() {
        let warnings = loosening_warnings_for_entry(
            "K",
            &base_entry(),
            MinTrust::Registry,
            3600,
            LintBaseline::default(),
        );
        assert!(warnings.is_empty());
    }

    #[test]
    fn caveat_mentions_per_machine_vs_per_repository() {
        assert!(LintResult::CAVEAT.contains("per-machine"));
        assert!(LintResult::CAVEAT.contains("per-repository"));
        assert!(LintResult::CAVEAT.contains("advisory"));
    }

    #[test]
    fn unattended_restart_warning_fires_on_require_presence_per_use() {
        let entry = ProfileEntry {
            require_presence_per_use: true,
            ..base_entry()
        };
        assert!(unattended_restart_warning_for_entry("K", &entry).is_some());
    }

    #[test]
    fn unattended_restart_warning_fires_on_require_presence_at_mint() {
        let entry = ProfileEntry {
            require_presence_per_use: false,
            require_presence_at_mint: true,
            ..base_entry()
        };
        assert!(unattended_restart_warning_for_entry("K", &entry).is_some());
    }

    #[test]
    fn unattended_restart_warning_absent_when_no_presence_required() {
        let entry = ProfileEntry {
            require_presence_per_use: false,
            require_presence_at_mint: false,
            ..base_entry()
        };
        assert!(unattended_restart_warning_for_entry("K", &entry).is_none());
    }
}
