//! `vaultkeeper run` verb (issue #279): flag semantics, `--set` overlay
//! merging, and `--dry-run` rendering — shared by every host so the native
//! Rust CLI and any future host render byte-identical output. Only argument
//! parsing and the final process spawn/signal-forwarding are per-host (see
//! `vaultkeeper-cli`'s `run` subcommand).
//!
//! `run` is deliberately a **new** verb, not an extension of `exec`: `exec
//! --token <jwe> -- cmd` is token *redemption*; `run --profile <name> -- cmd`
//! is environment *composition* (named declaration, minting where needed,
//! launch). This module owns exactly the composition half — resolving a
//! [`LoadedProfile`] plus any `--set` overrides into a [`RunPlan`] and
//! rendering it — never the spawn itself, matching `crate::resolve`'s
//! "never spawns" boundary (`run` layers directly on top of
//! `crate::resolve::resolve_profile`, never on `HostPlatform::exec`, which
//! captures output and would break MCP stdio transparency).

use std::collections::BTreeSet;

use crate::errors::VaultError;
use crate::profile::loader::{
    EntrySource, LoadedProfile, ProfileDefaults, ProfileEntry, is_valid_env_var_name,
};
use crate::profile::types::{MaterializeMode, MinTrust};

/// One parsed, validated `run --set VAR=SECRET` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetEntry {
    /// The env-var name the resolved secret is exposed as.
    pub var: String,
    /// The secret's name in the active backend (not the value itself — the
    /// value is only ever resolved at launch time, via
    /// [`crate::resolve::resolve_profile`]).
    pub secret_name: String,
}

/// Parse and validate a single `--set` flag's raw value (`VAR=SECRET`).
///
/// # Errors
/// Returns [`VaultError::ConfigValidation`] when:
/// - `raw` has no `=` separator,
/// - the `VAR` half fails the same `[A-Z_][A-Z0-9_]*` shape every profile
///   entry name must match (see `crate::profile::loader`'s load-time
///   invariant #3) — an ad-hoc `--set` entry is held to the identical
///   invariant a profile-file-declared entry is,
/// - the `SECRET` half is empty.
pub fn parse_set_flag(raw: &str) -> Result<SetEntry, VaultError> {
    fn invalid(message: impl Into<String>) -> VaultError {
        VaultError::ConfigValidation {
            message: message.into(),
            field: "--set".to_string(),
            config_file_path: None,
        }
    }

    let Some((var, secret_name)) = raw.split_once('=') else {
        return Err(invalid(format!(
            "--set \"{raw}\" is not of the form VAR=SECRET (missing \"=\")"
        )));
    };

    if !is_valid_env_var_name(var) {
        return Err(invalid(format!(
            "--set \"{raw}\": \"{var}\" is not a valid env var name — must match \
             [A-Z_][A-Z0-9_]*"
        )));
    }

    if secret_name.is_empty() {
        return Err(invalid(format!(
            "--set \"{raw}\": the SECRET name (after \"=\") must not be empty"
        )));
    }

    Ok(SetEntry {
        var: var.to_string(),
        secret_name: secret_name.to_string(),
    })
}

/// A profile with every `--set` overlay applied — ready for `--dry-run`
/// rendering or resolution via [`crate::resolve::resolve_profile`].
#[derive(Debug, Clone)]
pub struct RunPlan {
    /// The merged profile: every declared entry, with `--set` overrides/
    /// additions applied.
    pub profile: LoadedProfile,
    /// Env-var names sourced from `--set` rather than the declared profile
    /// file — rendered as `UNREVIEWED` in `--dry-run` output, per the
    /// issue's contract: "so improvised policy is visibly distinct from
    /// declared-and-reviewed policy".
    pub ad_hoc: BTreeSet<String>,
}

/// Layer parsed `--set` entries over an already-loaded profile.
///
/// Each `--set VAR=SECRET` becomes a `materialize: "secret"` entry at the
/// active `defaults.trustTier` — never `"lease"` (an ad-hoc CLI flag is not
/// a place to improvise a mint policy) and never carrying either presence
/// flag. A `--set` naming a var the profile already declares *overrides*
/// that entry for this invocation only (the on-disk profile is never
/// written back), rather than erroring — the same "last write wins" flag
/// semantics `dev-mode --enable`/omit already uses elsewhere in this CLI.
#[must_use]
pub fn apply_set_overlay(
    mut profile: LoadedProfile,
    set_entries: &[SetEntry],
    defaults: &ProfileDefaults,
) -> RunPlan {
    let mut ad_hoc = BTreeSet::new();
    for entry in set_entries {
        let overlay_entry = ProfileEntry {
            source: EntrySource::Secret(entry.secret_name.clone()),
            materialize: MaterializeMode::Secret,
            min_trust: MinTrust::from_trust_tier(defaults.trust_tier),
            ttl_seconds: None,
            use_limit: None,
            require_presence_per_use: false,
            require_presence_at_mint: false,
        };
        if let Some(existing) = profile
            .entries
            .iter_mut()
            .find(|(name, _)| name == &entry.var)
        {
            existing.1 = overlay_entry;
        } else {
            profile.entries.push((entry.var.clone(), overlay_entry));
        }
        ad_hoc.insert(entry.var.clone());
    }
    RunPlan { profile, ad_hoc }
}

/// Render `run --dry-run`: every var, its rung (materialize mode), source
/// backend, and resolved policy — **never a value**, and never touching a
/// backend or minting anything (issue #279's plan-only contract). Printed to
/// stdout by the caller; `run --dry-run` is the one `run` invocation allowed
/// to write to stdout, because it exits before any child launches.
#[must_use]
pub fn render_dry_run(
    plan: &RunPlan,
    active_backend_type: &str,
    require_presence_at_issuance: bool,
) -> String {
    let mut out = String::from(
        "vaultkeeper run --dry-run: plan only \u{2014} nothing minted, nothing launched.\n\n",
    );

    if require_presence_at_issuance {
        // `--dry-run` never launches or mints regardless, so disclosing this
        // is harmless — but it must not imply a *real* run would silently
        // proceed: `run` refuses outright (never a silent no-op) when this
        // flag is set, because presence-at-issuance enforcement (verifying
        // every minted lease entry's `pres` claim) is not yet wired into
        // `resolve_profile` (issue #279 — fail-closed, matching the
        // NotCapable/MaterializeModeUnsupported posture used elsewhere in
        // this codebase for an unbacked guarantee).
        out.push_str(
            "--require-presence-at-issuance: true (a real, non-dry-run `run` REFUSES with \
             this flag set \u{2014} presence-at-issuance enforcement is not yet wired into \
             `run`)\n\n",
        );
    }

    if plan.profile.entries.is_empty() {
        out.push_str("  (no entries)\n");
        return out;
    }

    for (name, entry) in &plan.profile.entries {
        let rung = match entry.materialize {
            MaterializeMode::Secret => "2 (secret)",
            MaterializeMode::Lease => "3 (lease)",
        };
        out.push_str(&format!("  {name}\n"));
        out.push_str(&format!("    rung:        {rung}\n"));
        out.push_str(&format!("    backend:     {active_backend_type}\n"));
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
        if plan.ad_hoc.contains(name) {
            out.push_str("    UNREVIEWED (ad hoc --set entry, not part of the declared profile)\n");
        }
    }

    out
}

/// The default env var a `run --token`/`exec` redeemed secret is injected
/// under when `--as` is not given — matching `exec`'s long-standing
/// `VAULTKEEPER_SECRET` default so `exec --token <jwe> -- cmd` and
/// `run --token <jwe> -- cmd` (no `--as`) are byte-for-byte identical on the
/// child's environment (issue #333 AC1).
pub const DEFAULT_TOKEN_VAR: &str = "VAULTKEEPER_SECRET";

/// Validate a `run --as <VAR>` / redeemed-token target env var name.
///
/// Reuses the identical `[A-Z_][A-Z0-9_]*` shape every other env-var-name
/// surface in this crate is held to ([`is_valid_env_var_name`], also used by
/// `--set`'s `VAR` half and every profile entry name) — an `--as` name is not
/// a looser or stricter invariant than those.
///
/// # Errors
/// Returns [`VaultError::ConfigValidation`] (field `"--as"`) when `name`
/// does not match that shape.
pub fn validate_as_var_name(name: &str) -> Result<(), VaultError> {
    if is_valid_env_var_name(name) {
        return Ok(());
    }
    Err(VaultError::ConfigValidation {
        message: format!(
            "--as \"{name}\" is not a valid env var name — must match [A-Z_][A-Z0-9_]*"
        ),
        field: "--as".to_string(),
        config_file_path: None,
    })
}

/// Render `run --token --dry-run`: the single var the redeemed token will be
/// injected under, plus any `--set` overlay entries — mirroring
/// [`render_dry_run`]'s shape for the profile source, but for the token
/// source: the primary entry is never resolved through the active backend
/// (a token is redeemed directly, not minted/looked up), so it is rendered
/// with an explicit `source: --token (redeemed at launch)` line instead of a
/// `backend:` column, keeping the two sources visually distinct rather than
/// implying the token entry went through backend resolution it never did.
/// Never touches the vault or decrypts the token — dry-run must never mint,
/// resolve, or launch (issue #279's plan-only contract, extended to the
/// token source by issue #333).
#[must_use]
pub fn render_token_dry_run(as_var: &str, set_plan: &RunPlan, active_backend_type: &str) -> String {
    let mut out = String::from(
        "vaultkeeper run --dry-run: plan only \u{2014} nothing redeemed, nothing launched.\n\n",
    );

    out.push_str(&format!("  {as_var}\n"));
    out.push_str("    rung:        2 (secret)\n");
    out.push_str("    source:      --token (redeemed at launch, not resolved now)\n");

    for (name, entry) in &set_plan.profile.entries {
        let rung = match entry.materialize {
            MaterializeMode::Secret => "2 (secret)",
            MaterializeMode::Lease => "3 (lease)",
        };
        out.push_str(&format!("  {name}\n"));
        out.push_str(&format!("    rung:        {rung}\n"));
        out.push_str(&format!("    backend:     {active_backend_type}\n"));
        out.push_str("    UNREVIEWED (ad hoc --set entry, not part of the declared profile)\n");
    }

    out
}

/// The file-only degradation notice: emitted on **stderr only, never
/// stdout**, whenever every entry `run` resolves goes through the `file`
/// backend. File-only resolution buys organizational hygiene — no plaintext
/// at rest, centralized rotation, a TTL/policy/audit trail — but explicitly
/// not "the OS is protecting your key" the way a platform keychain or
/// hardware token would (issue #279).
pub const FILE_ONLY_DEGRADATION_NOTICE: &str = "Notice: every entry in this run resolved through the file backend. This buys \
     organizational hygiene (no plaintext at rest, centralized rotation, a \
     TTL/policy/audit trail) but not OS-level key protection the way a platform \
     keychain or hardware token would. Configure a platform backend for a stronger \
     guarantee.";

/// Whether the file-only degradation notice applies: the active backend is
/// `file` and the plan resolves at least one entry through it. An empty
/// profile resolves nothing, so it never fires the notice.
#[must_use]
pub fn file_only_degradation_applies(plan: &RunPlan, active_backend_type: &str) -> bool {
    active_backend_type == "file" && !plan.profile.entries.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::loader::load_profile_from_str;
    use crate::types::TrustTier;
    use assert_matches::assert_matches;

    fn defaults() -> ProfileDefaults {
        ProfileDefaults {
            ttl_seconds: 3600,
            trust_tier: TrustTier::Dev,
        }
    }

    // --- parse_set_flag ---

    #[test]
    fn parse_set_flag_accepts_var_equals_secret() {
        let parsed = parse_set_flag("GITHUB_TOKEN=github-pat").unwrap();
        assert_eq!(parsed.var, "GITHUB_TOKEN");
        assert_eq!(parsed.secret_name, "github-pat");
    }

    #[test]
    fn parse_set_flag_rejects_missing_equals() {
        let err = parse_set_flag("GITHUB_TOKEN").unwrap_err();
        assert_matches!(err, VaultError::ConfigValidation { field, .. } if field == "--set");
    }

    #[test]
    fn parse_set_flag_rejects_invalid_var_name() {
        let err = parse_set_flag("lower_case=secret").unwrap_err();
        assert_matches!(err, VaultError::ConfigValidation { .. });
    }

    #[test]
    fn parse_set_flag_rejects_empty_secret_name() {
        let err = parse_set_flag("VAR=").unwrap_err();
        assert_matches!(err, VaultError::ConfigValidation { .. });
    }

    #[test]
    fn parse_set_flag_allows_equals_signs_inside_the_secret_name() {
        // split_once takes the *first* '=' — a secret name containing '=' is
        // unusual but not invalid, and must not be rejected or truncated.
        let parsed = parse_set_flag("VAR=secret=with=equals").unwrap();
        assert_eq!(parsed.secret_name, "secret=with=equals");
    }

    // --- apply_set_overlay ---

    #[test]
    fn set_overlay_adds_a_new_entry_as_materialize_secret_and_marks_it_ad_hoc() {
        let profile = load_profile_from_str(
            r#"{ "version": 1, "name": "p", "entries": {} }"#,
            &defaults(),
        )
        .unwrap();
        let sets = vec![SetEntry {
            var: "TOKEN".to_string(),
            secret_name: "my-secret".to_string(),
        }];
        let plan = apply_set_overlay(profile, &sets, &defaults());

        assert_eq!(plan.profile.entries.len(), 1);
        let (name, entry) = &plan.profile.entries[0];
        assert_eq!(name, "TOKEN");
        assert_eq!(entry.source, EntrySource::Secret("my-secret".to_string()));
        assert_eq!(entry.materialize, MaterializeMode::Secret);
        assert!(!entry.require_presence_per_use);
        assert!(!entry.require_presence_at_mint);
        assert!(plan.ad_hoc.contains("TOKEN"));
    }

    #[test]
    fn set_overlay_overrides_an_existing_declared_entry() {
        let profile = load_profile_from_str(
            r#"{
                "version": 1, "name": "p",
                "entries": { "TOKEN": { "secret": "declared", "materialize": "secret" } }
            }"#,
            &defaults(),
        )
        .unwrap();
        let sets = vec![SetEntry {
            var: "TOKEN".to_string(),
            secret_name: "improvised".to_string(),
        }];
        let plan = apply_set_overlay(profile, &sets, &defaults());

        // Override, not a duplicate entry.
        assert_eq!(plan.profile.entries.len(), 1);
        let (_, entry) = &plan.profile.entries[0];
        assert_eq!(entry.source, EntrySource::Secret("improvised".to_string()));
        assert!(plan.ad_hoc.contains("TOKEN"));
    }

    #[test]
    fn set_overlay_never_produces_a_lease_entry() {
        let profile = load_profile_from_str(
            r#"{ "version": 1, "name": "p", "entries": {} }"#,
            &defaults(),
        )
        .unwrap();
        let sets = vec![SetEntry {
            var: "TOKEN".to_string(),
            secret_name: "s".to_string(),
        }];
        let plan = apply_set_overlay(profile, &sets, &defaults());
        assert_eq!(
            plan.profile.entries[0].1.materialize,
            MaterializeMode::Secret
        );
    }

    // --- render_dry_run ---

    #[test]
    fn dry_run_render_never_includes_a_value_and_marks_set_entries_unreviewed() {
        let profile = load_profile_from_str(
            r#"{
                "version": 1, "name": "p",
                "entries": {
                    "DECLARED": { "secret": "declared-secret-VALUE-sentinel", "materialize": "secret" }
                }
            }"#,
            &defaults(),
        )
        .unwrap();
        let sets = vec![SetEntry {
            var: "ADHOC".to_string(),
            secret_name: "adhoc-secret".to_string(),
        }];
        let plan = apply_set_overlay(profile, &sets, &defaults());
        let rendered = render_dry_run(&plan, "file", false);

        assert!(rendered.contains("DECLARED"));
        assert!(rendered.contains("ADHOC"));
        assert!(rendered.contains("UNREVIEWED"));
        // The DECLARED entry's line must not be marked UNREVIEWED — only
        // check the ADHOC entry's own block carries the marker by asserting
        // the marker count matches the ad-hoc entry count.
        assert_eq!(rendered.matches("UNREVIEWED").count(), 1);
        assert!(!rendered.contains("declared-secret-VALUE-sentinel"));
        assert!(!rendered.contains("adhoc-secret\n")); // secret *name* may appear via source, but no value does
    }

    #[test]
    fn dry_run_render_reports_require_presence_at_issuance_would_refuse_a_real_run() {
        let profile = load_profile_from_str(
            r#"{ "version": 1, "name": "p", "entries": {} }"#,
            &defaults(),
        )
        .unwrap();
        let plan = apply_set_overlay(profile, &[], &defaults());
        let rendered = render_dry_run(&plan, "file", true);
        assert!(rendered.contains("--require-presence-at-issuance: true"));
        assert!(rendered.contains("REFUSES"));
    }

    #[test]
    fn dry_run_render_includes_use_limit_for_an_entry_that_has_one() {
        let profile = load_profile_from_str(
            r#"{
                "version": 1, "name": "p",
                "entries": {
                    "LIMITED": { "secret": "s", "materialize": "secret", "useLimit": 3 }
                }
            }"#,
            &defaults(),
        )
        .unwrap();
        let plan = apply_set_overlay(profile, &[], &defaults());
        let rendered = render_dry_run(&plan, "file", false);
        assert!(rendered.contains("    useLimit:    3\n"));
    }

    #[test]
    fn dry_run_render_reports_use_limit_as_unlimited_when_absent() {
        let profile = load_profile_from_str(
            r#"{
                "version": 1, "name": "p",
                "entries": {
                    "UNLIMITED": { "secret": "s", "materialize": "secret" }
                }
            }"#,
            &defaults(),
        )
        .unwrap();
        let plan = apply_set_overlay(profile, &[], &defaults());
        let rendered = render_dry_run(&plan, "file", false);
        assert!(rendered.contains("    useLimit:    unlimited\n"));
    }

    #[test]
    fn dry_run_render_handles_an_empty_plan() {
        let profile = load_profile_from_str(
            r#"{ "version": 1, "name": "p", "entries": {} }"#,
            &defaults(),
        )
        .unwrap();
        let plan = apply_set_overlay(profile, &[], &defaults());
        let rendered = render_dry_run(&plan, "file", false);
        assert!(rendered.contains("(no entries)"));
    }

    // --- file_only_degradation_applies ---

    #[test]
    fn degradation_notice_applies_for_a_nonempty_plan_on_the_file_backend() {
        let profile = load_profile_from_str(
            r#"{
                "version": 1, "name": "p",
                "entries": { "K": { "secret": "s", "materialize": "secret" } }
            }"#,
            &defaults(),
        )
        .unwrap();
        let plan = apply_set_overlay(profile, &[], &defaults());
        assert!(file_only_degradation_applies(&plan, "file"));
    }

    #[test]
    fn degradation_notice_does_not_apply_for_a_non_file_backend() {
        let profile = load_profile_from_str(
            r#"{
                "version": 1, "name": "p",
                "entries": { "K": { "secret": "s", "materialize": "secret" } }
            }"#,
            &defaults(),
        )
        .unwrap();
        let plan = apply_set_overlay(profile, &[], &defaults());
        assert!(!file_only_degradation_applies(&plan, "keychain"));
    }

    #[test]
    fn degradation_notice_does_not_apply_for_an_empty_plan() {
        let profile = load_profile_from_str(
            r#"{ "version": 1, "name": "p", "entries": {} }"#,
            &defaults(),
        )
        .unwrap();
        let plan = apply_set_overlay(profile, &[], &defaults());
        assert!(!file_only_degradation_applies(&plan, "file"));
    }

    // --- validate_as_var_name (issue #333 AC2) ---

    #[test]
    fn validate_as_var_name_accepts_the_shout_case_shape() {
        assert!(validate_as_var_name("VAULTKEEPER_SECRET").is_ok());
        assert!(validate_as_var_name("_PRIVATE").is_ok());
        assert!(validate_as_var_name("A1").is_ok());
    }

    #[test]
    fn validate_as_var_name_rejects_lower_case() {
        let err = validate_as_var_name("lower_case").unwrap_err();
        assert_matches!(err, VaultError::ConfigValidation { field, .. } if field == "--as");
    }

    #[test]
    fn validate_as_var_name_rejects_empty() {
        assert_matches!(
            validate_as_var_name("").unwrap_err(),
            VaultError::ConfigValidation { field, .. } if field == "--as"
        );
    }

    #[test]
    fn validate_as_var_name_rejects_a_leading_digit() {
        assert_matches!(
            validate_as_var_name("1ABC").unwrap_err(),
            VaultError::ConfigValidation { .. }
        );
    }

    // --- render_token_dry_run (issue #333) ---

    #[test]
    fn token_dry_run_render_shows_the_as_var_and_never_touches_backend_for_it() {
        let empty = load_profile_from_str(
            r#"{ "version": 1, "name": "p", "entries": {} }"#,
            &defaults(),
        )
        .unwrap();
        let plan = apply_set_overlay(empty, &[], &defaults());
        let rendered = render_token_dry_run("VAULTKEEPER_SECRET", &plan, "file");
        assert!(rendered.contains("VAULTKEEPER_SECRET"));
        assert!(rendered.contains("source:      --token"));
        assert!(rendered.contains("rung:        2 (secret)"));
    }

    #[test]
    fn token_dry_run_render_includes_combined_set_entries_marked_unreviewed() {
        let empty = load_profile_from_str(
            r#"{ "version": 1, "name": "p", "entries": {} }"#,
            &defaults(),
        )
        .unwrap();
        let sets = vec![SetEntry {
            var: "EXTRA".to_string(),
            secret_name: "extra-secret".to_string(),
        }];
        let plan = apply_set_overlay(empty, &sets, &defaults());
        let rendered = render_token_dry_run("VAULTKEEPER_SECRET", &plan, "file");
        assert!(rendered.contains("EXTRA"));
        assert!(rendered.contains("UNREVIEWED"));
        assert!(rendered.contains("backend:     file"));
    }
}
