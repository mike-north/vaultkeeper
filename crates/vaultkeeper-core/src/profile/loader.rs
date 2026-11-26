//! Fail-closed loader for the environment profile primitive (issue #277).
//!
//! Parses a profile file (see `crate::profile::types`) and applies every
//! load-time invariant. All failures are typed [`VaultError`] variants — a
//! caller never receives a partially-validated profile.

use super::types::{
    Materialize, MaterializeMode, MinTrust, ProfileEntryRaw, ProfileFile as RawProfileFile,
};
use crate::errors::VaultError;
use crate::types::TrustTier;

/// Default TTL (seconds) for a session-signing lease (`signingKey` +
/// `materialize: "lease"`) when `ttlSeconds` is omitted. 8 hours.
pub const SIGNING_LEASE_DEFAULT_TTL_SECONDS: u64 = 28_800;

/// Hard cap (seconds) on a session-signing lease's `ttlSeconds`, regardless
/// of what the profile requests. 24 hours.
pub const SIGNING_LEASE_MAX_TTL_SECONDS: u64 = 86_400;

/// Config-sourced defaults the loader applies when a profile entry omits a
/// field. Constructed from the active `VaultConfig.defaults` — see
/// [`ProfileDefaults::from_vault_defaults`].
#[derive(Debug, Clone, Copy)]
pub struct ProfileDefaults {
    /// `config.json`'s `defaults.ttlMinutes`, already converted to seconds
    /// (JWE `exp` is Unix seconds — issue #277's schema section). Applied to
    /// a lease entry backed by a `secret` source that omits `ttlSeconds`.
    pub ttl_seconds: u64,
    /// `config.json`'s `defaults.trustTier`, applied to an entry that omits
    /// `minTrust`.
    pub trust_tier: TrustTier,
}

impl ProfileDefaults {
    /// Build the loader defaults from a loaded `VaultConfig`'s `defaults`,
    /// converting `ttlMinutes` to seconds.
    #[must_use]
    pub fn from_vault_defaults(defaults: &crate::types::VaultDefaults) -> Self {
        Self {
            ttl_seconds: u64::from(defaults.ttl_minutes) * 60,
            trust_tier: defaults.trust_tier,
        }
    }
}

/// The validated source of an entry's resolved value — exactly one of a
/// secret name or a signing-key name (issue #277's discriminated union).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EntrySource {
    /// Resolve from the secret backend under this name.
    Secret(String),
    /// Resolve from the signing-key backend under this name.
    SigningKey(String),
}

/// A single, fully-validated profile entry, with every default resolved.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileEntry {
    pub source: EntrySource,
    pub materialize: MaterializeMode,
    pub min_trust: MinTrust,
    /// Resolved TTL in seconds. `None` when `materialize` is `"secret"`
    /// (TTL/lease-lifetime does not apply to a raw secret materialization).
    pub ttl_seconds: Option<u64>,
    pub use_limit: Option<u64>,
    pub require_presence_per_use: bool,
    pub require_presence_at_mint: bool,
}

/// A fully-validated, loaded profile.
///
/// `entries` is a `Vec<(String, ProfileEntry)>` internally (not a `HashMap`)
/// to preserve file order, but its wire form must match the *input* schema
/// — a JSON object keyed by env-var name — not an array of pairs. See the
/// manual [`serde::Serialize`] impl below.
#[derive(Debug, Clone)]
pub struct LoadedProfile {
    pub version: u32,
    pub name: String,
    pub entries: Vec<(String, ProfileEntry)>,
}

impl serde::Serialize for LoadedProfile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        /// Serializes `Vec<(String, ProfileEntry)>` as a JSON object
        /// (`{ name: entry, ... }`), preserving entry order — the same
        /// object shape `ProfileEntries` accepts on input.
        struct EntriesAsObject<'a>(&'a [(String, ProfileEntry)]);

        impl serde::Serialize for EntriesAsObject<'_> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(self.0.len()))?;
                for (name, entry) in self.0 {
                    map.serialize_entry(name, entry)?;
                }
                map.end()
            }
        }

        let mut state = serializer.serialize_struct("LoadedProfile", 3)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("entries", &EntriesAsObject(&self.entries))?;
        state.end()
    }
}

fn validation_error(entry: &str, field: &str, message: impl Into<String>) -> VaultError {
    VaultError::ConfigValidation {
        message: message.into(),
        field: format!("entries[{entry}].{field}"),
        config_file_path: None,
    }
}

/// `[A-Z_][A-Z0-9_]*` — load-time invariant #3 (env var name shape).
///
/// `pub(crate)`, not private: [`crate::run::parse_set_flag`] reuses this
/// exact shape check for a `run --set VAR=SECRET` flag's `VAR`, so a
/// `--set`-declared entry name is held to the identical invariant a
/// profile-file-declared entry name is (issue #279).
pub(crate) fn is_valid_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_uppercase() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// Parse and validate a profile from its raw JSON text.
///
/// # Errors
/// Returns [`VaultError::ConfigParse`] if `json` is not valid JSON or
/// violates the structural schema (unknown fields, duplicate entry names,
/// wrong types). Returns [`VaultError::ConfigValidation`] or
/// [`VaultError::MaterializeModeUnsupported`] if it parses but violates a
/// semantic load-time invariant.
pub fn load_profile_from_str(
    json: &str,
    defaults: &ProfileDefaults,
) -> Result<LoadedProfile, VaultError> {
    let raw: RawProfileFile = serde_json::from_str(json).map_err(|e| VaultError::ConfigParse {
        message: format!("Failed to parse profile: {e}"),
        path: String::new(),
        line: Some(e.line() as u32),
        column: Some(e.column() as u32),
    })?;

    if raw.version != 1 {
        return Err(VaultError::ConfigValidation {
            message: format!("Unsupported profile version: {}", raw.version),
            field: "version".to_string(),
            config_file_path: None,
        });
    }

    let mut entries = Vec::with_capacity(raw.entries.iter().count());
    for (name, raw_entry) in raw.entries.iter() {
        if !is_valid_env_var_name(name) {
            return Err(validation_error(
                name,
                "<name>",
                format!(
                    "Env var name \"{name}\" is invalid: entry names must match \
                     [A-Z_][A-Z0-9_]*"
                ),
            ));
        }
        let entry = validate_entry(name, raw_entry, defaults)?;
        entries.push((name.clone(), entry));
    }

    Ok(LoadedProfile {
        version: raw.version,
        name: raw.name,
        entries,
    })
}

fn validate_entry(
    name: &str,
    raw: &ProfileEntryRaw,
    defaults: &ProfileDefaults,
) -> Result<ProfileEntry, VaultError> {
    let source = match (&raw.secret, &raw.signing_key) {
        (Some(secret), None) => EntrySource::Secret(secret.clone()),
        (None, Some(key)) => EntrySource::SigningKey(key.clone()),
        (Some(_), Some(_)) => {
            return Err(validation_error(
                name,
                "secret",
                "Entry must specify exactly one of \"secret\" or \"signingKey\", not both",
            ));
        }
        (None, None) => {
            return Err(validation_error(
                name,
                "secret",
                "Entry must specify exactly one of \"secret\" or \"signingKey\"",
            ));
        }
    };

    // Load-time invariant #5: a `materialize` object value is reserved and
    // always rejected, with a typed error naming the mode — never a generic
    // parse failure (issue #277 AC2).
    let materialize = match &raw.materialize {
        Materialize::Simple(mode) => *mode,
        Materialize::Extended(extended) => {
            return Err(VaultError::MaterializeModeUnsupported {
                message: format!(
                    "entries[{name}].materialize: mode \"{}\" is reserved and not yet \
                     supported. Valid forms are the strings \"secret\" or \"lease\", or a \
                     reserved object naming its mode (e.g. {{ \"mode\": \"reference\", ... }})",
                    extended.mode
                ),
                mode: extended.mode.clone(),
            });
        }
    };

    // Load-time invariant #1: signingKey + materialize:"secret" is rejected
    // — a signing key has no value to materialize as a secret; the private
    // key never leaves the backend.
    if matches!(source, EntrySource::SigningKey(_)) && materialize == MaterializeMode::Secret {
        return Err(validation_error(
            name,
            "materialize",
            "signingKey entries cannot use materialize: \"secret\" — a signing key has no \
             value to materialize; the private key never leaves the backend",
        ));
    }

    // Load-time invariant #2: requirePresenceAtMint is only valid with
    // materialize: "lease".
    let require_presence_at_mint = raw.require_presence_at_mint.unwrap_or(false);
    if require_presence_at_mint && materialize != MaterializeMode::Lease {
        return Err(validation_error(
            name,
            "requirePresenceAtMint",
            "requirePresenceAtMint is only valid with materialize: \"lease\"",
        ));
    }

    let min_trust = raw
        .min_trust
        .unwrap_or_else(|| MinTrust::from_trust_tier(defaults.trust_tier));

    let ttl_seconds = resolve_ttl_seconds(name, &source, materialize, raw.ttl_seconds, defaults)?;

    Ok(ProfileEntry {
        source,
        materialize,
        min_trust,
        ttl_seconds,
        use_limit: raw.use_limit,
        require_presence_per_use: raw.require_presence_per_use.unwrap_or(false),
        require_presence_at_mint,
    })
}

/// Hard cap for a secret-backed lease's `ttlSeconds`, matching the
/// resolver's `LEASE_TTL_MAX_SECONDS` (30 days). Enforced here at load time
/// with a typed error so a profile requesting more is refused rather than
/// silently minted shorter.
pub(crate) const SECRET_LEASE_MAX_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;

fn resolve_ttl_seconds(
    name: &str,
    source: &EntrySource,
    materialize: MaterializeMode,
    ttl_seconds: Option<u64>,
    defaults: &ProfileDefaults,
) -> Result<Option<u64>, VaultError> {
    if materialize != MaterializeMode::Lease {
        // TTL/lease-lifetime does not apply to a raw secret materialization.
        return Ok(None);
    }

    // An explicit `ttlSeconds: 0` would mint an already-expired lease the
    // instant it's created — reject it at load time rather than letting it
    // reach the resolver as a silently-useless lease.
    if ttl_seconds == Some(0) {
        return Err(validation_error(
            name,
            "ttlSeconds",
            "ttlSeconds must not be 0 — a 0-second TTL would mint an already-expired lease",
        ));
    }

    match source {
        EntrySource::SigningKey(_) => {
            let resolved = ttl_seconds.unwrap_or(SIGNING_LEASE_DEFAULT_TTL_SECONDS);
            if resolved > SIGNING_LEASE_MAX_TTL_SECONDS {
                return Err(validation_error(
                    name,
                    "ttlSeconds",
                    format!(
                        "ttlSeconds {resolved} exceeds the session-signing-lease hard cap of \
                         {SIGNING_LEASE_MAX_TTL_SECONDS} seconds (24h)"
                    ),
                ));
            }
            Ok(Some(resolved))
        }
        EntrySource::Secret(_) => {
            let resolved = ttl_seconds.unwrap_or(defaults.ttl_seconds);
            // Fail closed instead of silently rewriting: a profile asking
            // for more than the resolver's hard cap gets a typed validation
            // error at load time, never a quietly shortened lease.
            if resolved > SECRET_LEASE_MAX_TTL_SECONDS {
                return Err(validation_error(
                    name,
                    "ttlSeconds",
                    format!(
                        "ttlSeconds {resolved} exceeds the secret-backed-lease hard cap of \
                         {SECRET_LEASE_MAX_TTL_SECONDS} seconds (30 days)"
                    ),
                ));
            }
            Ok(Some(resolved))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::VaultError;
    use assert_matches::assert_matches;

    fn defaults() -> ProfileDefaults {
        ProfileDefaults {
            ttl_seconds: 3600,
            trust_tier: TrustTier::Dev,
        }
    }

    const SCHEMA_EXAMPLE: &str = r#"{
      "version": 1,
      "name": "github-mcp",
      "entries": {
        "GITHUB_TOKEN": {
          "secret": "github-pat",
          "materialize": "secret",
          "minTrust": "registry",
          "requirePresencePerUse": false
        },
        "VK_DB_CREDENTIAL": {
          "secret": "prod-db-password",
          "materialize": "lease",
          "minTrust": "sigstore",
          "ttlSeconds": 900,
          "useLimit": 5
        },
        "VK_SIGNING_LEASE": {
          "signingKey": "release-signer",
          "materialize": "lease",
          "ttlSeconds": 28800,
          "useLimit": 200,
          "requirePresenceAtMint": true
        }
      }
    }"#;

    #[test]
    fn loads_the_schema_example() {
        let loaded = load_profile_from_str(SCHEMA_EXAMPLE, &defaults()).unwrap();
        assert_eq!(loaded.name, "github-mcp");
        assert_eq!(loaded.entries.len(), 3);

        let (_, github) = &loaded.entries[0];
        assert_eq!(github.source, EntrySource::Secret("github-pat".to_string()));
        assert_eq!(github.materialize, MaterializeMode::Secret);
        assert_eq!(github.min_trust, MinTrust::Registry);
        assert!(!github.require_presence_per_use);
        assert_eq!(github.ttl_seconds, None);

        let (_, db) = &loaded.entries[1];
        assert_eq!(db.ttl_seconds, Some(900));
        assert_eq!(db.use_limit, Some(5));

        let (_, signing) = &loaded.entries[2];
        assert_eq!(
            signing.source,
            EntrySource::SigningKey("release-signer".to_string())
        );
        assert!(signing.require_presence_at_mint);
        assert_eq!(signing.ttl_seconds, Some(28800));
        // Absent minTrust on the signing-lease entry defaults from config.
        assert_eq!(signing.min_trust, MinTrust::from_trust_tier(TrustTier::Dev));
    }

    // --- Load-time invariant #1: signingKey + materialize:"secret" ---

    #[test]
    fn rejects_signing_key_with_materialize_secret() {
        let json = r#"{
            "version": 1, "name": "p",
            "entries": { "K": { "signingKey": "s", "materialize": "secret" } }
        }"#;
        let err = load_profile_from_str(json, &defaults()).unwrap_err();
        assert_matches!(err, VaultError::ConfigValidation { field, .. } if field == "entries[K].materialize");
    }

    // --- Load-time invariant #2: requirePresenceAtMint only with lease ---

    #[test]
    fn rejects_require_presence_at_mint_with_materialize_secret() {
        let json = r#"{
            "version": 1, "name": "p",
            "entries": {
                "K": { "secret": "s", "materialize": "secret", "requirePresenceAtMint": true }
            }
        }"#;
        let err = load_profile_from_str(json, &defaults()).unwrap_err();
        assert_matches!(
            err,
            VaultError::ConfigValidation { field, .. } if field == "entries[K].requirePresenceAtMint"
        );
    }

    // --- minTrust outside the three enum values ---

    #[test]
    fn rejects_min_trust_outside_the_enum() {
        let json = r#"{
            "version": 1, "name": "p",
            "entries": { "K": { "secret": "s", "materialize": "secret", "minTrust": "bogus" } }
        }"#;
        let err = load_profile_from_str(json, &defaults()).unwrap_err();
        assert_matches!(err, VaultError::ConfigParse { .. });
    }

    // --- Load-time invariant #3: env var name shape + duplicates ---

    #[test]
    fn rejects_env_var_name_violating_the_regex() {
        let json = r#"{
            "version": 1, "name": "p",
            "entries": { "lower_case": { "secret": "s", "materialize": "secret" } }
        }"#;
        let err = load_profile_from_str(json, &defaults()).unwrap_err();
        assert_matches!(err, VaultError::ConfigValidation { field, .. } if field == "entries[lower_case].<name>");
    }

    #[test]
    fn rejects_env_var_name_starting_with_digit() {
        let json = r#"{
            "version": 1, "name": "p",
            "entries": { "1ABC": { "secret": "s", "materialize": "secret" } }
        }"#;
        let err = load_profile_from_str(json, &defaults()).unwrap_err();
        assert_matches!(err, VaultError::ConfigValidation { .. });
    }

    #[test]
    fn accepts_valid_env_var_names() {
        assert!(is_valid_env_var_name("GITHUB_TOKEN"));
        assert!(is_valid_env_var_name("_PRIVATE"));
        assert!(is_valid_env_var_name("A1"));
        assert!(!is_valid_env_var_name(""));
        assert!(!is_valid_env_var_name("1A"));
        assert!(!is_valid_env_var_name("lower"));
        assert!(!is_valid_env_var_name("HAS-DASH"));
    }

    #[test]
    fn rejects_duplicate_env_var_names() {
        // Raw JSON with a literal duplicate key — the custom `ProfileEntries`
        // Deserialize visitor must catch this before a HashMap would
        // silently collapse it.
        let json = r#"{
            "version": 1, "name": "p",
            "entries": {
                "GITHUB_TOKEN": { "secret": "a", "materialize": "secret" },
                "GITHUB_TOKEN": { "secret": "b", "materialize": "secret" }
            }
        }"#;
        let err = load_profile_from_str(json, &defaults()).unwrap_err();
        assert_matches!(err, VaultError::ConfigParse { .. });
    }

    // --- Load-time invariant #4: unknown fields rejected ---

    #[test]
    fn rejects_unknown_top_level_field() {
        let json = r#"{
            "version": 1, "name": "p", "entries": {}, "unexpected": true
        }"#;
        let err = load_profile_from_str(json, &defaults()).unwrap_err();
        assert_matches!(err, VaultError::ConfigParse { .. });
    }

    #[test]
    fn rejects_unknown_entry_field() {
        let json = r#"{
            "version": 1, "name": "p",
            "entries": { "K": { "secret": "s", "materialize": "secret", "minTrst": "registry" } }
        }"#;
        let err = load_profile_from_str(json, &defaults()).unwrap_err();
        assert_matches!(err, VaultError::ConfigParse { .. });
    }

    // --- Load-time invariant #5: materialize object value ---

    #[test]
    fn rejects_materialize_object_with_typed_reserved_mode_error() {
        let json = r#"{
            "version": 1, "name": "p",
            "entries": {
                "K": {
                    "secret": "s",
                    "materialize": { "mode": "reference", "backend": "1password" }
                }
            }
        }"#;
        let err = load_profile_from_str(json, &defaults()).unwrap_err();
        assert!(!matches!(err, VaultError::ConfigParse { .. }));
        assert_matches!(
            err,
            VaultError::MaterializeModeUnsupported { mode, .. } if mode == "reference"
        );
    }

    #[test]
    fn rejects_materialize_bare_empty_object_with_typed_unspecified_mode_error() {
        // A `materialize: {}` with no `mode` key must still be caught by the
        // typed reserved-mode error, not fall through to a generic
        // untagged-enum parse failure.
        let json = r#"{
            "version": 1, "name": "p",
            "entries": { "K": { "secret": "s", "materialize": {} } }
        }"#;
        let err = load_profile_from_str(json, &defaults()).unwrap_err();
        assert!(!matches!(err, VaultError::ConfigParse { .. }));
        assert_matches!(
            err,
            VaultError::MaterializeModeUnsupported { mode, .. } if mode == "unspecified"
        );
    }

    // --- Discriminated union: exactly one of secret/signingKey ---

    #[test]
    fn rejects_entry_with_both_secret_and_signing_key() {
        let json = r#"{
            "version": 1, "name": "p",
            "entries": {
                "K": { "secret": "s", "signingKey": "sk", "materialize": "lease" }
            }
        }"#;
        let err = load_profile_from_str(json, &defaults()).unwrap_err();
        assert_matches!(err, VaultError::ConfigValidation { .. });
    }

    #[test]
    fn rejects_entry_with_neither_secret_nor_signing_key() {
        let json = r#"{
            "version": 1, "name": "p",
            "entries": { "K": { "materialize": "secret" } }
        }"#;
        let err = load_profile_from_str(json, &defaults()).unwrap_err();
        assert_matches!(err, VaultError::ConfigValidation { .. });
    }

    // --- TTL defaults ---

    #[test]
    fn signing_lease_defaults_ttl_to_eight_hours() {
        let json = r#"{
            "version": 1, "name": "p",
            "entries": { "K": { "signingKey": "sk", "materialize": "lease" } }
        }"#;
        let loaded = load_profile_from_str(json, &defaults()).unwrap();
        assert_eq!(
            loaded.entries[0].1.ttl_seconds,
            Some(SIGNING_LEASE_DEFAULT_TTL_SECONDS)
        );
    }

    /// Pins the literal values, not just the symbol: issue #299 / the
    /// PRFAQ's session-signing-lease bound is an 8h default, hard-capped at
    /// 24h — a change to either constant is a deliberate spec change, not a
    /// refactor, and must fail this test to be noticed (`docs/product/PRFAQ.md`).
    #[test]
    fn signing_lease_ttl_constants_match_the_issue_299_spec() {
        assert_eq!(
            SIGNING_LEASE_DEFAULT_TTL_SECONDS, 28_800,
            "8h default session-signing-lease TTL (issue #299)"
        );
        assert_eq!(
            SIGNING_LEASE_MAX_TTL_SECONDS, 86_400,
            "24h hard cap on a session-signing-lease TTL (issue #299)"
        );
    }

    #[test]
    fn signing_lease_rejects_ttl_over_the_hard_cap() {
        let json = r#"{
            "version": 1, "name": "p",
            "entries": {
                "K": { "signingKey": "sk", "materialize": "lease", "ttlSeconds": 86401 }
            }
        }"#;
        let err = load_profile_from_str(json, &defaults()).unwrap_err();
        assert_matches!(err, VaultError::ConfigValidation { field, .. } if field == "entries[K].ttlSeconds");
    }

    #[test]
    fn rejects_secret_backed_lease_ttl_above_the_thirty_day_cap() {
        let json = format!(
            r#"{{
                "version": 1, "name": "p",
                "entries": {{
                    "K": {{ "secret": "s", "materialize": "lease", "ttlSeconds": {} }}
                }}
            }}"#,
            SECRET_LEASE_MAX_TTL_SECONDS + 1
        );
        let err = load_profile_from_str(&json, &defaults()).unwrap_err();
        assert_matches!(
            err,
            VaultError::ConfigValidation { ref message, ref field, .. }
                if message.contains("hard cap") && field.contains("K")
        );
    }

    #[test]
    fn accepts_secret_backed_lease_ttl_at_exactly_the_cap() {
        let json = format!(
            r#"{{
                "version": 1, "name": "p",
                "entries": {{
                    "K": {{ "secret": "s", "materialize": "lease", "ttlSeconds": {} }}
                }}
            }}"#,
            SECRET_LEASE_MAX_TTL_SECONDS
        );
        assert!(load_profile_from_str(&json, &defaults()).is_ok());
    }

    #[test]
    fn rejects_explicit_ttl_seconds_zero_on_a_secret_backed_lease() {
        let json = r#"{
            "version": 1, "name": "p",
            "entries": { "K": { "secret": "s", "materialize": "lease", "ttlSeconds": 0 } }
        }"#;
        let err = load_profile_from_str(json, &defaults()).unwrap_err();
        assert_matches!(err, VaultError::ConfigValidation { field, .. } if field == "entries[K].ttlSeconds");
    }

    #[test]
    fn rejects_explicit_ttl_seconds_zero_on_a_signing_key_backed_lease() {
        let json = r#"{
            "version": 1, "name": "p",
            "entries": { "K": { "signingKey": "sk", "materialize": "lease", "ttlSeconds": 0 } }
        }"#;
        let err = load_profile_from_str(json, &defaults()).unwrap_err();
        assert_matches!(err, VaultError::ConfigValidation { field, .. } if field == "entries[K].ttlSeconds");
    }

    #[test]
    fn secret_backed_lease_defaults_ttl_from_config_minutes_converted_to_seconds() {
        // Load-time invariant / AC4: the loader converts a config.json
        // ttlMinutes default into ttlSeconds when applying the default.
        let config_defaults = ProfileDefaults {
            ttl_seconds: 5 * 60, // simulates VaultDefaults { ttl_minutes: 5, .. } converted
            trust_tier: TrustTier::Dev,
        };
        let json = r#"{
            "version": 1, "name": "p",
            "entries": { "K": { "secret": "s", "materialize": "lease" } }
        }"#;
        let loaded = load_profile_from_str(json, &config_defaults).unwrap();
        assert_eq!(loaded.entries[0].1.ttl_seconds, Some(300));
    }

    #[test]
    fn profile_defaults_from_vault_defaults_converts_minutes_to_seconds() {
        let vault_defaults = crate::types::VaultDefaults {
            ttl_minutes: 15,
            trust_tier: TrustTier::Sigstore,
        };
        let defaults = ProfileDefaults::from_vault_defaults(&vault_defaults);
        assert_eq!(defaults.ttl_seconds, 900);
        assert_eq!(defaults.trust_tier, TrustTier::Sigstore);
    }

    // --- Wire-format symmetry: `entries` serializes as an object, matching
    // --- the input schema, not as an array of pairs (review follow-up).

    #[test]
    fn loaded_profile_entries_serialize_as_an_object_not_an_array_of_pairs() {
        let loaded = load_profile_from_str(SCHEMA_EXAMPLE, &defaults()).unwrap();
        let value = serde_json::to_value(&loaded).unwrap();
        let entries = value.get("entries").expect("entries field");
        assert!(
            entries.is_object(),
            "entries must serialize as a JSON object, got {entries:?}"
        );
        assert!(entries.get("GITHUB_TOKEN").is_some());
        assert!(entries.get("VK_DB_CREDENTIAL").is_some());
        assert!(entries.get("VK_SIGNING_LEASE").is_some());
    }

    #[test]
    fn loaded_profile_entries_preserve_file_order_when_serialized() {
        // serde_json::Value collapses object keys into a sorted map (this
        // crate's `serde_json` has no `preserve_order` feature), so order is
        // asserted against the raw serialized string instead.
        let loaded = load_profile_from_str(SCHEMA_EXAMPLE, &defaults()).unwrap();
        let json = serde_json::to_string(&loaded).unwrap();
        let github_pos = json.find("GITHUB_TOKEN").expect("GITHUB_TOKEN present");
        let db_pos = json
            .find("VK_DB_CREDENTIAL")
            .expect("VK_DB_CREDENTIAL present");
        let signing_pos = json
            .find("VK_SIGNING_LEASE")
            .expect("VK_SIGNING_LEASE present");
        assert!(
            github_pos < db_pos,
            "GITHUB_TOKEN must precede VK_DB_CREDENTIAL"
        );
        assert!(
            db_pos < signing_pos,
            "VK_DB_CREDENTIAL must precede VK_SIGNING_LEASE"
        );
    }
}
