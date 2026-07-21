//! Serde schema for the environment profile primitive (issue #277).
//!
//! A profile is a named, declarative binding set: env-var name → secret
//! source → materialization mode → policy. It lives on disk at
//! `$CONFIG_DIR/profiles/<name>.json` (or a `--profile-file <path>` override)
//! — never inside `config.json`. These types describe exactly the on-disk
//! shape; they carry no secrets, only names and policy, so a profile file is
//! safe to commit.
//!
//! This module is intentionally permissive about *structure* (anything that
//! parses becomes a [`ProfileFile`]) and defers all *semantic* validation
//! (the fail-closed invariants) to [`crate::profile::loader`]. Keeping the
//! two separate means a structurally valid-but-semantically-rejected profile
//! (e.g. a `signingKey` entry with `materialize: "secret"`) still parses here
//! and produces a precise, typed rejection in the loader rather than an
//! opaque serde error.

use serde::de::{Error as DeError, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashSet;
use std::fmt;

/// Top-level profile file — the exact on-disk / wire shape.
///
/// `deny_unknown_fields` is deliberate: a typo'd top-level key must fail
/// loudly rather than being silently ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileFile {
    /// Profile schema version. Currently must be `1`.
    pub version: u32,
    /// Human-readable profile name (independent of the filename).
    pub name: String,
    /// Env-var name → entry bindings.
    pub entries: ProfileEntries,
}

/// The `entries` map, preserving encounter order and rejecting duplicate
/// keys.
///
/// A plain `HashMap<String, ProfileEntryRaw>` cannot detect duplicate JSON
/// object keys — `serde_json` silently keeps the last occurrence when
/// populating a map, the same way `JSON.parse` does in JS. Detecting the
/// duplicate (load-time invariant #3 — see `crate::profile::loader`)
/// therefore requires a custom [`Deserialize`] impl that inspects each
/// key as it streams past, before a map collapses it away.
#[derive(Debug, Clone, Default)]
pub struct ProfileEntries(pub Vec<(String, ProfileEntryRaw)>);

impl ProfileEntries {
    /// Iterate over `(name, entry)` pairs in file order.
    pub fn iter(&self) -> impl Iterator<Item = &(String, ProfileEntryRaw)> {
        self.0.iter()
    }
}

impl Serialize for ProfileEntries {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in &self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for ProfileEntries {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EntriesVisitor;

        impl<'de> Visitor<'de> for EntriesVisitor {
            type Value = ProfileEntries;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a map of env var name to profile entry")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut seen = HashSet::new();
                let mut entries = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(DeError::custom(format!(
                            "duplicate profile entry name: {key}"
                        )));
                    }
                    let value: ProfileEntryRaw = map.next_value()?;
                    entries.push((key, value));
                }
                Ok(ProfileEntries(entries))
            }
        }

        deserializer.deserialize_map(EntriesVisitor)
    }
}

/// A single, structurally-parsed profile entry — before semantic validation.
///
/// Both `secret` and `signingKey` are optional at this layer: the "exactly
/// one" discriminated-union invariant is a semantic check enforced by
/// `crate::profile::loader::load_profile_from_str`, not a structural one, so
/// a violation produces a precise [`crate::errors::VaultError::ConfigValidation`]
/// rather than an opaque serde parse error.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileEntryRaw {
    /// The secret name to resolve, when this entry is secret-backed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// The signing-key name to resolve, when this entry is signing-key-backed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key: Option<String>,
    /// How the resolved source is materialized into the environment.
    pub materialize: Materialize,
    /// The minimum trust tier the resolving executable must meet, or exceed
    /// (`sigstore` > `registry` > `unverified`). Defaults from
    /// `config.json`'s `defaults.trustTier` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_trust: Option<MinTrust>,
    /// JWE `exp` lifetime, in seconds. Only meaningful for `materialize:
    /// "lease"` entries. Defaults per `crate::profile::loader`'s TTL rules
    /// when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    /// Usage limit (`None`/absent for unlimited).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_limit: Option<u64>,
    /// Require the backend to force a fresh, per-use human presence action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_presence_per_use: Option<bool>,
    /// Require a fresh human presence action at mint time. Only valid with
    /// `materialize: "lease"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_presence_at_mint: Option<bool>,
}

/// `materialize`'s v1 string values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MaterializeMode {
    /// Resolve to the real secret value.
    Secret,
    /// Resolve to a VaultKeeper lease (JWE).
    Lease,
}

impl MaterializeMode {
    /// The profile-facing wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Lease => "lease",
        }
    }
}

/// `materialize` is polymorphic by design (v1 = strings only): an untagged
/// enum of either the v1 string value, or a reserved object form
/// (`{ "mode": "reference", ... }`) that parses successfully here but is
/// always refused at validation with a typed error (issue #277 AC2) — so the
/// reservation is discoverable today and a real v2 implementation is
/// non-breaking later.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Materialize {
    /// The v1, implemented string form.
    Simple(MaterializeMode),
    /// The reserved, not-yet-implemented object form.
    Extended(MaterializeExtended),
}

/// The reserved object form of `materialize`. Only `mode` is inspected;
/// everything else is captured (but ignored) so future fields don't break
/// parsing of an otherwise-recognized reserved shape.
///
/// `mode` defaults to `"unspecified"` when absent (e.g. a bare
/// `"materialize": {}`) so that shape still parses as `Extended` rather
/// than falling through to a generic untagged-enum parse failure; the
/// loader then rejects it with the typed
/// [`crate::errors::VaultError::MaterializeModeUnsupported`] error naming
/// `"unspecified"`, which is discoverable and precise, rather than an opaque
/// serde message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaterializeExtended {
    /// The reserved mode name (e.g. `"reference"`), or `"unspecified"` when
    /// the object omitted `mode` entirely.
    #[serde(default = "unspecified_materialize_mode")]
    pub mode: String,
    /// Any additional fields the reserved shape carries. Not interpreted.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

fn unspecified_materialize_mode() -> String {
    "unspecified".to_string()
}

/// The profile-facing minimum-trust name. Ordered `Sigstore > Registry >
/// Unverified`, with an or-stronger semantic: the resolving executable must
/// be at least this trusted.
///
/// This replaces the earlier numeric `trustTier` (whose scale was inverted)
/// at the profile surface; [`MinTrust::to_trust_tier`] maps to the existing
/// internal numeric [`crate::types::TrustTier`] so only the profile-facing
/// name/representation changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MinTrust {
    /// Weakest — orders first so `#[derive(PartialOrd, Ord)]` gives
    /// `Unverified < Registry < Sigstore`, matching the "or-stronger" compare
    /// direction used throughout `crate::profile::lint`.
    Unverified,
    Registry,
    Sigstore,
}

impl MinTrust {
    /// Map to the internal numeric trust tier.
    #[must_use]
    pub fn to_trust_tier(self) -> crate::types::TrustTier {
        match self {
            Self::Sigstore => crate::types::TrustTier::Sigstore,
            Self::Registry => crate::types::TrustTier::Tofu,
            Self::Unverified => crate::types::TrustTier::Dev,
        }
    }

    /// Map from the internal numeric trust tier.
    #[must_use]
    pub fn from_trust_tier(tier: crate::types::TrustTier) -> Self {
        match tier {
            crate::types::TrustTier::Sigstore => Self::Sigstore,
            crate::types::TrustTier::Tofu => Self::Registry,
            crate::types::TrustTier::Dev => Self::Unverified,
        }
    }

    /// The profile-facing wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sigstore => "sigstore",
            Self::Registry => "registry",
            Self::Unverified => "unverified",
        }
    }
}

#[cfg(test)]
mod materialize_extended_tests {
    use super::*;

    #[test]
    fn empty_object_parses_as_extended_with_unspecified_mode() {
        let parsed: Materialize = serde_json::from_str("{}").unwrap();
        match parsed {
            Materialize::Extended(extended) => assert_eq!(extended.mode, "unspecified"),
            Materialize::Simple(_) => panic!("expected Extended, got Simple"),
        }
    }

    #[test]
    fn reserved_mode_object_round_trips_through_serde_unchanged() {
        let original: Materialize =
            serde_json::from_str(r#"{ "mode": "reference", "backend": "1password" }"#).unwrap();
        let round_tripped: serde_json::Value = serde_json::to_value(&original).unwrap();
        let expected: serde_json::Value =
            serde_json::from_str(r#"{ "mode": "reference", "backend": "1password" }"#).unwrap();
        assert_eq!(round_tripped, expected);
    }

    #[test]
    fn simple_string_form_still_parses_as_simple() {
        let parsed: Materialize = serde_json::from_str(r#""secret""#).unwrap();
        assert!(matches!(
            parsed,
            Materialize::Simple(MaterializeMode::Secret)
        ));
    }
}
