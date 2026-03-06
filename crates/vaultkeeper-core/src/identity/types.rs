//! Types for the executable identity and trust layer.

use crate::types::TrustTier;
use std::collections::HashMap;

/// Identity information about a verified executable.
#[derive(Debug, Clone)]
pub struct IdentityInfo {
    /// SHA-256 hex digest of the executable binary.
    pub hash: String,
    /// Achieved trust tier for this executable.
    pub trust_tier: TrustTier,
    /// Whether the identity was positively verified (not merely observed).
    pub verified: bool,
}

/// Result returned by trust verification.
#[derive(Debug, Clone)]
pub struct TrustVerificationResult {
    /// The computed identity information.
    pub identity: IdentityInfo,
    /// True when TOFU detected a hash change (re-approval required).
    pub tofu_conflict: bool,
    /// Human-readable description of how trust was established.
    pub reason: String,
}

/// Options controlling how trust verification is performed.
#[derive(Debug, Clone, Default)]
pub struct TrustOptions {
    /// Directory where the trust manifest is stored.
    pub config_dir: Option<String>,
    /// Namespace for TOFU and manifest lookups.
    pub namespace: Option<String>,
    /// When `true`, skip Sigstore verification.
    pub skip_sigstore: Option<bool>,
}

/// Per-namespace entry in the trust manifest.
#[derive(Debug, Clone)]
pub struct TrustManifestEntry {
    /// Approved hashes for this namespace.
    pub hashes: Vec<String>,
    /// Trust tier recorded when the hash was first approved.
    pub trust_tier: TrustTier,
}

/// The on-disk trust manifest.
/// Maps a namespace string to its approved-hash entry.
pub type TrustManifest = HashMap<String, TrustManifestEntry>;
