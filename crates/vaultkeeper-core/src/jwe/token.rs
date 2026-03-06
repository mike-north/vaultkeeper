//! JWE token operations — create, decrypt, validate, block.
//!
//! Implements compact JWE serialization (RFC 7516) using `dir` + `A256GCM`.
//! Wire-compatible with the `jose` npm library.
//!
//! Format: 5 base64url segments separated by `.`:
//!   `header.encryptedKey.iv.ciphertext.tag`
//!
//! For `dir`, the encrypted key segment is empty (zero-length).
//! AAD for AES-GCM is the ASCII bytes of the base64url-encoded header segment.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64ct::{Base64UrlUnpadded, Encoding};

use crate::errors::VaultError;
use crate::types::VaultClaims;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use super::types::VaultJweHeader;

/// Maximum number of JTIs the blocklist will retain (matches TS implementation).
const BLOCKLIST_MAX_SIZE: usize = 10_000;

/// In-memory blocklist for revoked token JTIs.
/// Uses a HashMap with insertion order tracked via a counter for LRU eviction.
static BLOCKLIST: Mutex<Option<BlocklistState>> = Mutex::new(None);

struct BlocklistState {
    entries: HashMap<String, u64>,
    counter: u64,
}

fn blocklist() -> std::sync::MutexGuard<'static, Option<BlocklistState>> {
    BLOCKLIST.lock().expect("blocklist lock poisoned")
}

/// Options for token creation.
pub struct CreateTokenOptions {
    /// Key ID to embed in the JWE header.
    pub kid: Option<String>,
}

/// Create a compact JWE token from claims using the given 32-byte AES-256 key.
///
/// The output format is wire-compatible with the `jose` npm library using
/// `dir` + `A256GCM`.
///
/// # Errors
/// Returns `VaultError` if the key is not 32 bytes or encryption fails.
pub fn create_token(
    key: &[u8],
    claims: &VaultClaims,
    options: &CreateTokenOptions,
) -> Result<String, VaultError> {
    if key.len() != 32 {
        return Err(VaultError::Other(format!(
            "AES-256 key must be 32 bytes, got {}",
            key.len()
        )));
    }

    // Build protected header
    let header = VaultJweHeader {
        kid: options.kid.clone(),
        ..VaultJweHeader::default()
    };

    let header_json = serde_json::to_string(&header)
        .map_err(|e| VaultError::Other(format!("Failed to serialize JWE header: {e}")))?;
    let header_b64 = Base64UrlUnpadded::encode_string(header_json.as_bytes());

    // Serialize claims to JSON plaintext
    let plaintext = serde_json::to_string(claims)
        .map_err(|e| VaultError::Other(format!("Failed to serialize claims: {e}")))?;

    // Generate 12-byte IV
    let mut iv_bytes = [0u8; 12];
    getrandom::fill(&mut iv_bytes)
        .map_err(|e| VaultError::Other(format!("Failed to generate IV: {e}")))?;

    // Encrypt with AES-256-GCM, AAD = ASCII bytes of base64url header
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::Other(format!("Invalid AES key: {e}")))?;

    let nonce = Nonce::from_slice(&iv_bytes);
    let payload = Payload {
        msg: plaintext.as_bytes(),
        aad: header_b64.as_bytes(),
    };

    let ciphertext_and_tag = cipher
        .encrypt(nonce, payload)
        .map_err(|e| VaultError::Other(format!("AES-GCM encryption failed: {e}")))?;

    // aes-gcm appends the 16-byte tag to the ciphertext
    let (ciphertext, tag) = ciphertext_and_tag.split_at(ciphertext_and_tag.len() - 16);

    // Assemble compact JWE: header.encryptedKey.iv.ciphertext.tag
    // For `dir`, encrypted key is empty
    let iv_b64 = Base64UrlUnpadded::encode_string(&iv_bytes);
    let ciphertext_b64 = Base64UrlUnpadded::encode_string(ciphertext);
    let tag_b64 = Base64UrlUnpadded::encode_string(tag);

    Ok(format!(
        "{header_b64}..{iv_b64}.{ciphertext_b64}.{tag_b64}"
    ))
}

/// Decrypt a compact JWE token and return the claims.
///
/// # Errors
/// Returns `VaultError` if the JWE structure is invalid, decryption fails,
/// or the payload doesn't match `VaultClaims` schema.
pub fn decrypt_token(key: &[u8], jwe: &str) -> Result<VaultClaims, VaultError> {
    if key.len() != 32 {
        return Err(VaultError::Other(format!(
            "AES-256 key must be 32 bytes, got {}",
            key.len()
        )));
    }

    let parts: Vec<&str> = jwe.split('.').collect();
    if parts.len() != 5 {
        return Err(VaultError::Other(
            "Invalid JWE compact serialization: expected 5 parts".to_string(),
        ));
    }

    let header_b64 = parts[0];
    // parts[1] is encrypted key — empty for `dir`
    let iv_b64 = parts[2];
    let ciphertext_b64 = parts[3];
    let tag_b64 = parts[4];

    // Decode IV
    let iv_bytes = Base64UrlUnpadded::decode_vec(iv_b64)
        .map_err(|e| VaultError::Other(format!("Invalid IV base64url: {e}")))?;
    if iv_bytes.len() != 12 {
        return Err(VaultError::Other(format!(
            "AES-GCM IV must be 12 bytes, got {}",
            iv_bytes.len()
        )));
    }

    // Decode ciphertext and tag
    let ciphertext = Base64UrlUnpadded::decode_vec(ciphertext_b64)
        .map_err(|e| VaultError::Other(format!("Invalid ciphertext base64url: {e}")))?;
    let tag = Base64UrlUnpadded::decode_vec(tag_b64)
        .map_err(|e| VaultError::Other(format!("Invalid tag base64url: {e}")))?;
    if tag.len() != 16 {
        return Err(VaultError::Other(format!(
            "AES-GCM tag must be 16 bytes, got {}",
            tag.len()
        )));
    }

    // Reassemble ciphertext + tag (aes-gcm expects them concatenated)
    let mut ciphertext_with_tag = ciphertext;
    ciphertext_with_tag.extend_from_slice(&tag);

    // Decrypt
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::Other(format!("Invalid AES key: {e}")))?;

    let nonce = Nonce::from_slice(&iv_bytes);
    let payload = Payload {
        msg: &ciphertext_with_tag,
        aad: header_b64.as_bytes(),
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| VaultError::Other("JWE decryption failed: authentication failed".to_string()))?;

    // Parse claims
    let claims: VaultClaims = serde_json::from_slice(&plaintext)
        .map_err(|e| VaultError::Other(format!("JWE payload does not match VaultClaims schema: {e}")))?;

    Ok(claims)
}

/// Extract the `kid` (key ID) from a JWE's protected header without decrypting.
///
/// # Errors
/// Returns `VaultError` if the JWE structure is invalid.
pub fn extract_kid(jwe: &str) -> Result<Option<String>, VaultError> {
    let parts: Vec<&str> = jwe.split('.').collect();
    if parts.len() != 5 {
        return Err(VaultError::Other(
            "Invalid JWE compact serialization: expected 5 parts".to_string(),
        ));
    }

    let header_b64 = parts[0];
    if header_b64.is_empty() {
        return Err(VaultError::Other(
            "Invalid JWE compact serialization: missing header segment".to_string(),
        ));
    }

    let header_bytes = Base64UrlUnpadded::decode_vec(header_b64)
        .map_err(|_| VaultError::Other("Invalid JWE compact serialization: header is not valid Base64URL".to_string()))?;

    let header: VaultJweHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| VaultError::Other("Invalid JWE compact serialization: header is not valid JSON".to_string()))?;

    Ok(header.kid)
}

/// Validate claims: check expiry, blocklist, usage limits, and required fields.
///
/// # Errors
/// Returns appropriate `VaultError` variant if validation fails.
pub fn validate_claims(claims: &VaultClaims, current_usage: u64) -> Result<(), VaultError> {
    // Validate required fields are non-empty
    if claims.jti.trim().is_empty() {
        return Err(VaultError::Other(
            "Invalid token: jti must not be empty".to_string(),
        ));
    }
    if claims.sub.trim().is_empty() {
        return Err(VaultError::Other(
            "Invalid token: sub must not be empty".to_string(),
        ));
    }
    if claims.exe.trim().is_empty() {
        return Err(VaultError::Other(
            "Invalid token: exe must not be empty".to_string(),
        ));
    }
    if claims.bkd.trim().is_empty() {
        return Err(VaultError::Other(
            "Invalid token: bkd must not be empty".to_string(),
        ));
    }
    if claims.val.trim().is_empty() {
        return Err(VaultError::Other(
            "Invalid token: val must not be empty".to_string(),
        ));
    }
    if claims.reference.trim().is_empty() {
        return Err(VaultError::Other(
            "Invalid token: ref must not be empty".to_string(),
        ));
    }

    // Validate timestamp ordering
    if claims.iat > claims.exp {
        return Err(VaultError::Other(
            "Invalid token: iat must not be after exp".to_string(),
        ));
    }

    // Check expiration
    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now_sec >= claims.exp {
        return Err(VaultError::TokenExpired {
            message: format!("Token expired at {} (now: {})", claims.exp, now_sec),
            can_refresh: false,
        });
    }

    // Check blocklist
    {
        let bl = blocklist();
        if let Some(ref state) = *bl
            && state.entries.contains_key(&claims.jti)
        {
            return Err(VaultError::TokenRevoked {
                message: format!("Token {} has been revoked", claims.jti),
            });
        }
    }

    // Check usage limit
    if let Some(limit) = claims.use_limit {
        if limit == 0 {
            return Err(VaultError::UsageLimitExceeded {
                message: format!(
                    "Token {} has a non-positive usage limit: {}",
                    claims.jti, limit
                ),
            });
        }
        if current_usage >= limit {
            return Err(VaultError::UsageLimitExceeded {
                message: format!(
                    "Token {} usage limit of {} exceeded (used: {})",
                    claims.jti, limit, current_usage
                ),
            });
        }
    }

    Ok(())
}

/// Add a token JTI to the blocklist.
pub fn block_token(jti: &str) {
    let mut bl = blocklist();
    let state = bl.get_or_insert_with(|| BlocklistState {
        entries: HashMap::new(),
        counter: 0,
    });

    // If already present, refresh its position
    if state.entries.contains_key(jti) {
        state.counter += 1;
        state.entries.insert(jti.to_string(), state.counter);
        return;
    }

    // Evict oldest if at capacity
    if state.entries.len() >= BLOCKLIST_MAX_SIZE
        && let Some(oldest_key) = state
            .entries
            .iter()
            .min_by_key(|(_, v)| **v)
            .map(|(k, _)| k.clone())
    {
        state.entries.remove(&oldest_key);
    }

    state.counter += 1;
    state.entries.insert(jti.to_string(), state.counter);
}

/// Check if a JTI is blocked.
pub fn is_blocked(jti: &str) -> bool {
    let bl = blocklist();
    bl.as_ref()
        .is_some_and(|state| state.entries.contains_key(jti))
}

/// Clear all blocked JTIs (for testing).
pub fn clear_blocklist() {
    let mut bl = blocklist();
    *bl = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TrustTier;

    fn test_claims() -> VaultClaims {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        VaultClaims {
            jti: "test-jti-001".to_string(),
            exp: now + 3600,
            iat: now,
            sub: "my-secret".to_string(),
            exe: "dev".to_string(),
            use_limit: None,
            tid: TrustTier::Dev,
            bkd: "file".to_string(),
            val: "s3cret-value".to_string(),
            reference: "my-secret".to_string(),
        }
    }

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).unwrap();
        key
    }

    #[test]
    fn create_and_decrypt_round_trip() {
        let key = test_key();
        let claims = test_claims();
        let opts = CreateTokenOptions { kid: Some("k-123".to_string()) };

        let jwe = create_token(&key, &claims, &opts).unwrap();

        // Verify 5-part structure
        let parts: Vec<&str> = jwe.split('.').collect();
        assert_eq!(parts.len(), 5);
        assert!(parts[1].is_empty(), "encrypted key must be empty for dir");

        // Decrypt and verify claims match
        let decrypted = decrypt_token(&key, &jwe).unwrap();
        assert_eq!(decrypted.jti, claims.jti);
        assert_eq!(decrypted.sub, claims.sub);
        assert_eq!(decrypted.val, claims.val);
        assert_eq!(decrypted.exe, claims.exe);
        assert_eq!(decrypted.tid, claims.tid);
        assert_eq!(decrypted.bkd, claims.bkd);
        assert_eq!(decrypted.reference, claims.reference);
        assert_eq!(decrypted.exp, claims.exp);
        assert_eq!(decrypted.iat, claims.iat);
        assert_eq!(decrypted.use_limit, claims.use_limit);
    }

    #[test]
    fn extract_kid_from_jwe() {
        let key = test_key();
        let claims = test_claims();
        let opts = CreateTokenOptions { kid: Some("k-456".to_string()) };

        let jwe = create_token(&key, &claims, &opts).unwrap();
        let kid = extract_kid(&jwe).unwrap();
        assert_eq!(kid, Some("k-456".to_string()));
    }

    #[test]
    fn extract_kid_none_when_absent() {
        let key = test_key();
        let claims = test_claims();
        let opts = CreateTokenOptions { kid: None };

        let jwe = create_token(&key, &claims, &opts).unwrap();
        let kid = extract_kid(&jwe).unwrap();
        assert_eq!(kid, None);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key1 = test_key();
        let key2 = test_key();
        let claims = test_claims();
        let opts = CreateTokenOptions { kid: None };

        let jwe = create_token(&key1, &claims, &opts).unwrap();
        let result = decrypt_token(&key2, &jwe);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let key = test_key();
        let claims = test_claims();
        let opts = CreateTokenOptions { kid: None };

        let jwe = create_token(&key, &claims, &opts).unwrap();
        let mut parts: Vec<&str> = jwe.split('.').collect();

        // Tamper with ciphertext
        let tampered = format!("{}X", parts[3]);
        parts[3] = &tampered;
        let tampered_jwe = parts.join(".");

        let result = decrypt_token(&key, &tampered_jwe);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_jwe_structure() {
        let key = test_key();
        assert!(decrypt_token(&key, "not.a.jwe").is_err());
        assert!(decrypt_token(&key, "").is_err());
        assert!(extract_kid("only.two.parts").is_err());
    }

    #[test]
    fn key_must_be_32_bytes() {
        let short_key = [0u8; 16];
        let claims = test_claims();
        let opts = CreateTokenOptions { kid: None };

        assert!(create_token(&short_key, &claims, &opts).is_err());
        assert!(decrypt_token(&short_key, "a.b.c.d.e").is_err());
    }

    #[test]
    fn blocklist_operations() {
        clear_blocklist();

        assert!(!is_blocked("jti-1"));
        block_token("jti-1");
        assert!(is_blocked("jti-1"));

        clear_blocklist();
        assert!(!is_blocked("jti-1"));
    }

    #[test]
    fn validate_claims_rejects_expired() {
        let mut claims = test_claims();
        claims.exp = 1000; // Far in the past
        claims.iat = 900;

        let result = validate_claims(&claims, 0);
        assert!(matches!(result, Err(VaultError::TokenExpired { .. })));
    }

    #[test]
    fn validate_claims_rejects_blocked() {
        // Use a unique JTI to avoid races with other blocklist tests
        let mut claims = test_claims();
        claims.jti = "blocked-test-unique-jti".to_string();
        block_token(&claims.jti);

        let result = validate_claims(&claims, 0);
        assert!(matches!(result, Err(VaultError::TokenRevoked { .. })));
    }

    #[test]
    fn validate_claims_rejects_usage_exceeded() {
        let mut claims = test_claims();
        claims.use_limit = Some(3);

        let result = validate_claims(&claims, 3);
        assert!(matches!(result, Err(VaultError::UsageLimitExceeded { .. })));

        // Under limit should pass
        let result = validate_claims(&claims, 2);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_claims_rejects_empty_required_fields() {
        let mut claims = test_claims();
        claims.jti = "  ".to_string();
        assert!(validate_claims(&claims, 0).is_err());

        let mut claims = test_claims();
        claims.sub = "".to_string();
        assert!(validate_claims(&claims, 0).is_err());

        let mut claims = test_claims();
        claims.val = "".to_string();
        assert!(validate_claims(&claims, 0).is_err());
    }

    #[test]
    fn validate_claims_rejects_iat_after_exp() {
        let mut claims = test_claims();
        claims.iat = claims.exp + 100;
        assert!(validate_claims(&claims, 0).is_err());
    }

    #[test]
    fn validate_claims_accepts_valid() {
        let mut claims = test_claims();
        claims.jti = "valid-test-unique-jti".to_string();
        assert!(validate_claims(&claims, 0).is_ok());
    }
}
