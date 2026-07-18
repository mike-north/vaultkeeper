//! Detached-payload Compact JWS assembly and verification (Ed25519 / EdDSA).
//!
//! The signature format is the documented, stable contract: a
//! detached-payload Compact JWS (RFC 7515 §7.2.2 + RFC 7797 `b64:false`,
//! `crit:["b64"]`). The serialization is `<protected>..<signature>` with the
//! payload omitted; the algorithm is `EdDSA` (Ed25519); all encoding is
//! base64url without padding. This is byte-for-byte what the TypeScript
//! reference implementation (`packages/vaultkeeper/src/access/jws.ts`, which
//! uses `jose` for its own verification step) produces for the same header
//! and payload, so output from either implementation verifies under any
//! standards-compliant JOSE library.
//!
//! Signing is performed by a caller-supplied [`SigningBackend`] so the
//! private key never enters this module — only the resulting signature bytes
//! do (see [`create_detached_jws`]).
//!
//! @see https://www.rfc-editor.org/rfc/rfc7515 (JWS)
//! @see https://www.rfc-editor.org/rfc/rfc7797 (Unencoded Payload Option)

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::Serialize;

use crate::backend::SigningBackend;
use crate::errors::VaultError;
use crate::types::VerifyRequest;

use super::ed25519;

/// The single supported JWS `alg` (Ed25519).
pub const JWS_ALG: &str = "EdDSA";

/// The protected header shape, serialized in field order `alg, b64, crit,
/// kid` to match the TypeScript reference's `JSON.stringify({ alg, b64,
/// crit, kid })` byte-for-byte (a `derive`d struct serializes fields in
/// declaration order, never a `BTreeMap`/`Value`, which could reorder keys).
#[derive(Debug, Serialize)]
struct ProtectedHeader<'a> {
    alg: &'static str,
    b64: bool,
    crit: [&'static str; 1],
    kid: &'a str,
}

/// Build the RFC 7797 (`b64:false`) JWS Signing Input:
/// `ASCII(BASE64URL(UTF8(protected)) || '.') || payload`, with the payload
/// appended un-encoded (raw bytes, not base64url).
fn signing_input(protected_b64: &str, payload: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(protected_b64.len() + 1 + payload.len());
    input.extend_from_slice(protected_b64.as_bytes());
    input.push(b'.');
    input.extend_from_slice(payload);
    input
}

/// Assemble a detached-payload Compact JWS over `payload`, delegating the raw
/// signature to `backend.sign_with_key(kid, ..)`. The private key never
/// leaves the backend — this function only ever sees the resulting signature
/// bytes.
///
/// # Errors
/// Propagates whatever [`VaultError`] `backend.sign_with_key` returns (e.g.
/// [`VaultError::SigningKeyNotFound`]).
pub async fn create_detached_jws<B>(
    backend: &B,
    kid: &str,
    payload: &[u8],
) -> Result<String, VaultError>
where
    B: SigningBackend + ?Sized,
{
    let header = ProtectedHeader {
        alg: JWS_ALG,
        b64: false,
        crit: ["b64"],
        kid,
    };
    // `serde_json::to_vec` on a struct (never a `Value`/map) preserves
    // declaration field order and emits compact JSON with no extra
    // whitespace — identical byte output to `JSON.stringify` on the
    // equivalent JS object literal.
    let header_json = serde_json::to_vec(&header).map_err(|e| VaultError::Other(e.to_string()))?;
    let protected_b64 = Base64UrlUnpadded::encode_string(&header_json);

    let input = signing_input(&protected_b64, payload);
    let signature = backend.sign_with_key(kid, &input).await?;
    let signature_b64 = Base64UrlUnpadded::encode_string(&signature);

    Ok(format!("{protected_b64}..{signature_b64}"))
}

/// Shape of the protected header we require for a valid detached JWS.
/// Anything that does not match is treated as a non-verifying signature (not
/// an error) — mirrors the TypeScript verifier's `hasExpectedHeader`.
///
/// Per RFC 7515 §4.1.11, a verifier MUST reject a JWS whose `crit` lists any
/// extension it does not understand. This verifier understands only the RFC
/// 7797 `b64` extension, so `crit` must be exactly `["b64"]` — a `crit`
/// carrying any additional (un-understood) parameter, e.g. `["b64","x"]`, is
/// rejected.
fn has_expected_header(header: &serde_json::Value) -> bool {
    let Some(object) = header.as_object() else {
        return false;
    };
    let alg_ok = object.get("alg").and_then(serde_json::Value::as_str) == Some(JWS_ALG);
    let b64_ok = object.get("b64").and_then(serde_json::Value::as_bool) == Some(false);
    let crit_ok = object
        .get("crit")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|crit| crit.len() == 1 && crit[0].as_str() == Some("b64"));
    alg_ok && b64_ok && crit_ok
}

/// Verify a detached-payload Compact JWS against a public key, fully
/// offline.
///
/// Returns `Ok(false)` for a signature that does not verify — a tampered
/// payload, the wrong key, or a structurally malformed JWS. Returns
/// `Err(VaultError::InvalidKeyMaterial)` only when the *public key* itself is
/// not parseable (or a private key was supplied), which is an operational
/// fault rather than a bad signature.
///
/// # Errors
/// Returns [`VaultError::InvalidKeyMaterial`] if `request.public_key` is not
/// a valid SPKI PEM EdDSA public key, or is a private key.
pub fn verify_detached_jws(request: &VerifyRequest) -> Result<bool, VaultError> {
    // Validate the JWS envelope — its structure and, critically, its
    // declared algorithm and `crit` — BEFORE parsing any key material. The
    // algorithm this verifier accepts is fixed (EdDSA); an unsupported
    // algorithm, or a `crit` listing an un-understood extension, must be
    // rejected on the envelope's own terms (RFC 7515 §4.1.11 crit
    // semantics). Doing this first guarantees a malformed key can never mask
    // that decision or be reported in its place.
    let trimmed = request.jws.trim();
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() != 3 {
        return Ok(false);
    }
    let (protected_b64, middle, signature_b64) = (parts[0], parts[1], parts[2]);
    // A detached compact JWS has an empty payload segment.
    if !middle.is_empty() {
        return Ok(false);
    }

    let Ok(header_bytes) = Base64UrlUnpadded::decode_vec(protected_b64) else {
        return Ok(false);
    };
    let Ok(header) = serde_json::from_slice::<serde_json::Value>(&header_bytes) else {
        return Ok(false);
    };
    if !has_expected_header(&header) {
        return Ok(false);
    }

    // Only once the algorithm/envelope is accepted do we parse the public
    // key. `ed25519::parse_public_key_pem` rejects a private key supplied as
    // the public key with a typed `InvalidKeyMaterial` error before
    // attempting any cryptographic parse — the documented contract is an
    // SPKI *public* key only.
    let verifying_key = ed25519::parse_public_key_pem(&request.public_key)?;

    let Ok(signature_bytes) = Base64UrlUnpadded::decode_vec(signature_b64) else {
        return Ok(false);
    };

    let input = signing_input(protected_b64, &request.payload);
    Ok(ed25519::verify(&verifying_key, &input, &signature_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_header_serializes_in_field_order_matching_jose() {
        let header = ProtectedHeader {
            alg: JWS_ALG,
            b64: false,
            crit: ["b64"],
            kid: "my-key",
        };
        let json = serde_json::to_string(&header).unwrap();
        assert_eq!(
            json,
            r#"{"alg":"EdDSA","b64":false,"crit":["b64"],"kid":"my-key"}"#
        );
    }

    #[test]
    fn signing_input_is_protected_dot_payload_unencoded() {
        let input = signing_input("HEADER", b"payload-bytes");
        assert_eq!(input, b"HEADER.payload-bytes");
    }

    #[test]
    fn signing_input_with_empty_payload() {
        let input = signing_input("HEADER", b"");
        assert_eq!(input, b"HEADER.");
    }

    #[test]
    fn has_expected_header_accepts_canonical_shape() {
        let header =
            serde_json::json!({ "alg": "EdDSA", "b64": false, "crit": ["b64"], "kid": "k" });
        assert!(has_expected_header(&header));
    }

    #[test]
    fn has_expected_header_rejects_wrong_alg() {
        let header =
            serde_json::json!({ "alg": "RS256", "b64": false, "crit": ["b64"], "kid": "k" });
        assert!(!has_expected_header(&header));
    }

    #[test]
    fn has_expected_header_rejects_wrong_crit() {
        let header =
            serde_json::json!({ "alg": "EdDSA", "b64": false, "crit": ["b64", "x"], "kid": "k" });
        assert!(!has_expected_header(&header));
    }

    #[test]
    fn has_expected_header_rejects_missing_crit() {
        let header = serde_json::json!({ "alg": "EdDSA", "b64": false, "kid": "k" });
        assert!(!has_expected_header(&header));
    }

    #[test]
    fn has_expected_header_rejects_b64_true() {
        let header =
            serde_json::json!({ "alg": "EdDSA", "b64": true, "crit": ["b64"], "kid": "k" });
        assert!(!has_expected_header(&header));
    }

    #[test]
    fn has_expected_header_rejects_non_object() {
        assert!(!has_expected_header(&serde_json::json!([
            "not", "an", "object"
        ])));
        assert!(!has_expected_header(&serde_json::json!(null)));
    }

    #[test]
    fn verify_detached_jws_rejects_structurally_malformed_jws() {
        let request = VerifyRequest {
            payload: b"payload".to_vec(),
            jws: "only-one-part".into(),
            public_key: "irrelevant".into(),
        };
        assert!(!verify_detached_jws(&request).unwrap());
    }

    #[test]
    fn verify_detached_jws_rejects_non_empty_middle_segment() {
        let request = VerifyRequest {
            payload: b"payload".to_vec(),
            jws: "aGVhZGVy.bWlkZGxl.c2ln".into(),
            public_key: "irrelevant".into(),
        };
        assert!(!verify_detached_jws(&request).unwrap());
    }

    #[test]
    fn verify_detached_jws_rejects_bad_header_before_parsing_a_bad_key() {
        // The header carries a wrong `alg`, AND the "public key" is garbage
        // that would also fail to parse. This proves ordering: the header
        // check runs first and returns `Ok(false)`, never reaching (and
        // therefore never erroring on) key parsing.
        let bad_header =
            serde_json::json!({ "alg": "RS256", "b64": false, "crit": ["b64"], "kid": "k" });
        let header_b64 =
            Base64UrlUnpadded::encode_string(&serde_json::to_vec(&bad_header).unwrap());
        let request = VerifyRequest {
            payload: b"payload".to_vec(),
            jws: format!("{header_b64}..c2ln"),
            public_key: "not a pem at all".into(),
        };
        assert!(!verify_detached_jws(&request).unwrap());
    }
}
