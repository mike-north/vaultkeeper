//! Integration tests for the persistent, tamper-evident, two-axis lease
//! revocation store (issue #298).
//!
//! Each `VaultKeeper`/`TestHost` pair below is constructed fresh with no
//! shared Rust statics between them — the only thing two "process" instances
//! in a test share is the backing file map (via `Arc<Mutex<..>>`), exactly
//! mirroring what two real OS processes share: the files under the host
//! config directory, nothing in-memory. `validate_lease_revocation` reads
//! entirely from that shared backing store, so this genuinely exercises the
//! cross-process persistence the design is for, without needing to spawn a
//! real subprocess (the native-CLI subprocess surface for this is
//! `vaultkeeper-cli`'s `session revoke`; the same `VaultKeeper` methods this
//! file drives directly are exactly what that CLI command calls).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use vaultkeeper_core::backend::{ExecOptions, ExecOutput, HostPlatform, Platform};
use vaultkeeper_core::errors::VaultError;
use vaultkeeper_core::types::{ClaimsKind, TrustTier, VaultClaims};
use vaultkeeper_core::vault::{VaultKeeper, VaultKeeperOptions};

/// A `HostPlatform` backed by a shared, in-memory file map. Two `TestHost`
/// instances built via [`TestHost::sharing`] see the same files but are
/// otherwise fully independent objects — no shared statics, no shared
/// `KeyManager`/`VaultKeeper` state — the same isolation two real OS
/// processes have.
struct TestHost {
    files: Arc<Mutex<HashMap<PathBuf, Vec<u8>>>>,
    config_dir: PathBuf,
}

impl TestHost {
    fn new() -> Self {
        Self {
            files: Arc::new(Mutex::new(HashMap::new())),
            config_dir: PathBuf::from("/test/config"),
        }
    }

    fn sharing(&self) -> Self {
        Self {
            files: Arc::clone(&self.files),
            config_dir: self.config_dir.clone(),
        }
    }
}

#[async_trait::async_trait]
impl HostPlatform for TestHost {
    async fn exec(
        &self,
        _cmd: &str,
        _args: &[&str],
        _options: ExecOptions<'_>,
    ) -> Result<ExecOutput, VaultError> {
        Ok(ExecOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_code: 0,
        })
    }
    async fn read_file(&self, path: &Path) -> Result<Vec<u8>, VaultError> {
        self.files
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .ok_or_else(|| VaultError::Other(format!("not found: {}", path.display())))
    }
    async fn write_file(&self, path: &Path, content: &[u8], _mode: u32) -> Result<(), VaultError> {
        self.files
            .lock()
            .unwrap()
            .insert(path.to_path_buf(), content.to_vec());
        Ok(())
    }
    async fn file_exists(&self, path: &Path) -> Result<bool, VaultError> {
        Ok(self.files.lock().unwrap().contains_key(path))
    }
    async fn delete_file(&self, path: &Path) -> Result<(), VaultError> {
        self.files.lock().unwrap().remove(path);
        Ok(())
    }
    async fn rename_file(&self, from: &Path, to: &Path) -> Result<(), VaultError> {
        let data = self
            .files
            .lock()
            .unwrap()
            .remove(from)
            .ok_or_else(|| VaultError::Other(format!("not found: {}", from.display())))?;
        self.files.lock().unwrap().insert(to.to_path_buf(), data);
        Ok(())
    }
    async fn list_dir(&self, _path: &Path) -> Result<Vec<String>, VaultError> {
        Ok(Vec::new())
    }
    fn platform(&self) -> Platform {
        Platform::Linux
    }
    fn config_dir(&self) -> &Path {
        &self.config_dir
    }
}

async fn init_vault(host: &TestHost) -> VaultKeeper {
    VaultKeeper::init(
        host,
        Some(VaultKeeperOptions {
            skip_doctor: true,
            ..Default::default()
        }),
    )
    .await
    .expect("VaultKeeper::init should succeed against a fresh in-memory host")
}

fn signing_lease_claims(jti: &str, sub: &str, kgen: u64, exp: u64) -> VaultClaims {
    VaultClaims {
        jti: jti.to_string(),
        exp,
        iat: 0,
        sub: sub.to_string(),
        exe: "dev".to_string(),
        use_limit: None,
        tid: TrustTier::Dev,
        bkd: None,
        val: None,
        reference: sub.to_string(),
        kty: Some(ClaimsKind::SigningKey),
        kid: Some(format!("kid-for-{sub}")),
        kgen: Some(kgen),
        pres: None,
    }
}

const FAR_FUTURE: u64 = 9_999_999_999;

fn assert_revoked(result: Result<(), VaultError>) {
    match result {
        Err(VaultError::TokenRevoked { .. }) => {}
        other => panic!("expected VaultError::TokenRevoked, got {other:?}"),
    }
}

/// AC1: a jti revoked by one `VaultKeeper` instance is refused by a
/// completely independent instance backed by the same persisted store — the
/// cross-process case (persistence across the process boundary is the whole
/// point).
#[tokio::test]
async fn ac1_revoked_jti_refused_in_a_different_process() {
    let host_a = TestHost::new();
    let mut vault_a = init_vault(&host_a).await;

    vault_a
        .revoke_lease_jti(&host_a, "revoked-jti", FAR_FUTURE)
        .await
        .unwrap();

    // A wholly independent "process": fresh TestHost sharing only the
    // backing file map, fresh VaultKeeper, no shared in-memory state.
    let host_b = host_a.sharing();
    let mut vault_b = init_vault(&host_b).await;

    let claims = signing_lease_claims("revoked-jti", "release-signer", 0, FAR_FUTURE);
    let result = vault_b.validate_lease_revocation(&host_b, &claims).await;
    assert_revoked(result);

    // A lease with a different jti for the same key is unaffected.
    let other = signing_lease_claims("other-jti", "release-signer", 0, FAR_FUTURE);
    vault_b
        .validate_lease_revocation(&host_b, &other)
        .await
        .expect("an unrevoked jti must still validate");
}

/// AC2: `revoke --key` invalidates multiple outstanding leases for that key
/// in one operation.
#[tokio::test]
async fn ac2_revoke_key_invalidates_multiple_leases_in_one_operation() {
    let host_a = TestHost::new();
    let mut vault_a = init_vault(&host_a).await;

    vault_a
        .revoke_lease_key(&host_a, "release-signer")
        .await
        .unwrap();

    let host_b = host_a.sharing();
    let mut vault_b = init_vault(&host_b).await;

    // Two distinct leases, both minted under generation 0 (before the
    // revocation), both for the same key.
    let lease_one = signing_lease_claims("jti-one", "release-signer", 0, FAR_FUTURE);
    let lease_two = signing_lease_claims("jti-two", "release-signer", 0, FAR_FUTURE);

    assert_revoked(vault_b.validate_lease_revocation(&host_b, &lease_one).await);
    assert_revoked(vault_b.validate_lease_revocation(&host_b, &lease_two).await);

    // A lease minted under the new generation is unaffected.
    let fresh = signing_lease_claims("jti-fresh", "release-signer", 1, FAR_FUTURE);
    vault_b
        .validate_lease_revocation(&host_b, &fresh)
        .await
        .expect("a lease minted at the current generation must still validate");
}

/// AC3: deleting and re-enrolling a signing key under the same name does not
/// revive previously revoked leases — `key_generations` is never reset, so a
/// freshly re-created key's lease-minting path (which would naturally start
/// counting from generation 0 again if it kept no memory of the past) must
/// still be checked against the *store's* generation, not its own count.
#[tokio::test]
async fn ac3_delete_and_reenroll_does_not_revive_revoked_leases() {
    let host_a = TestHost::new();
    let mut vault_a = init_vault(&host_a).await;

    vault_a
        .revoke_lease_key(&host_a, "release-signer")
        .await
        .unwrap();
    vault_a
        .revoke_lease_key(&host_a, "release-signer")
        .await
        .unwrap();

    // Simulate deleting the signing key's own private-key material (a
    // separate store — `backend::signing_store` — entirely untouched by
    // this revocation store) and re-enrolling under the same name. A naive
    // re-enrollment might mint its first lease claiming `kgen: 0` again,
    // believing it is starting fresh.
    let revived_attempt =
        signing_lease_claims("jti-after-reenroll", "release-signer", 0, FAR_FUTURE);

    let host_b = host_a.sharing();
    let mut vault_b = init_vault(&host_b).await;
    assert_revoked(
        vault_b
            .validate_lease_revocation(&host_b, &revived_attempt)
            .await,
    );

    // Only a lease minted at (or above) the store's true generation — 2,
    // after two revocations — validates.
    let honest_lease = signing_lease_claims("jti-honest", "release-signer", 2, FAR_FUTURE);
    vault_b
        .validate_lease_revocation(&host_b, &honest_lease)
        .await
        .expect("a lease minted at the store's true current generation must validate");
}

/// AC5 (integration companion to the unit-level check in
/// `crates/vaultkeeper-core/src/jwe/token.rs`): a lease with no `kgen` claim
/// is rejected by `validate_lease_revocation` itself, fail-closed, never
/// defaulted to generation 0 — exercised end-to-end against a persisted
/// store rather than in isolation.
#[tokio::test]
async fn ac5_lease_without_kgen_is_rejected_not_defaulted_to_zero() {
    let host = TestHost::new();
    let mut vault = init_vault(&host).await;

    let mut claims = signing_lease_claims("jti-no-kgen", "release-signer", 0, FAR_FUTURE);
    claims.kgen = None;

    assert_revoked(vault.validate_lease_revocation(&host, &claims).await);
}

/// AC8 (deletion): a missing revocation store fails closed for lease
/// validation, but ordinary secret authorization is entirely unaffected —
/// a corrupted/missing revocation store must not brick the MCP wrapper.
#[tokio::test]
async fn ac8_missing_store_fails_closed_for_leases_only_not_secret_authorization() {
    let host = TestHost::new();
    let mut vault = init_vault(&host).await;

    // Mint an ordinary secret token and confirm it authorizes normally.
    let token = vault
        .setup(
            &host,
            "my-secret",
            "s3cret-value",
            Some(&vaultkeeper_core::vault::SetupOptions {
                skip_trust: Some(true),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // Delete keys.enc entirely — the revocation store's anchor now says
    // "there should be a store" (key state was persisted at init) but the
    // file is gone.
    host.delete_file(&host.config_dir().join("keys.enc"))
        .await
        .unwrap();

    // Lease validation must fail closed.
    let lease = signing_lease_claims("jti-x", "release-signer", 0, FAR_FUTURE);
    assert_revoked(vault.validate_lease_revocation(&host, &lease).await);

    // Ordinary secret authorization must be entirely unaffected — `authorize`
    // resolves purely from the in-memory key manager it already holds, never
    // touching the revocation store.
    let (_, claims, _) = vault
        .authorize(&token)
        .expect("secret authorization must be unaffected by a missing revocation store");
    assert_eq!(claims.sub, "my-secret");
}

/// AC9: `rotateKey` leaves a previously revoked jti and a bumped
/// `keyGenerations` still enforced — rotating the vault's own encryption key
/// must not reset revocation state, or rotation becomes a revocation bypass.
#[tokio::test]
async fn ac9_rotate_key_does_not_reset_revocation_state() {
    let host = TestHost::new();
    let mut vault = init_vault(&host).await;

    vault
        .revoke_lease_jti(&host, "jti-before-rotation", FAR_FUTURE)
        .await
        .unwrap();
    vault
        .revoke_lease_key(&host, "release-signer")
        .await
        .unwrap();

    vault.rotate_key(&host).await.unwrap();

    let host_b = host.sharing();
    let mut vault_b = init_vault(&host_b).await;

    let revoked_jti = signing_lease_claims("jti-before-rotation", "other-key", 0, FAR_FUTURE);
    assert_revoked(
        vault_b
            .validate_lease_revocation(&host_b, &revoked_jti)
            .await,
    );

    let revoked_key = signing_lease_claims("jti-after-rotation", "release-signer", 0, FAR_FUTURE);
    assert_revoked(
        vault_b
            .validate_lease_revocation(&host_b, &revoked_key)
            .await,
    );
}

/// AC9 companion: `revokeKey` (the *encryption*-key emergency-revocation
/// path, distinct from lease revocation) also leaves lease revocation state
/// untouched.
#[tokio::test]
async fn ac9_encryption_key_revoke_does_not_reset_lease_revocation_state() {
    let host = TestHost::new();
    let mut vault = init_vault(&host).await;

    vault
        .revoke_lease_jti(&host, "jti-before-key-revoke", FAR_FUTURE)
        .await
        .unwrap();

    vault.revoke_key(&host).await.unwrap();

    let claims = signing_lease_claims("jti-before-key-revoke", "release-signer", 0, FAR_FUTURE);
    assert_revoked(vault.validate_lease_revocation(&host, &claims).await);
}

/// AC10: a `session revoke` sequenced closely with a `rotateKey` clobbers
/// neither — each writer reads the current on-disk state for the portion it
/// does not own immediately before its own write (read-modify-write, not a
/// blind overwrite), so this holds regardless of which happens first.
#[tokio::test]
async fn ac10_concurrent_revoke_and_rotate_clobber_neither_order() {
    // Order 1: revoke, then rotate.
    {
        let host = TestHost::new();
        let mut vault = init_vault(&host).await;
        let original_key_id = vault.key_manager().get_current_key().unwrap().id.clone();

        vault
            .revoke_lease_jti(&host, "concurrent-jti", FAR_FUTURE)
            .await
            .unwrap();
        vault.rotate_key(&host).await.unwrap();

        // The rotation actually happened...
        let rotated_key_id = vault.key_manager().get_current_key().unwrap().id.clone();
        assert_ne!(original_key_id, rotated_key_id);

        // ...and the revoke was not clobbered by it.
        let host_b = host.sharing();
        let mut vault_b = init_vault(&host_b).await;
        let claims = signing_lease_claims("concurrent-jti", "release-signer", 0, FAR_FUTURE);
        assert_revoked(vault_b.validate_lease_revocation(&host_b, &claims).await);
    }

    // Order 2: rotate, then revoke.
    {
        let host = TestHost::new();
        let mut vault = init_vault(&host).await;
        let original_key_id = vault.key_manager().get_current_key().unwrap().id.clone();

        vault.rotate_key(&host).await.unwrap();
        vault
            .revoke_lease_jti(&host, "concurrent-jti-2", FAR_FUTURE)
            .await
            .unwrap();

        let rotated_key_id = vault.key_manager().get_current_key().unwrap().id.clone();
        assert_ne!(original_key_id, rotated_key_id);

        let host_b = host.sharing();
        let mut vault_b = init_vault(&host_b).await;
        let claims = signing_lease_claims("concurrent-jti-2", "release-signer", 0, FAR_FUTURE);
        assert_revoked(vault_b.validate_lease_revocation(&host_b, &claims).await);

        // And the rotated key material itself survived too, in a fresh
        // hydration of the persisted state.
        assert_eq!(
            vault_b.key_manager().get_current_key().unwrap().id,
            rotated_key_id
        );
    }
}
