//! Admission ordering tests using the native filesystem and key operations.

use std::path::Path;
use std::task::{Context, Poll, Waker};

use tokio::sync::Notify;
use vaultkeeper_core::backend::{ExecOptions, ExecOutput, HostPlatform, Platform};
use vaultkeeper_core::errors::VaultError;
use vaultkeeper_core::vault::{SetupOptions, VaultKeeper, VaultKeeperOptions};

use crate::host::NativeHostPlatform;

/// Pause the admission's fresh read once it holds the old encrypted snapshot.
/// The revoker uses its own native host for the same directory.
struct SnapshotGate<'a> {
    native: &'a NativeHostPlatform,
    captured: Notify,
    resume: Notify,
}

#[async_trait::async_trait]
impl HostPlatform for SnapshotGate<'_> {
    async fn read_file(&self, path: &Path) -> Result<Vec<u8>, VaultError> {
        let bytes = self.native.read_file(path).await?;
        if path == self.config_dir().join("keys.enc") {
            self.captured.notify_one();
            self.resume.notified().await;
        }
        Ok(bytes)
    }

    async fn exec(
        &self,
        cmd: &str,
        args: &[&str],
        options: ExecOptions<'_>,
    ) -> Result<ExecOutput, VaultError> {
        self.native.exec(cmd, args, options).await
    }

    async fn write_file(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<(), VaultError> {
        self.native.write_file(path, bytes, mode).await
    }

    async fn file_exists(&self, path: &Path) -> Result<bool, VaultError> {
        self.native.file_exists(path).await
    }

    async fn delete_file(&self, path: &Path) -> Result<(), VaultError> {
        self.native.delete_file(path).await
    }

    async fn list_dir(&self, path: &Path) -> Result<Vec<String>, VaultError> {
        self.native.list_dir(path).await
    }

    fn platform(&self) -> Platform {
        self.native.platform()
    }

    fn config_dir(&self) -> &Path {
        self.native.config_dir()
    }
}

/// A revoker cannot finish once admission reads the old snapshot and before
/// that admission commits its durable reservation.
#[tokio::test]
async fn revoke_key_cannot_finish_between_snapshot_read_and_usage_commit() {
    let dir = tempfile::tempdir().unwrap();
    let native = NativeHostPlatform::new(dir.path().to_owned());
    let mut vault = VaultKeeper::init(
        &native,
        Some(VaultKeeperOptions {
            skip_doctor: true,
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    let token = vault
        .setup(
            &native,
            "test-token",
            "fixture-value",
            Some(&SetupOptions {
                ttl_minutes: None,
                use_limit: Some(2),
                executable_path: None,
                skip_trust: Some(true),
                trust_tier: None,
                backend_type: None,
            }),
        )
        .await
        .unwrap();
    let (handle, claims, _) = vault.authorize(&token).unwrap();
    vault.release_handle(&handle);
    let fingerprint = vaultkeeper_core::identity::hash::hash_bytes(claims.jti.as_bytes());
    let counter = dir
        .path()
        .join("token-usage")
        .join(format!("{fingerprint}.json"));
    let gate = SnapshotGate {
        native: &native,
        captured: Notify::new(),
        resume: Notify::new(),
    };
    let mut revocation = std::pin::pin!(crate::cmd_change_key(&native, crate::KeyChange::Revoke));
    let before_commit = {
        let mut admission = std::pin::pin!(super::reserve(
            &gate,
            &token,
            &claims,
            vault.key_manager_mut()
        ));
        tokio::select! {
            () = gate.captured.notified() => {},
            result = &mut admission => panic!("admission finished before snapshot pause: {result:?}"),
        }
        assert!(!counter.exists());

        // Native key I/O completes synchronously when uncontended. Polling
        // drives the actual command to completion or lock contention.
        let state = revocation
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()));
        gate.resume.notify_one();
        admission.await.unwrap();
        state
    };
    assert_eq!(super::read_usage(&counter).unwrap(), 1);
    assert!(
        matches!(before_commit, Poll::Pending),
        "emergency revocation finished before the old key's admission committed"
    );
    assert_eq!(revocation.await, 0);
    assert!(matches!(
        super::reserve(&native, &token, &claims, vault.key_manager_mut()).await,
        Err(VaultError::KeyRevoked { .. })
    ));
    assert_eq!(super::read_usage(&counter).unwrap(), 1);
}
