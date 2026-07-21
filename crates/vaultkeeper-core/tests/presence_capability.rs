//! Tests for the presence/capability model (issue #242).
//!
//! Ports the TypeScript reference test suites for this contract:
//! `packages/vaultkeeper/test/unit/backend/capabilities.test.ts` (AC1) and
//! `packages/vaultkeeper/test/integration/presence-enforcement.test.ts`
//! (AC3/AC4/AC5/AC6). `vaultkeeper-core`'s `VaultKeeper` does not yet have
//! backend-touching `store`/`retrieve`/`delete`/`sign` methods (see the seam
//! note on `enforce_presence_requirement`), so these tests drive
//! `enforce_presence_requirement` directly against a mock presence backend —
//! the same shared primitive those future methods must call — rather than
//! through `VaultKeeper`.
//!
//! @see https://github.com/mike-north/vaultkeeper/issues/242
//! @see https://github.com/mike-north/vaultkeeper/issues/122

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use vaultkeeper_core::InMemoryBackend;
use vaultkeeper_core::backend::{
    BackendCapabilities, PresenceCapableBackend, PresenceOperation, SecretBackend,
    get_backend_capabilities, is_presence_capable_backend,
};
use vaultkeeper_core::errors::VaultError;
use vaultkeeper_core::vault::enforce_presence_requirement;

/// A scheduled human response to an upcoming fresh-presence demand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PresenceResponse {
    Approve,
    Decline,
}

/// A mock presence-per-use backend, mirroring the TypeScript reference's
/// `MockPresenceBackend` (`packages/vaultkeeper/test/helpers/presence-backend.ts`).
///
/// Models a touch/biometric device: every *keyed* operation
/// (`store`/`retrieve`/`delete`) demands a distinct, fresh human action that
/// must be primed with [`MockPresenceBackend::arm`] beforehand. An unprimed
/// demand raises [`VaultError::PresenceTimeout`]; a demand primed to decline
/// raises [`VaultError::PresenceDeclined`]. `exists` is a probe (no keyed
/// material) and does not demand presence.
struct MockPresenceBackend {
    presence_per_use: bool,
    enforced_operations: Option<Vec<PresenceOperation>>,
    /// When `true`, `get_capabilities` itself fails instead of reporting.
    capabilities_error: bool,
    get_capabilities_calls: AtomicUsize,
    fresh_action_demands: AtomicUsize,
    armed: Mutex<VecDeque<PresenceResponse>>,
    secrets: Mutex<HashMap<String, String>>,
}

impl MockPresenceBackend {
    fn new(presence_per_use: bool) -> Self {
        Self {
            presence_per_use,
            enforced_operations: None,
            capabilities_error: false,
            get_capabilities_calls: AtomicUsize::new(0),
            fresh_action_demands: AtomicUsize::new(0),
            armed: Mutex::new(VecDeque::new()),
            secrets: Mutex::new(HashMap::new()),
        }
    }

    fn with_enforced_operations(mut self, ops: Vec<PresenceOperation>) -> Self {
        self.enforced_operations = Some(ops);
        self
    }

    fn with_capabilities_error(mut self) -> Self {
        self.capabilities_error = true;
        self
    }

    /// Prime `count` upcoming fresh-presence demands with `response`.
    fn arm(&self, response: PresenceResponse, count: usize) {
        let mut armed = self.armed.lock().expect("armed lock poisoned");
        for _ in 0..count {
            armed.push_back(response);
        }
    }

    fn get_capabilities_calls(&self) -> usize {
        self.get_capabilities_calls.load(Ordering::SeqCst)
    }

    fn fresh_action_demands(&self) -> usize {
        self.fresh_action_demands.load(Ordering::SeqCst)
    }

    /// Demand one distinct fresh human action, consuming a single primed response.
    fn demand_presence(&self) -> Result<(), VaultError> {
        self.fresh_action_demands.fetch_add(1, Ordering::SeqCst);
        let next = self.armed.lock().expect("armed lock poisoned").pop_front();
        match next {
            None => Err(VaultError::PresenceTimeout {
                message: "No fresh presence action within 1000ms".to_string(),
                backend_type: self.backend_type().to_string(),
                timeout_ms: 1000,
            }),
            Some(PresenceResponse::Decline) => Err(VaultError::PresenceDeclined {
                message: "Human declined the fresh presence action".to_string(),
                backend_type: self.backend_type().to_string(),
            }),
            Some(PresenceResponse::Approve) => Ok(()),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl SecretBackend for MockPresenceBackend {
    fn backend_type(&self) -> &str {
        "mock-presence"
    }

    fn display_name(&self) -> &str {
        "Mock Presence Backend"
    }

    async fn is_available(&self) -> bool {
        true
    }

    async fn store(&self, id: &str, secret: &str) -> Result<(), VaultError> {
        self.demand_presence()?;
        self.secrets
            .lock()
            .expect("secrets lock poisoned")
            .insert(id.to_string(), secret.to_string());
        Ok(())
    }

    async fn retrieve(&self, id: &str) -> Result<String, VaultError> {
        self.demand_presence()?;
        self.secrets
            .lock()
            .expect("secrets lock poisoned")
            .get(id)
            .cloned()
            .ok_or_else(|| VaultError::SecretNotFound {
                message: format!("Secret not found: {id}"),
            })
    }

    async fn delete(&self, id: &str) -> Result<(), VaultError> {
        self.demand_presence()?;
        self.secrets
            .lock()
            .expect("secrets lock poisoned")
            .remove(id);
        Ok(())
    }

    async fn exists(&self, id: &str) -> Result<bool, VaultError> {
        Ok(self
            .secrets
            .lock()
            .expect("secrets lock poisoned")
            .contains_key(id))
    }

    fn as_presence_capable(&self) -> Option<&dyn PresenceCapableBackend> {
        Some(self)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl PresenceCapableBackend for MockPresenceBackend {
    async fn get_capabilities(&self) -> Result<BackendCapabilities, VaultError> {
        self.get_capabilities_calls.fetch_add(1, Ordering::SeqCst);
        if self.capabilities_error {
            return Err(VaultError::Other(
                "capability probe failed: device unreachable".to_string(),
            ));
        }
        Ok(BackendCapabilities {
            presence_per_use: self.presence_per_use,
            presence_enforced_operations: self.enforced_operations.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// AC1: backend capability contract
// ---------------------------------------------------------------------------

#[tokio::test]
async fn plain_backend_reports_no_capability_via_helper() {
    // A backend that never implements PresenceCapableBackend never silently
    // claims presence.
    let backend = InMemoryBackend::new();
    let caps = get_backend_capabilities(&backend).await.unwrap();
    assert_eq!(caps, BackendCapabilities::none());
}

#[tokio::test]
async fn is_presence_capable_backend_false_for_plain_backend() {
    let backend = InMemoryBackend::new();
    assert!(!is_presence_capable_backend(&backend));
}

#[tokio::test]
async fn is_presence_capable_backend_true_for_capable_backend() {
    let backend = MockPresenceBackend::new(true);
    assert!(is_presence_capable_backend(&backend));
}

#[tokio::test]
async fn helper_delegates_to_get_capabilities_when_present() {
    let backend = MockPresenceBackend::new(true);
    let caps = get_backend_capabilities(&backend).await.unwrap();
    assert_eq!(
        caps,
        BackendCapabilities {
            presence_per_use: true,
            presence_enforced_operations: None,
        }
    );
}

#[tokio::test]
async fn helper_propagates_error_from_erroring_capability_report() {
    let backend = MockPresenceBackend::new(true).with_capabilities_error();
    let err = get_backend_capabilities(&backend).await.unwrap_err();
    assert!(matches!(err, VaultError::Other(_)));
}

// ---------------------------------------------------------------------------
// AC2/AC4: enforce_presence_requirement — fail-closed refusal
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_op_when_require_is_not_true() {
    let backend = MockPresenceBackend::new(false);
    enforce_presence_requirement(&backend, PresenceOperation::Store, None)
        .await
        .unwrap();
    enforce_presence_requirement(&backend, PresenceOperation::Store, Some(false))
        .await
        .unwrap();
    // Capabilities were never even queried — a pure no-op.
    assert_eq!(backend.get_capabilities_calls(), 0);
}

#[tokio::test]
async fn refuses_before_any_backend_touch_when_not_capable() {
    let backend = MockPresenceBackend::new(false);
    let err = enforce_presence_requirement(&backend, PresenceOperation::Store, Some(true))
        .await
        .unwrap_err();
    assert!(matches!(err, VaultError::NotCapable { .. }));
    // The backend's keyed path was never reached — refusal happened first.
    assert_eq!(backend.fresh_action_demands(), 0);
}

#[tokio::test]
async fn not_capable_error_carries_machine_readable_fields_and_qualifying_backends() {
    let backend = MockPresenceBackend::new(false);
    let err = enforce_presence_requirement(&backend, PresenceOperation::Store, Some(true))
        .await
        .unwrap_err();
    match err {
        VaultError::NotCapable {
            message,
            backend_type,
            capability,
        } => {
            assert_eq!(backend_type, "mock-presence");
            assert_eq!(capability, "presencePerUse");
            assert!(message.contains("YubiKey"));
            assert!(message.contains("1Password"));
        }
        other => panic!("expected NotCapable, got {other:?}"),
    }
}

#[tokio::test]
async fn delete_also_refused_before_touching_backend() {
    let backend = MockPresenceBackend::new(false);
    let err = enforce_presence_requirement(&backend, PresenceOperation::Delete, Some(true))
        .await
        .unwrap_err();
    assert!(matches!(err, VaultError::NotCapable { .. }));
    assert_eq!(backend.fresh_action_demands(), 0);
}

#[tokio::test]
async fn erroring_capability_report_fails_closed_without_touching_backend() {
    // AC2/AC4: an absent-or-erroring capability report must never be silently
    // treated as capable — the error propagates and the backend is untouched.
    let backend = MockPresenceBackend::new(true).with_capabilities_error();
    let err = enforce_presence_requirement(&backend, PresenceOperation::Store, Some(true))
        .await
        .unwrap_err();
    assert!(matches!(err, VaultError::Other(_)));
    assert_eq!(backend.fresh_action_demands(), 0);
}

#[tokio::test]
async fn permits_and_backend_proceeds_when_covered() {
    let backend = MockPresenceBackend::new(true);
    backend.arm(PresenceResponse::Approve, 1);
    enforce_presence_requirement(&backend, PresenceOperation::Store, Some(true))
        .await
        .unwrap();
    // Enforcement passing doesn't itself demand the action — the caller's
    // subsequent backend call does.
    assert_eq!(backend.fresh_action_demands(), 0);
    backend.store("k", "v").await.unwrap();
    assert_eq!(backend.fresh_action_demands(), 1);
}

// ---------------------------------------------------------------------------
// AC4: capabilities queried fresh per call, non-bypassability
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_operations_each_query_capabilities_and_force_a_fresh_action() {
    let backend = MockPresenceBackend::new(true);
    backend.arm(PresenceResponse::Approve, 2);

    enforce_presence_requirement(&backend, PresenceOperation::Store, Some(true))
        .await
        .unwrap();
    backend.store("a", "1").await.unwrap();

    enforce_presence_requirement(&backend, PresenceOperation::Store, Some(true))
        .await
        .unwrap();
    backend.store("b", "2").await.unwrap();

    // No caching across operations: capabilities re-queried for each call.
    assert_eq!(backend.get_capabilities_calls(), 2);
    // Each call forced its own fresh action regardless of the first's state.
    assert_eq!(backend.fresh_action_demands(), 2);
}

#[tokio::test]
async fn declined_presence_action_surfaces_presence_declined() {
    let backend = MockPresenceBackend::new(true);
    backend.arm(PresenceResponse::Decline, 1);
    enforce_presence_requirement(&backend, PresenceOperation::Store, Some(true))
        .await
        .unwrap();
    let err = backend.store("k", "v").await.unwrap_err();
    match err {
        VaultError::PresenceDeclined { backend_type, .. } => {
            assert_eq!(backend_type, "mock-presence");
        }
        other => panic!("expected PresenceDeclined, got {other:?}"),
    }
}

#[tokio::test]
async fn timed_out_presence_action_surfaces_presence_timeout() {
    let backend = MockPresenceBackend::new(true);
    // Not armed → the demand times out.
    enforce_presence_requirement(&backend, PresenceOperation::Store, Some(true))
        .await
        .unwrap();
    let err = backend.store("k", "v").await.unwrap_err();
    match err {
        VaultError::PresenceTimeout {
            backend_type,
            timeout_ms,
            ..
        } => {
            assert_eq!(backend_type, "mock-presence");
            assert_eq!(timeout_ms, 1000);
        }
        other => panic!("expected PresenceTimeout, got {other:?}"),
    }
}

#[tokio::test]
async fn two_consecutive_required_presence_operations_each_demand_a_distinct_fresh_action() {
    // Non-bypassability (mirrors the TS reference's "non-bypassability across
    // consecutive operations" test in presence-enforcement.test.ts): only ONE
    // fresh action is primed, so the second operation must not be satisfied
    // by the first's resolution or any cached material.
    let backend = MockPresenceBackend::new(true);
    backend.arm(PresenceResponse::Approve, 1);

    enforce_presence_requirement(&backend, PresenceOperation::Store, Some(true))
        .await
        .unwrap();
    backend.store("a", "1").await.unwrap();

    enforce_presence_requirement(&backend, PresenceOperation::Store, Some(true))
        .await
        .unwrap();
    let err = backend.store("b", "2").await.unwrap_err();
    assert!(matches!(err, VaultError::PresenceTimeout { .. }));

    // Both operations reached the fresh-action demand independently.
    assert_eq!(backend.fresh_action_demands(), 2);
}

// ---------------------------------------------------------------------------
// Operation-aware, fail-closed enforcement (1Password per-access shape)
// ---------------------------------------------------------------------------

/// Models 1Password per-access: presence-capable, but only the `Read`
/// operation forces a fresh action — store/delete route through a cached
/// session. A flagged store/delete must fail closed (NotCapable), never
/// silently pass without a fresh action.
fn read_only_presence_backend() -> MockPresenceBackend {
    MockPresenceBackend::new(true).with_enforced_operations(vec![PresenceOperation::Read])
}

#[tokio::test]
async fn flagged_store_refused_with_not_capable_before_any_fresh_action() {
    let backend = read_only_presence_backend();
    let err = enforce_presence_requirement(&backend, PresenceOperation::Store, Some(true))
        .await
        .unwrap_err();
    match err {
        VaultError::NotCapable {
            message,
            backend_type,
            ..
        } => {
            assert_eq!(backend_type, "mock-presence");
            // The message names the covered operation and the refused one.
            assert!(message.contains("read"));
            assert!(message.contains("store"));
        }
        other => panic!("expected NotCapable, got {other:?}"),
    }
    // Fail closed: no fresh action was demanded.
    assert_eq!(backend.fresh_action_demands(), 0);
}

#[tokio::test]
async fn flagged_delete_refused_with_not_capable() {
    let backend = read_only_presence_backend();
    let err = enforce_presence_requirement(&backend, PresenceOperation::Delete, Some(true))
        .await
        .unwrap_err();
    assert!(matches!(err, VaultError::NotCapable { .. }));
    assert_eq!(backend.fresh_action_demands(), 0);
}

#[tokio::test]
async fn flagged_read_is_covered_and_forces_a_fresh_action() {
    let backend = read_only_presence_backend();
    // Seed the secret through an unflagged store — still needs a primed
    // action (the mock is a touch device), but no presence *requirement* is
    // asserted for it.
    backend.arm(PresenceResponse::Approve, 1);
    backend.store("k", "v").await.unwrap();

    // The read IS covered, so enforcement passes and the retrieve forces its
    // own fresh action.
    backend.arm(PresenceResponse::Approve, 1);
    enforce_presence_requirement(&backend, PresenceOperation::Read, Some(true))
        .await
        .unwrap();
    let value = backend.retrieve("k").await.unwrap();
    assert_eq!(value, "v");
    // One action for the seed store, one for the presence-gated read.
    assert_eq!(backend.fresh_action_demands(), 2);
}
