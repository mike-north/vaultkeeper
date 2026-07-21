//! Backend trait definitions and host platform abstraction.

use crate::errors::VaultError;
use crate::types::{SigningAlgorithm, SigningPublicKey};
use std::path::Path;

/// Output from a subprocess execution.
#[derive(Debug, Clone)]
pub struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
}

/// Platform identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Darwin,
    Linux,
    Windows,
}

/// Options for [`HostPlatform::exec`] (issue #239).
///
/// Every field is optional, and omitting all of them preserves the exact
/// pre-#239 `exec` behavior: no stdin piped in, the child inherits the host
/// process's environment unchanged, and the child inherits the host
/// process's current working directory unchanged. `#[derive(Default)]`
/// (all-`None`) is exactly that pre-#239 behavior.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExecOptions<'a> {
    /// Bytes piped to the child process's stdin. `None` pipes nothing in
    /// (the pre-#239 default).
    pub stdin: Option<&'a [u8]>,
    /// Extra/overriding environment variables layered onto the host
    /// process's inherited environment — existing variables not named here
    /// are preserved, mirroring the Node bridge's `{ ...process.env, ...env }`
    /// spread. `None` leaves the environment untouched (the pre-#239
    /// default).
    pub env: Option<&'a [(&'a str, &'a str)]>,
    /// Working directory for the child process. `None` inherits the host
    /// process's current working directory (the pre-#239 default).
    pub cwd: Option<&'a Path>,
}

/// A minimal HTTP request description for [`HostPlatform::http_fetch`].
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

/// The response produced by [`HostPlatform::http_fetch`].
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Context for a [`HostPlatform::prompt_approval`] request.
#[derive(Debug, Clone, Copy)]
pub struct ApprovalContext<'a> {
    /// Short machine-readable identifier for the action being approved
    /// (e.g. `"delegated-fetch"`).
    pub action: &'a str,
    /// Human-readable detail shown to the approver (e.g. the resolved URL).
    pub detail: &'a str,
}

/// Host platform abstraction for OS interactions.
///
/// In native mode, implementations use `std::process::Command` and `std::fs`.
/// In WASM mode, implementations call back into JavaScript host functions.
///
/// # No-reentrancy contract
///
/// No `HostPlatform` method may call back into the vault (no `VaultKeeper`
/// method calls, no `authorize()`/`setup()`) during its own execution. Core
/// does not guard against reentrant calls; a host callback that violates
/// this can deadlock or corrupt in-flight state.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait HostPlatform: Send + Sync {
    /// Execute a subprocess, returning stdout, stderr, and exit code.
    ///
    /// `options` (issue #239) carries stdin, environment overrides, and a
    /// working directory — all optional. Passing `ExecOptions::default()`
    /// (or omitting all its fields) reproduces the pre-#239 3-argument
    /// `exec(cmd, args, stdin)` behavior exactly.
    async fn exec(
        &self,
        cmd: &str,
        args: &[&str],
        options: ExecOptions<'_>,
    ) -> Result<ExecOutput, VaultError>;

    /// Perform an HTTP request through the host's networking stack (native:
    /// a real HTTP client the host wires in; WASM: the global `fetch`).
    ///
    /// This is a Phase 0 primitive (issue #239): no core consumer calls it
    /// yet — the delegated-access port (a later issue) is the first real
    /// caller. The default implementation fails with [`VaultError::Fetch`]
    /// so existing hosts and test doubles don't need to implement real
    /// networking just to satisfy the trait; a host opts in by overriding
    /// this method.
    async fn http_fetch(&self, request: HttpRequest) -> Result<HttpResponse, VaultError> {
        Err(VaultError::Fetch {
            message: format!(
                "http_fetch is not implemented by this host platform (requested {})",
                request.url
            ),
            url: request.url,
        })
    }

    /// Ask a human to approve a sensitive action.
    ///
    /// This is an **optional** host capability (issue #239): hosts without an
    /// interactive approval mechanism keep this default, which fails closed
    /// (`Ok(false)`) rather than silently allowing. No consumer wires this up
    /// yet — a later phase gates a real action behind it.
    async fn prompt_approval(&self, _context: ApprovalContext<'_>) -> Result<bool, VaultError> {
        Ok(false)
    }

    /// Read a file.
    async fn read_file(&self, path: &Path) -> Result<Vec<u8>, VaultError>;

    /// Write a file with the given Unix permission `mode` (e.g. `0o600`).
    /// On non-Unix platforms the mode hint may be ignored.
    async fn write_file(&self, path: &Path, content: &[u8], mode: u32) -> Result<(), VaultError>;

    /// Check if a file exists.
    async fn file_exists(&self, path: &Path) -> Result<bool, VaultError>;

    /// Delete a file. Returns `Ok(())` if the file was deleted.
    async fn delete_file(&self, path: &Path) -> Result<(), VaultError>;

    /// Replace `to` with `from`, e.g. for write-to-temp-then-rename
    /// persistence (see `keys::storage`). Real hosts (native, wasm) must
    /// implement this with a genuine atomic filesystem rename — on POSIX and
    /// Windows that is atomic, and callers rely on it to guarantee a
    /// concurrent reader never observes a half-written file.
    ///
    /// The default implementation (read `from`, write it to `to`, delete
    /// `from`) is **not** atomic and does **not** satisfy that requirement —
    /// it exists only so test doubles that don't exercise this path can skip
    /// overriding it. Any host backing real persistence must override this
    /// with a true atomic rename rather than relying on the default.
    async fn rename_file(&self, from: &Path, to: &Path) -> Result<(), VaultError> {
        let data = self.read_file(from).await?;
        self.write_file(to, &data, 0o600).await?;
        self.delete_file(from).await
    }

    /// List filenames in a directory. Returns an empty vec if the dir doesn't exist.
    async fn list_dir(&self, path: &Path) -> Result<Vec<String>, VaultError>;

    /// Get platform type.
    fn platform(&self) -> Platform;

    /// Get config directory.
    fn config_dir(&self) -> &Path;
}

/// Abstraction interface for all secret storage backends.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait SecretBackend: Send + Sync {
    /// Unique type identifier for this backend.
    fn backend_type(&self) -> &str;

    /// Human-readable display name for this backend.
    fn display_name(&self) -> &str;

    /// Check whether this backend is available on the current system.
    async fn is_available(&self) -> bool;

    /// Store a secret under the given id.
    async fn store(&self, id: &str, secret: &str) -> Result<(), VaultError>;

    /// Retrieve a secret by id.
    async fn retrieve(&self, id: &str) -> Result<String, VaultError>;

    /// Delete a secret by id.
    async fn delete(&self, id: &str) -> Result<(), VaultError>;

    /// Check whether a secret exists for the given id.
    async fn exists(&self, id: &str) -> Result<bool, VaultError>;

    /// Returns this backend's presence-capability view when it implements
    /// [`PresenceCapableBackend`], or `None` otherwise.
    ///
    /// Mirrors the TypeScript library's `isPresenceCapableBackend` runtime
    /// duck-type check (`packages/vaultkeeper/src/backend/types.ts`) via a
    /// static probe, since Rust has no structural interface check on trait
    /// objects: a backend that implements [`PresenceCapableBackend`] MUST
    /// override this to return `Some(self)`. The default `None` is what makes
    /// [`get_backend_capabilities`] safely report `presence_per_use: false`
    /// for a backend that never opted in — an unknown backend never silently
    /// claims presence.
    fn as_presence_capable(&self) -> Option<&dyn PresenceCapableBackend> {
        None
    }
}

/// Backend that can enumerate stored secret IDs.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait ListableBackend: SecretBackend {
    /// List IDs of all secrets managed by this backend.
    async fn list(&self) -> Result<Vec<String>, VaultError>;
}

/// A keyed backend operation that a presence-per-use requirement can gate.
///
/// Mirrors the TypeScript library's `PresenceOperation`
/// (`packages/vaultkeeper/src/backend/types.ts`). Used by
/// [`BackendCapabilities::presence_enforced_operations`] to express that an
/// instance forces a fresh per-use action for only *some* operations. `Read`
/// covers a backend retrieve; `Store`, `Delete`, and `Sign` are the write,
/// removal, and signing paths.
///
/// In the TypeScript library, `Read` gates the secret read behind
/// `setup`/`exec` (`setup` fetches the secret from the backend before minting
/// the token). `vaultkeeper-core`'s `VaultKeeper::setup()` does not — it mints
/// a token directly from the caller-supplied secret value with no backend
/// read, and its CLI `exec` gets the secret from the JWE claims rather than a
/// live retrieve (see the seam note on
/// [`crate::vault::enforce_presence_requirement`]). `Read` here names the
/// backend operation the capability model gates, independent of which
/// caller-facing operation eventually performs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PresenceOperation {
    Read,
    Store,
    Delete,
    Sign,
}

impl PresenceOperation {
    /// Stable lowercase name matching the TypeScript `PresenceOperation`
    /// string-literal union (`'read' | 'store' | 'delete' | 'sign'`), used in
    /// `NotCapable` error messages.
    pub fn as_str(self) -> &'static str {
        match self {
            PresenceOperation::Read => "read",
            PresenceOperation::Store => "store",
            PresenceOperation::Delete => "delete",
            PresenceOperation::Sign => "sign",
        }
    }
}

impl std::fmt::Display for PresenceOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The set of security capabilities a configured backend instance advertises.
///
/// Mirrors the TypeScript library's `BackendCapabilities`
/// (`packages/vaultkeeper/src/backend/types.ts`).
///
/// Capabilities describe what a **specific configured instance** guarantees,
/// not what its backend *type* is generally able to do. Two instances of the
/// same backend type can report different capabilities depending on their
/// configuration (e.g. a YubiKey slot with a touch policy vs. one without, or
/// 1Password in `per-access` vs. `session` mode). Never derive a capability
/// from [`SecretBackend::backend_type`] alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendCapabilities {
    /// `true` when this configured instance can force a distinct, fresh
    /// physical human action (e.g. a YubiKey touch, a gpg-smartcard tap, or a
    /// 1Password per-use biometric approval) — a deliberate action taken *for
    /// this operation, right now*, not merely "a vault was unlocked at some
    /// point."
    ///
    /// The guarantee is **operation-scoped**, not blanket: see
    /// [`BackendCapabilities::presence_enforced_operations`] and
    /// [`BackendCapabilities::enforces`].
    ///
    /// Backends that do not implement [`PresenceCapableBackend`] are treated
    /// as `false` by [`get_backend_capabilities`] — an unknown backend never
    /// silently claims presence.
    pub presence_per_use: bool,

    /// The keyed operations for which this instance actually forces a fresh
    /// per-use human action. When `None`, a `presence_per_use: true` instance
    /// is taken to force presence for **all** keyed operations — the default
    /// for a touch device (e.g. a YubiKey whose challenge-response touch fires
    /// on every `store`/`retrieve`/`delete`).
    ///
    /// A backend that can force presence for only *some* operations must list
    /// exactly those, so a presence-per-use request for an **uncovered**
    /// operation fails closed with [`VaultError::NotCapable`] rather than
    /// silently passing without a fresh action. For example, 1Password
    /// `per-access` forces a fresh biometric on reads (`setup`/`exec`) but
    /// routes `store`/`delete` through the cached session client, so it
    /// reports `Some(vec![PresenceOperation::Read])` — a flagged
    /// `store`/`delete` is then correctly refused.
    ///
    /// Ignored when [`BackendCapabilities::presence_per_use`] is `false`.
    pub presence_enforced_operations: Option<Vec<PresenceOperation>>,
}

impl BackendCapabilities {
    /// The safe default reported for a backend that does not implement
    /// [`PresenceCapableBackend`] — never silently claims presence.
    pub fn none() -> Self {
        Self {
            presence_per_use: false,
            presence_enforced_operations: None,
        }
    }

    /// Whether this capability report forces a fresh per-use human action for
    /// `operation`.
    ///
    /// `false` whenever [`BackendCapabilities::presence_per_use`] is `false`.
    /// When `presence_per_use` is `true` and
    /// [`BackendCapabilities::presence_enforced_operations`] is `None`, every
    /// keyed operation is covered (a touch device). Otherwise only the listed
    /// operations are covered.
    pub fn enforces(&self, operation: PresenceOperation) -> bool {
        if !self.presence_per_use {
            return false;
        }
        match &self.presence_enforced_operations {
            None => true,
            Some(ops) => ops.contains(&operation),
        }
    }
}

/// Backend that can report its security [`BackendCapabilities`] for its
/// configured instance.
///
/// Mirrors the TypeScript library's `PresenceCapableBackend`
/// (`packages/vaultkeeper/src/backend/types.ts`).
///
/// This is an optional extension interface, mirroring [`ListableBackend`]: it
/// is **not** a required member of [`SecretBackend`]. Prefer
/// [`get_backend_capabilities`] over calling
/// [`PresenceCapableBackend::get_capabilities`] directly, so a backend that
/// does not implement the interface safely defaults to no capabilities rather
/// than being assumed to have them.
///
/// [`PresenceCapableBackend::get_capabilities`] must reflect the **current
/// configured/live state** of the instance (configuration, or a live
/// device/session probe) rather than a hardcoded per-type answer, and must
/// not itself trigger a human-presence prompt.
///
/// # Capability self-report trust limit (issue #242 AC5)
///
/// [`BackendCapabilities`] is **host-attested**: the core trusts the value a
/// backend implementation chooses to report rather than independently
/// verifying it. Core-owned backends (e.g. [`super::FileBackend`],
/// [`super::InMemoryBackend`], and other backends implemented directly in
/// this crate) are trustworthy self-reporters because their
/// `get_capabilities` bodies ship as part of this codebase and are reviewed
/// like any other core logic. A backend bridged from a **dishonest host**
/// (for example, a JS-callback backend running under a compromised embedder)
/// that falsely reports `presence_per_use: true` could defeat this guarantee.
/// Defending against a dishonest host is explicitly out of scope — the trust
/// boundary is the host itself, which is assumed to be the trusted embedder
/// (see `docs/specs/005-single-core-consolidation.md`).
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait PresenceCapableBackend: SecretBackend {
    /// Report the capabilities of this configured instance.
    async fn get_capabilities(&self) -> Result<BackendCapabilities, VaultError>;
}

/// Type-level probe for backends that implement the capability-reporting
/// contract, mirroring the TypeScript library's `isPresenceCapableBackend`.
///
/// Prefer [`get_backend_capabilities`] for actually reading capabilities;
/// this is exposed for parity with the TS API and for callers that only need
/// the yes/no answer.
pub fn is_presence_capable_backend(backend: &dyn SecretBackend) -> bool {
    backend.as_presence_capable().is_some()
}

/// Resolve a backend's [`BackendCapabilities`], defaulting safely for
/// backends that do not implement [`PresenceCapableBackend`].
///
/// Mirrors the TypeScript library's `getBackendCapabilities`
/// (`packages/vaultkeeper/src/backend/types.ts`).
///
/// A backend without the capability interface reports
/// [`BackendCapabilities::none`] (`presence_per_use: false`) — an unknown
/// backend never silently claims a security guarantee it cannot prove. This
/// is the only supported way to query capabilities; callers must not assume a
/// capability from [`SecretBackend::backend_type`] alone.
///
/// Propagates whatever error a capable backend's own `get_capabilities()`
/// call returns, so a backend whose capability probe itself fails is refused
/// by callers (see [`crate::vault::enforce_presence_requirement`]) rather
/// than silently treated as either capable or non-capable.
pub async fn get_backend_capabilities(
    backend: &dyn SecretBackend,
) -> Result<BackendCapabilities, VaultError> {
    match backend.as_presence_capable() {
        Some(capable) => capable.get_capabilities().await,
        None => Ok(BackendCapabilities::none()),
    }
}

/// Backend that can enroll and use signing keys entirely on its own side.
///
/// Signing keys are a distinct resource from secrets: a private key must
/// never flow through [`SecretBackend::store`]/[`SecretBackend::retrieve`] or
/// a capability token's claims. A signing backend generates the keypair,
/// exposes only the public half, and performs the signature itself — the
/// private key never leaves the backend. This is what keeps a key out of any
/// JWE claims token, and it is what lets [`crate::signing::create_detached_jws`]
/// assemble a JWS without ever seeing key material: it calls
/// [`SigningBackend::sign_with_key`] and only ever handles the resulting
/// signature bytes.
///
/// Implementations must keep signing keys in a namespace that cannot collide
/// with or be read as ordinary secrets. Mirrors the TypeScript
/// `SigningBackend` (`packages/vaultkeeper/src/backend/types.ts`).
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait SigningBackend: SecretBackend {
    /// Enroll a new signing keypair under `id`.
    ///
    /// # Errors
    /// Returns [`VaultError::SigningKeyAlreadyExists`] if a signing key
    /// already exists under `id`, or [`VaultError::InvalidAlgorithm`] if
    /// `algorithm` is not supported by this backend.
    async fn generate_signing_key(
        &self,
        id: &str,
        algorithm: SigningAlgorithm,
    ) -> Result<(), VaultError>;

    /// Return the public half of the signing key stored under `id`.
    ///
    /// # Errors
    /// Returns [`VaultError::SigningKeyNotFound`] if no signing key exists
    /// under `id`.
    async fn get_public_key(&self, id: &str) -> Result<SigningPublicKey, VaultError>;

    /// Sign `data` with the private key stored under `id`, returning the raw
    /// signature bytes. The private key never leaves the backend.
    ///
    /// # Errors
    /// Returns [`VaultError::SigningKeyNotFound`] if no signing key exists
    /// under `id`.
    async fn sign_with_key(&self, id: &str, data: &[u8]) -> Result<Vec<u8>, VaultError>;
}
