//! vaultkeeper CLI — native binary entry point.
//!
//! Matches the command surface and output format of the TypeScript CLI.

mod host;

use clap::{ArgGroup, Parser, Subcommand};
use host::NativeHostPlatform;
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use vaultkeeper_core::backend::{
    FileBackend, HostPlatform, PresenceOperation, SecretBackend, get_backend_capabilities,
};
use vaultkeeper_core::config;
use vaultkeeper_core::profile::{EntrySource, MaterializeMode};
use vaultkeeper_core::resolve::{ResolveOptions, resolve_profile};
use vaultkeeper_core::run::{
    DEFAULT_TOKEN_VAR, FILE_ONLY_DEGRADATION_NOTICE, apply_set_overlay,
    file_only_degradation_applies, parse_set_flag, render_dry_run, render_token_dry_run,
    validate_as_var_name,
};
use vaultkeeper_core::vault::{MintLeaseOptions, enforce_presence_requirement};
use zeroize::{Zeroize, Zeroizing};

#[derive(Parser)]
#[command(
    name = "vaultkeeper",
    about = "Unified, policy-enforced secret storage",
    version,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Deprecated alias for `run --token` (issue #333, surface-governance
    /// ruling B9). Hidden from `--help` — `run` is the single documented
    /// launcher verb — but kept working, unhidden, until 1.0. Emits a
    /// single-line deprecation notice on stderr (never stdout) pointing at
    /// `run --token`.
    #[command(hide = true)]
    Exec {
        /// JWE token
        #[arg(long)]
        token: String,
        /// Command to execute
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Launch a command with one or more secrets available in its subshell —
    /// full stdio and signal transparency. The source options (`--profile`/
    /// `--profile-file`, `--token`) describe only *how* the environment is
    /// populated; `--token`'s `--as`-named entry can be combined with
    /// `--set` overlay entries in the same launch.
    ///
    /// `run` is the single launcher verb (surface-governance ruling B9,
    /// issue #333): `exec` is a deprecated alias for `run --token`.
    #[command(group(
        ArgGroup::new("run_source")
            .args(["profile", "profile_file", "token"])
            .required(true)
    ))]
    Run {
        /// Named profile from `$CONFIG_DIR/profiles/<NAME>.json`. Mutually
        /// exclusive with `--profile-file` and `--token`.
        #[arg(long)]
        profile: Option<String>,
        /// Load a profile from an explicit path instead. Mutually exclusive
        /// with `--profile` and `--token`.
        #[arg(long)]
        profile_file: Option<String>,
        /// Redeem an already-minted JWE token and inject its secret as an
        /// env var (the `exec --token` behavior, folded into `run`).
        /// Mutually exclusive with `--profile`/`--profile-file`;
        /// combinable with `--set`.
        #[arg(long)]
        token: Option<String>,
        /// Env var the `--token`-redeemed secret is injected under. Ignored
        /// without `--token`. Defaults to `VAULTKEEPER_SECRET` — the same
        /// default `exec` has always injected under.
        #[arg(long = "as", default_value_t = String::from(DEFAULT_TOKEN_VAR))]
        as_var: String,
        /// Ad-hoc rung-2 entry, layered over the profile (repeatable).
        /// Marked UNREVIEWED in --dry-run output.
        #[arg(long = "set")]
        set: Vec<String>,
        /// Print each var, its rung, source backend, and resolved policy,
        /// then exit without launching. Never prints values.
        #[arg(long)]
        dry_run: bool,
        /// Fail unless every minted lease entry proved fresh human presence
        /// at issuance (distinct from `--require-presence-per-use`, which
        /// forces a fresh action per operation). Not yet enforced: a real
        /// (non-dry-run) invocation with this flag set refuses rather than
        /// proceeding without the guarantee. Not applicable to `--token` (a
        /// redeemed token is never minted by `run`) — combining the two is a
        /// usage error rather than a silent no-op, since `--token` has
        /// nothing for this flag to apply to.
        #[arg(long, conflicts_with = "token")]
        require_presence_at_issuance: bool,
        /// Command to launch, with the resolved environment
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Run preflight checks
    Doctor,
    /// Pre-record a script hash in the TOFU manifest
    Approve {
        /// Path to the executable
        #[arg(long)]
        path: String,
    },
    /// Enable or disable development mode for a script
    DevMode {
        /// Path to the executable
        #[arg(long)]
        path: String,
        /// Enable dev mode for the given path (omit to disable)
        #[arg(long)]
        enable: bool,
    },
    /// Store a secret (reads from stdin)
    Store {
        /// Secret name
        #[arg(long)]
        name: String,
        /// Require the active backend to force a fresh, per-use human presence
        /// action for this store. Refuses with a NotCapable error — before
        /// the backend is touched — if it cannot guarantee one.
        #[arg(long)]
        require_presence_per_use: bool,
    },
    /// Delete a secret
    Delete {
        /// Secret name
        #[arg(long)]
        name: String,
        /// Require the active backend to force a fresh, per-use human presence
        /// action for this delete. Refuses with a NotCapable error — before
        /// the backend is touched — if it cannot guarantee one.
        #[arg(long)]
        require_presence_per_use: bool,
    },
    /// Manage configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Inspect the active backend (e.g. its capabilities)
    Backend {
        #[command(subcommand)]
        action: BackendAction,
    },
    /// Rotate the encryption key
    RotateKey,
    /// Emergency key revocation
    RevokeKey,
    /// Manage environment profiles (env-var name → secret source →
    /// materialization mode → policy)
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Manage signing-key leases (mint, revoke)
    Session {
        #[command(subcommand)]
        action: SessionAction,
    },
}

#[derive(Subcommand)]
enum SessionAction {
    /// Revoke a signing-key lease, by JTI (a single lease) or by key name
    /// (every outstanding lease for that key, at once)
    Revoke {
        /// Revoke the single lease with this JTI
        #[arg(long, conflicts_with = "key")]
        jti: Option<String>,
        /// Revoke every outstanding lease for this signing key name
        #[arg(long, conflicts_with = "jti")]
        key: Option<String>,
    },
    /// Mint a session signing-key lease for a `signingKey` +
    /// `materialize: "lease"` profile entry, printing the JWE to stdout
    Mint {
        /// The profile to resolve the entry from — positional, matching
        /// every other profile-scoped command (`profile show`/`profile lint`)
        profile: String,
        /// The env-var entry name within the profile
        #[arg(long)]
        entry: String,
    },
}

#[derive(Subcommand)]
enum ProfileAction {
    /// Scaffold a new profile at `$CONFIG_DIR/profiles/<NAME>.json`
    Init {
        /// Profile name — also embedded as the scaffold's `name` field, even
        /// when `--profile-file` overrides the write location.
        name: String,
        /// Write the scaffold to this path instead of the default profiles directory
        #[arg(long)]
        profile_file: Option<String>,
    },
    /// Render a profile's shape and policy. Never prints secret values.
    Show {
        /// Profile name — mutually exclusive with `--profile-file`
        #[arg(required_unless_present = "profile_file")]
        name: Option<String>,
        /// Load from this path instead of the default profiles directory —
        /// mutually exclusive with NAME
        #[arg(long, conflicts_with = "name")]
        profile_file: Option<String>,
    },
    /// List profiles in the default profiles directory
    List,
    /// Validate a profile's schema and report policy warnings. Advisory
    /// only — always exits 0 on a successfully-loaded profile, regardless
    /// of any warnings printed.
    Lint {
        /// Profile name — mutually exclusive with `--profile-file`
        #[arg(required_unless_present = "profile_file")]
        name: Option<String>,
        /// Load from this path instead of the default profiles directory —
        /// mutually exclusive with NAME
        #[arg(long, conflicts_with = "name")]
        profile_file: Option<String>,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Initialize a new configuration file
    Init,
    /// Show current configuration
    Show,
}

#[derive(Subcommand)]
enum BackendAction {
    /// Report the active (configured) backend's security capabilities
    Capabilities {
        /// Emit a machine-readable JSON array instead of human-readable text
        #[arg(long)]
        json: bool,
    },
}

fn make_host() -> Arc<NativeHostPlatform> {
    let config_dir = NativeHostPlatform::default_config_dir();
    Arc::new(NativeHostPlatform::new(config_dir))
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let exit_code = match cli.command {
        None => {
            print_help();
            0
        }
        Some(cmd) => match cmd {
            Commands::Store {
                name,
                require_presence_per_use,
            } => cmd_store(&name, require_presence_per_use).await,
            Commands::Delete {
                name,
                require_presence_per_use,
            } => cmd_delete(&name, require_presence_per_use).await,
            Commands::Exec { token, command } => cmd_exec(&token, &command).await,
            Commands::Run {
                profile,
                profile_file,
                token,
                as_var,
                set,
                dry_run,
                require_presence_at_issuance,
                command,
            } => {
                // The `run_source` `ArgGroup` (required, exactly-one) guarantees
                // exactly one of profile/profile_file/token is `Some` here.
                let source = match token {
                    Some(token) => RunSource::Token { token, as_var },
                    None => RunSource::Profile {
                        profile,
                        profile_file,
                    },
                };
                cmd_run(source, set, dry_run, require_presence_at_issuance, command).await
            }
            Commands::Doctor => cmd_doctor().await,
            Commands::Approve { path } => cmd_approve(&path).await,
            Commands::DevMode { path, enable } => cmd_dev_mode(&path, enable).await,
            Commands::Config { action } => cmd_config(action).await,
            Commands::Backend { action } => cmd_backend(action).await,
            Commands::RotateKey => cmd_rotate_key().await,
            Commands::RevokeKey => cmd_revoke_key().await,
            Commands::Profile { action } => cmd_profile(action).await,
            Commands::Session { action } => cmd_session(action).await,
        },
    };

    std::process::exit(exit_code);
}

fn print_help() {
    use clap::CommandFactory;
    Cli::command().print_help().ok();
}

async fn cmd_store(name: &str, require_presence_per_use: bool) -> i32 {
    // Read secret from stdin
    let mut secret = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut secret) {
        eprintln!("Error: Failed to read stdin: {e}");
        return 1;
    }
    let secret = secret.trim_end();

    if secret.is_empty() {
        eprintln!("Error: No secret provided on stdin");
        return 1;
    }

    let host = make_host();
    let backend = FileBackend::new(host.clone());

    // Non-bypassable presence gate (issue #242): refuses before the backend is
    // ever touched when the flag is set and the active backend can't force a
    // fresh per-use action for `store`. A no-op when the flag is unset.
    if let Err(e) = enforce_presence_requirement(
        &backend,
        PresenceOperation::Store,
        Some(require_presence_per_use),
    )
    .await
    {
        eprintln!("Error: {e}");
        return 1;
    }

    if let Err(e) = backend.store(name, secret).await {
        eprintln!("Error: {e}");
        return 1;
    }

    println!("Secret \"{name}\" stored successfully.");
    0
}

async fn cmd_delete(name: &str, require_presence_per_use: bool) -> i32 {
    let host = make_host();
    let backend = FileBackend::new(host);

    // Non-bypassable presence gate (issue #242): see cmd_store.
    if let Err(e) = enforce_presence_requirement(
        &backend,
        PresenceOperation::Delete,
        Some(require_presence_per_use),
    )
    .await
    {
        eprintln!("Error: {e}");
        return 1;
    }

    match backend.delete(name).await {
        Ok(()) => {}
        Err(vaultkeeper_core::VaultError::SecretNotFound { .. }) => {
            // Idempotent delete — treat as success
        }
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    }

    println!("Secret \"{name}\" deleted.");
    0
}

/// `exec` — a hidden, deprecated alias for `run --token` (issue #333,
/// surface-governance ruling B9). Emits a single-line deprecation notice on
/// **stderr only** (never stdout, so a byte-exact stdout comparison against
/// `run --token` is unaffected), then delegates entirely to
/// [`cmd_run_token`] — same authorize/read-secret/launch path, same
/// `VAULTKEEPER_SECRET` default target var, same full stdio/signal-
/// transparency contract `run` already provides. Retired at 1.0.
async fn cmd_exec(token: &str, command: &[String]) -> i32 {
    stderr_diag(
        "Warning: `exec` is deprecated and will be removed at 1.0 — use \
         `vaultkeeper run --token <jwe> -- <command>` instead.",
    );
    cmd_run_token(
        token,
        DEFAULT_TOKEN_VAR,
        Vec::new(),
        false,
        command.to_vec(),
    )
    .await
}

/// Write a single diagnostic line to stderr without panicking on a write
/// failure (e.g. a broken pipe). `eprintln!`/`writeln!(io::stderr(), ..)`
/// panics on an `Err` by default — acceptable everywhere else in this file,
/// but `run` launches a long-lived child whose consumer may legitimately
/// close its pipes early, and a diagnostic write racing that must never
/// crash the wrapper (issue #279 AC4: "handle EPIPE without a panic or
/// stack trace, and never on stdout" — this helper is stderr-only, matching
/// that stdout is the child's alone).
fn stderr_diag(message: &str) {
    use std::io::Write as _;
    let _ = writeln!(io::stderr(), "{message}");
}

/// Write `text` to stdout without panicking on a write failure. Used only by
/// `run --dry-run` (the one `run` invocation allowed to write to stdout —
/// see `cmd_run`): `run --dry-run --profile x | head -1` closing the pipe
/// early must not print a `BrokenPipe` stack trace, mirroring
/// [`stderr_diag`]'s same non-panicking discipline for stderr.
fn stdout_write(text: &str) {
    use std::io::Write as _;
    let _ = write!(io::stdout(), "{text}");
}

/// Where `run` draws its environment composition from.
///
/// A dedicated enum — not `--profile`/`--profile-file` hard-wired as the
/// only entry point into [`cmd_run`] — specifically so a future
/// mutually-exclusive `--token <JWE>` source (issue #333's planned
/// absorption of `exec`'s token-redemption path into `run`) can slot in as
/// a sibling variant here without reshaping this dispatch. The launch step
/// ([`launch_and_wait`]) already only ever sees a plain
/// [`vaultkeeper_core::ResolvedEnv`] (a `HashMap<String, String>`) and a
/// command line — it has no dependency on `RunSource` or on profile types
/// at all, so a new source only has to produce that same map to reuse the
/// entire stdio/signal-forwarding launcher unchanged.
enum RunSource {
    /// A named profile (`--profile <NAME>`) or an explicit path to one
    /// (`--profile-file <PATH>`) — mutually exclusive at the clap layer.
    Profile {
        profile: Option<String>,
        profile_file: Option<String>,
    },
    /// An already-minted JWE (`--token <JWE>`), redeemed directly and
    /// injected as `as_var` — the `exec --token` behavior (issue #333),
    /// folded into `run` as a second source alongside `Profile`. Mutually
    /// exclusive with `Profile` at the clap layer (`run_source` `ArgGroup`);
    /// combinable with `--set`, which layers additional profile-resolved
    /// entries into the same launched environment.
    Token { token: String, as_var: String },
}

/// `run` — resolve an environment (currently always [`RunSource::Profile`],
/// plus any `--set` overlay) and launch a child command with it, with full
/// stdio and signal transparency (issue #279). A distinct verb from `exec`:
/// `exec` redeems an already-minted token; `run` composes an environment
/// from a named source and mints where needed.
///
/// Flag semantics, `--set` parsing/validation, and `--dry-run` rendering all
/// live in `vaultkeeper_core::run` so a future host renders byte-identical
/// output; this function only parses arguments (already done by clap) and
/// performs the final spawn/signal-forwarding/exit-code translation — the
/// per-host half of the contract.
#[allow(clippy::too_many_arguments)]
async fn cmd_run(
    source: RunSource,
    set: Vec<String>,
    dry_run: bool,
    require_presence_at_issuance: bool,
    command: Vec<String>,
) -> i32 {
    // Flag-content validation (`--set`'s VAR=SECRET shape) happens before
    // any filesystem access — a malformed flag is a usage error the caller
    // should see regardless of whether the named profile/token happens to
    // resolve, and is shared by both sources.
    let mut set_entries = Vec::with_capacity(set.len());
    for raw in &set {
        match parse_set_flag(raw) {
            Ok(entry) => set_entries.push(entry),
            Err(e) => {
                stderr_diag(&format!("Error: {e}"));
                return 1;
            }
        }
    }

    match source {
        RunSource::Profile {
            profile,
            profile_file,
        } => {
            cmd_run_profile(
                profile,
                profile_file,
                set_entries,
                dry_run,
                require_presence_at_issuance,
                command,
            )
            .await
        }
        RunSource::Token { token, as_var } => {
            cmd_run_token(&token, &as_var, set_entries, dry_run, command).await
        }
    }
}

/// `run --profile`/`--profile-file` — resolve a named profile plus any
/// `--set` overlay, then launch (issue #279). See [`cmd_run`]'s doc comment
/// for the source-dispatch shape shared with [`cmd_run_token`].
async fn cmd_run_profile(
    profile: Option<String>,
    profile_file: Option<String>,
    set_entries: Vec<vaultkeeper_core::run::SetEntry>,
    dry_run: bool,
    require_presence_at_issuance: bool,
    command: Vec<String>,
) -> i32 {
    let host = make_host();

    let path = match resolve_profile_path(&host, profile.as_deref(), profile_file) {
        Ok(p) => p,
        Err(e) => {
            stderr_diag(&format!("Error: {e}"));
            return 1;
        }
    };
    let (loaded_profile, cfg) = match load_named_profile(&host, &path).await {
        Ok(loaded) => loaded,
        Err(e) => {
            stderr_diag(&format!("Error: {e}"));
            return 1;
        }
    };

    let defaults = vaultkeeper_core::profile::ProfileDefaults::from_vault_defaults(&cfg.defaults);
    let plan = apply_set_overlay(loaded_profile, &set_entries, &defaults);

    // The native CLI only ever operates against the `file` backend today
    // (see `cmd_backend_capabilities`/`cmd_profile_lint`'s identical
    // pattern) — this reads the *configured* backend name for `--dry-run`'s
    // "source backend" column and the file-only degradation check, without
    // instantiating a backend or touching the filesystem.
    let active_backend_type = cfg
        .backends
        .iter()
        .find(|b| b.enabled)
        .map(|b| b.backend_type.as_str())
        .unwrap_or("none");

    if dry_run {
        // Plan-only: never mints, never touches a backend, never launches —
        // so disclosing --require-presence-at-issuance's not-yet-enforced
        // status here is safe (see render_dry_run's doc comment); a real
        // run instead refuses outright, below.
        stdout_write(&render_dry_run(
            &plan,
            active_backend_type,
            require_presence_at_issuance,
        ));
        return 0;
    }

    // Fail-closed, not a silent no-op: `--require-presence-at-issuance`
    // promises every minted lease entry proved fresh human presence at
    // issuance, but `resolve_profile` has no way to enforce that yet (it
    // takes no `HostPlatform` to prompt with, and verifying an
    // already-minted lease's `pres` claim doesn't apply to entries being
    // minted right now). Proceeding anyway — silently, or with a warning —
    // would let a caller believe the guarantee held when it didn't; refuse
    // instead, the same posture `resolve_profile` itself already takes for
    // a profile-level `requirePresenceAtMint` entry it can't enforce
    // (`VaultError::MaterializeModeUnsupported`, in `resolve.rs`). Checked
    // before any backend/key-manager initialization or resolution — this
    // must never even attempt to mint.
    if require_presence_at_issuance {
        stderr_diag(&format!(
            "Error: {}",
            vaultkeeper_core::VaultError::MaterializeModeUnsupported {
                message: "--require-presence-at-issuance is not yet enforced by `run` \
                          (verifying every minted lease entry's `pres` claim is not yet wired \
                          into resolve_profile) — refusing rather than proceeding without the \
                          guarantee this flag promises."
                    .to_string(),
                mode: "run-require-presence-at-issuance".to_string(),
            }
        ));
        return 1;
    }

    if command.is_empty() {
        stderr_diag("Error: No command specified");
        return 1;
    }

    let vault = match vaultkeeper_core::VaultKeeper::init(
        host.as_ref(),
        Some(vaultkeeper_core::vault::VaultKeeperOptions {
            skip_doctor: true,
            ..Default::default()
        }),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            stderr_diag(&format!("Error: {e}"));
            return 1;
        }
    };

    let backend = FileBackend::new(host.clone());

    // The file-only degradation notice — stderr only, never stdout, and
    // emitted *before* resolution so it is visible even if resolution then
    // fails (issue #279).
    if file_only_degradation_applies(&plan, active_backend_type) {
        stderr_diag(FILE_ONLY_DEGRADATION_NOTICE);
    }

    let resolve_options = ResolveOptions {
        backend: &backend,
        key_manager: vault.key_manager(),
        // `run` does not yet perform executable-trust verification of the
        // launched command (that would require resolving `command[0]` to a
        // real file path — via `$PATH` — and hashing it, mirroring
        // `VaultKeeper::setup`'s `executable_path`/TOFU flow). Until that
        // lands, a `materialize: "lease"` entry whose resolved trust tier is
        // `sigstore`/`registry` is refused by `resolve_profile` itself
        // (`VaultError::ExecutableTrustRequired`) rather than silently
        // minted with an incoherent "dev" exe marker — see the PR
        // description for the tracked follow-up.
        executable_hash: None,
    };

    let resolved = match resolve_profile(&plan.profile, &resolve_options).await {
        Ok(r) => r,
        Err(e) => {
            stderr_diag(&format!("Error: {e}"));
            return 1;
        }
    };

    launch_and_wait(&command, Zeroizing::new(ResolvedEnvMap(resolved))).await
}

/// `run --token`/`exec` — redeem an already-minted JWE directly (never mints,
/// never touches a profile file) and inject its secret as `as_var`, combined
/// with any `--set` overlay entries resolved through the active profile
/// machinery (issue #333). This is `exec`'s historical behavior, now shared
/// by both verbs via [`cmd_exec`] delegating here.
///
/// `--require-presence-at-issuance` has no effect on this source — `run
/// --token` never mints a lease, so there is nothing for that flag to
/// refuse (unlike [`cmd_run_profile`], which fails closed on it).
async fn cmd_run_token(
    token: &str,
    as_var: &str,
    set_entries: Vec<vaultkeeper_core::run::SetEntry>,
    dry_run: bool,
    command: Vec<String>,
) -> i32 {
    if let Err(e) = validate_as_var_name(as_var) {
        stderr_diag(&format!("Error: {e}"));
        return 1;
    }

    let host = make_host();

    if dry_run {
        // Plan-only: --set entries still need config defaults to render their
        // rung/backend, but the primary --token entry never touches the
        // backend or decrypts the token — see render_token_dry_run's doc
        // comment. A missing/invalid config for the --set half is reported
        // the same way `run --profile --dry-run` reports it.
        let cfg = match vaultkeeper_core::config::load_config(host.as_ref()).await {
            Ok(c) => c,
            Err(e) => {
                stderr_diag(&format!("Error: {e}"));
                return 1;
            }
        };
        let defaults =
            vaultkeeper_core::profile::ProfileDefaults::from_vault_defaults(&cfg.defaults);
        let empty_profile = vaultkeeper_core::profile::LoadedProfile {
            version: 1,
            name: "run --token".to_string(),
            entries: Vec::new(),
        };
        let plan = apply_set_overlay(empty_profile, &set_entries, &defaults);
        if let Err(e) = vaultkeeper_core::run::check_as_var_collision(as_var, &plan) {
            stderr_diag(&format!("Error: {e}"));
            return 1;
        }
        let active_backend_type = cfg
            .backends
            .iter()
            .find(|b| b.enabled)
            .map(|b| b.backend_type.as_str())
            .unwrap_or("none");
        stdout_write(&render_token_dry_run(as_var, &plan, active_backend_type));
        return 0;
    }

    if command.is_empty() {
        stderr_diag("Error: No command specified");
        return 1;
    }

    // Initialize VaultKeeper with doctor checks skipped — matches `exec`'s
    // historical fast-path and `run --profile`'s own init call.
    let mut vault = match vaultkeeper_core::VaultKeeper::init(
        host.as_ref(),
        Some(vaultkeeper_core::vault::VaultKeeperOptions {
            skip_doctor: true,
            ..Default::default()
        }),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            stderr_diag(&format!("Error: {e}"));
            return 1;
        }
    };

    // Decrypt and validate the JWE token.
    let (handle, claims, _response) = match vault.authorize(token) {
        Ok(r) => r,
        Err(e) => {
            stderr_diag(&format!("Error: Failed to authorize token: {e}"));
            return 1;
        }
    };

    // A signing-key lease carries no secret value to inject (see
    // `cmd_exec`'s identical historical check — `authorize` itself already
    // rejects a signing-key JWE before returning, so this is defense in
    // depth, not the only guard).
    if claims.kty == Some(vaultkeeper_core::ClaimsKind::SigningKey) {
        stderr_diag("Error: token does not authorize a secret value");
        return 1;
    }

    let secret = match vault.read_secret(&handle) {
        Ok(s) => s,
        Err(e) => {
            stderr_diag(&format!("Error: Failed to read secret: {e}"));
            return 1;
        }
    };

    // Wrapped in `Zeroizing` from the moment the secret enters this map —
    // not deferred to `launch_and_wait` — so every early return below (a
    // failed config load, a failed profile resolution, or the --set/--as
    // collision) scrubs the buffer on drop too, not only the happy path
    // that reaches `launch_and_wait` (see that function's doc comment for
    // why the wrapper is needed at all).
    let mut env = Zeroizing::new(ResolvedEnvMap(std::collections::HashMap::new()));
    env.insert(as_var.to_string(), secret.to_string());

    if !set_entries.is_empty() {
        let cfg = match vaultkeeper_core::config::load_config(host.as_ref()).await {
            Ok(c) => c,
            Err(e) => {
                stderr_diag(&format!("Error: {e}"));
                return 1;
            }
        };
        let defaults =
            vaultkeeper_core::profile::ProfileDefaults::from_vault_defaults(&cfg.defaults);
        let empty_profile = vaultkeeper_core::profile::LoadedProfile {
            version: 1,
            name: "run --token".to_string(),
            entries: Vec::new(),
        };
        let plan = apply_set_overlay(empty_profile, &set_entries, &defaults);
        if let Err(e) = vaultkeeper_core::run::check_as_var_collision(as_var, &plan) {
            stderr_diag(&format!("Error: {e}"));
            return 1;
        }
        let backend = FileBackend::new(host.clone());

        let active_backend_type = cfg
            .backends
            .iter()
            .find(|b| b.enabled)
            .map(|b| b.backend_type.as_str())
            .unwrap_or("none");
        if file_only_degradation_applies(&plan, active_backend_type) {
            stderr_diag(FILE_ONLY_DEGRADATION_NOTICE);
        }

        let resolve_options = ResolveOptions {
            backend: &backend,
            key_manager: vault.key_manager(),
            executable_hash: None,
        };
        let resolved = match resolve_profile(&plan.profile, &resolve_options).await {
            Ok(r) => r,
            Err(e) => {
                stderr_diag(&format!("Error: {e}"));
                return 1;
            }
        };

        for (var, value) in resolved {
            env.insert(var, value);
        }
    }

    launch_and_wait(&command, env).await
}

/// Launch `command` with `env` injected, full stdio inheritance (never
/// piped/captured — see the module docs), and signal forwarding, then wait
/// for it to exit — returning the process's own exit-code convention: the
/// child's real exit code, or `128 + N` if it was killed by signal `N`
/// (issue #279 AC4).
///
/// On Unix, the SIGINT/SIGTERM signal streams are installed **before**
/// `spawn()` (see [`SignalGuard::install`]) — installing them only after
/// spawn, inside the wait loop, would leave a window between spawn and
/// registration where a signal delivered to this process hits the default
/// disposition (terminate) instead of being forwarded, killing the wrapper
/// and orphaning the just-spawned child. Closing that window is what makes
/// AC3 ("the wrapper must never exit before the child does") hold for a
/// signal that arrives immediately after launch, not just one that arrives
/// once the wait loop is already running.
///
/// `env`'s own `HashMap<String, String>` storage is wrapped in
/// [`zeroize::Zeroizing`] (via the local [`ResolvedEnvMap`] newtype, since
/// `Zeroize` has no blanket impl for `HashMap`) — the same wrapper the
/// resolver already uses for individual secret values (see `resolve.rs`),
/// extended here to the whole map. Callers wrap the map at the point the
/// first secret value enters it (not here) so the buffer is zeroized on
/// **every** exit path from *both* this function and the caller building
/// `env` — including a caller's own early returns before `env` is ever
/// passed here (e.g. `cmd_run_token`'s config-load, profile-resolution, or
/// `--set`/`--as` collision failures), not only the paths internal to this
/// function (`SignalGuard::install()` or `cmd.spawn()` failing). The happy
/// path still scrubs the buffer explicitly, immediately after `spawn()`
/// returns, rather than deferring to the implicit end-of-function drop —
/// the wrapper's `Drop` then re-zeroizes an already-empty buffer on that
/// path, which is a harmless no-op. This does **not** scrub every
/// in-process copy of the resolved values: `cmd.envs(...)` below has
/// already copied each one into `tokio::process::Command`'s internal
/// `OsString` env storage, which `cmd` (and therefore that copy) outlives
/// this function — it is dropped, un-zeroized, only once the child exits
/// and `cmd` goes out of scope. Neither `tokio::process::Command` nor
/// `std::ffi::OsString` expose a way to scrub that storage. So this is
/// defense-in-depth against the risk of an accidental *second* reference to
/// `env`'s own buffer sticking around past its useful lifetime (e.g. a
/// future refactor holding onto it, a panic unwind path, or a debug print)
/// — not a claim that every copy of the plaintext is scrubbed from this
/// process's heap for the child's lifetime.
async fn launch_and_wait(command: &[String], mut env: Zeroizing<ResolvedEnvMap>) -> i32 {
    use std::process::Stdio;

    #[cfg(unix)]
    let signal_guard = match SignalGuard::install() {
        Ok(g) => g,
        Err(e) => {
            stderr_diag(&format!("Error: Failed to install signal handlers: {e}"));
            return 1;
        }
    };

    let mut cmd = tokio::process::Command::new(&command[0]);
    cmd.args(&command[1..]);
    cmd.envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    // Fd inheritance, not piping: the child gets the wrapper's real stdin/
    // stdout/stderr file descriptors directly, which is what makes
    // byte-exact, zero-added-buffering passthrough true by construction
    // (issue #279 — never route through `HostPlatform::exec`, which
    // captures output).
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            stderr_diag(&format!("Error: Failed to launch command: {e}"));
            return 1;
        }
    };

    // See the doc comment above: this scrubs `env`'s own buffer, not the
    // separate copy `cmd.envs(...)` already made. Every other exit path —
    // including the two early returns above — scrubs it too, via `env`'s
    // `Zeroizing` wrapper running on drop.
    env.zeroize();

    let status = match wait_forwarding_signals(
        child,
        #[cfg(unix)]
        signal_guard,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            stderr_diag(&format!("Error: Failed to wait for command: {e}"));
            return 1;
        }
    };

    exit_code_for_status(status)
}

/// A [`vaultkeeper_core::ResolvedEnv`] wrapped so [`zeroize::Zeroizing`] can
/// scrub it on drop — see [`launch_and_wait`]'s doc comment. `Zeroize` has
/// no blanket impl for `HashMap`, so this newtype supplies one by zeroizing
/// every value; [`std::ops::Deref`] passes reads (`.iter()`, etc.) straight
/// through to the underlying map.
struct ResolvedEnvMap(vaultkeeper_core::ResolvedEnv);

impl std::ops::Deref for ResolvedEnvMap {
    type Target = vaultkeeper_core::ResolvedEnv;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ResolvedEnvMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Zeroize for ResolvedEnvMap {
    fn zeroize(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}

/// The SIGINT/SIGTERM signal streams, installed once and threaded into
/// [`wait_forwarding_signals`]. A distinct type (not inlined into that
/// function) specifically so [`launch_and_wait`] can install it **before**
/// `cmd.spawn()` — see that function's doc comment for why the ordering
/// matters (issue #279 AC3).
#[cfg(unix)]
struct SignalGuard {
    sigint: tokio::signal::unix::Signal,
    sigterm: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl SignalGuard {
    fn install() -> std::io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            sigint: signal(SignalKind::interrupt())?,
            sigterm: signal(SignalKind::terminate())?,
        })
    }
}

/// Wait for `child` to exit, forwarding SIGINT/SIGTERM sent to *this*
/// process on to the child and then continuing to wait — the wrapper must
/// never exit before the child does, or it orphans it (issue #279 AC3).
///
/// MCP clients typically terminate the wrapper directly (not via a
/// controlling tty's process-group signal delivery), which is exactly the
/// case this handles: a signal delivered to the wrapper's own pid must
/// still reach the child. (When the wrapper and child *do* share a
/// controlling tty's foreground process group, a `Ctrl+C` there delivers
/// SIGINT to the whole group by the kernel — including the child directly
/// — and this forwards the same signal again; a benign double-delivery for
/// well-behaved signal handling, not a correctness issue this function
/// needs to suppress.)
#[cfg(unix)]
async fn wait_forwarding_signals(
    mut child: tokio::process::Child,
    mut guard: SignalGuard,
) -> std::io::Result<std::process::ExitStatus> {
    loop {
        tokio::select! {
            status = child.wait() => return status,
            _ = guard.sigint.recv() => forward_signal(&child, libc::SIGINT),
            _ = guard.sigterm.recv() => forward_signal(&child, libc::SIGTERM),
        }
    }
}

#[cfg(unix)]
fn forward_signal(child: &tokio::process::Child, sig: libc::c_int) {
    if let Some(pid) = child.id() {
        // SAFETY: `pid` is this child's own pid, as reported by the OS via
        // `tokio::process::Child::id()`. `kill(2)` on a pid that has already
        // exited (a benign race with the child's own natural exit) simply
        // returns `ESRCH`, which is intentionally ignored here — forwarding
        // a signal to an about-to-be-reaped child is a no-op, not an error.
        unsafe {
            libc::kill(pid as libc::pid_t, sig);
        }
    }
}

/// Non-Unix fallback: no `SIGTERM` equivalent exists to forward, but a
/// Ctrl+C sent to the wrapper's own console still must not orphan the child
/// — this still waits for the child's real exit rather than racing it.
#[cfg(not(unix))]
async fn wait_forwarding_signals(
    mut child: tokio::process::Child,
) -> std::io::Result<std::process::ExitStatus> {
    loop {
        tokio::select! {
            status = child.wait() => return status,
            _ = tokio::signal::ctrl_c() => {
                // Best-effort: no per-child signal-forwarding primitive is
                // available outside Unix here; continue waiting rather than
                // exiting first, matching the outlive-the-child contract.
            }
        }
    }
}

/// Translate a completed child's [`std::process::ExitStatus`] into this
/// process's own exit code: the child's real exit code when it exited
/// normally, or `128 + N` when it was terminated by signal `N` (POSIX
/// convention — issue #279 AC4).
fn exit_code_for_status(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    1
}

async fn cmd_doctor() -> i32 {
    let host = make_host();

    // Load config so doctor checks are scoped to the enabled backends.
    // Fall back to None (platform defaults) if config loading fails.
    let backends = match vaultkeeper_core::config::load_config(host.as_ref()).await {
        Ok(cfg) => Some(cfg.backends),
        Err(_) => None,
    };
    let result = vaultkeeper_core::doctor::run_doctor(host.as_ref(), backends.as_deref()).await;

    // A check that is not required for the active/configured backend(s)
    // (e.g. `ykman`/`op` when no plugin backend is enabled) is informational,
    // not a failure — rendering it with a ✗ alongside genuine failures made a
    // safe, file-default first run look broken (issue #116). Checks that are
    // both optional and unsatisfied are left out of the pass/fail list; they
    // still surface, without the failure icon, in the "Warnings" section
    // below — that's the visual separation between "checks for your active
    // backend" and "optional plugin backends (not configured)".
    let primary_checks = result.checks.iter().filter(|check| {
        check.required || check.check.status == vaultkeeper_core::PreflightCheckStatus::Ok
    });

    for check in primary_checks {
        let icon = if check.check.status == vaultkeeper_core::PreflightCheckStatus::Ok {
            "\u{2713}"
        } else {
            "\u{2717}"
        };
        let version = check
            .check
            .version
            .as_ref()
            .map(|v| format!(" ({v})"))
            .unwrap_or_default();
        let reason = check
            .check
            .reason
            .as_ref()
            .map(|r| format!(" \u{2014} {r}"))
            .unwrap_or_default();
        println!("  {icon} {}{version}{reason}", check.check.name);
    }

    if !result.warnings.is_empty() {
        println!("\nWarnings:");
        for warning in &result.warnings {
            println!("  \u{26A0} {warning}");
        }
    }

    if result.ready {
        println!("\nSystem ready.");
        return 0;
    }

    println!("\nNext steps:");
    for step in &result.next_steps {
        println!("  \u{2192} {step}");
    }
    1
}

async fn cmd_approve(path: &str) -> i32 {
    let host = make_host();

    // Hash the executable
    let hash = match vaultkeeper_core::identity::hash::hash_executable(
        host.as_ref(),
        std::path::Path::new(path),
    )
    .await
    {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Error: Failed to hash executable: {e}");
            return 1;
        }
    };

    // Load and update the trust manifest
    let manifest = match vaultkeeper_core::identity::manifest::load_manifest(host.as_ref()).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error: Failed to load trust manifest: {e}");
            return 1;
        }
    };

    let updated = vaultkeeper_core::identity::manifest::add_trusted_hash(&manifest, path, &hash);

    if let Err(e) =
        vaultkeeper_core::identity::manifest::save_manifest(host.as_ref(), &updated).await
    {
        eprintln!("Error: Failed to save trust manifest: {e}");
        return 1;
    }

    println!("Approved {path} (hash: {hash})");
    0
}

async fn cmd_dev_mode(path: &str, enable: bool) -> i32 {
    let host = make_host();
    let config_path = host.config_dir().join("config.json");

    // Load config
    let cfg = match vaultkeeper_core::config::load_config(host.as_ref()).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };

    // Update development_mode
    let mut cfg = cfg;
    if enable {
        let mut executables = cfg
            .development_mode
            .map(|dm| dm.executables)
            .unwrap_or_default();
        if !executables.iter().any(|e| e == path) {
            executables.push(path.to_string());
        }
        cfg.development_mode = Some(vaultkeeper_core::types::DevelopmentMode { executables });
    } else {
        // Remove the specific path from dev mode executables
        if let Some(dm) = cfg.development_mode.as_mut() {
            dm.executables.retain(|e| e != path);
            if dm.executables.is_empty() {
                cfg.development_mode = None;
            }
        }
    }

    let json = match serde_json::to_string_pretty(&cfg) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };

    if let Err(e) = host
        .write_file(&config_path, format!("{json}\n").as_bytes(), 0o600)
        .await
    {
        eprintln!("Error: {e}");
        return 1;
    }

    let state = if enable { "enabled" } else { "disabled" };
    println!("Dev mode {state} for {path}");
    0
}

async fn cmd_config(action: ConfigAction) -> i32 {
    let config_dir = NativeHostPlatform::default_config_dir();

    match action {
        ConfigAction::Init => {
            let config_path = config_dir.join("config.json");

            // Create config directory with restrictive permissions
            if let Err(e) = create_config_dir(&config_dir) {
                eprintln!("Error: {e}");
                return 1;
            }

            if config_path.exists() {
                eprintln!("Error: Config already exists at {}", config_path.display());
                return 1;
            }

            let default_cfg = config::default_config();
            let json = match serde_json::to_string_pretty(&default_cfg) {
                Ok(j) => j,
                Err(e) => {
                    eprintln!("Error: {e}");
                    return 1;
                }
            };

            if let Err(e) = write_config_file(&config_path, &json) {
                eprintln!("Error: {e}");
                return 1;
            }

            println!("Config created at {}", config_path.display());
            0
        }
        ConfigAction::Show => {
            let config_path = config_dir.join("config.json");
            match std::fs::read_to_string(&config_path) {
                Ok(content) => {
                    print!("{content}");
                    if !content.ends_with('\n') {
                        println!();
                    }
                    0
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    eprintln!(
                        "Error: No config file found. Run 'vaultkeeper config init' to create one."
                    );
                    1
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    1
                }
            }
        }
    }
}

/// `backend capabilities` — resolves the active backend (the same `FileBackend`
/// instance `store`/`delete` use) and reports its
/// [`vaultkeeper_core::backend::BackendCapabilities`] via
/// `get_backend_capabilities`, so a caller can check ahead of time whether the
/// configured backend qualifies for `--require-presence-per-use` (issue #262).
///
/// Mirrors the TypeScript CLI's `vaultkeeper backend capabilities` command:
/// the same subcommand name, `--json` flag, JSON row shape (`type`,
/// `displayName`, `presencePerUse`), and human-readable text (see
/// `packages/cli/src/commands/backend.ts`).
async fn cmd_backend(action: BackendAction) -> i32 {
    match action {
        BackendAction::Capabilities { json } => cmd_backend_capabilities(json).await,
    }
}

/// One row of `backend capabilities --json` output. Field declaration order
/// matches the TypeScript CLI's `BackendCapabilityRow` (`type`,
/// `displayName`, `presencePerUse` — see
/// `packages/cli/src/commands/backend.ts`) so a row shared by both CLIs
/// serializes byte-identically (the TS CLI still emits more rows — it
/// enumerates every registered backend type, while this CLI reports only the
/// active backend); a `serde_json::Value` object built with `json!` would
/// instead emit keys in the `BTreeMap`'s alphabetical order.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BackendCapabilityRow<'a> {
    #[serde(rename = "type")]
    backend_type: &'a str,
    display_name: &'a str,
    presence_per_use: bool,
}

async fn cmd_backend_capabilities(json: bool) -> i32 {
    let host = make_host();
    let backend = FileBackend::new(host);

    let capabilities = match get_backend_capabilities(&backend).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };

    let backend_type = backend.backend_type();
    let display_name = backend.display_name();

    if json {
        let rows = [BackendCapabilityRow {
            backend_type,
            display_name,
            presence_per_use: capabilities.presence_per_use,
        }];
        match serde_json::to_string_pretty(&rows) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("Error: {e}");
                return 1;
            }
        }
    } else {
        let presence = if capabilities.presence_per_use {
            "yes"
        } else {
            "no"
        };
        print!(
            "Backend capabilities (per configured instance):\n\n  {backend_type}  {display_name}  presence-per-use: {presence}\n\nA backend with presence-per-use: yes forces a distinct, fresh human action\nper operation and can satisfy `--require-presence-per-use`.\n"
        );
    }

    0
}

fn create_config_dir(dir: &Path) -> Result<(), String> {
    // Delegates to the same owner-only (0o700) directory creation
    // `NativeHostPlatform::write_file` uses (see #255), so `config init` and
    // every other write path agree on the contract: freshly created
    // directories are 0o700 on Unix, and an already-existing directory
    // (regardless of its current permissions) is left untouched.
    host::create_dir_all_secure(dir).map_err(|e| format!("Failed to create config directory: {e}"))
}

fn write_config_file(path: &PathBuf, json: &str) -> Result<(), String> {
    let content = format!("{json}\n");
    std::fs::write(path, &content).map_err(|e| format!("Failed to write config file: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)
            .map_err(|e| format!("Failed to set permissions on config file: {e}"))?;
    }

    Ok(())
}

async fn cmd_rotate_key() -> i32 {
    let host = make_host();

    let mut vault = match vaultkeeper_core::VaultKeeper::init(
        host.as_ref(),
        Some(vaultkeeper_core::vault::VaultKeeperOptions {
            skip_doctor: true,
            ..Default::default()
        }),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };

    if let Err(e) = vault.rotate_key(host.as_ref()).await {
        eprintln!("Error: {e}");
        return 1;
    }

    println!("Key rotated successfully.");
    0
}

async fn cmd_revoke_key() -> i32 {
    let host = make_host();

    let mut vault = match vaultkeeper_core::VaultKeeper::init(
        host.as_ref(),
        Some(vaultkeeper_core::vault::VaultKeeperOptions {
            skip_doctor: true,
            ..Default::default()
        }),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };

    if let Err(e) = vault.revoke_key(host.as_ref()).await {
        eprintln!("Error: {e}");
        return 1;
    }

    println!("Key revoked successfully.");
    0
}

/// `session revoke` — dispatches on the mutually exclusive `--jti`/`--key`
/// axes (issue #298). Clap's `conflicts_with` guarantees at most one is
/// `Some`; neither being set is still possible (both flags are optional), so
/// that case is rejected here rather than silently doing nothing.
async fn cmd_session(action: SessionAction) -> i32 {
    match action {
        SessionAction::Revoke { jti, key } => match (jti, key) {
            (Some(jti), None) => cmd_session_revoke_jti(&jti).await,
            (None, Some(key)) => cmd_session_revoke_key(&key).await,
            (None, None) => {
                eprintln!("Error: `session revoke` requires exactly one of --jti or --key");
                1
            }
            (Some(_), Some(_)) => {
                unreachable!("clap's conflicts_with rejects --jti and --key together")
            }
        },
        SessionAction::Mint { profile, entry } => cmd_session_mint(&profile, &entry).await,
    }
}

async fn init_vault(host: &NativeHostPlatform) -> Result<vaultkeeper_core::VaultKeeper, i32> {
    vaultkeeper_core::VaultKeeper::init(
        host,
        Some(vaultkeeper_core::vault::VaultKeeperOptions {
            skip_doctor: true,
            ..Default::default()
        }),
    )
    .await
    .map_err(|e| {
        eprintln!("Error: {e}");
        1
    })
}

/// Revoke a single lease by `jti`. The CLI has no access to the real lease's
/// own `exp` (it is only given the `jti`, not the token) — the revocation
/// entry is instead given the most conservative possible expiry, the
/// session-signing-lease hard TTL cap
/// ([`vaultkeeper_core::profile::SIGNING_LEASE_MAX_TTL_SECONDS`], 24h) from
/// now, so it can never be swept before any lease that could legitimately
/// carry this `jti` has itself expired.
async fn cmd_session_revoke_jti(jti: &str) -> i32 {
    let host = make_host();
    let mut vault = match init_vault(&host).await {
        Ok(v) => v,
        Err(code) => return code,
    };

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let exp = now_secs + vaultkeeper_core::profile::SIGNING_LEASE_MAX_TTL_SECONDS;
    if let Err(e) = vault.revoke_lease_jti(host.as_ref(), jti, exp).await {
        eprintln!("Error: {e}");
        return 1;
    }

    println!("Lease {jti} revoked.");
    0
}

async fn cmd_session_revoke_key(key: &str) -> i32 {
    let host = make_host();
    let mut vault = match init_vault(&host).await {
        Ok(v) => v,
        Err(code) => return code,
    };

    if let Err(e) = vault.revoke_lease_key(host.as_ref(), key).await {
        eprintln!("Error: {e}");
        return 1;
    }

    println!("Every outstanding lease for key \"{key}\" revoked.");
    0
}

/// `session mint <PROFILE> --entry <VAR>` (issue #299): resolve a
/// `signingKey` + `materialize: "lease"` profile entry and mint a session
/// signing-key lease, printing the JWE to stdout.
///
/// `interactive` (whether `stderr` is a terminal) is computed here, once, and
/// threaded into [`MintLeaseOptions::interactive`] — core never queries the
/// terminal itself, keeping the presence-mint logic platform-agnostic. When
/// `stderr` is not a terminal, [`vaultkeeper_core::vault::VaultKeeper::mint_signing_lease`]
/// never calls [`HostPlatform::prompt_approval`] at all for a
/// presence-requiring entry — see that method's doc comment for the
/// non-interactive fail-closed rule this guarantees (issue #299).
async fn cmd_session_mint(profile: &str, entry: &str) -> i32 {
    let host = make_host();

    let path = match resolve_profile_path(&host, Some(profile), None) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };

    let (loaded_profile, _cfg) = match load_named_profile(&host, &path).await {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };

    let Some((_, profile_entry)) = loaded_profile
        .entries
        .iter()
        .find(|(name, _)| name == entry)
    else {
        eprintln!(
            "Error: profile '{profile}' has no entry '{entry}' \
             (run `vaultkeeper profile show {profile}` to see its entries)"
        );
        return 1;
    };

    // Friendlier, earlier rejection than core's own — `mint_signing_lease`
    // re-checks `source`/`materialize` itself and fails closed regardless,
    // so this is UX only, not the enforcement point (issue #299).
    if matches!(profile_entry.source, EntrySource::Secret(_)) {
        eprintln!(
            "Error: entry '{entry}' in profile '{profile}' is secret-backed; \
             `session mint` only mints signing-key leases"
        );
        return 1;
    }

    if profile_entry.materialize != MaterializeMode::Lease {
        eprintln!(
            "Error: entry '{entry}' in profile '{profile}' does not use \
             materialize: \"lease\" — nothing to mint"
        );
        return 1;
    }

    let ttl_seconds = profile_entry
        .ttl_seconds
        .unwrap_or(vaultkeeper_core::profile::SIGNING_LEASE_DEFAULT_TTL_SECONDS);

    let mut vault = match init_vault(&host).await {
        Ok(v) => v,
        Err(code) => return code,
    };

    let backend = FileBackend::new(host.clone());
    let interactive = io::stderr().is_terminal();

    let options = MintLeaseOptions {
        profile_name: profile,
        entry_name: entry,
        source: &profile_entry.source,
        materialize: profile_entry.materialize,
        ttl_seconds,
        trust_tier: profile_entry.min_trust.to_trust_tier(),
        use_limit: profile_entry.use_limit,
        require_presence_at_mint: profile_entry.require_presence_at_mint,
        interactive,
    };

    match vault
        .mint_signing_lease(host.as_ref(), &backend, &options)
        .await
    {
        Ok(jwe) => {
            println!("{jwe}");
            0
        }
        Err(e) => {
            eprintln!("Error: {e}");
            1
        }
    }
}

/// `profile` — dispatches to the `init`/`show`/`list`/`lint` subcommands.
/// All schema, validation, and output rendering live in
/// `vaultkeeper_core::profile`; this function only parses arguments and
/// resolves file paths (issue #277).
async fn cmd_profile(action: ProfileAction) -> i32 {
    match action {
        ProfileAction::Init { name, profile_file } => cmd_profile_init(&name, profile_file).await,
        ProfileAction::Show { name, profile_file } => cmd_profile_show(name, profile_file).await,
        ProfileAction::List => cmd_profile_list().await,
        ProfileAction::Lint { name, profile_file } => cmd_profile_lint(name, profile_file).await,
    }
}

/// Resolve the on-disk path a profile subcommand should read/write.
///
/// `name` and `profile_file` are mutually exclusive at the clap layer for
/// `show`/`lint` (`--profile-file` `conflicts_with` NAME) — `name` is only
/// `None` when `profile_file` is `Some`. `init` always supplies `name`
/// (it is also embedded in the scaffold body), so passes `Some` even when
/// `profile_file` overrides the write location.
///
/// # Errors
/// Returns [`vaultkeeper_core::errors::VaultError::ConfigValidation`] if
/// `name` fails `vaultkeeper_core::profile::validate_profile_name` — checked
/// before any path is constructed.
fn resolve_profile_path(
    host: &NativeHostPlatform,
    name: Option<&str>,
    profile_file: Option<String>,
) -> Result<PathBuf, vaultkeeper_core::errors::VaultError> {
    if let Some(file) = profile_file {
        return Ok(PathBuf::from(file));
    }
    let name = name.expect(
        "clap enforces NAME is present when --profile-file is absent (required_unless_present)",
    );
    vaultkeeper_core::profile::profile_path(host.config_dir(), name)
}

async fn cmd_profile_init(name: &str, profile_file: Option<String>) -> i32 {
    let host = make_host();
    let path = match resolve_profile_path(&host, Some(name), profile_file) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };

    match host.file_exists(&path).await {
        Ok(true) => {
            eprintln!("Error: Profile already exists at {}", path.display());
            return 1;
        }
        Ok(false) => {}
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    }

    let scaffold = vaultkeeper_core::profile::scaffold_profile(name);
    let json = match serde_json::to_string_pretty(&scaffold) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };

    // Profiles carry no secret *values* — only names and policy — so
    // unlike config/key/secret storage they are safe to freely copy or
    // commit elsewhere (e.g. into a project repo). They are still written
    // owner-only (0o600), matching every other file this CLI writes (#267);
    // that is a filesystem-permissions default, not a secrecy requirement,
    // and callers are free to loosen or relocate the copy they commit.
    if let Err(e) = host
        .write_file(&path, format!("{json}\n").as_bytes(), 0o600)
        .await
    {
        eprintln!("Error: {e}");
        return 1;
    }

    println!("Profile created at {}", path.display());
    0
}

/// Load a validated profile from `path`, resolving TTL/trust defaults from
/// the active `config.json`. Returns the loaded profile alongside the same
/// `VaultConfig` it loaded, so a caller that also needs config fields (e.g.
/// `profile lint`'s active backend) doesn't have to load `config.json` a
/// second time.
async fn load_named_profile(
    host: &NativeHostPlatform,
    path: &Path,
) -> Result<
    (
        vaultkeeper_core::profile::LoadedProfile,
        vaultkeeper_core::types::VaultConfig,
    ),
    String,
> {
    if !host.file_exists(path).await.map_err(|e| e.to_string())? {
        return Err(format!("No profile found at {}", path.display()));
    }
    let content = host.read_file(path).await.map_err(|e| e.to_string())?;
    let json = String::from_utf8(content).map_err(|e| e.to_string())?;

    let cfg = vaultkeeper_core::config::load_config(host)
        .await
        .map_err(|e| e.to_string())?;
    let defaults = vaultkeeper_core::profile::ProfileDefaults::from_vault_defaults(&cfg.defaults);

    let profile =
        vaultkeeper_core::profile::load_profile_from_str(&json, &defaults).map_err(|e| {
            e.with_config_file_path(path.display().to_string())
                .to_string()
        })?;
    Ok((profile, cfg))
}

async fn cmd_profile_show(name: Option<String>, profile_file: Option<String>) -> i32 {
    let host = make_host();
    let path = match resolve_profile_path(&host, name.as_deref(), profile_file) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };

    match load_named_profile(&host, &path).await {
        Ok((profile, _cfg)) => {
            print!("{}", vaultkeeper_core::profile::render_show(&profile));
            0
        }
        Err(e) => {
            eprintln!("Error: {e}");
            1
        }
    }
}

async fn cmd_profile_list() -> i32 {
    let host = make_host();
    let profiles_dir = host
        .config_dir()
        .join(vaultkeeper_core::profile::PROFILES_DIR_NAME);

    let entries = match host.list_dir(&profiles_dir).await {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };

    let mut names: Vec<String> = entries
        .into_iter()
        .filter_map(|entry| {
            entry
                .strip_suffix(vaultkeeper_core::profile::PROFILE_FILE_EXTENSION)
                .map(str::to_string)
        })
        .collect();
    names.sort();

    print!("{}", vaultkeeper_core::profile::render_list(&names));
    0
}

async fn cmd_profile_lint(name: Option<String>, profile_file: Option<String>) -> i32 {
    let host = make_host();
    let path = match resolve_profile_path(&host, name.as_deref(), profile_file) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };

    // Single config.json load, shared with the profile loader above — see
    // `load_named_profile`'s doc comment.
    let (profile, cfg) = match load_named_profile(&host, &path).await {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("Error: {e}");
            return 1;
        }
    };

    let active_backend_type = cfg
        .backends
        .iter()
        .find(|b| b.enabled)
        .map(|b| b.backend_type.as_str())
        .unwrap_or("none");

    let lint = vaultkeeper_core::profile::lint_profile(
        &profile,
        cfg.defaults.trust_tier,
        u64::from(cfg.defaults.ttl_minutes) * 60,
        vaultkeeper_core::profile::LintBaseline::default(),
    );

    print!(
        "{}",
        vaultkeeper_core::profile::render_lint(&profile, &lint, active_backend_type)
    );
    0
}

#[cfg(test)]
mod tests {
    use super::ResolvedEnvMap;
    use zeroize::Zeroize;

    // `launch_and_wait` wraps its resolved env in `Zeroizing<ResolvedEnvMap>`
    // specifically so every exit path — not just the happy path after a
    // successful `spawn()` — scrubs the buffer on drop. That "scrubbed on
    // every path" guarantee itself comes from Rust's own `Drop` semantics
    // (a value's destructor runs on every exit from its scope, including an
    // early `return`), which isn't something a test can regress
    // independently of the language — there is no assertable surface for
    // "did drop run on this particular early return," short of reading the
    // process's freed memory, which isn't observable from safe Rust. What
    // *can* regress, and is worth covering, is `ResolvedEnvMap`'s own
    // `Zeroize` impl — e.g. someone changing the loop to skip a key, or
    // zeroizing keys instead of values. This test pins that behavior.
    #[test]
    fn resolved_env_map_zeroize_clears_every_value() {
        let mut map = ResolvedEnvMap(
            [
                ("GITHUB_TOKEN".to_string(), "ghp_sentinel_value".to_string()),
                ("OTHER_SECRET".to_string(), "another_sentinel".to_string()),
            ]
            .into_iter()
            .collect(),
        );

        map.zeroize();

        for value in map.0.values() {
            assert_eq!(value, "", "zeroize must clear every value in the map");
        }
        // Keys are not secret material (env var names), so `Zeroize` is
        // deliberately scoped to values only — confirm they survive.
        assert!(map.0.contains_key("GITHUB_TOKEN"));
        assert!(map.0.contains_key("OTHER_SECRET"));
    }
}
