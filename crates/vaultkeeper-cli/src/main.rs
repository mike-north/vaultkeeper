//! vaultkeeper CLI — native binary entry point.
//!
//! Matches the command surface and output format of the TypeScript CLI.

mod host;

use clap::{Parser, Subcommand};
use host::NativeHostPlatform;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use vaultkeeper_core::backend::{
    FileBackend, HostPlatform, PresenceOperation, SecretBackend, get_backend_capabilities,
};
use vaultkeeper_core::config;
use vaultkeeper_core::vault::enforce_presence_requirement;

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
    /// Run a command with a secret injected as an env var
    Exec {
        /// JWE token
        #[arg(long)]
        token: String,
        /// Command to execute
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
            Commands::Doctor => cmd_doctor().await,
            Commands::Approve { path } => cmd_approve(&path).await,
            Commands::DevMode { path, enable } => cmd_dev_mode(&path, enable).await,
            Commands::Config { action } => cmd_config(action).await,
            Commands::Backend { action } => cmd_backend(action).await,
            Commands::RotateKey => cmd_rotate_key().await,
            Commands::RevokeKey => cmd_revoke_key().await,
            Commands::Profile { action } => cmd_profile(action).await,
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

async fn cmd_exec(token: &str, command: &[String]) -> i32 {
    if command.is_empty() {
        eprintln!("Error: No command specified");
        return 1;
    }

    let host = make_host();

    // Initialize VaultKeeper with doctor checks skipped (exec should be fast)
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

    // Decrypt and validate the JWE token
    let (handle, claims, _response) = match vault.authorize(token) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: Failed to authorize token: {e}");
            return 1;
        }
    };

    // `exec` only makes sense for a secret claim — a signing-key lease
    // carries no secret value to inject, and its handle refuses `read_secret`
    // outright (issue #241 AC3). Check `kty` up front so that refusal is
    // reported with the same message as before the handle-table refactor,
    // rather than a lower-level handle error.
    if claims.kty == Some(vaultkeeper_core::ClaimsKind::SigningKey) {
        eprintln!("Error: token does not authorize a secret value");
        return 1;
    }

    // Read the secret exactly once (issue #241) — it never traveled through
    // `authorize()`'s return value.
    let secret = match vault.read_secret(&handle) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: Failed to read secret: {e}");
            return 1;
        }
    };

    // Run the command with the secret injected as VAULTKEEPER_SECRET env var
    let cmd_name = &command[0];
    let cmd_args: Vec<&str> = command[1..].iter().map(String::as_str).collect();

    use std::process::Command;
    let status = Command::new(cmd_name)
        .args(&cmd_args)
        .env("VAULTKEEPER_SECRET", secret.as_str())
        .status();

    match status {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => {
            eprintln!("Error: Failed to execute command: {e}");
            1
        }
    }
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
