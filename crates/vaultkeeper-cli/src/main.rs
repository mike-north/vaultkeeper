//! vaultkeeper CLI — native binary entry point.
//!
//! Matches the command surface and output format of the TypeScript CLI.

mod host;

use clap::{Parser, Subcommand};
use host::NativeHostPlatform;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::Arc;
use vaultkeeper_core::backend::{FileBackend, HostPlatform, SecretBackend};
use vaultkeeper_core::config;

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
    /// Toggle development mode for a script
    DevMode {
        /// Path to the executable
        #[arg(long)]
        path: String,
        /// Enable or disable dev mode
        #[arg(long)]
        enable: bool,
    },
    /// Store a secret (reads from stdin)
    Store {
        /// Secret name
        #[arg(long)]
        name: String,
    },
    /// Delete a secret
    Delete {
        /// Secret name
        #[arg(long)]
        name: String,
    },
    /// Manage configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Rotate the encryption key
    RotateKey,
    /// Emergency key revocation
    RevokeKey,
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Initialize a new configuration file
    Init,
    /// Show current configuration
    Show,
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
            Commands::Store { name } => cmd_store(&name).await,
            Commands::Delete { name } => cmd_delete(&name).await,
            Commands::Exec { token, command } => cmd_exec(&token, &command).await,
            Commands::Doctor => cmd_doctor().await,
            Commands::Approve { path } => cmd_approve(&path).await,
            Commands::DevMode { path, enable } => cmd_dev_mode(&path, enable).await,
            Commands::Config { action } => cmd_config(action).await,
            Commands::RotateKey => cmd_rotate_key().await,
            Commands::RevokeKey => cmd_revoke_key().await,
        },
    };

    std::process::exit(exit_code);
}

fn print_help() {
    use clap::CommandFactory;
    Cli::command().print_help().ok();
}

async fn cmd_store(name: &str) -> i32 {
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

    if let Err(e) = backend.store(name, secret).await {
        eprintln!("Error: {e}");
        return 1;
    }

    println!("Secret \"{name}\" stored successfully.");
    0
}

async fn cmd_delete(name: &str) -> i32 {
    let host = make_host();
    let backend = FileBackend::new(host);

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
    let (claims, _response) = match vault.authorize(token) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: Failed to authorize token: {e}");
            return 1;
        }
    };

    // Run the command with the secret injected as VAULTKEEPER_SECRET env var
    let cmd_name = &command[0];
    let cmd_args: Vec<&str> = command[1..].iter().map(String::as_str).collect();

    use std::process::Command;
    let status = Command::new(cmd_name)
        .args(&cmd_args)
        .env("VAULTKEEPER_SECRET", &claims.val)
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
    let result = vaultkeeper_core::doctor::run_doctor(host.as_ref()).await;

    for check in &result.checks {
        let icon = if check.status == vaultkeeper_core::PreflightCheckStatus::Ok {
            "\u{2713}"
        } else {
            "\u{2717}"
        };
        let version = check
            .version
            .as_ref()
            .map(|v| format!(" ({v})"))
            .unwrap_or_default();
        let reason = check
            .reason
            .as_ref()
            .map(|r| format!(" \u{2014} {r}"))
            .unwrap_or_default();
        println!("  {icon} {}{version}{reason}", check.name);
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
                eprintln!("Config already exists at {}", config_path.display());
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
                Err(e) => {
                    eprintln!("Error: {e}");
                    1
                }
            }
        }
    }
}

fn create_config_dir(dir: &PathBuf) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("Failed to create config directory: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(dir, perms)
            .map_err(|e| format!("Failed to set permissions on config directory: {e}"))?;
    }

    Ok(())
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

    if let Err(e) = vault.rotate_key() {
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

    if let Err(e) = vault.revoke_key() {
        eprintln!("Error: {e}");
        return 1;
    }

    println!("Key revoked successfully.");
    0
}
