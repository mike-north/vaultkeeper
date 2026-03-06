//! vaultkeeper CLI — native binary entry point.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "vaultkeeper", about = "Unified, policy-enforced secret storage")]
#[command(version, propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Store a secret in the vault
    Store {
        /// Secret name
        #[arg(long)]
        name: String,
    },
    /// Delete a secret from the vault
    Delete {
        /// Secret name
        #[arg(long)]
        name: String,
    },
    /// Execute a command with secret injection
    Exec {
        /// JWE token
        #[arg(long)]
        token: String,
        /// Command to execute
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Run preflight system checks
    Doctor,
    /// Approve an executable for identity binding
    Approve {
        /// Path to the executable
        #[arg(long)]
        path: String,
    },
    /// Toggle development mode for an executable
    DevMode {
        /// Path to the executable
        #[arg(long)]
        path: String,
        /// Enable or disable dev mode
        #[arg(long)]
        enable: bool,
    },
    /// Manage vault configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Rotate the encryption key
    RotateKey,
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show current configuration
    Show,
    /// Reset configuration to defaults
    Reset,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Store { name } => cmd_store(&name).await,
        Commands::Delete { name } => cmd_delete(&name).await,
        Commands::Exec { token, command } => cmd_exec(&token, &command).await,
        Commands::Doctor => cmd_doctor().await,
        Commands::Approve { path } => cmd_approve(&path).await,
        Commands::DevMode { path, enable } => cmd_dev_mode(&path, enable).await,
        Commands::Config { action } => cmd_config(action).await,
        Commands::RotateKey => cmd_rotate_key().await,
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn cmd_store(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("store: {name} (not yet implemented)");
    Ok(())
}

async fn cmd_delete(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("delete: {name} (not yet implemented)");
    Ok(())
}

async fn cmd_exec(token: &str, command: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("exec: token={token}, command={command:?} (not yet implemented)");
    Ok(())
}

async fn cmd_doctor() -> Result<(), Box<dyn std::error::Error>> {
    let result = vaultkeeper_core::VaultKeeper::doctor().await;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

async fn cmd_approve(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("approve: {path} (not yet implemented)");
    Ok(())
}

async fn cmd_dev_mode(path: &str, enable: bool) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("dev-mode: {path} enable={enable} (not yet implemented)");
    Ok(())
}

async fn cmd_config(action: ConfigAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        ConfigAction::Show => {
            let config = vaultkeeper_core::config::default_config();
            println!("{}", serde_json::to_string_pretty(&config)?);
        }
        ConfigAction::Reset => {
            eprintln!("config reset (not yet implemented)");
        }
    }
    Ok(())
}

async fn cmd_rotate_key() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("rotate-key (not yet implemented)");
    Ok(())
}
