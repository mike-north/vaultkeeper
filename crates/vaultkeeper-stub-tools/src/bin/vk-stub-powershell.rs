//! Fake `powershell(1)` — thin wrapper around the shared, table-driven
//! `vaultkeeper_stub_tools::cli::run_stub_process` engine (issue #313).
//! All `powershell`-specific behavior lives in
//! `vaultkeeper_stub_tools::tables::powershell`, not here.

use std::process::ExitCode;

fn main() -> ExitCode {
    vaultkeeper_stub_tools::cli::run_stub_process("powershell")
}
