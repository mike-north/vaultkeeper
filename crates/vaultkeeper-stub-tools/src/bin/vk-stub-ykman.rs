//! Fake `ykman(1)` — thin wrapper around the shared, table-driven
//! `vaultkeeper_stub_tools::cli::run_stub_process` engine (issue #313).
//! All `ykman`-specific behavior lives in
//! `vaultkeeper_stub_tools::tables::ykman`, not here.

use std::process::ExitCode;

fn main() -> ExitCode {
    vaultkeeper_stub_tools::cli::run_stub_process("ykman")
}
