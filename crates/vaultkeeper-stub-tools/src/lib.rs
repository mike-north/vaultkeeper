//! `vaultkeeper-stub-tools` — a generic, table-driven fake-CLI harness
//! (issue #313).
//!
//! Every subprocess-driven vaultkeeper backend (`security`, `op`, `ykman`,
//! `secret-tool`, `powershell`) presents the same observable contract: argv
//! and stdin in, stdout, stderr, and exit code out, against a mutable
//! "world." [`StubTool`] is the one engine that reproduces that contract
//! for all five; the differences between tools live entirely in which
//! [`BehaviorTable`] is loaded (see [`tables`]), never as a per-tool branch
//! in the engine.
//!
//! This crate is consumed two ways:
//!
//! - **In-process** (fast, hermetic Rust tests): construct a [`World`] and
//!   call [`StubTool::run`] directly — no subprocess, no filesystem. See
//!   `crates/vaultkeeper-core/src/backend/yubikey.rs`'s ported `TestHost`.
//! - **As a real subprocess** (`src/bin/vk-stub-*.rs`): each binary is a
//!   thin wrapper around [`cli::run_stub_process`], which enforces the
//!   guardrails (test-only env sentinel required; world persisted to a JSON
//!   file across invocations so a `store` in one process is visible to a
//!   `get` in the next) and is what both the Rust integration tests (spawn
//!   through a real `HostPlatform::exec`) and the JS conformance runner
//!   (resolved from a test-scoped `PATH`) actually execute.

pub mod cli;
pub mod engine;
pub mod table;
pub mod tables;
pub mod world;

pub use engine::{NO_MATCH_EXIT_CODE, RunResult, StubTool};
pub use table::{
    ArgToken, BehaviorRule, BehaviorTable, Emit, EmitBody, FieldSource, Mutation, StdinMatch,
    WorldPredicate,
};
pub use world::{Item, World};

/// The env var a stub binary requires to be set (to any non-empty value)
/// before it will do anything — issue #313 guardrail 1. A stub run without
/// it refuses immediately rather than risk ever being invoked outside a
/// test.
pub const SENTINEL_ENV_VAR: &str = "VAULTKEEPER_STUB_TOOLS_SENTINEL";

/// Env var naming the JSON file a stub process loads its [`World`] from at
/// startup and persists it back to on exit, so state survives across the
/// separate process per `exec` call a real subprocess-driven backend makes.
pub const WORLD_PATH_ENV_VAR: &str = "VAULTKEEPER_STUB_TOOLS_WORLD_PATH";

/// Env var overriding which built-in [`BehaviorTable`] a stub process loads
/// (by tool name — see [`tables::by_tool_name`]), instead of inferring it
/// from the binary's own name. Primarily for tests that want a `vk-stub-*`
/// binary to run a fixture table other than its default.
pub const TABLE_NAME_ENV_VAR: &str = "VAULTKEEPER_STUB_TOOLS_TABLE_NAME";
