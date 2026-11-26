//! Shared entry point every `vk-stub-*` binary in `src/bin/` calls into.
//!
//! Keeping this logic here (rather than duplicated per binary) is what
//! keeps the five `vk-stub-*` binaries genuinely table-driven rather than
//! five hand-written stubs: each `src/bin/vk-stub-<tool>.rs` is a two-line
//! wrapper naming its own tool; every guardrail and the match/emit/persist
//! loop live exactly once, here.

use std::io::{Read, Write};
use std::process::ExitCode;

use crate::engine::StubTool;
use crate::table::BehaviorTable;
use crate::world::World;
use crate::{SENTINEL_ENV_VAR, TABLE_NAME_ENV_VAR, WORLD_PATH_ENV_VAR};

/// Runs one stub-tool invocation end to end: guardrail checks, argv/stdin
/// read, world load, engine dispatch, world persist, stdout/stderr/exit.
///
/// `default_tool_name` is the tool this specific `vk-stub-*` binary
/// impersonates (e.g. `"ykman"`) — used to select the built-in
/// [`BehaviorTable`] unless overridden by [`TABLE_NAME_ENV_VAR`].
pub fn run_stub_process(default_tool_name: &str) -> ExitCode {
    // Guardrail 1 (issue #313): refuse to run at all without the test-only
    // sentinel — never resolvable to a real invocation outside a test.
    match std::env::var(SENTINEL_ENV_VAR) {
        Ok(v) if !v.is_empty() => {}
        _ => {
            eprintln!(
                "vk-stub-{default_tool_name}: refusing to run — {SENTINEL_ENV_VAR} is not set. \
                 This binary only ever runs inside a test harness that sets it explicitly."
            );
            return ExitCode::from(111);
        }
    }

    let tool_name =
        std::env::var(TABLE_NAME_ENV_VAR).unwrap_or_else(|_| default_tool_name.to_string());
    let table = match load_table(&tool_name) {
        Some(table) => table,
        None => {
            eprintln!(
                "vk-stub-{default_tool_name}: no built-in behavior table named '{tool_name}'"
            );
            return ExitCode::from(111);
        }
    };

    let world_path = std::env::var(WORLD_PATH_ENV_VAR).ok();
    let mut world = world_path
        .as_deref()
        .and_then(load_world)
        .unwrap_or_default();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut stdin_bytes = Vec::new();
    // Guardrail 4 (issue #313): a stub never prompts. Every caller in this
    // harness spawns the process with stdin as either a pipe it writes and
    // closes, or `Stdio::null()` (never an inherited TTY) — so reading to
    // EOF here always returns promptly, and no code path in this crate ever
    // interactively reads from a terminal to resolve a touch/unlock/approval
    // decision; that always comes from the behavior table instead.
    let _ = std::io::stdin().read_to_end(&mut stdin_bytes);

    let result = StubTool::run(&table, &mut world, &args, &stdin_bytes);

    if let Some(path) = world_path.as_deref() {
        save_world(path, &world);
    }

    let _ = std::io::stdout().write_all(&result.stdout);
    let _ = std::io::stderr().write_all(&result.stderr);

    #[allow(clippy::cast_sign_loss)]
    ExitCode::from(result.exit_code.clamp(0, 255) as u8)
}

fn load_table(tool_name: &str) -> Option<BehaviorTable> {
    crate::tables::by_tool_name(tool_name)
}

fn load_world(path: &str) -> Option<World> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.is_empty() {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

fn save_world(path: &str, world: &World) {
    if let Ok(json) = serde_json::to_vec_pretty(world) {
        let _ = std::fs::write(path, json);
    }
}
