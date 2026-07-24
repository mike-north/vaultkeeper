//! The `StubTool` matching/mutation/emit engine.
//!
//! This is the one piece of logic every fake CLI shares — argv + stdin in,
//! stdout + stderr + exit code out, against a mutable [`World`] — driven
//! entirely by a [`BehaviorTable`]'s data. There is no tool-specific branch
//! anywhere in this file (issue #313 AC1): per-tool differences live purely
//! in which table is loaded (see [`crate::tables`]).

use std::collections::BTreeMap;

use crate::table::{
    ArgToken, BehaviorRule, BehaviorTable, EmitBody, FieldSource, Mutation, StdinMatch,
    WorldPredicate,
};
use crate::world::{Item, World};

/// The result of running one [`StubTool::run`] invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
}

/// Exit code emitted when no rule in the table matches — deliberately
/// mirrors the "command not found" family (127) real shells use, so a
/// consuming backend's exit-code-based error classification is exercised
/// exactly as it would be against an unexpected real-tool invocation.
pub const NO_MATCH_EXIT_CODE: i32 = 127;

/// The generic fake-CLI engine (issue #313). Stateless — all mutable state
/// lives in the caller-owned [`World`], so the same engine can be driven
/// either in-process (fast, hermetic Rust unit/integration tests) or from a
/// real subprocess binary that loads/persists `World` to a file across
/// invocations (see `src/bin/*.rs`).
pub struct StubTool;

impl StubTool {
    /// Match `args`/`stdin` against `table` in order, apply the first
    /// matching rule's mutation (if any) to `world`, and render its emit.
    pub fn run(
        table: &BehaviorTable,
        world: &mut World,
        args: &[String],
        stdin: &[u8],
    ) -> RunResult {
        for rule in &table.rules {
            let Some(captures) = match_rule(rule, args, stdin, world) else {
                continue;
            };

            if let Some(mutation) = &rule.mutation {
                apply_mutation(mutation, world, &captures);
            }

            // `{item.<field>}` placeholders are resolved by `render_body`
            // by looking `world` up *after* the mutation above has already
            // been applied, so a rule that both writes and echoes back sees
            // its own write — this is what makes the shape round-trip
            // assertion meaningful (AC5).
            let stdout = render_body(&rule.emit.stdout, world, &captures);
            let stderr = render_body(&rule.emit.stderr, world, &captures);
            return RunResult {
                stdout,
                stderr,
                exit_code: rule.emit.exit_code,
            };
        }

        RunResult {
            stdout: Vec::new(),
            stderr: format!(
                "vk-stub[{}]: no behavior-table rule matched argv {:?}",
                table.tool, args
            )
            .into_bytes(),
            exit_code: NO_MATCH_EXIT_CODE,
        }
    }
}

/// Attempts to match a single rule against `args`/`stdin`/`world`, returning
/// the bound captures on success.
fn match_rule(
    rule: &BehaviorRule,
    args: &[String],
    stdin: &[u8],
    world: &World,
) -> Option<BTreeMap<String, String>> {
    let mut captures = match_args(&rule.args, args)?;
    match_stdin(&rule.stdin, stdin, &mut captures)?;
    for (name, value) in &rule.fixed_captures {
        captures.insert(name.clone(), value.clone());
    }
    for predicate in &rule.world {
        if !predicate_holds(predicate, world, &captures) {
            return None;
        }
    }
    Some(captures)
}

fn match_args(pattern: &[ArgToken], args: &[String]) -> Option<BTreeMap<String, String>> {
    let mut captures = BTreeMap::new();
    let mut i = 0usize;
    for (idx, token) in pattern.iter().enumerate() {
        match token {
            ArgToken::Exact(expected) => {
                if args.get(i)? != expected {
                    return None;
                }
                i += 1;
            }
            ArgToken::Capture(name) => {
                let value = args.get(i)?;
                captures.insert(name.clone(), value.clone());
                i += 1;
            }
            ArgToken::Rest(name) => {
                debug_assert_eq!(idx, pattern.len() - 1, "Rest must be the final token");
                let rest = args.get(i..)?.join(" ");
                captures.insert(name.clone(), rest);
                i = args.len();
            }
        }
    }
    if i != args.len() {
        // Extra trailing args beyond the pattern, and the pattern didn't
        // end in Rest — not a match.
        return None;
    }
    Some(captures)
}

fn match_stdin(
    matcher: &StdinMatch,
    stdin: &[u8],
    captures: &mut BTreeMap<String, String>,
) -> Option<()> {
    match matcher {
        StdinMatch::Any => Some(()),
        StdinMatch::Exact(expected) => {
            let actual = std::str::from_utf8(stdin).ok()?;
            if actual == expected { Some(()) } else { None }
        }
        StdinMatch::CaptureRaw { capture } => {
            let actual = std::str::from_utf8(stdin).ok()?;
            captures.insert(capture.clone(), actual.to_string());
            Some(())
        }
        StdinMatch::JsonPointerCapture { pointer, capture } => {
            let value: serde_json::Value = serde_json::from_slice(stdin).ok()?;
            let found = lookup_pointer(&value, pointer)?;
            let found = found.as_str()?;
            captures.insert(capture.clone(), found.to_string());
            Some(())
        }
    }
}

/// Looks up a dot-separated path (e.g. `"fields.password.value"`) in a JSON
/// value. Deliberately strict/structural — a value at the wrong nesting
/// level or under the wrong key is simply not found, which is exactly the
/// shape-mismatch case AC5 needs to reproduce.
fn lookup_pointer<'a>(
    value: &'a serde_json::Value,
    pointer: &str,
) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for segment in pointer.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

fn predicate_holds(
    predicate: &WorldPredicate,
    world: &World,
    captures: &BTreeMap<String, String>,
) -> bool {
    match predicate {
        WorldPredicate::Locked(expected) => world.locked == *expected,
        WorldPredicate::ItemExists { id_capture, exists } => {
            let Some(id) = captures.get(id_capture) else {
                return false;
            };
            world.items.contains_key(id) == *exists
        }
        WorldPredicate::Flag { name, value } => world.flag(name) == *value,
    }
}

fn apply_mutation(mutation: &Mutation, world: &mut World, captures: &BTreeMap<String, String>) {
    match mutation {
        Mutation::SetLocked(value) => world.locked = *value,
        Mutation::SetFlag { name, value } => {
            world.flags.insert(name.clone(), *value);
        }
        Mutation::UpsertItem { id_capture, fields } => {
            let Some(id) = captures.get(id_capture) else {
                return;
            };
            let item = world
                .items
                .entry(id.clone())
                .or_insert_with(|| Item::new(id.clone()));
            for (field, source) in fields {
                let value = match source {
                    FieldSource::Fixed(v) => v.clone(),
                    FieldSource::Captured(name) => captures.get(name).cloned().unwrap_or_default(),
                };
                item.fields.insert(field.clone(), value);
            }
        }
        Mutation::DeleteItem { id_capture } => {
            if let Some(id) = captures.get(id_capture) {
                world.items.remove(id);
            }
        }
    }
}

fn render_body(body: &EmitBody, world: &World, captures: &BTreeMap<String, String>) -> Vec<u8> {
    match body {
        EmitBody::Empty => Vec::new(),
        EmitBody::Fixed(s) => s.clone().into_bytes(),
        EmitBody::Template {
            template,
            id_capture,
        } => {
            let mut rendered = template.clone();
            for (name, value) in captures {
                rendered = rendered.replace(&format!("{{{name}}}"), value);
            }
            if let Some(id_capture) = id_capture
                && let Some(id) = captures.get(id_capture)
                && let Some(item) = world.item(id)
            {
                for (field, value) in &item.fields {
                    rendered = rendered.replace(&format!("{{item.{field}}}"), value);
                }
            }
            rendered.into_bytes()
        }
    }
}
