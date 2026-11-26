//! The behavior table format a [`crate::StubTool`] is configured from.
//!
//! A table is pure data (`Serialize`/`Deserialize`): argv + stdin match
//! rules mapped to an emitted stdout/stderr/exit-code plus an optional world
//! mutation. Every one of the five subprocess-driven tools (`security`,
//! `op`, `ykman`, `secret-tool`, `powershell`) is configured by loading a
//! different table into the same engine — see [`crate::engine::StubTool`] —
//! so tool differences live entirely here as data, never as Rust branches in
//! the engine.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One token in an argv match pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ArgToken {
    /// Must equal this literal string exactly.
    Exact(String),
    /// Matches any single argv token, capturing it under this name (e.g.
    /// the hex challenge in `ykman otp calculate 2 <hex>`, or an item id).
    Capture(String),
    /// Matches every remaining argv token (may be zero), joined with a
    /// single space and captured under this name. Must be the final token
    /// in a rule's pattern.
    Rest(String),
}

/// How a rule's stdin requirement is matched, and optionally captured for
/// use by a [`Mutation`] or [`EmitBody::Template`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum StdinMatch {
    /// Any stdin content (including none) satisfies the rule.
    #[default]
    Any,
    /// Stdin, as UTF-8, must equal this string exactly.
    Exact(String),
    /// Captures the entire stdin payload verbatim as UTF-8 under `capture`.
    /// Always matches (empty stdin captures as an empty string) — for tools
    /// like `secret-tool` whose stdin contract is the raw secret bytes, not
    /// JSON.
    CaptureRaw { capture: String },
    /// Stdin must parse as JSON and contain a string value at this
    /// dot-separated pointer (e.g. `"fields.password.value"`, matching the
    /// real `op item get --format json` field shape). The value found there
    /// is captured under `capture` — this is the shape-assertion axis
    /// (issue #313): a case whose stdin does not put the value at the exact
    /// expected structural location fails to match, and the table's next
    /// (lower-priority) rule — typically one that emits success but leaves
    /// the field empty — is what actually reproduces the historical
    /// op-spike silent-field-drop defect by construction.
    JsonPointerCapture { pointer: String, capture: String },
}

/// A precondition on [`crate::World`] state a rule additionally requires,
/// beyond argv/stdin matching. This is the state-conditional-response axis
/// (issue #313): the same argv can legitimately produce different output
/// depending on whether the world is locked, or whether an item already
/// exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum WorldPredicate {
    /// `world.locked` must equal this value.
    Locked(bool),
    /// Whether an item exists must equal `exists`. `id_capture` names a
    /// capture bound earlier in the same rule's argv/stdin match.
    ItemExists { id_capture: String, exists: bool },
    /// A named `World::flags` entry must equal `value` (see
    /// [`crate::world::World::flag`]).
    Flag { name: String, value: bool },
}

/// Where a mutated item's field value comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum FieldSource {
    /// A literal value, independent of this invocation's argv/stdin.
    Fixed(String),
    /// The value captured under this name during argv/stdin matching (see
    /// [`ArgToken::Capture`] / [`StdinMatch::JsonPointerCapture`]).
    Captured(String),
}

/// The world-mutation axis (issue #313): how a matched rule mutates
/// [`crate::World`] — e.g. a `store` rule upserts an item a later `get`
/// rule must be able to find and read back through the real item shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Mutation {
    /// Sets `world.locked`.
    SetLocked(bool),
    /// Sets a named `World::flags` entry.
    SetFlag { name: String, value: bool },
    /// Inserts or replaces the item named by `id_capture`, setting exactly
    /// the fields listed in `fields` (existing fields not listed are left
    /// untouched on an upsert of an already-existing item).
    UpsertItem {
        id_capture: String,
        fields: BTreeMap<String, FieldSource>,
    },
    /// Removes the item named by `id_capture`, if present.
    DeleteItem { id_capture: String },
}

/// The body of an emitted stdout/stderr stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum EmitBody {
    /// No output.
    Empty,
    /// A fixed literal string, independent of captures/world.
    Fixed(String),
    /// A template string. `{name}` is replaced with the capture bound under
    /// `name` (from argv/stdin matching). `{item.<field>}` is replaced with
    /// the value of `<field>` on the item named by `id_capture` — resolved
    /// *after* this rule's own mutation has been applied, so a rule that
    /// both writes and echoes back sees its own write (needed for the
    /// shape-round-trip assertion: write-then-read must return the value
    /// through the real item shape, not a value captured pre-write).
    Template {
        template: String,
        id_capture: Option<String>,
    },
}

/// What a matched rule emits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Emit {
    pub stdout: EmitBody,
    #[serde(default = "default_empty_body")]
    pub stderr: EmitBody,
    pub exit_code: i32,
}

fn default_empty_body() -> EmitBody {
    EmitBody::Empty
}

/// A single behavior-table rule: an argv + stdin + world-state match,
/// paired with an emitted response and an optional world mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BehaviorRule {
    /// Human-readable name, surfaced in the "no rule matched" diagnostic.
    pub name: String,
    pub args: Vec<ArgToken>,
    /// Defaults to [`StdinMatch::Any`] so tables that don't care about
    /// stdin can omit the field entirely.
    #[serde(default)]
    pub stdin: StdinMatch,
    /// Named values bound into this rule's captures unconditionally (before
    /// world predicates are evaluated), independent of argv/stdin — for
    /// tools whose real CLI doesn't put an item id on the invocation this
    /// rule matches (e.g. `op item create` generates its own id).
    #[serde(default)]
    pub fixed_captures: BTreeMap<String, String>,
    #[serde(default)]
    pub world: Vec<WorldPredicate>,
    #[serde(default)]
    pub mutation: Option<Mutation>,
    pub emit: Emit,
}

/// A named, ordered set of [`BehaviorRule`]s. Rules are tried in order; the
/// first one whose argv pattern, stdin requirement, and world predicates all
/// match wins. This ordering is exactly what lets a table encode "shape
/// matched -> full success" as a higher-priority rule than "shape did not
/// match -> degraded/empty success", reproducing the op-spike
/// silent-field-drop defect class by construction (issue #313 AC5) whenever
/// a case's stdin doesn't hit the shape-faithful rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BehaviorTable {
    pub tool: String,
    pub rules: Vec<BehaviorRule>,
}
