//! (issue #313 AC5) Shape-assertion axis, driven end to end through the real
//! `op` behavior table + [`StubTool`] engine + [`World`] wired together (no
//! mocks) — an integration test in the sense the repo's testing rules use:
//! components exercising their real contract with each other, not a single
//! function in isolation.
//!
//! The canonical motivating defect: a hand-built `op item create` stdin
//! template that puts the password at the wrong JSON path silently succeeds
//! (exit 0, item created) but drops the field — the item comes back from
//! `item get` with the field present in shape but empty in value. Both
//! tests below call the exact same [`assert_shape_round_trips`] helper; only
//! the input stdin shape differs, so it is the assertion itself — not a
//! different code path — that catches the defect.

use vaultkeeper_stub_tools::{StubTool, World, tables};

/// Real `op` shape: `{"fields": {"password": {"value": "<secret>"}}}`. This
/// stdin puts the value at the shape-faithful path the table's
/// higher-priority rule requires, so it is captured and the round trip
/// preserves it.
const SHAPE_FAITHFUL_STDIN: &str = r#"{"fields":{"password":{"value":"hunter2"}}}"#;

/// The historically-buggy shape from the op-CLI spike: a hand-built stdin
/// template that puts the secret at a flattened top-level `password` key
/// instead of nesting it under `fields.password.value`. Structurally
/// plausible (still valid JSON, still describes "a password"), but not the
/// shape the real tool's field array actually round-trips through.
const SHAPE_MISMATCHED_STDIN: &str = r#"{"password":"hunter2"}"#;

/// Runs `item create` (with `stdin`) then `item get`, and asserts the field
/// value survives the round trip through the real `op` field-array shape —
/// not just "some value was stored somewhere," but specifically
/// `fields[].value` on the item `op item get` reports back.
fn assert_shape_round_trips(stdin: &str) {
    let table = tables::op();
    let mut world = World::new();

    let create = StubTool::run(
        &table,
        &mut world,
        &[
            "item".to_string(),
            "create".to_string(),
            "--format".to_string(),
            "json".to_string(),
        ],
        stdin.as_bytes(),
    );
    // Exit 0 either way — this is the defect's whole danger: nothing about
    // the create call's own exit code signals the drop.
    assert_eq!(create.exit_code, 0, "op item create must report success");

    let get = StubTool::run(
        &table,
        &mut world,
        &[
            "item".to_string(),
            "get".to_string(),
            "op-item".to_string(),
            "--format".to_string(),
            "json".to_string(),
        ],
        b"",
    );
    assert_eq!(get.exit_code, 0);

    let parsed: serde_json::Value =
        serde_json::from_slice(&get.stdout).expect("op item get must emit valid JSON");
    let round_tripped = parsed["fields"][0]["value"].as_str().unwrap_or_default();

    assert_eq!(
        round_tripped, "hunter2",
        "write-then-read must return the value through op's real field shape, not just \
         succeed with the field silently empty"
    );
}

#[test]
fn shape_faithful_stdin_passes_the_round_trip_assertion() {
    assert_shape_round_trips(SHAPE_FAITHFUL_STDIN);
}

#[test]
#[should_panic(expected = "write-then-read must return the value")]
fn shape_mismatched_stdin_fails_the_round_trip_assertion_reproducing_the_op_spike_defect() {
    // This is the failing half of AC5: reproduces the op-CLI spike's
    // silent-field-drop defect (exit 0, item "created", field present in
    // shape but empty in value) as a failing assertion via the identical
    // helper the passing case above uses — a shape-faithful double catches
    // this class of bug by construction, without any special-cased "detect
    // the drop" logic.
    assert_shape_round_trips(SHAPE_MISMATCHED_STDIN);
}
