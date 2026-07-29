//! (issue #313 AC1) A `StubTool` from a behavior table reproduces the
//! argv+stdin -> stdout+stderr+exit contract for at least two distinct tool
//! shapes, driven purely by table data — this file makes exactly one call
//! into `StubTool::run` per case and never branches on which tool is under
//! test; every difference between `ykman` and `secret-tool` below comes from
//! which `BehaviorTable` is passed in.

use vaultkeeper_stub_tools::{StubTool, World, tables};

#[test]
fn ykman_version_reproduces_the_real_tool_contract() {
    let table = tables::ykman(tables::YKMAN_DEFAULT_HMAC_RESPONSE);
    let mut world = World::new();

    let result = StubTool::run(&table, &mut world, &["--version".to_string()], b"");

    assert_eq!(result.exit_code, 0);
    assert_eq!(
        String::from_utf8(result.stdout).unwrap(),
        "YubiKey Manager (ykman) version: 5.4.0"
    );
    assert!(result.stderr.is_empty());
}

#[test]
fn ykman_otp_calculate_captures_the_challenge_argv_and_returns_the_fixed_hmac_response() {
    let table = tables::ykman(tables::YKMAN_DEFAULT_HMAC_RESPONSE);
    let mut world = World::new();

    let result = StubTool::run(
        &table,
        &mut world,
        &[
            "otp".to_string(),
            "calculate".to_string(),
            "2".to_string(),
            "cafefeed00112233".to_string(),
        ],
        b"",
    );

    assert_eq!(result.exit_code, 0);
    assert_eq!(
        String::from_utf8(result.stdout).unwrap(),
        "deadbeefcafe01234567deadbeefcafe01234567"
    );
}

#[test]
fn ykman_unrecognized_argv_falls_through_to_the_no_match_contract() {
    let table = tables::ykman(tables::YKMAN_DEFAULT_HMAC_RESPONSE);
    let mut world = World::new();

    let result = StubTool::run(&table, &mut world, &["reset".to_string()], b"");

    assert_eq!(result.exit_code, vaultkeeper_stub_tools::NO_MATCH_EXIT_CODE);
    assert!(result.stdout.is_empty());
    assert!(!result.stderr.is_empty());
}

#[test]
fn secret_tool_store_then_lookup_round_trips_the_secret_through_the_same_process_world() {
    let table = tables::secret_tool();
    let mut world = World::new();

    let store = StubTool::run(
        &table,
        &mut world,
        &[
            "store".to_string(),
            "--label".to_string(),
            "vaultkeeper:demo".to_string(),
            "--".to_string(),
            "vaultkeeper-id".to_string(),
            "demo".to_string(),
        ],
        b"s3cret",
    );
    assert_eq!(store.exit_code, 0);

    let lookup = StubTool::run(
        &table,
        &mut world,
        &[
            "lookup".to_string(),
            "--".to_string(),
            "vaultkeeper-id".to_string(),
            "demo".to_string(),
        ],
        b"",
    );

    assert_eq!(lookup.exit_code, 0);
    assert_eq!(String::from_utf8(lookup.stdout).unwrap(), "s3cret\n");
}

#[test]
fn secret_tool_lookup_reports_locked_regardless_of_item_existence() {
    let table = tables::secret_tool();
    let mut world = World::new();

    // Stored while unlocked; the world is then locked before the lookup
    // below — the item still exists, but the locked check must win (state-
    // conditional-response axis, issue #313 AC4): the identical argv as a
    // "found" lookup must not leak the existing item's value while locked.
    let store = StubTool::run(
        &table,
        &mut world,
        &[
            "store".to_string(),
            "--label".to_string(),
            "vaultkeeper:demo".to_string(),
            "--".to_string(),
            "vaultkeeper-id".to_string(),
            "demo".to_string(),
        ],
        b"s3cret",
    );
    assert_eq!(store.exit_code, 0);
    world.locked = true;

    let lookup = StubTool::run(
        &table,
        &mut world,
        &[
            "lookup".to_string(),
            "--".to_string(),
            "vaultkeeper-id".to_string(),
            "demo".to_string(),
        ],
        b"",
    );

    assert_eq!(lookup.exit_code, 1);
    assert!(lookup.stdout.is_empty());
    assert!(String::from_utf8(lookup.stderr).unwrap().contains("locked"));
}

#[test]
fn secret_tool_lookup_of_a_never_stored_id_reports_not_found_by_exit_code() {
    let table = tables::secret_tool();
    let mut world = World::new();

    let lookup = StubTool::run(
        &table,
        &mut world,
        &[
            "lookup".to_string(),
            "--".to_string(),
            "vaultkeeper-id".to_string(),
            "never-stored".to_string(),
        ],
        b"",
    );

    assert_eq!(lookup.exit_code, 1);
    assert!(lookup.stdout.is_empty());
}
