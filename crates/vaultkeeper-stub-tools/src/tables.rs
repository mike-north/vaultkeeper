//! Built-in default behavior tables — one per real tool, all pure data
//! consumed by the shared [`crate::engine::StubTool`] (issue #313 AC1: no
//! per-tool Rust branches in the engine, only data here).

use std::collections::BTreeMap;

use crate::table::{
    ArgToken, BehaviorRule, BehaviorTable, Emit, EmitBody, FieldSource, Mutation, StdinMatch,
    WorldPredicate,
};

fn tok(s: &str) -> ArgToken {
    ArgToken::Exact(s.to_string())
}

/// The `World::flags` key ykman's table uses for "is a device physically
/// present" — a caller building an initial `World` for ykman must set this
/// explicitly (default `World::new()` leaves every flag `false`, i.e. "no
/// device"); see [`ykman`].
pub const YKMAN_DEVICE_AVAILABLE_FLAG: &str = "device_available";

/// Default HMAC-SHA1 challenge-response hex string [`ykman`] emits when no
/// scenario-specific override is needed — mirrors the ported seed's
/// `FAKE_HMAC_RESPONSE`.
pub const YKMAN_DEFAULT_HMAC_RESPONSE: &str = "deadbeefcafe01234567deadbeefcafe01234567";

/// `ykman` — ports the `TestHost` seed from issue #293's `YubikeyBackend`
/// tests (`crates/vaultkeeper-core/src/backend/yubikey.rs`) onto the
/// generalized [`crate::BehaviorTable`] format: `--version`, `list`
/// (present/absent device, keyed by [`YKMAN_DEVICE_AVAILABLE_FLAG`]), and
/// `otp calculate 2 <hex>` (a fixed HMAC response regardless of the
/// challenge — matches the ported seed's `FAKE_HMAC_RESPONSE` behavior).
/// `hmac_response` is a parameter (rather than hardcoded) because several of
/// the ported YubikeyBackend tests swap in a different fixture/malformed
/// response mid-test.
pub fn ykman(hmac_response: &str) -> BehaviorTable {
    BehaviorTable {
        tool: "ykman".to_string(),
        rules: vec![
            BehaviorRule {
                name: "--version".to_string(),
                args: vec![tok("--version")],
                stdin: StdinMatch::Any,
                fixed_captures: BTreeMap::new(),
                world: vec![],
                mutation: None,
                emit: Emit {
                    stdout: EmitBody::Fixed("YubiKey Manager (ykman) version: 5.4.0".to_string()),
                    stderr: EmitBody::Empty,
                    exit_code: 0,
                },
            },
            BehaviorRule {
                name: "list (device present)".to_string(),
                args: vec![tok("list")],
                stdin: StdinMatch::Any,
                fixed_captures: BTreeMap::new(),
                world: vec![WorldPredicate::Flag {
                    name: YKMAN_DEVICE_AVAILABLE_FLAG.to_string(),
                    value: true,
                }],
                mutation: None,
                emit: Emit {
                    stdout: EmitBody::Fixed(
                        "YubiKey 5 NFC (5.4.3) [OTP+FIDO+CCID] Serial: 12345".to_string(),
                    ),
                    stderr: EmitBody::Empty,
                    exit_code: 0,
                },
            },
            BehaviorRule {
                name: "list (device absent — no matching flag predicate, so this is the fallback)"
                    .to_string(),
                args: vec![tok("list")],
                stdin: StdinMatch::Any,
                fixed_captures: BTreeMap::new(),
                world: vec![],
                mutation: None,
                emit: Emit {
                    stdout: EmitBody::Empty,
                    stderr: EmitBody::Empty,
                    exit_code: 0,
                },
            },
            BehaviorRule {
                name: "otp calculate 2 <challenge>".to_string(),
                args: vec![
                    tok("otp"),
                    tok("calculate"),
                    tok("2"),
                    ArgToken::Capture("challenge".to_string()),
                ],
                stdin: StdinMatch::Any,
                fixed_captures: BTreeMap::new(),
                world: vec![],
                mutation: None,
                emit: Emit {
                    stdout: EmitBody::Fixed(hmac_response.to_string()),
                    stderr: EmitBody::Empty,
                    exit_code: 0,
                },
            },
        ],
    }
}

/// `secret-tool` (GNOME Keyring / Linux Secret Service) — models the
/// argv/stdin shape `SecretToolBackend`
/// (`crates/vaultkeeper-core/src/backend/secret_tool.rs`) actually drives:
/// `store --label <label> -- vk-id <id>` (secret on stdin), `lookup --
/// vk-id <id>`, `clear -- vk-id <id>`.
pub fn secret_tool() -> BehaviorTable {
    let mut store_fields = BTreeMap::new();
    store_fields.insert(
        "secret".to_string(),
        FieldSource::Captured("secret".to_string()),
    );

    BehaviorTable {
        tool: "secret-tool".to_string(),
        rules: vec![
            BehaviorRule {
                name: "--version".to_string(),
                args: vec![tok("--version")],
                stdin: StdinMatch::Any,
                fixed_captures: BTreeMap::new(),
                world: vec![],
                mutation: None,
                emit: Emit {
                    stdout: EmitBody::Fixed("secret-tool 0.20.5".to_string()),
                    stderr: EmitBody::Empty,
                    exit_code: 0,
                },
            },
            BehaviorRule {
                name: "store".to_string(),
                args: vec![
                    tok("store"),
                    tok("--label"),
                    ArgToken::Capture("label".to_string()),
                    tok("--"),
                    tok("vaultkeeper-id"),
                    ArgToken::Capture("id".to_string()),
                ],
                stdin: StdinMatch::CaptureRaw {
                    capture: "secret".to_string(),
                },
                fixed_captures: BTreeMap::new(),
                world: vec![],
                mutation: Some(Mutation::UpsertItem {
                    id_capture: "id".to_string(),
                    fields: store_fields,
                }),
                emit: Emit {
                    stdout: EmitBody::Empty,
                    stderr: EmitBody::Empty,
                    exit_code: 0,
                },
            },
            BehaviorRule {
                // State-conditional-response axis (issue #313 AC4): the
                // identical argv used by "lookup (found)" below produces a
                // different response depending purely on `world.locked` —
                // checked first (rule order), so a locked world always wins
                // over an existence check.
                name: "lookup (secret service locked)".to_string(),
                args: vec![
                    tok("lookup"),
                    tok("--"),
                    tok("vaultkeeper-id"),
                    ArgToken::Capture("id".to_string()),
                ],
                stdin: StdinMatch::Any,
                fixed_captures: BTreeMap::new(),
                world: vec![WorldPredicate::Locked(true)],
                mutation: None,
                emit: Emit {
                    stdout: EmitBody::Empty,
                    stderr: EmitBody::Fixed(
                        "secret-tool: Cannot lookup: Secret Service is locked".to_string(),
                    ),
                    exit_code: 1,
                },
            },
            BehaviorRule {
                name: "lookup (found)".to_string(),
                args: vec![
                    tok("lookup"),
                    tok("--"),
                    tok("vaultkeeper-id"),
                    ArgToken::Capture("id".to_string()),
                ],
                stdin: StdinMatch::Any,
                fixed_captures: BTreeMap::new(),
                world: vec![
                    WorldPredicate::Locked(false),
                    WorldPredicate::ItemExists {
                        id_capture: "id".to_string(),
                        exists: true,
                    },
                ],
                mutation: None,
                emit: Emit {
                    stdout: EmitBody::Template {
                        template: "{item.secret}\n".to_string(),
                        id_capture: Some("id".to_string()),
                    },
                    stderr: EmitBody::Empty,
                    exit_code: 0,
                },
            },
            BehaviorRule {
                name: "lookup (not found)".to_string(),
                args: vec![
                    tok("lookup"),
                    tok("--"),
                    tok("vaultkeeper-id"),
                    ArgToken::Capture("id".to_string()),
                ],
                stdin: StdinMatch::Any,
                fixed_captures: BTreeMap::new(),
                world: vec![WorldPredicate::ItemExists {
                    id_capture: "id".to_string(),
                    exists: false,
                }],
                mutation: None,
                emit: Emit {
                    stdout: EmitBody::Empty,
                    stderr: EmitBody::Empty,
                    exit_code: 1,
                },
            },
            BehaviorRule {
                name: "clear (found)".to_string(),
                args: vec![
                    tok("clear"),
                    tok("--"),
                    tok("vaultkeeper-id"),
                    ArgToken::Capture("id".to_string()),
                ],
                stdin: StdinMatch::Any,
                fixed_captures: BTreeMap::new(),
                world: vec![WorldPredicate::ItemExists {
                    id_capture: "id".to_string(),
                    exists: true,
                }],
                mutation: Some(Mutation::DeleteItem {
                    id_capture: "id".to_string(),
                }),
                emit: Emit {
                    stdout: EmitBody::Empty,
                    stderr: EmitBody::Empty,
                    exit_code: 0,
                },
            },
            BehaviorRule {
                name: "clear (not found)".to_string(),
                args: vec![
                    tok("clear"),
                    tok("--"),
                    tok("vaultkeeper-id"),
                    ArgToken::Capture("id".to_string()),
                ],
                stdin: StdinMatch::Any,
                fixed_captures: BTreeMap::new(),
                world: vec![WorldPredicate::ItemExists {
                    id_capture: "id".to_string(),
                    exists: false,
                }],
                mutation: None,
                emit: Emit {
                    stdout: EmitBody::Empty,
                    stderr: EmitBody::Empty,
                    exit_code: 1,
                },
            },
        ],
    }
}

/// `op` (1Password CLI) — a shape-assertion demonstration table (issue #313
/// AC5). Models the real `op item get <id> --format json` output shape,
/// where a field's value lives at `fields[].value` keyed by `id`/`label`,
/// NOT at a flattened top-level key. The canonical motivating defect (a
/// hand-built stdin template silently dropping the field value unless the
/// piped JSON matched that exact structure) is reproduced by construction:
/// this table's `item create` rule only captures the password when stdin
/// puts it at `fields.password.value` (the real shape); any other shape
/// falls through to the lower-priority "created but empty" rule, which
/// upserts the item with an empty `fields` map. On the following `item get`,
/// `render_body`'s `{item.<field>}` substitution only replaces placeholders
/// for fields actually present on the item (see `engine::render_body`), so
/// with no `password` field to substitute, the `{item.password}` placeholder
/// in the `item get` template is left in the emitted JSON verbatim, unresolved
/// — not an empty string — exactly mirroring the spike's "exit 0, item
/// created, password field silently missing from the round trip" symptom.
pub fn op() -> BehaviorTable {
    let mut correct_fields = BTreeMap::new();
    correct_fields.insert(
        "password".to_string(),
        FieldSource::Captured("password".to_string()),
    );

    BehaviorTable {
        tool: "op".to_string(),
        rules: vec![
            BehaviorRule {
                name: "item create (shape-faithful stdin — password captured)".to_string(),
                args: vec![tok("item"), tok("create"), tok("--format"), tok("json")],
                stdin: StdinMatch::JsonPointerCapture {
                    pointer: "fields.password.value".to_string(),
                    capture: "password".to_string(),
                },
                fixed_captures: BTreeMap::from([("__op_item_id".to_string(), "op-item".to_string())]),
                world: vec![],
                mutation: Some(Mutation::UpsertItem {
                    id_capture: "__op_item_id".to_string(),
                    fields: correct_fields,
                }),
                emit: Emit {
                    stdout: EmitBody::Fixed(r#"{"id":"op-item","fields":[{"id":"password"}]}"#.to_string()),
                    stderr: EmitBody::Empty,
                    exit_code: 0,
                },
            },
            BehaviorRule {
                name: "item create (shape-mismatched stdin — silent field drop, reproduces the op-spike defect)".to_string(),
                args: vec![tok("item"), tok("create"), tok("--format"), tok("json")],
                stdin: StdinMatch::Any,
                fixed_captures: BTreeMap::from([("__op_item_id".to_string(), "op-item".to_string())]),
                world: vec![],
                mutation: Some(Mutation::UpsertItem {
                    id_capture: "__op_item_id".to_string(),
                    fields: BTreeMap::new(),
                }),
                emit: Emit {
                    stdout: EmitBody::Fixed(r#"{"id":"op-item","fields":[{"id":"password"}]}"#.to_string()),
                    stderr: EmitBody::Empty,
                    exit_code: 0,
                },
            },
            BehaviorRule {
                name: "item get --format json (echoes stored shape)".to_string(),
                args: vec![
                    tok("item"),
                    tok("get"),
                    ArgToken::Capture("id".to_string()),
                    tok("--format"),
                    tok("json"),
                ],
                stdin: StdinMatch::Any,
                fixed_captures: BTreeMap::new(),
                world: vec![WorldPredicate::ItemExists {
                    id_capture: "id".to_string(),
                    exists: true,
                }],
                mutation: None,
                emit: Emit {
                    stdout: EmitBody::Template {
                        template: r#"{"id":"{id}","fields":[{"id":"password","value":"{item.password}"}]}"#
                            .to_string(),
                        id_capture: Some("id".to_string()),
                    },
                    stderr: EmitBody::Empty,
                    exit_code: 0,
                },
            },
        ],
    }
}

/// `security` (macOS Keychain) — a minimal probe/version table. The real
/// `KeychainBackend` drives `security -i` with a multi-command stdin script
/// (see `crates/vaultkeeper-core/src/backend/keychain.rs`); modeling that
/// interactive-script mode is out of scope for this table (`secret-tool` and
/// `ykman`/`op` above already exercise every StubTool axis end to end).
/// Kept here so `vk-stub-security` exists and is table-driven like every
/// other tool, satisfying the "no per-tool Rust branches" contract even for
/// tools this PR doesn't yet drive through a full round trip.
pub fn security() -> BehaviorTable {
    BehaviorTable {
        tool: "security".to_string(),
        rules: vec![BehaviorRule {
            name: "list-keychains".to_string(),
            args: vec![tok("list-keychains")],
            stdin: StdinMatch::Any,
            fixed_captures: BTreeMap::new(),
            world: vec![],
            mutation: None,
            emit: Emit {
                stdout: EmitBody::Fixed(
                    "\"/Users/test/Library/Keychains/login.keychain-db\"".to_string(),
                ),
                stderr: EmitBody::Empty,
                exit_code: 0,
            },
        }],
    }
}

/// `powershell` (Windows DPAPI backend probe) — same minimal-probe scope
/// rationale as [`security`].
pub fn powershell() -> BehaviorTable {
    BehaviorTable {
        tool: "powershell".to_string(),
        rules: vec![BehaviorRule {
            name: "-Command $PSVersionTable.PSVersion".to_string(),
            args: vec![tok("-Command"), ArgToken::Capture("script".to_string())],
            stdin: StdinMatch::Any,
            fixed_captures: BTreeMap::new(),
            world: vec![],
            mutation: None,
            emit: Emit {
                stdout: EmitBody::Fixed("5.1.22621.1".to_string()),
                stderr: EmitBody::Empty,
                exit_code: 0,
            },
        }],
    }
}

/// Look up the built-in table for a tool name (e.g. `"ykman"`), matching
/// the `vk-stub-<name>` binary naming convention (issue #313 guardrail 2).
pub fn by_tool_name(name: &str) -> Option<BehaviorTable> {
    match name {
        "ykman" => Some(ykman(YKMAN_DEFAULT_HMAC_RESPONSE)),
        "secret-tool" => Some(secret_tool()),
        "op" => Some(op()),
        "security" => Some(security()),
        "powershell" => Some(powershell()),
        _ => None,
    }
}
