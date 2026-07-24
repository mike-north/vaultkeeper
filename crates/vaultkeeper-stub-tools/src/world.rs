//! The mutable "world" a [`crate::StubTool`] behavior table matches against
//! and mutates.
//!
//! Deliberately **shape-faithful**: an [`Item`] is a real object with a
//! field map, not a flattened `id -> secret` string. This is the structural
//! fix for the defect class described in issue #313 — a hand-built stub that
//! only tracks `id -> secret` can never catch a backend that writes the
//! wrong *shape* (e.g. drops a field, nests it under the wrong key) because
//! there is no shape to check against. `World` gives every stub tool a real
//! item store so shape-assertion cases (see
//! [`crate::table::Mutation::UpsertItemFromField`]) have something to
//! assert on.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A single item in the stub tool's world — modeled as a real object with
/// named fields (e.g. `password`, `username`, `notesPlain`), matching how
/// real tools (1Password items, Keychain entries, YubiKey slots) represent
/// entries, rather than a bare `id -> secret` string pair.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub id: String,
    /// Ordered by key for deterministic serialization/diffing.
    pub fields: BTreeMap<String, String>,
}

impl Item {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            fields: BTreeMap::new(),
        }
    }

    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }
}

/// The full mutable state a stub tool process reads and writes across
/// invocations. Persisted to a JSON file between subprocess invocations (a
/// stub binary is a fresh process per `exec` call, so in-memory state alone
/// would not survive a store-then-get round trip).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct World {
    pub items: BTreeMap<String, Item>,
    /// Whether the simulated backend is presently locked (e.g. Keychain
    /// requiring interactive unlock, a 1Password vault requiring
    /// re-authentication). Drives the state-conditional-response axis.
    pub locked: bool,
    /// Additional named booleans a tool's table needs beyond `locked` (e.g.
    /// `ykman`'s "is a device physically present" — a distinct concept from
    /// "locked," but still a world-state precondition a rule may require).
    /// Named rather than hardcoded so no tool needs its own `World` variant.
    pub flags: BTreeMap<String, bool>,
}

impl World {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn locked() -> Self {
        Self {
            locked: true,
            ..Self::default()
        }
    }

    pub fn item(&self, id: &str) -> Option<&Item> {
        self.items.get(id)
    }

    /// Reads a named flag (see [`World::flags`]), defaulting to `false` if
    /// never set.
    pub fn flag(&self, name: &str) -> bool {
        self.flags.get(name).copied().unwrap_or(false)
    }
}
