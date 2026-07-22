# Manual verification: YubiKey backend live round trip

This check confirms the **real-hardware** behavior of the `vaultkeeper-core`
`YubikeyBackend` port (issue #293) that cannot run in CI: `ykman` challenge-response
against a physical YubiKey is not available on any CI runner, so the automated
suite exercises it with a stub `ykman` on `PATH`/a mocked `HostPlatform::exec`
(`crates/vaultkeeper-core/src/backend/yubikey.rs` unit tests — argv-sentinel,
versioned-GCM round trip, legacy-CBC detection, TS-fixture compat, and negative
decrypt/corruption cases all run against that stub, never real hardware). What
follows verifies the parts only real hardware can prove: that a genuine
challenge-response round-trips through a physical device, and that the two
implementations' on-disk formats are truly interoperable outside a fixture.

Preconditions: `ykman` installed; a YubiKey plugged in with the challenge-response
slot (2) configured (`ykman otp chalresp 2`, no touch policy required for this
check — see `docs/manual-tests/presence-per-use.md` for the touch-policy-specific
verification).

## Round trip against real hardware

1. Using the Rust core (via a small harness binary or the native CLI once wired
   to select `yubikey`), `store` a known secret under a fixed id.
2. Confirm `<config_dir>/yubikey/metadata.json` and a `<hex-id>.enc` entry exist,
   and that the entry starts with the `1:` version prefix (base64 `iv:authTag:ciphertext`
   after it).
3. `retrieve` the same id — confirm it returns the exact original secret.
4. `delete` the id — confirm the entry file and its `metadata.json` entry are both
   gone, and a subsequent `retrieve` fails with `SecretNotFound`.
5. Unplug the YubiKey (or use a different one) and attempt `retrieve` — confirm a
   `DeviceNotPresent` error, not a hang or a decrypt failure.

## Cross-implementation interop against real hardware

6. `store` a secret with the TypeScript `YubikeyBackend`
   (`packages/vaultkeeper/src/backend/yubikey-backend.ts`) against the real device,
   then `retrieve` the same id with the Rust core port (same device, same slot) —
   confirm the exact same plaintext comes back. Repeat in the opposite direction
   (Rust writes, TS reads). This is the live-hardware counterpart to the
   fixture-based compat test in
   `crates/vaultkeeper-core/src/backend/yubikey.rs`
   (`reads_a_metadata_and_entry_pair_written_by_the_ts_backend`), which proves the
   same thing against a captured fixture rather than a live challenge-response.

Record: `ykman` version, YubiKey firmware version, and the observed outcome for
each numbered step.
