# Manual verification: presence-per-use

These checks confirm the **real-hardware** behavior of `--require-presence-per-use`
(issue #122) that cannot run in CI, because they need a physical device and a
human to perform (or withhold) a touch/biometric action.

The automated suite already proves the _enforcement logic_ is non-bypassable
(`packages/vaultkeeper/test/integration/presence-enforcement.test.ts`, using a
mock backend that demands a distinct fresh action per keyed operation) and that
each backend reports the correct capability for its configured instance
(`packages/vaultkeeper/test/unit/backend/capabilities.test.ts`). What follows
verifies the _device wiring_: that a capable backend's operation truly forces a
fresh physical action, and that declining or waiting produces the typed errors.

For each backend, record: the CLI/library command run, whether a fresh prompt
appeared, and the observed outcome (success / `PresenceDeclinedError` /
`PresenceTimeoutError` / `NotCapableError`).

## YubiKey (touch-per-operation slot)

Preconditions: `ykman` installed; a YubiKey whose challenge-response slot (2) is
configured to **require touch** (`ykman otp info` shows the touch policy); config
sets `{ "type": "yubikey", "enabled": true, "options": { "touchPolicy": "required" } }`.

1. `vaultkeeper backend capabilities --json` → the `yubikey` row shows
   `presencePerUse: true`.
2. Store a secret, then run two consecutive presence-gated reads:
   - `vaultkeeper exec --secret S --env S --caller <path> --require-presence-per-use -- true`
   - Expect the device LED to blink and a **new** tap to be required. Confirm the
     command completes only after you tap.
   - Run it a **second** time. A second, distinct tap must be required — the first
     tap must not satisfy the second run.
3. Withhold the tap past the device timeout → expect a `PresenceTimeoutError`
   (exit 1), distinct from `DeviceNotPresentError`.
4. Reconfigure the slot **without** a touch policy (`touchPolicy` absent) → the
   `yubikey` row now shows `presencePerUse: false`, and `--require-presence-per-use`
   fails with `NotCapableError` before any device access.

## 1Password (per-access mode)

Preconditions: 1Password desktop app installed and unlocked with biometric unlock
enabled; config sets `{ "type": "1password", "enabled": true, "options": { "accessMode": "per-access", "vault": "<id>" } }`.

1. `vaultkeeper backend capabilities --json` → the `1password` row shows
   `presencePerUse: true` (in `session` mode it shows `false`).
2. `vaultkeeper exec --secret S --env S --caller <path> --require-presence-per-use -- true`
   → expect a fresh Touch ID / system biometric prompt for the read.
3. Run it again → expect a **second** prompt (subject to the caveat below).
4. Cancel the biometric prompt → expect the read to fail (surfaced as an
   authorization/decline failure from the 1Password worker).

> **Cached-OS-unlock caveat.** 1Password `per-access` creates a fresh SDK client
> per read, but the OS may satisfy the biometric from a cached Touch ID / Windows
> Hello unlock without re-prompting. If step 3 does **not** re-prompt, that is the
> OS caching the unlock, not a vaultkeeper defect — the guarantee for 1Password is
> "fresh SDK client plus whatever the OS enforces at that moment." For a hard
> per-tap guarantee, use a touch device. Note also that `store`/`delete` route
> through the cached session client, so only reads (`exec`/`setup`) are presence-
> gated on 1Password.

## gpg smartcard (touch-to-sign) — if/when a backend ships

Not currently a built-in backend. When a gpg-smartcard signing backend is added,
verify: `sign --require-presence-per-use` forces a card tap per signature, and two
consecutive signs require two distinct taps.
