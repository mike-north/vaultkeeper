# Manual verification: presence-per-use

> For the separate, cadence/cost-tracked "run the shared conformance corpus against the real
> adapter" residue (as opposed to this doc's real-hardware _behavior_ verification), see
> [`manual-residue-register.md`](./manual-residue-register.md).

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
5. **`delete` is not touch-enforced (issue #326).** Even with the slot's touch
   policy `required`, `delete()` never performs challenge-response — it only
   probes that a YubiKey is connected, then unlinks the entry file. Store a
   secret, then run `vaultkeeper delete --name S --require-presence-per-use`.
   Expect it to fail immediately with `NotCapableError` (exit 1) — no tap
   prompt, no device access — because `presenceEnforcedOperations` for this
   instance covers `read`/`store` only, never `delete`. Confirm the secret
   still exists afterward (`vaultkeeper delete --name S` without the flag
   removes it normally).

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

5. Confirm writes now force a fresh action too (issue #211 closed the earlier
   fail-closed gap): `vaultkeeper store --name S --require-presence-per-use`
   → expect a fresh Touch ID / system biometric prompt (a distinct worker
   process from the read prompt), and the store succeeds only after approval.
   Repeat for `vaultkeeper delete --name S --require-presence-per-use` → expect
   its own fresh prompt.
6. Cancel the biometric prompt during a flagged `store`/`delete` → expect the
   command to fail (exit 1) as a declined presence action (`PresenceDeclinedError`),
   not a generic authorization failure — and confirm nothing was written/deleted.
7. Withhold the prompt past the wait window during a flagged `store`/`delete` →
   expect `PresenceTimeoutError` (exit 1), distinct from `PresenceDeclinedError`.
8. Confirm the secret value never appears in a process listing during a flagged
   `store`: while the command is running, run `ps aux | grep vaultkeeper` (or
   equivalent) in another terminal and confirm the value is absent — it travels
   to the worker over stdin, never as a spawn argument.

> **Cached-OS-unlock caveat.** 1Password `per-access` creates a fresh SDK client
> per operation, but the OS may satisfy the biometric from a cached Touch ID /
> Windows Hello unlock without re-prompting. If step 3 does **not** re-prompt,
> that is the OS caching the unlock, not a vaultkeeper defect — the guarantee for
> 1Password is "fresh SDK client plus whatever the OS enforces at that moment."
> For a hard per-tap guarantee, use a touch device. `store` and `delete` now
> route through the same per-access worker as reads (issue #211), each forcing
> its own fresh action — verified by steps 5–8 and by the automated
> `store — per-access mode` / `delete — per-access mode` unit test suites.

## gpg smartcard (touch-to-sign) — if/when a backend ships

Not currently a built-in backend. When a gpg-smartcard signing backend is added,
verify: `sign --require-presence-per-use` forces a card tap per signature, and two
consecutive signs require two distinct taps.
