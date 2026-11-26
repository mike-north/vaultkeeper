# Manual residue register

This is the complete, auditable human residue that remains once every backend has a paired
double — a TS/Rust `InMemoryBackend` (or, where a backend has no in-memory equivalent, the
narrowest available double) — running the shared conformance corpus in CI (issue #312).

## Framing: tool-upgrade-triggered, not calendar-triggered

**The residue below fires when a backend's underlying tool/OS/SDK version bumps — it is not a
scheduled, calendar-driven manual QA pass.** A `security`/`ykman`/`op`/`secret-tool`/`powershell`
(or OS) version bump is the trigger; the conformance corpus's own diff against the new tool
output is what tells a maintainer whether a re-run is even warranted. This is what makes the
residue self-timing rather than something that silently rots the way a fixed six-month manual
test suite does: there is no ambiguous "is it time yet?" — the answer is always "did the backend's
tool/OS dependency version change since the last run?"

Everything the shared corpus asserts _around_ the physical/licensed ceremony is already
CI-automated against each backend's double: argv construction, stdin/stdout parsing, error
classification, locked/unlocked and expired-session branches, response-shape round-trips,
presence _refusal_ logic (`NotCapableError` when a backend cannot honor
`--require-presence-per-use`), lease minting, registry dispatch, and fail-closed paths on every
error branch. None of that is part of the manual residue below — it runs on every PR, in every
language, against the double. Real-hardware/device _behavior_ wiring (does a capable backend
truly force a fresh physical action) is separately covered by
[`presence-per-use.md`](./presence-per-use.md); this register is about the run-the-corpus-against-the-real-adapter
step specifically.

## The register

| Backend     | Manual residue = run shared corpus vs. real adapter | Physical ceremony       | Cadence · cost                     |
| ----------- | --------------------------------------------------- | ----------------------- | ---------------------------------- |
| keychain    | corpus vs. real `security` on macOS                 | Touch-ID-gated read tap | per `security`/OS bump · ~2 min    |
| 1Password   | corpus vs. real DesktopAuth account                 | one Touch ID grant      | per `op`-app / dylib bump · ~3 min |
| yubikey     | corpus vs. real `ykman`                             | one hardware touch      | per `ykman` bump · ~2 min          |
| secret-tool | corpus vs. real `gnome-keyring` (Linux desktop)     | keyring unlock          | per `secret-tool` bump · ~2 min    |
| dpapi       | corpus vs. real DPAPI on Windows                    | none (machine key)      | per `powershell`/OS bump · ~2 min  |

Once every backend's paired double is running the shared contract corpus in CI, each backend's
manual residue collapses to exactly one line: **run the double's exact CI corpus, re-pointed at
the real tool/account/hardware** — plus, only where a biometric/hardware ceremony gates it, the
physical tap/grant/unlock named above.

## Why each ceremony cannot be automated

The ceremony column is genuinely physical or a licensed real service — none has a headless
equivalent, and none of the underlying constructs can be simulated without either defeating the
security property they exist to provide or requiring hardware/licensing CI does not have:

- **keychain (Touch-ID-gated read tap):** the tap unlocks a Secure Enclave biometric match. There
  is no software path around it — that is the entire point of Secure Enclave-backed key access.
- **1Password (Touch ID grant):** `per-access` mode requests a fresh, per-process Mach-port grant
  from the desktop app for each operation; the grant is tied to a live biometric prompt in a GUI
  process CI cannot drive headlessly.
- **yubikey (hardware touch):** the touch policy requires a human's physical finger on the device
  — there is no simulated touch that preserves the guarantee the touch policy exists to provide.
- **secret-tool (keyring unlock):** requires a logged-in D-Bus Secret Service session (a real
  `gnome-keyring` daemon under an unlocked login session) — CI's `dbus-run-session` wrapper gets
  the daemon and bus running, but a _locked_ keyring's unlock prompt is still a human action.
- **dpapi (machine key, no ceremony):** DPAPI's master key is bound to the Windows machine/user
  account itself, not a biometric or hardware step — hence "none" in the ceremony column — but the
  binding is still real-OS-only and cannot be faked by a double.

## When to consult this register

Wire this into the release process: **before cutting a release that bumps a backend's underlying
tool/OS/SDK dependency** (`security`, `op`/1Password desktop app, `ykman`, `secret-tool`/
`gnome-keyring`, `powershell`/Windows), run the shared conformance corpus against that backend's
real adapter per the row above, and record the result in the release notes. See
[`.github/workflows/release.yml`](../../.github/workflows/release.yml)'s header comment, which
points back here.

## See also

- [`presence-per-use.md`](./presence-per-use.md) — real-hardware/device _behavior_ verification
  (does a capable backend truly force a fresh physical action) — a different, complementary manual
  check from the corpus-vs-real-adapter residue this register tracks.
- [`yubikey-backend-live.md`](./yubikey-backend-live.md) — the YubiKey-specific real-device manual
  test this register's yubikey row refers to.
- `packages/cli-tests/test/conformance/` — the shared CLI-level conformance corpus.
- `crates/vaultkeeper-conformance/src/backend_cases.rs` — the shared backend-level conformance
  corpus (issue #312), run against every in-memory double in both languages.
