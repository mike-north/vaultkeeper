/**
 * Generates the `metadata.json` + `<hex-id>.enc` pair consumed by the Rust
 * core's TS-fixture-compat test for `YubikeyBackend`
 * (`crates/vaultkeeper-core/src/backend/yubikey.rs`, issue #293 AC3).
 *
 * This runs the REAL production TypeScript module
 * (`packages/vaultkeeper/src/backend/yubikey-backend.ts`) end-to-end via its
 * public `store()` method, so the committed fixture is not a hand-rolled
 * re-implementation of the on-disk format — it is genuine `YubikeyBackend`
 * output. No real YubiKey is involved: a tiny stub `ykman` shell script is
 * placed on `PATH` for the duration of the run — this offline fixture
 * generator is the only place in the repo that uses a stub `ykman` binary;
 * the Rust tests in `crates/vaultkeeper-core/src/backend/yubikey.rs` instead
 * exercise a mocked `HostPlatform`, never a real or stubbed subprocess. The
 * stub always answers the slot-2 challenge-response with
 * `FAKE_HMAC_RESPONSE` below, regardless of the challenge — mirroring
 * `packages/vaultkeeper/test/unit/backend/yubikey-backend.test.ts`'s
 * `mockChallengeResponse` helper, so the fixture's key derivation is
 * reproducible from the constants documented here.
 *
 * Usage (regenerates `metadata.json` and the `.enc` entry; safe to re-run —
 * the IV is fresh each time but the plaintext/id/HMAC response are fixed):
 *
 *   pnpm exec tsx crates/vaultkeeper-core/tests/fixtures/ts-written-yubikey/generate-fixture.mts
 *
 * Fixture parameters (also asserted by the Rust compat test):
 *   - id:              "yubikey-ts-fixture-id"
 *   - plaintext:        "ts-core-compat-secret-🔐"
 *   - HMAC response:    "deadbeefcafe01234567deadbeefcafe01234567" (40 hex chars)
 */
import { chmodSync, cpSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { YubikeyBackend } from '../../../../../packages/vaultkeeper/src/backend/yubikey-backend.js'

const here = dirname(fileURLToPath(import.meta.url))

const FAKE_HMAC_RESPONSE = 'deadbeefcafe01234567deadbeefcafe01234567'
const FIXTURE_ID = 'yubikey-ts-fixture-id'
const FIXTURE_PLAINTEXT = 'ts-core-compat-secret-\u{1F510}'

const FAKE_YKMAN_SCRIPT = `#!/bin/sh
# Stub ykman used only to generate a byte-for-byte real TS-backend fixture.
# See crates/vaultkeeper-core/tests/fixtures/ts-written-yubikey/generate-fixture.mts
case "$1" in
  --version)
    echo "YubiKey Manager (ykman) version: 5.4.0"
    exit 0
    ;;
  list)
    echo "YubiKey 5 NFC (5.4.3) [OTP+FIDO+CCID] Serial: 12345"
    exit 0
    ;;
  otp)
    # otp calculate 2 <challenge-hex> — always answer with the fixed response,
    # regardless of the challenge, matching the TS test suite's mock.
    echo "${FAKE_HMAC_RESPONSE}"
    exit 0
    ;;
  *)
    echo "fake-ykman: unrecognized invocation: $*" >&2
    exit 1
    ;;
esac
`

async function main(): Promise<void> {
  const binDir = mkdtempSync(join(tmpdir(), 'vaultkeeper-fake-ykman-'))
  const storageDir = mkdtempSync(join(tmpdir(), 'vaultkeeper-yubikey-fixture-'))
  const ykmanPath = join(binDir, 'ykman')
  writeFileSync(ykmanPath, FAKE_YKMAN_SCRIPT, { mode: 0o755 })
  chmodSync(ykmanPath, 0o755)

  const originalPath = process.env['PATH'] ?? ''
  process.env['PATH'] = `${binDir}:${originalPath}`

  try {
    const backend = new YubikeyBackend(storageDir)
    await backend.store(FIXTURE_ID, FIXTURE_PLAINTEXT)

    const destDir = here
    for (const entry of readdirSync(storageDir)) {
      cpSync(join(storageDir, entry), join(destDir, entry))
    }

    console.log(`Wrote fixture files to ${destDir}:`)
    console.log(readdirSync(destDir).filter((f) => f !== 'generate-fixture.mts'))
  } finally {
    process.env['PATH'] = originalPath
    rmSync(binDir, { recursive: true, force: true })
    rmSync(storageDir, { recursive: true, force: true })
  }
}

await main()
