/**
 * Cross-implementation compatibility test for issue #238, AC2: a key store
 * written by the Rust core (`crates/vaultkeeper-core/src/keys/storage.rs`)
 * must be readable by the TS `loadKeyState`.
 *
 * The fixture under `test/fixtures/rust-written-keystate/` was produced by a
 * one-off Rust test calling `save_key_state` with the fixed `KeyMaterial`
 * asserted below (id `k-rust-fixture-1700000000-wxyz`, key bytes `0x40..=0x5f`,
 * `created_at` 1700000000 epoch seconds). To regenerate after a deliberate
 * format change, re-run that generator against the same fixed `KeyMaterial`
 * and overwrite the two files in that directory.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/238
 */
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, it, expect } from 'vitest'
import { loadKeyState } from '../../../src/keys/storage.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const FIXTURE_DIR = path.join(__dirname, '../../fixtures/rust-written-keystate')

describe('loadKeyState hydrates a Rust-written fixture (AC2)', () => {
  it('decodes the id, key bytes, and createdAt written by the Rust core', async () => {
    const loaded = await loadKeyState(FIXTURE_DIR)

    // Assert the fixture actually loaded before dereferencing `current` — a
    // regressed loader returning `undefined` should fail here with a clear,
    // actionable message rather than throwing an opaque TypeError out of the
    // `.toISOString()` call below.
    expect(loaded).toBeDefined()
    if (loaded === undefined) throw new Error('unreachable: asserted above')

    expect(loaded.current.id).toBe('k-rust-fixture-1700000000-wxyz')
    expect(Buffer.from(loaded.current.key).toString('hex')).toBe(
      Buffer.from(Array.from({ length: 32 }, (_, i) => 0x40 + i)).toString('hex'),
    )
    expect(loaded.current.createdAt.toISOString()).toBe('2023-11-14T22:13:20.000Z')
    expect(loaded.previous).toBeUndefined()
  })
})
