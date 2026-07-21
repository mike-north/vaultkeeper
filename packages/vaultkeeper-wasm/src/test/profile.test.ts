/**
 * WASM-bridge half of issue #277 AC7: proves the core-resident environment
 * profile loader (`vaultkeeper_core::profile::load_profile_from_str`) is
 * reachable from the TS path through the real compiled WASM binary. The
 * Rust half of this proof is
 * `crates/vaultkeeper-core/tests/profile_loader_integration.rs`.
 *
 * Drives the diagnostic-only `__testLoadProfile` export directly, mirroring
 * `bridge-contracts.test.ts`'s pattern for other diagnostic exports — not
 * part of the SDK's public TypeScript API (`../index.ts` does not re-export
 * it).
 *
 * Uses node:test (not vitest) since this package compiles with plain tsc.
 */

/* eslint-disable @typescript-eslint/no-floating-promises -- node:test it() returns Promise but is not meant to be awaited inside describe() */
/* eslint-disable n/no-unsupported-features/node-builtins -- test.describe is stable in our CI Node version */

import { describe, it } from 'node:test'
import * as assert from 'node:assert/strict'
import { mapWasmError, VaultError } from '../errors.js'

interface DiagnosticBindings {
  __testLoadProfile: (
    json: string,
    configDefaults: { ttlMinutes: number; trustTier: number },
  ) => unknown
}

async function loadDiagnosticBindings(): Promise<DiagnosticBindings> {
  return import('../../wasm/vaultkeeper_wasm.js')
}

/** Loose shape of a value thrown across the WASM boundary (see `../errors.ts`). */
interface BridgeErrorShape {
  vaultErrorCode: string
  message: string
}

function isBridgeErrorShape(value: unknown): value is BridgeErrorShape {
  if (typeof value !== 'object' || value === null) return false
  const record: Record<string, unknown> = { ...value }
  return typeof record.vaultErrorCode === 'string' && typeof record.message === 'string'
}

interface LoadedProfileShape {
  version: number
  name: string
  // `entries` is a JSON object keyed by env-var name, matching the input
  // schema — not an array of pairs (review follow-up: wire-format symmetry
  // between `LoadedProfile.entries` and `ProfileFile.entries`).
  entries: Record<string, LoadedEntryShape>
}

interface LoadedEntryShape {
  source: { secret?: string; signingKey?: string }
  materialize: string
  minTrust: string
  ttlSeconds?: number
  useLimit?: number
  requirePresencePerUse: boolean
  requirePresenceAtMint: boolean
}

function assertLoadedProfileShape(value: unknown): asserts value is LoadedProfileShape {
  assert.ok(typeof value === 'object' && value !== null, 'expected an object')
  const record: Record<string, unknown> = { ...value }
  assert.ok(typeof record.version === 'number')
  assert.ok(typeof record.name === 'string')
  assert.ok(
    typeof record.entries === 'object' && record.entries !== null && !Array.isArray(record.entries),
    'entries must be a JSON object, not an array',
  )
}

const SCHEMA_EXAMPLE = JSON.stringify({
  version: 1,
  name: 'github-mcp',
  entries: {
    GITHUB_TOKEN: {
      secret: 'github-pat',
      materialize: 'secret',
      minTrust: 'registry',
      requirePresencePerUse: false,
    },
    VK_DB_CREDENTIAL: {
      secret: 'prod-db-password',
      materialize: 'lease',
      minTrust: 'sigstore',
      ttlSeconds: 900,
      useLimit: 5,
    },
  },
})

describe('__testLoadProfile — the core profile loader through the WASM bridge (issue #277 AC7)', () => {
  it('loads a valid profile and resolves entry policy', async () => {
    const bindings = await loadDiagnosticBindings()
    const result = bindings.__testLoadProfile(SCHEMA_EXAMPLE, { ttlMinutes: 60, trustTier: 3 })
    assertLoadedProfileShape(result)
    assert.equal(result.name, 'github-mcp')
    assert.deepEqual(Object.keys(result.entries), ['GITHUB_TOKEN', 'VK_DB_CREDENTIAL'])

    const githubEntry = result.entries.GITHUB_TOKEN
    assert.ok(githubEntry !== undefined, 'expected a GITHUB_TOKEN entry')
    assert.equal(githubEntry.source.secret, 'github-pat')
    assert.equal(githubEntry.materialize, 'secret')
    assert.equal(githubEntry.minTrust, 'registry')
    assert.equal(githubEntry.requirePresencePerUse, false)
  })

  it('converts the config.json ttlMinutes default into ttlSeconds (AC4, via the WASM bridge)', async () => {
    const bindings = await loadDiagnosticBindings()
    const json = JSON.stringify({
      version: 1,
      name: 'p',
      entries: {
        K: { secret: 's', materialize: 'lease' },
      },
    })
    const result = bindings.__testLoadProfile(json, { ttlMinutes: 5, trustTier: 3 })
    assertLoadedProfileShape(result)
    const entry = result.entries.K
    assert.ok(entry !== undefined, 'expected a K entry')
    assert.equal(entry.ttlSeconds, 300)
  })

  it('rejects a signingKey entry with materialize: "secret" (load-time invariant)', async () => {
    const bindings = await loadDiagnosticBindings()
    const json = JSON.stringify({
      version: 1,
      name: 'p',
      entries: {
        K: { signingKey: 'sk', materialize: 'secret' },
      },
    })
    assert.throws(
      () => bindings.__testLoadProfile(json, { ttlMinutes: 60, trustTier: 3 }),
      (thrown: unknown) => {
        assert.ok(isBridgeErrorShape(thrown))
        const err = mapWasmError(thrown)
        assert.ok(err instanceof VaultError, `expected VaultError, got ${err.constructor.name}`)
        return true
      },
    )
  })

  it('rejects a materialize object value with a typed materialize-mode-unsupported error', async () => {
    const bindings = await loadDiagnosticBindings()
    const json = JSON.stringify({
      version: 1,
      name: 'p',
      entries: {
        K: { secret: 's', materialize: { mode: 'reference', backend: '1password' } },
      },
    })
    assert.throws(
      () => bindings.__testLoadProfile(json, { ttlMinutes: 60, trustTier: 3 }),
      (thrown: unknown) => {
        assert.ok(isBridgeErrorShape(thrown))
        assert.equal(thrown.vaultErrorCode, 'materialize-mode-unsupported')
        return true
      },
    )
  })
})
