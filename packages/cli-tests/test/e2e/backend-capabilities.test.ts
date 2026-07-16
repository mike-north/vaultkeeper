/**
 * UATs for `vaultkeeper backend capabilities` (issue #122).
 *
 * Exercises the real CLI binary as a subprocess: the JSON introspection shape
 * (a flat array of `{ type, displayName, presencePerUse }`), the human-readable
 * form, and per-configured-instance truth (a YubiKey slot configured with a
 * touch policy reports presence-per-use).
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/122
 */
import { describe, it, expect, afterEach } from 'vitest'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliTestEnv } from '@vaultkeeper/cli-test-helpers'

interface CapabilityRow {
  type: string
  displayName: string
  presencePerUse: boolean
}

function isCapabilityRow(value: unknown): value is CapabilityRow {
  if (value === null || typeof value !== 'object') {
    return false
  }
  return (
    'type' in value &&
    typeof value.type === 'string' &&
    'displayName' in value &&
    typeof value.displayName === 'string' &&
    'presencePerUse' in value &&
    typeof value.presencePerUse === 'boolean'
  )
}

function parseRows(stdout: string): CapabilityRow[] {
  const parsed: unknown = JSON.parse(stdout)
  if (!Array.isArray(parsed)) {
    throw new Error('expected a JSON array')
  }
  const rows: CapabilityRow[] = []
  for (const entry of parsed) {
    if (!isCapabilityRow(entry)) {
      throw new Error(`unexpected row shape: ${JSON.stringify(entry)}`)
    }
    rows.push(entry)
  }
  return rows
}

describe('backend capabilities', () => {
  let env: CliTestEnv | undefined

  afterEach(async () => {
    if (env !== undefined) {
      await env.cleanup()
      env = undefined
    }
  })

  it('--json emits a flat array of { type, displayName, presencePerUse }', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['backend', 'capabilities', '--json'])
    expect(result.exitCode).toBe(0)

    const rows = parseRows(result.stdout)
    expect(rows.length).toBeGreaterThan(0)
    for (const row of rows) {
      // Documented shape: exactly these three fields, correctly typed.
      expect(Object.keys(row).sort()).toEqual(['displayName', 'presencePerUse', 'type'])
      expect(typeof row.type).toBe('string')
      expect(typeof row.displayName).toBe('string')
      expect(typeof row.presencePerUse).toBe('boolean')
    }
    // The built-in non-presence backends must be present and report false.
    const file = rows.find((r) => r.type === 'file')
    expect(file?.presencePerUse).toBe(false)
  })

  it('human-readable output (no --json) lists backends and the presence column', async () => {
    env = await createCliTestEnv()
    const result = await env.run(['backend', 'capabilities'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('Backend capabilities')
    expect(result.stdout).toContain('presence-per-use')
    expect(result.stdout).toContain('file')
  })

  it('reflects the configured instance: a YubiKey slot with touchPolicy required reports true', async () => {
    env = await createCliTestEnv({
      config: {
        version: 1,
        backends: [{ type: 'yubikey', enabled: true, options: { touchPolicy: 'required' } }],
        keyRotation: { gracePeriodDays: 7 },
        defaults: { ttlMinutes: 60, trustTier: 3 },
      },
    })
    const result = await env.run(['backend', 'capabilities', '--json'])
    expect(result.exitCode).toBe(0)
    const rows = parseRows(result.stdout)
    const yubikey = rows.find((r) => r.type === 'yubikey')
    expect(yubikey?.presencePerUse).toBe(true)
  })

  it('backend --help documents --json under the capabilities subcommand, not as a top-level option', async () => {
    // Regression: --json is only accepted by `backend capabilities`, so the help
    // must not present it as a bare top-level `backend` option.
    env = await createCliTestEnv()
    const result = await env.run(['backend', '--help'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('capabilities [--json]')
    // No standalone top-level `  --json ` option line.
    expect(/\n {2}--json /.test(result.stdout)).toBe(false)
  })

  it('a YubiKey slot without a touch policy reports false', async () => {
    env = await createCliTestEnv({
      config: {
        version: 1,
        backends: [{ type: 'yubikey', enabled: true, options: {} }],
        keyRotation: { gracePeriodDays: 7 },
        defaults: { ttlMinutes: 60, trustTier: 3 },
      },
    })
    const result = await env.run(['backend', 'capabilities', '--json'])
    const rows = parseRows(result.stdout)
    const yubikey = rows.find((r) => r.type === 'yubikey')
    expect(yubikey?.presencePerUse).toBe(false)
  })
})
