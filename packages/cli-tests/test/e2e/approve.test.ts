/**
 * UATs for the approve command — the real CLI subprocess contract.
 *
 * approve records a script's SHA-256 in the TOFU trust manifest
 * (trust-manifest.json) under the isolated config dir.
 *
 * @see https://github.com/mike-north/vaultkeeper/issues/57
 */
import * as crypto from 'node:crypto'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { describe, it, expect, afterEach } from 'vitest'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliTestEnv } from '@vaultkeeper/cli-test-helpers'

/** Independent SHA-256 reference (the spec) — not the implementation under test. */
function sha256Hex(bytes: string): string {
  return crypto.createHash('sha256').update(bytes).digest('hex')
}

interface RawManifest {
  version: number
  entries: Record<string, { hashes: string[]; trustTier: number }>
}

function isRawManifest(value: unknown): value is RawManifest {
  return (
    typeof value === 'object' &&
    value !== null &&
    'entries' in value &&
    typeof value.entries === 'object' &&
    value.entries !== null
  )
}

async function readManifest(configDir: string): Promise<RawManifest> {
  const raw = await fs.readFile(path.join(configDir, 'trust-manifest.json'), 'utf8')
  const parsed: unknown = JSON.parse(raw)
  if (!isRawManifest(parsed)) {
    throw new Error('unexpected manifest shape')
  }
  return parsed
}

describe('approve command', () => {
  let env: CliTestEnv | undefined

  afterEach(async () => {
    if (env !== undefined) {
      await env.cleanup()
      env = undefined
    }
  })

  it('should approve a script and exit 0', async () => {
    env = await createCliTestEnv()
    const script = path.join(env.configDir, 'test.sh')
    await fs.writeFile(script, '#!/bin/sh\necho hi\n', { mode: 0o755 })

    const result = await env.run(['approve', '--script', script])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('Approved')
  })

  // Criterion 1 + Criterion 7 (approve writes the manifest file):
  it('writes the script SHA-256 into trust-manifest.json', async () => {
    env = await createCliTestEnv()
    const contents = '#!/bin/sh\necho deploy\n'
    const script = path.join(env.configDir, 'deploy.sh')
    await fs.writeFile(script, contents, { mode: 0o755 })

    const result = await env.run(['approve', '--script', script])
    expect(result.exitCode).toBe(0)

    const manifest = await readManifest(env.configDir)
    const entry = manifest.entries[path.resolve(script)]
    expect(entry).toBeDefined()
    expect(entry?.hashes).toEqual([sha256Hex(contents)])
  })

  // Criterion 1: idempotent — twice exits 0 both times, one entry, one hash.
  it('is idempotent across repeated approvals', async () => {
    env = await createCliTestEnv()
    const contents = 'payload\n'
    const script = path.join(env.configDir, 'tool.sh')
    await fs.writeFile(script, contents, { mode: 0o755 })

    const first = await env.run(['approve', '--script', script])
    const second = await env.run(['approve', '--script', script])
    expect(first.exitCode).toBe(0)
    expect(second.exitCode).toBe(0)

    const manifest = await readManifest(env.configDir)
    const entry = manifest.entries[path.resolve(script)]
    expect(entry?.hashes).toEqual([sha256Hex(contents)])
  })

  // Criterion 2: nonexistent path exits non-zero, error names the path.
  it('exits non-zero and names the missing path', async () => {
    env = await createCliTestEnv()
    const missing = path.join(env.configDir, 'nope.sh')

    const result = await env.run(['approve', '--script', missing])
    expect(result.exitCode).not.toBe(0)
    expect(result.stderr).toContain(path.resolve(missing))
    // No manifest is written for a failed approval.
    await expect(readManifest(env.configDir)).rejects.toThrow()
  })
})
