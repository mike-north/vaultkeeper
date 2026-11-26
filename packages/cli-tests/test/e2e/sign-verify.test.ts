/**
 * UATs for the signing surface: `key create`, `key export`, `sign`, `verify`.
 *
 * These drive the real CLI as a subprocess, covering pipeline-safety (the
 * signature is the only thing on stdout), the empty-stdin usage error, and the
 * full exit-code matrix including `verify`'s exit 3 for a bad signature.
 *
 * Signature format under test: detached-payload Compact JWS
 * (RFC 7515 §7.2.2 + RFC 7797 b64:false, crit:["b64"], alg EdDSA).
 *
 * @see https://www.rfc-editor.org/rfc/rfc7515
 * @see https://www.rfc-editor.org/rfc/rfc7797
 */
import { describe, it, expect, afterEach } from 'vitest'
import * as fs from 'node:fs/promises'
import * as path from 'node:path'
import { createCliTestEnv } from '@vaultkeeper/cli-test-helpers'
import type { CliTestEnv } from '@vaultkeeper/cli-test-helpers'

const PAYLOAD = 'gate1:abc123:1706000000'

let env: CliTestEnv | undefined

/** Create the test env, tracking it for cleanup, and return it narrowed. */
async function newEnv(): Promise<CliTestEnv> {
  env = await createCliTestEnv()
  return env
}

afterEach(async () => {
  if (env !== undefined) {
    await env.cleanup()
    env = undefined
  }
})

/** Enroll a signing key and return the exported SPKI PEM public key path. */
async function enrollAndExport(e: CliTestEnv, name: string): Promise<string> {
  const created = await e.run([
    'key',
    'create',
    '--name',
    name,
    '--type',
    'ed25519',
    '--skip-doctor',
  ])
  expect(created.exitCode).toBe(0)
  const exported = await e.run(['key', 'export', '--name', name, '--skip-doctor'])
  expect(exported.exitCode).toBe(0)
  expect(exported.stdout).toContain('-----BEGIN PUBLIC KEY-----')
  const pubPath = path.join(e.configDir, `${name}.pub`)
  await fs.writeFile(pubPath, exported.stdout, 'utf8')
  return pubPath
}

/** Sign PAYLOAD with the named key and return the signature file path. */
async function signPayload(e: CliTestEnv, name: string, payload: string): Promise<string> {
  const signed = await e.runWithStdin(['sign', '--name', name, '--skip-doctor'], payload)
  expect(signed.exitCode).toBe(0)
  const sigPath = path.join(e.configDir, `${name}.sig`)
  await fs.writeFile(sigPath, signed.stdout, 'utf8')
  return sigPath
}

describe('key create (AC1)', () => {
  it('provisions an ed25519 signing key (exit 0)', async () => {
    const e = await newEnv()
    const result = await e.run([
      'key',
      'create',
      '--name',
      'k',
      '--type',
      'ed25519',
      '--skip-doctor',
    ])
    expect(result.exitCode).toBe(0)
  })

  it('unknown --type exits 2 with no silent default', async () => {
    const e = await newEnv()
    const result = await e.run(['key', 'create', '--name', 'k', '--type', 'rsa', '--skip-doctor'])
    expect(result.exitCode).toBe(2)
    expect(result.stderr).toContain("unknown --type 'rsa'")
  })

  it('missing --type exits 2', async () => {
    const e = await newEnv()
    const result = await e.run(['key', 'create', '--name', 'k', '--skip-doctor'])
    expect(result.exitCode).toBe(2)
  })

  it('missing --name exits 2', async () => {
    const e = await newEnv()
    const result = await e.run(['key', 'create', '--type', 'ed25519', '--skip-doctor'])
    expect(result.exitCode).toBe(2)
  })
})

describe('key export (AC2)', () => {
  it('prints the SPKI PEM public key to stdout', async () => {
    const e = await newEnv()
    await e.run(['key', 'create', '--name', 'k', '--type', 'ed25519', '--skip-doctor'])
    const result = await e.run(['key', 'export', '--name', 'k', '--skip-doctor'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('-----BEGIN PUBLIC KEY-----')
    expect(result.stdout).toContain('-----END PUBLIC KEY-----')
  })

  it('a missing signing key exits 1 with SigningKeyNotFoundError', async () => {
    const e = await newEnv()
    const result = await e.run(['key', 'export', '--name', 'nope', '--skip-doctor'])
    expect(result.exitCode).toBe(1)
    expect(result.stderr).toContain('SigningKeyNotFoundError')
  })
})

describe('sign (AC3, AC9 pipeline-safety)', () => {
  it('writes exactly the detached JWS to stdout and nothing else', async () => {
    const e = await newEnv()
    await e.run(['key', 'create', '--name', 'k', '--type', 'ed25519', '--skip-doctor'])
    const signed = await e.runWithStdin(['sign', '--name', 'k', '--skip-doctor'], PAYLOAD)
    expect(signed.exitCode).toBe(0)
    // stdout is exactly one line: the compact detached JWS (empty payload segment).
    const lines = signed.stdout.split('\n').filter((l) => l.length > 0)
    expect(lines).toHaveLength(1)
    const parts = (lines[0] ?? '').split('.')
    expect(parts).toHaveLength(3)
    expect(parts[1]).toBe('')
    // The default-backend notice and any status must be on stderr, not stdout.
    expect(signed.stdout).not.toContain('No config file found')
  })

  it('empty stdin exits 2 (usage)', async () => {
    const e = await newEnv()
    await e.run(['key', 'create', '--name', 'k', '--type', 'ed25519', '--skip-doctor'])
    const signed = await e.runWithStdin(['sign', '--name', 'k', '--skip-doctor'], '')
    expect(signed.exitCode).toBe(2)
    expect(signed.stderr).toContain('no payload provided on stdin')
  })

  it('signing with a missing key exits 1', async () => {
    const e = await newEnv()
    const signed = await e.runWithStdin(['sign', '--name', 'nope', '--skip-doctor'], PAYLOAD)
    expect(signed.exitCode).toBe(1)
  })
})

describe('verify exit-code matrix (AC4, AC9)', () => {
  it('exit 0 for a valid signature, verified offline against the exported key', async () => {
    const e = await newEnv()
    const pubPath = await enrollAndExport(e, 'k')
    const sigPath = await signPayload(e, 'k', PAYLOAD)
    const result = await e.runWithStdin(
      ['verify', '--public-key', pubPath, '--signature', sigPath],
      PAYLOAD,
    )
    expect(result.exitCode).toBe(0)
  })

  it('exit 3 for a tampered payload', async () => {
    const e = await newEnv()
    const pubPath = await enrollAndExport(e, 'k')
    const sigPath = await signPayload(e, 'k', PAYLOAD)
    const result = await e.runWithStdin(
      ['verify', '--public-key', pubPath, '--signature', sigPath],
      'tampered-payload',
    )
    expect(result.exitCode).toBe(3)
  })

  it('exit 3 for the wrong public key', async () => {
    const e = await newEnv()
    const pubPath = await enrollAndExport(e, 'k')
    const sigPath = await signPayload(e, 'k', PAYLOAD)
    // Export a different key and verify the first signature against it.
    const otherPub = await enrollAndExport(e, 'other')
    const result = await e.runWithStdin(
      ['verify', '--public-key', otherPub, '--signature', sigPath],
      PAYLOAD,
    )
    expect(result.exitCode).toBe(3)
    // Sanity: the original key still verifies (proves the sig itself is good).
    const good = await e.runWithStdin(
      ['verify', '--public-key', pubPath, '--signature', sigPath],
      PAYLOAD,
    )
    expect(good.exitCode).toBe(0)
  })

  it('exit 3 for a malformed JWS', async () => {
    const e = await newEnv()
    const pubPath = await enrollAndExport(e, 'k')
    const sigPath = path.join(e.configDir, 'bad.sig')
    await fs.writeFile(sigPath, 'this-is-not-a-jws', 'utf8')
    const result = await e.runWithStdin(
      ['verify', '--public-key', pubPath, '--signature', sigPath],
      PAYLOAD,
    )
    expect(result.exitCode).toBe(3)
  })

  it('exit 2 for missing flags', async () => {
    const e = await newEnv()
    const result = await e.runWithStdin(['verify'], PAYLOAD)
    expect(result.exitCode).toBe(2)
  })

  it('exit 2 for empty stdin', async () => {
    const e = await newEnv()
    const pubPath = await enrollAndExport(e, 'k')
    const sigPath = await signPayload(e, 'k', PAYLOAD)
    const result = await e.runWithStdin(
      ['verify', '--public-key', pubPath, '--signature', sigPath],
      '',
    )
    expect(result.exitCode).toBe(2)
  })

  it('exit 1 for an unreadable signature file (operational fault)', async () => {
    const e = await newEnv()
    const pubPath = await enrollAndExport(e, 'k')
    const missingSig = path.join(e.configDir, 'does-not-exist.sig')
    const result = await e.runWithStdin(
      ['verify', '--public-key', pubPath, '--signature', missingSig],
      PAYLOAD,
    )
    expect(result.exitCode).toBe(1)
  })

  it('exit 1 for an unparseable public key (operational fault)', async () => {
    const e = await newEnv()
    const badPub = path.join(e.configDir, 'bad.pub')
    await fs.writeFile(badPub, 'not a pem', 'utf8')
    await enrollAndExport(e, 'k')
    const sigPath = await signPayload(e, 'k', PAYLOAD)
    const result = await e.runWithStdin(
      ['verify', '--public-key', badPub, '--signature', sigPath],
      PAYLOAD,
    )
    expect(result.exitCode).toBe(1)
  })
})
