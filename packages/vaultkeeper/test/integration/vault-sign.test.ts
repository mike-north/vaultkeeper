/**
 * Integration tests for VaultKeeper sign() and verify().
 *
 * Exercises the full flow: init → store key → setup → authorize → sign → verify.
 *
 * @see https://nodejs.org/api/crypto.html#ed25519-and-ed448
 */

import * as crypto from 'node:crypto'
import { describe, it, expect, beforeEach } from 'vitest'
import { VaultKeeper, BackendRegistry } from '../../src/index.js'
import type { VaultConfig, SecretBackend } from '../../src/index.js'
import { createInMemoryBackend } from '../helpers/backend.js'

const TEST_CONFIG: VaultConfig = {
  version: 1,
  backends: [{ type: 'memory', enabled: true }],
  keyRotation: { gracePeriodDays: 1 },
  defaults: { ttlMinutes: 5, trustTier: 1 },
  developmentMode: { executables: ['dev'] },
}

function generateEd25519Pem(): { privatePem: string; publicPem: string } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519')
  return {
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  }
}

let backend: SecretBackend

beforeEach(() => {
  backend = createInMemoryBackend()
  BackendRegistry.register('memory', () => backend)
})

async function createVault(): Promise<VaultKeeper> {
  return VaultKeeper.init({ skipDoctor: true, config: TEST_CONFIG })
}

describe('VaultKeeper sign/verify integration', () => {
  it('full flow: setup → authorize → sign → static verify', async () => {
    const { privatePem, publicPem } = generateEd25519Pem()
    await backend.store('signing-key', privatePem)

    const vault = await createVault()
    const jwe = await vault.setup('signing-key')
    const { token } = await vault.authorize(jwe)

    const data = 'gate1:abc123:1706000000'
    const { result } = await vault.sign(token, { data })

    expect(result.algorithm).toBe('ed25519')
    expect(result.signature).toBeTruthy()

    const valid = VaultKeeper.verify({
      data,
      signature: result.signature,
      publicKey: publicPem,
    })
    expect(valid).toBe(true)
  })

  it('verify rejects tampered data', async () => {
    const { privatePem, publicPem } = generateEd25519Pem()
    await backend.store('signing-key', privatePem)

    const vault = await createVault()
    const jwe = await vault.setup('signing-key')
    const { token } = await vault.authorize(jwe)

    const { result } = await vault.sign(token, { data: 'original' })

    const valid = VaultKeeper.verify({
      data: 'tampered',
      signature: result.signature,
      publicKey: publicPem,
    })
    expect(valid).toBe(false)
  })

  it('returns vaultResponse with keyStatus', async () => {
    const { privatePem } = generateEd25519Pem()
    await backend.store('signing-key', privatePem)

    const vault = await createVault()
    const jwe = await vault.setup('signing-key')
    const { token } = await vault.authorize(jwe)

    const { vaultResponse } = await vault.sign(token, { data: 'test' })

    expect(vaultResponse.keyStatus).toBe('current')
  })
})
